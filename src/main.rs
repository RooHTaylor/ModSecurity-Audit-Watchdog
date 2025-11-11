use clap::Parser;
use std::{
    fs::{File,OpenOptions},
    path::PathBuf,
    sync::{
        Arc,
        Mutex,
        mpsc,
    },
    thread,
    time::Duration,
    io::{BufRead, BufReader}
};
use log::{error, info, debug, trace};
use notify_debouncer_full::{
    new_debouncer,
    notify::{RecursiveMode, EventKind, event::ModifyKind, event::CreateKind}
};
use regex::Regex;
use once_cell::sync::Lazy;

/// Parse a modsecurity audit logfile or directory and consolidate volations into
/// a single syslog-style logfile
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// ModSecurity Audit log file or folder to parse
    #[arg(short, long)]
    input: PathBuf,

    /// Output log file
    #[arg(short, long)]
    output: PathBuf,

    /// Number of threads to use. (File mode ONLY)
    #[arg(short)]
    threads: Option<u8>,

    /// Toggle debug messages (INFO, DEBUG, TRACE) (-d -dd -ddd)
    #[arg(short, default_value_t = 0, action = clap::ArgAction::Count)]
    debug: u8,
}

fn main() -> Result<(), ()> {
    let args = Args::parse();

    // Get debug level from args to define the level of logging to use
    let log_level = match args.debug {
        0 => "error",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    // Enable logging at specified level
    env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or(log_level)
    ).init();
    info!("Log level: {}", log_level);
    debug!("Arguments: {:?}", args);

    // Leave main to execute the program. Return a Result.
    let result = match begin_watching(args.input, args.output, args.threads) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("{}", e);
            Err(())
        }
    };

    result
}

// Check if input exists.  Open output file.
// Create a thread pool and a crossbeam_channel to process the paths we find
// Create a notify watcher with 2sec debounce to capture OS notifications of 
//    new or modified files at the input.
// Pass notification paths to the crossbeam_channel to be picked up by threads
// TODO: implement parse function to parse file (from a last point if input is file)
fn begin_watching(input: PathBuf, output: PathBuf, num_threads_arg: Option<u8>) -> Result<(), String> {
    
    // Check if the file or folder exists.
    let input_string = input.to_string_lossy().to_string();
    match input.try_exists() {
        Ok(true) => {
            info!("Input file/folder {} exists.", input_string);
        },
        Ok(false) => {
            return Err(format!("Input file/folder {} does not exist!",
                input_string))
        },
        Err(e) => {
            trace!("{}", e);
            return Err(format!("Input file/folder {} could not be accessed!",
                input_string))
        }
    }

    // Open the output file for appending.  Wrap in Arc<Mutex<File>> for thread
    // safety
    let output_file = match open_output_file(&output) {
        Ok(f) => f,
        Err(e) => {
            return Err(e)
        }
    };

    // If we're only wathcing a file we only need 1 thread, but it we're
    // watching a folder spawn up to x threads.
    let num_threads = if input.is_dir() {
        let num_threads = match num_threads_arg {
            Some(n) => n,
            None => 4,
        };
        debug!("Input is a directory. Running {} threads.", num_threads);
        num_threads
    } else {
        debug!("Input is a file. Running 1 thread.");
        1
    };

    // Setup worker thread pool
    let (sender, receiver) = crossbeam_channel::unbounded::<PathBuf>();
    let mut threads = Vec::with_capacity(num_threads as usize);

    for i in 0..num_threads {
        let r = receiver.clone();
        let out_file = output_file.clone();
        
        let handle = thread::spawn(move || {
            trace!("[Thread {}] Worker started.", i);
            while let Ok(job_path) = r.recv() {
                // TODO: Process path notification
                info!("[Thread {}] Got a new notification for: {}", i, job_path.to_string_lossy());
                let _ = parse_audit_file(&job_path);
            }
            trace!("[Thread {}] Worker shutting down.", i);
        });
        threads.push(handle);
    }

    // Create an mpsc channel to queue the notifications.
    // Also create a debouncer to wait for 2 seconds before pshing to the channel
    let (tx, rx) = mpsc::channel();
    let mut debouncer = match new_debouncer(Duration::from_secs(2), None, tx) {
        Ok(d) => d,
        Err(e) => {
            return Err(e.to_string())
        }
    };
    debug!("Created channel debouncer for notifications");

    let recursive = if input.is_dir() {
        debug!("Input is a directory. Running watcher recursively.");
        RecursiveMode::Recursive
    } else {
        debug!("Input is a file. Running watcher non-recursively.");
        RecursiveMode::NonRecursive
    };

    match debouncer.watch(input.clone(), recursive) {
        Ok(_) => {},
        Err(e) => {
            return Err(e.to_string())
        }
    }
    info!("Watching {} ", input_string);

    // Loop over rx results for notify events
    for result in rx {
        match result {
            Ok(events) => {
                trace!("Got debounced events {:?}", events);
                // Due to the debounce, we will get a list of events
                // Loop over each event to check them
                for db_event in events {
                    trace!("Looking at debounced event: {:?}", db_event);
                    let event = db_event.event;
                    
                    // We want anything new or anything changed
                    if event.kind == EventKind::Create(
                        CreateKind::Any
                    ) || event.kind == EventKind::Modify(
                        ModifyKind::Any
                    ) {
                        debug!("Found relevant event: {:?}", event);
                        for path in &event.paths {
                            trace!("Looking at path {:?}", path);
                            match sender.send(path.clone()) {
                                Ok(_) => {
                                    debug!("Event path queued.");
                                },
                                Err(e) => {
                                    debug!(
                                        "Error queuing event path {}",
                                        path.to_string_lossy());
                                    trace!("{:?}", e);
                                }
                            }
                        }
                    }
                }
            },
            Err(e) => {
                debug!("Watch error!");
                trace!("{:?}", e);
            }
        }
    }

    // Wait for threads to finish.
    for handle in threads {
        handle.join().unwrap();
    }

    Ok(())
}

fn open_output_file(filepath: &PathBuf) -> Result<Arc<Mutex<File>>, String> {
    let file_string = filepath.to_string_lossy().to_string();
    let file = match OpenOptions::new()
        .append(true)
        .create(true)
        .open(filepath)
    {
        Ok(f) => {
            info!("Opened {}", file_string);
            Arc::new(Mutex::new(f))
        },
        Err(e) => {
            trace!("{e}");
            return Err(format!("Unable to create or open file {}",
                file_string))
        }
    };

    Ok(file)
}

// lazy load the regex for section headers
static SECTION_HEAD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^---(?P<tid>[a-zA-Z0-9]{8})---(?P<section>[A-Z])--"#
    ).unwrap()
});

// lazy load the regex for section A (connection summary)
static SUMMARY_A_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^\[(?P<datetime>[0-9]{1,2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}\s[0-9\-]+)\]\s[0-9]+\.[0-9]+\s(?P<ip>(?:(?:(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[a-fA-F0-9]{1,4}:){1,7}:?[a-fA-F0-9]{1,4}))\s[0-9]+\s(?:(?:(?:(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[a-fA-F0-9]{1,4}:){1,7}:?[a-fA-F0-9]{1,4}))\s[0-9]+"#
    ).unwrap()
});

// Parse a file using a PathBuf. Fail quickly if it doesn't look like an audit file.
fn parse_audit_file(filepath: &PathBuf) -> Result<(), String> {
    trace!("Parsing audit file {:?}", filepath);

    // Open the file to read
    let file = match File::open(filepath) {
        Ok(f) => f,
        Err(e) => {
            trace!("{:?}", e);
            return Err("Failed to open input file!".to_string())
        }
    };
    // Buffer read the output to save on memory and time. Logs can get BIG
    let reader = BufReader::new(file);

    let mut section: Option<Section> = None;
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                trace!("{:?}", e);
                continue;
            }
        };

        // Skip empty lines
        if line.trim().is_empty() {
            trace!("Empty line");
            continue;
        }

        // Check if the line is a section header and parse the new section
        if SECTION_HEAD_REGEX.is_match(line.trim()) {
            trace!("Section header match");
            // Safe to use unwrap here, because we already check for a match
            let caps = SECTION_HEAD_REGEX
                .captures(line.trim())
                .unwrap();
            debug!("Section {}", &caps["section"]);
            section = match &caps["section"] {
                "A" => Some(Section::A),
                "B" => Some(Section::B),
                "C" => Some(Section::C),
                "D" => Some(Section::D),
                "E" => Some(Section::E),
                "F" => Some(Section::F),
                "G" => Some(Section::G),
                "H" => Some(Section::H),
                "I" => Some(Section::I),
                "J" => Some(Section::J),
                "K" => Some(Section::K),
                "Z" => None,
                _ => {
                    debug!(
                        "Invalid section letter {:?}",
                         caps["section"].to_string()
                    );
                    continue;
                }
            };
            continue;
        }

        match section {
            Some(Section::A) => {
                trace!("Processing section A");
                if SUMMARY_A_REGEX.is_match(line.trim()) {
                    trace!("Connection summary match!");
                    // Safe to use unwrap here, because we already check for a match
                    let caps = SUMMARY_A_REGEX
                        .captures(line.trim())
                        .unwrap();
                    debug!("{:?}", caps);
                }
            },
            _ => {
                continue;
            }
        }

    }

    Ok(())
}

enum Section {
    A, // Audit log header (mandatory).
    B, //Request headers.
    C, //Request body.
    D, //Reserved for intermediary response headers; not implemented yet.
    E, //Intermediary response body
    F, //Final response headers
    G, //Reserved for the actual response body; not implemented yet.
    H, //Audit log trailer.
    I, //This part has not been implemented in ModSecurity v3.
    J, //This part contains information about the files uploaded using multipart/form-data encoding.
    K, // This part has not been implemented in ModSecurity v3.
    _Z, // Final boundary, signifies the end of the entry (mandatory).
}