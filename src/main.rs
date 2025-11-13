use clap::Parser;
use std::{
    fs::{
        File, OpenOptions,
    },
    io::{
        BufRead, BufReader, Write,
    },
    sync::{
        Arc, Mutex, mpsc,
        atomic::{
            AtomicBool, Ordering,
        },
    },
    net::{
        IpAddr,
    },
    thread, time::Duration, fmt, path::PathBuf, process,
};
use log::{
    error, info, debug, trace,
};
use notify_debouncer_full::{
    new_debouncer,
    notify::{
        RecursiveMode, EventKind, event::ModifyKind, event::CreateKind
    },
};
use regex::Regex;
use once_cell::sync::Lazy;
use chrono::{
    DateTime, FixedOffset,
};
use iprange::IpRange;
use ipnet::{
    IpNet,
    Ipv4Net,
    Ipv6Net,
};

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

    /// We're behind a proxy
    #[arg(short, default_value_t = false)]
    proxy: bool,

    /// Tusted Proxy IP addresses
    #[arg(long)]
    trusted_proxies: Option<String>,

    /// Check for CloudFlare headers
    #[arg(short, long, default_value_t = false)]
    cf: bool,

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

    // Capture Ctrl+C key-presses to cleanly exit the program instead of exiting
    // immediately. Use the AtomicBools to share the running state of the program
    // across threads, and base the running state of the loops on this. When the
    // Ctrl+C interupt is pressed the running state will become false, which will
    // stop the loops on their next itteration, allowing all the threads to finish,
    // join, and then exit main.
    // If Ctrl+C is pressed a second time, the process will forcefully terminate
    let running = Arc::new(AtomicBool::new(true));
    let first_interrupt = Arc::new(AtomicBool::new(true));
    {
        let running = Arc::clone(&running);
        let first_interrupt = Arc::clone(&first_interrupt);
        ctrlc::set_handler(move || {
            // Swap the value of first_interrupt for false and return the previous
            // value. If this value is false, we've already swapped it once, so
            // Ctrl+C has already been pressed. This means we want to forcefully
            // terminate now.
            if first_interrupt.swap(false, Ordering::SeqCst) {
                info!(
                    "\nGraceful shutdown requested (Ctrl+C). Finishing remaining work..."
                );
                running.store(false, Ordering::SeqCst);
            } else {
                error!("Force quitting!");
                process::exit(1);
            }
        }).expect("Error setting Ctrl-C handler");
    }
    
    let trusted_proxies = parse_trusted_ips(args.trusted_proxies);

    // Leave main to execute the program. Return a Result which will be the main
    // exit state.
    let result = match begin_watching(
        args.input,
        args.output,
        args.proxy,
        trusted_proxies,
        args.cf,
        args.threads,
        running
    ) {
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
// Threads pull paths from the channel and run parse_audit_file()
// TODO: add logic for parsing trusted proxy ip addresses to match X-Forwarded-For
fn begin_watching(
    input: PathBuf,
    output: PathBuf,
    proxy: bool,
    trusted_proxies: (IpRange<Ipv4Net>, IpRange<Ipv6Net>),
    cf_headers: bool,
    num_threads_arg: Option<u8>,
    running: Arc<AtomicBool>,
) -> Result<(), String> {
    
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
    // safety. Do this here so we haev earlier failure if we can't open the file.
    let output_file = match open_output_file(&output) {
        Ok(f) => f,
        Err(e) => {
            return Err(e)
        }
    };

    // If we're only wathcing a file we only need 1 thread, but if we're
    // watching a folder, spawn up to x threads in a pool.
    // TODO: move the thread pool logic into a struct someday
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

    // Setup worker thread pool and the queue for the discovered files to pass to
    // the threads
    let (sender, receiver) = crossbeam_channel::unbounded::<PathBuf>();
    let mut threads = Vec::with_capacity(num_threads as usize);
    let trusted_proxies_arc = Arc::new(trusted_proxies);
    let cf_headers_arc = Arc::new(cf_headers);
    let proxy_arc = Arc::new(proxy);

    for i in 0..num_threads {
        let r = receiver.clone();
        let out_file = output_file.clone();
        let running_clone = running.clone();
        let trusted_proxies_clone = Arc::clone(&trusted_proxies_arc);
        let cf_headers_clone = cf_headers_arc.clone();
        let proxy_clone = proxy_arc.clone();
        
        let handle = thread::spawn(move || {
            trace!("[Thread {}] Worker started.", i);
            // Loop on the running AtomicBool to allow graceful exiting.
            while running_clone.load(Ordering::SeqCst) {
                // On each itteration, try to grab a message from the queue
                match r.recv_timeout(Duration::from_secs(1)) {
                    // We got a message
                    Ok(job_path) => {
                        info!(
                            "[Thread {}] Got a new notification for: {}",
                            i,
                            job_path.to_string_lossy()
                        );

                        // Parse the path we pulled out of the queue. This will
                        // either give us a LogMessage that we can write to the
                        // output file, or an Error message.
                        let result = parse_audit_file(&job_path, &proxy_clone, &trusted_proxies_clone, &cf_headers_clone, &out_file);
                        match result {
                            Ok(_) => {
                                
                            }, Err(e) => {
                                // Only trace log here, as there may not have been
                                // an actual problem. Could have just not been an
                                // audit file. Debug log in the function itself.
                                trace!("{:?}", e);
                            }
                        }
                    },
                    // We didn't get a message, just loop again. The queue might
                    // just be empty.
                    Err(_e) => {
                        //trace!("{:?}", e);
                        continue
                    },
                }
            }
            // If we're outside the loop the program is stopping.
            trace!("[Thread {}] Worker shutting down.", i);
        });
        threads.push(handle);
    }

    // Start the notify listener to listen for OS notifications of changes at the
    // input.
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

    // If we're watching a file we don't need to be recursive.
    // If we're watching a dir we wan't to watch everything inside too.
    let recursive_mode = if input.is_dir() {
        debug!("Input is a directory. Running watcher recursively.");
        RecursiveMode::Recursive
    } else {
        debug!("Input is a file. Running watcher non-recursively.");
        RecursiveMode::NonRecursive
    };

    // Start the debounced watcher
    match debouncer.watch(input.clone(), recursive_mode) {
        Ok(_) => {},
        Err(e) => {
            return Err(e.to_string())
        }
    }
    info!("Watching {} ", input_string);

    // Loop on the running AtomicBool to allow graceful exiting.
    while running.load(Ordering::SeqCst) {
        // On each iteration, try to grab a notification from the queue
        if let Ok(result) = rx.recv_timeout(Duration::from_secs(1)) {
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
                            // Send each path into the thread pool queue
                            for path in &event.paths {
                                trace!("Looking at path {:?}", path);
                                match sender.send(path.clone()) {
                                    Ok(_) => {
                                        debug!(
                                            "Event path queued. {}",
                                            path.to_string_lossy()
                                        );
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
    }

    // Wait for threads to finish.
    for handle in threads {
        handle.join().unwrap();
    }

    Ok(())
}


// A helper function to create and open the output logfile for appending.
// The file handle is wrapped in an Arc<Mutex<>> for thread safety.
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

// Lazy load the regex for section headers
// Named capture groups: tid, section
static SECTION_HEAD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^---(?P<tid>[a-zA-Z0-9]{8})---(?P<section>[A-KZ])--$"#
    ).unwrap()
});

// Lazy load the regex for section A (connection summary)
// Named capture groups: datetime, ip
static SUMMARY_A_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(?i)\[(?P<datetime>[0-9]{1,2}/[a-z]{3}/[0-9]{4}:[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}\s[0-9\-]+)\]\s[0-9]+\.[0-9]+\s(?P<ip>(?:[0-9\.]+|[0-9a-f:]+))\s[0-9]+\s(?:(?:[0-9\.]+|[0-9a-f:]+))\s[0-9]+$"#
    ).unwrap()
});

// Lazy load the regex for section B (CF-Connecting-IP)
// Named capture groups: ip
static CFIP_B_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(?i)cf-connecting-ip:\s+(?P<ip>(?:(?:[0-9\.]+)|(?:[a-f0-9:]+)))$"#
    ).unwrap()
});

// Lazy load the regex for section B (X-Forwarded-For)
// Named capture groups: ips
static XFFIPS_B_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(?i)x-forwarded-for:\s+(?P<ips>(?:(?:(?:[0-9\.]+)|(?:[a-f0-9:]+)))(?:,\s*(?:(?:[0-9\.]+)|(?:[a-f0-9:]+)))*)$"#
    ).unwrap()
});

// Lazy load the regex for section H (rule violations)
// Named capture groups: ruleid, msg, hostname, uri
static VIOLATION_H_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^ModSecurity:.*\[id\s+"(?P<ruleid>[0-9]+)"\].*\[msg\s+"(?P<msg>[\d\w\s`~!@#$%^&*()\-_=+\[{\]};:',<.>/\?\\\|]+)"\].*\[hostname\s+"(?P<hostname>\S+)"\]\s+\[uri\s+"(?P<uri>\S+)"\].*$"#
    ).unwrap()
});

// Parse a file path for audit messages. Open the file and loop over it line by
// line, matching each line against different Regex patterns depending on the
// section we're in.
fn parse_audit_file(
    filepath: &PathBuf,
    proxy: &Arc<bool>,
    trusted_proxies: &Arc<(IpRange<Ipv4Net>, IpRange<Ipv6Net>)>,
    cf_headers: &Arc<bool>,
    out_file: &Arc<Mutex<File>>,
) -> Result<(), String> {
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

    // The captures we need
    let mut datetime: Option<DateTime<chrono::FixedOffset>> = None;
    let mut client_ip: Option<IpAddr> = None;
    let mut messages: Vec<String> = Vec::new();
    let mut cfip_match: bool = false; // Client IP set from CF-Connecting-IP
    let mut xffip_list: Vec<IpAddr> = Vec::new(); // List of IPs from X-Forwarded-For

    let mut section: Option<Section> = None;
    // Loop over the buffered lines
    for line_result in reader.lines() {
        // Unwrap the line
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

        // Check if the line is a section header
        if SECTION_HEAD_REGEX.is_match(line.trim()) {
            trace!("Section header match");
            // Safe to use unwrap on captures() here because we already confirmed
            // a match above.
            let caps = SECTION_HEAD_REGEX
                .captures(line.trim())
                .unwrap();
            debug!("Section {}", &caps["section"]);
            let prev_section = section.clone();
            // Match the section letter to the enum
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
                "Z" => Some(Section::Z),
                _ => {
                    debug!(
                        "Invalid section letter {:?}",
                         caps["section"].to_string()
                    );
                    continue;
                }
            };

            // If we know we're behind a proxy and we're leaving section B and
            // don't have a better client IP, then check X-Forwarded-For.
            if 
                **proxy &&
                prev_section == Some(Section::B) &&
                (!**cf_headers || !cfip_match ) &&
                xffip_list.len() > 0
            {
                debug!("We're leaving section B and there are XFF ips to review.");

                xffip_list.reverse();

                for ip in &xffip_list {
                    trace!("Checking if {:?} is trusted", ip);
                    match ip {
                        IpAddr::V4(ipv4) => {
                            let net = Ipv4Net::from(*ipv4);
                            if trusted_proxies.0.contains(&net) {
                                continue;
                            }
                        },
                        IpAddr::V6(ipv6) => {
                            let net = Ipv6Net::from(*ipv6);
                            if trusted_proxies.1.contains(&net) {
                                continue;
                            }
                        }
                    }

                    trace!("{} is NOT trusted!", ip);

                    client_ip = Some(*ip);
                    if let Some(ip) = client_ip {
                        debug!("Set client ip to {} based on X-Forwarded-For", ip);
                    }
                    break;
                }
            }

            // If we found a new section we can skip to the next line with the
            // section set.
            if section != Some(Section::Z) {
                continue;
            }
        }

        // If we don't have a section header, check each line for the appropriate
        // regex patterns based on the section we're in.
        match section {
            
            Some(Section::A) => {
                // We're in section A.  We should be looking for the connection 
                // summary. Check each line against that regex.
                trace!("Processing section A");
                if SUMMARY_A_REGEX.is_match(line.trim()) {
                    debug!("Connection summary match!");
                    // Safe to use unwrap on captures() here because we already
                    // confirmed a match above.
                    let caps = SUMMARY_A_REGEX
                        .captures(line.trim())
                        .unwrap();
                    trace!("{:?}", caps);

                    // Timestamp should be in typical Apache log format.
                    // Parse into Rust DateTime. The DateTime is mandatory for
                    // logging, so if we can't parse the timestamp then we skip
                    // processing this line.
                    let dt_string: String = caps["datetime"].to_string();
                    let dt_fmt = "%d/%b/%Y:%H:%M:%S %z";
                    datetime = Some(match DateTime::parse_from_str(&dt_string, dt_fmt) {
                        Ok(d) => d,
                        Err(e) => {
                            debug!("Failed to parse datetime");
                            trace!("{:?}", e);
                            continue;
                        }
                    });

                    // Set the client ip address to the connection IP address
                    // for now. May overwrite this later if a more accurate ip
                    // address is found. (e.g. behind a proxy)
                    let ip_string = caps["ip"].to_string();
                    client_ip = match ip_string.parse::<IpAddr>(){
                        Ok(ip) => Some(ip),
                        Err(e) => {
                            error!("Couldn't parse connection IP!");
                            trace!("{:?}", e);
                            continue;
                        }
                    };
                    if let Some(ip) = client_ip {
                        debug!("Set client ip to {} based on connection IP", ip);
                    }
                }
            },
            Some(Section::B) => {
                // We're in section B.  We should be looking for x-forwarded-for
                // HTTP headers, to see if there is a more accurate client-ip
                trace!("Processing section B");

                if !**proxy {
                    debug!("We aren't behind a proxy, so there's nothing we need in B");
                    continue;
                }

                // Check for CF-Connecting-IP header if args flag is set
                // Check for X-Forwarded-For headers. Collect into a list and at
                // the end of section B we will loop over the list in reverse
                // order to find the first IP that isn't "trusted"

                // Check for CF-Connecting-IP and X-Forwarded-For if we don't
                // have it or a bettern match
                if **cf_headers && !cfip_match {
                    trace!("No CF-Connecting-IP found yet");
                    if CFIP_B_REGEX.is_match(line.trim()) {
                        debug!("CF-Connecting-IP match!");
                        // Safe to use unwrap on captures() here because we already
                        // confirmed a match above.
                        let caps = CFIP_B_REGEX
                            .captures(line.trim())
                            .unwrap();
                        trace!("{:?}", caps);

                        // Set the client ip address
                        let ip_string = caps["ip"].to_string();
                        client_ip = match ip_string.parse::<IpAddr>(){
                            Ok(ip) => Some(ip),
                            Err(e) => {
                                error!("Couldn't parse connection IP!");
                                trace!("{:?}", e);
                                continue;
                            }
                        };
                        if let Some(ip) = client_ip {
                            debug!("Set client ip to {} based on CF-Connecting-IP header", ip);
                        }
                        // We found a CF-Connecting-IP
                        cfip_match = true;
                        continue;
                    }
                    trace!("No CF-Connecting-IP header match");
                }

                if XFFIPS_B_REGEX.is_match(line.trim()) {
                    debug!("X-Forward-For match!");
                    // Safe to use unwrap on captures() here because we already
                    // confirmed a match above.
                    let caps = XFFIPS_B_REGEX
                        .captures(line.trim())
                        .unwrap();
                    trace!("{:?}", caps);

                    // Parse the IPs into a Vec to process when leaving section B
                    let ips_string = caps["ips"].to_string();
                    let parts: Vec<&str> = ips_string.split(",").collect();
                    trace!("Found {} potential IPs", parts.len());
                    for pip in parts {
                        let ip = match pip.trim().parse::<IpAddr>() {
                            Ok(i) => i,
                            Err(e) => {
                                debug!("Failed to parse XFF ip");
                                trace!("{:?}", e);
                                continue;
                            }
                        };
                        trace!("Adding {} to X-Forwarded-For header list", ip);
                        xffip_list.push(ip);
                    }
                    continue;
                }
                trace!("No x-forwarded-for header match");
            },
            Some(Section::H) => {
                // We're in section H.
                // This section contains the matched violations. Grab some basic
                // information to drop in logs.
                trace!("Processing section H");

                if VIOLATION_H_REGEX.is_match(line.trim()) {
                    debug!("Connection summary match!");
                    // Safe to use unwrap on captures() here because we already
                    // confirmed a match above.
                    let caps = VIOLATION_H_REGEX
                        .captures(line.trim())
                        .unwrap();
                    trace!("{:?}", caps);

                    let mut message = String::new();
                    message.push_str("[uri ");
                    message.push_str(caps["hostname"].to_string().as_ref());
                    message.push_str(caps["uri"].to_string().as_ref());
                    message.push_str("] [id ");
                    message.push_str(caps["ruleid"].to_string().as_ref());
                    message.push_str("] [msg ");
                    message.push_str(caps["msg"].to_string().as_ref());
                    message.push_str("]");
                    messages.push(message);
                }
            },
            Some(Section::Z) => {
                trace!("Processing section Z");
                debug!("Writing log message.");
                let logmessage = match build_log_message(datetime, client_ip, &messages) {
                    Ok(m) => m,
                    Err(e) => {
                        debug!("Error generating log message!");
                        trace!("{:?}", e);
                        datetime = None;
                        client_ip = None;
                        messages = Vec::new();
                        cfip_match = false;
                        xffip_list = Vec::new();
                        section = None;
                        continue;
                    }
                };
                // Lock the output file [Blocking, so we'll wait for a lock]
                let mut output_file = out_file.lock().unwrap();

                // Try to write to the output_file
                match writeln!(output_file, "{}", logmessage) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Failed to write log line to file");
                        trace!("{:?}", e);
                        datetime = None;
                        client_ip = None;
                        messages = Vec::new();
                        cfip_match = false;
                        xffip_list = Vec::new();
                        section = None;
                        continue;
                    }
                }
                debug!("Resetting captures.");
                // We're in a new section.  Reset our captures.
                datetime = None;
                client_ip = None;
                messages = Vec::new();
                cfip_match = false;
                xffip_list = Vec::new();
                section = None;
            },
            _ => {
                // We're not in a section we care about. Skip to the next line.
                continue;
            }
        }
    }

    Ok(())
}

// Parse the trusted IPs into IpRanges (v4, v6)
fn parse_trusted_ips(input: Option<String>) -> (IpRange<Ipv4Net>, IpRange<Ipv6Net>) {
    let mut ipv4_range: IpRange<Ipv4Net> = IpRange::new();
    let mut ipv6_range: IpRange<Ipv6Net> = IpRange::new();

    if let Some(ipr_string) = input {
        let parts: Vec<&str> = ipr_string.split(",").collect();
        for pipr in parts {
            match pipr.trim().parse() {
                Ok(IpNet::V4(v4)) => {
                    ipv4_range.add(v4);
                },
                Ok(IpNet::V6(v6)) => {
                    ipv6_range.add(v6);
                },
                Err(e) => {
                    debug!("Failed to parse trusted IP");
                    trace!("{:?}", e);
                    continue;
                }
            }
        }
    }

    (ipv4_range, ipv6_range)
}

// Helper function to construct the LogMessage
// Unwrap each element and collapse the Vec of messages. Fail if any of the
// fields are empty/None
fn build_log_message(
    datetime: Option<DateTime<FixedOffset>>,
    client_ip: Option<IpAddr>,
    messages: &Vec<String>
) -> Result<LogMessage, String> {

    if let Some(datetime) = datetime {
        if let Some(client_ip) = client_ip {
            let messages = messages.join(", ");
            let log_message = LogMessage {
                datetime,
                client_ip,
                messages
            };
            return Ok(log_message)
        }
    }

    Err("Could not create log message.".to_string())
}

// The section of the audit log entry.
#[derive(Debug, PartialEq, Clone)]
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
    Z, // Final boundary, signifies the end of the entry (mandatory).
}

// The struct of a log message to be printed out to the log file.
#[derive(Debug)]
struct LogMessage {
    datetime: DateTime<FixedOffset>,
    client_ip: IpAddr,
    messages: String,
}

// Implement Display for LogMessage so we can print it out to the log file in the
// format we desire.
impl fmt::Display for LogMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}] [client {}] {}", self.datetime, self.client_ip, self.messages)
    }
}