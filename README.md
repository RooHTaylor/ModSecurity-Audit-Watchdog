### NOTICE

The develop branch is under active development and breaking changes may be 
pushed. Stable versions will be available as releases or in the main branch.

# ModSecurity-Audit-Watchdog

A simple log translator in Rust. ModSecurity audit logs are difficult to use on 
the best of days, so I created a tool that will parse the audit entries into a 
more typical syslog style format.

## Goal

The goal was to monitor 1 or more ModSecurity audit logfiles for creation or
changes, and parse those changes line by line to pull out relevant information
like transaction time, client IP address, and rule violations.

## Implementation

My implementation is very simple. An input directory or file is provided via 
command line argument. If the input is a directory, ModSecurity-Audit-Watchdog 
(MAW) will spawn a variable sized thread-pool and begin monitoring the folder 
for changes using the notify crate. As the OS detects changes, they're pushed 
into a channel which MAW will check for creation or modifications. If a valid 
change is detected, that path is pushed into a queue for the thread pool. The 
next available thread will grab the next path from the queue and attempt to 
parse the file line by line using Regex to match the individual sections and
grab the desired data. It then saves that data into a seperate logfile in a more
syslog-style format.

## Requrements

Requires at least ModSecurity v3, configured for either Serial or Concurrent 
audit logging, with sections A and H at a minimum.

Requires cargo to compile.

## Installation

```bash
git clone https://github.com/RooHTaylor/ModSecurity-Audit-Watchdog.git
cd ModSecurity-Audit-Watchdog
cargo build --release
```

Binaries will be available in `target/release/`

## Usage

```bash
./modsecurity-audit-watchdog --input /path/to/audit.log --output /path/to/output.log
```

| Arg | Doscription |
|:-:|-|
| `-i PATH`<br>`--input PATH` | A path to monitor for audit logfiles. Can be a file or a folder. |
| `-o PATH`<br>`--output PATH` | The output log file path. |
| `[-t N]` | The number of threads to use to process files. Only applies when input is a directory. Files are processed with a single thread. |
| `[-d]` | Toggle debug output. Supply multiple times to increase verbosity. ERROR (Default) -> INFO -> DEBUG -> TRACE |