# Log File Analyser

## Purpose
The Log File Analyser is a command-line tool designed to help cybersecurity analysts and system administrators quickly identify security threats within system logs. By automating the parsing of log files, it highlights critical events that may indicate an ongoing attack or a security breach.

## Features
- **Failed Login Detection**: Scans logs for repeated failed authentication attempts, which may indicate a brute-force attack.
- **Port Scan Detection**: Identifies patterns of connection attempts to multiple ports or from a single source, suggestive of reconnaissance activity.
- **Suspicious Behavior Analysis**: Flags other anomalous activities such as unauthorized command executions or access to sensitive files (based on customizable rules).
- **Report Generation**: Outputs a summary of findings to the console and optionally saves detailed reports.

## How to Run
The tool is a Python script that can be executed from the command line.

### Prerequisites
- Python 3.x
- Standard system logs (e.g., `/var/log/auth.log`, `/var/log/syslog`) or exported log files.

### Usage
```bash
# Basic usage to analyze a specific log file
python parser.py /path/to/logfile.log

# Analyze and save report
python parser.py /path/to/logfile.log --output report.txt
```

## Architecture
- **Parser Core**: A flexible parsing engine using regex patterns to identify log entries.
- **Analysis Modules**: specific modules for Login, Port Scan, and Behavior analysis.
- **Reporter**: specific module for formatting and outputting results.
