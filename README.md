# Log File Analyser

## Overview
The Log File Analyser is a Python-based security tool designed to parse system logs and identify potential threats such as brute-force attacks, port scans, and suspicious command executions. It provides a quick summary of security events to help analysts respond faster.

## Features
- **Brute-Force Detection**: Identifies IP addresses with multiple failed login attempts.
- **Port Scan Detection**: Detects sources probing multiple ports on the target machine.
- **Suspicious Activity Monitoring**: Flags dangerous commands (e.g., `rm -rf`, `mkfs`) and unauthorized `sudo` usage.
- **Reporting**: Generates a clear, readable report on the console or to a file.

## Installation
No special installation is required. Ensure you have Python 3.x installed.

```bash
git clone <repository-url>
cd Log_File_Analyser
```

## Usage

### Basic Analysis
Run the script providing the path to a log file:

```bash
python3 parser.py /var/log/auth.log
```

### Save Report to File
Use the `--output` or `-o` flag to save the results:

```bash
python3 parser.py /var/log/auth.log --output report.txt
```

## Example Output
```text
=== Log Analysis Report ===

--- Failed Login Attempts ---
IP: 192.168.1.100 | Attempts: 3 | Users: admin

--- Potential Port Scans ---
Source IP: 10.0.0.5 | Target Ports: 4 | Ports: 22, 80, 443, 8080

--- Suspicious Activity ---
[Failed Sudo Attempt by bob] ...
[Suspicious Command Detected] ...
```

## Customization
You can add or modify detection rules in `log_analysis/patterns.py`.
