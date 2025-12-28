import re

# Regex patterns for various log entries

# SSH Failed Login: "Failed password for [invalid user] <user> from <ip>"
SSH_FAILED_LOGIN = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")

# Sudo Failed: "sudo: <user> : command not allowed ; TTY=... ; PWD=... ; USER=... ; COMMAND=..."
# Or standard: "user : user NOT in sudoers ; TTY=... ; PWD=... ; USER=... ; COMMAND=..."
SUDO_FAILED = re.compile(r"sudo:\s+(\S+)\s*:(?:.*command not allowed|.*user NOT in sudoers)")

# Port Scan (Heuristic): Look for multiple connections from same IP to different ports
# This is hard to detect in standard auth.log alone without firewall logs (e.g., UFW/IPTables).
# We'll assume a UFW style log line for this example: "UFW BLOCK ... SRC=... DST=... PROTO=... DPT=..."
UFW_BLOCK = re.compile(r"UFW BLOCK.*SRC=(\S+).*DPT=(\d+)")

# Suspicious Command Execution (General pattern for "COMMAND=" in auth.log or syslog)
SUSPICIOUS_COMMANDS = [
    re.compile(r"COMMAND=.*(rm\s+-rf|mkfs|dd\s+if=|wget\s+http|curl\s+http)"),
    re.compile(r"COMMAND=.*(/etc/shadow|/etc/passwd)") 
]
