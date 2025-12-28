from collections import defaultdict
from . import patterns

class LogAnalyzer:
    def __init__(self):
        self.failed_logins = defaultdict(list)  # {ip: [usernames]}
        self.port_scan_candidates = defaultdict(set) # {src_ip: {ports}}
        self.suspicious_activity = [] # List of tuples (line, reason)

    def process_line(self, line):
        line = line.strip()
        if not line:
            return

        # Check Failed Logins
        login_match = patterns.SSH_FAILED_LOGIN.search(line)
        if login_match:
            user = login_match.group(1)
            ip = login_match.group(2)
            self.failed_logins[ip].append(user)
            return

        # Check Port Scans (UFW Style)
        ufw_match = patterns.UFW_BLOCK.search(line)
        if ufw_match:
            src_ip = ufw_match.group(1)
            dst_port = ufw_match.group(2)
            self.port_scan_candidates[src_ip].add(dst_port)
            return

        # Check Suspicious Commands
        for pattern in patterns.SUSPICIOUS_COMMANDS:
            if pattern.search(line):
                self.suspicious_activity.append((line, "Suspicious Command Detected"))
                return
        
        # Check Sudo Failures
        sudo_match = patterns.SUDO_FAILED.search(line)
        if sudo_match:
            user = sudo_match.group(1)
            self.suspicious_activity.append((line, f"Failed Sudo Attempt by {user}"))
            return

    def get_results(self):
        return {
            "failed_logins": dict(self.failed_logins),
            "port_scans": {ip: list(ports) for ip, ports in self.port_scan_candidates.items() if len(ports) > 3}, # Threshold > 3 ports
            "suspicious_activity": self.suspicious_activity
        }
