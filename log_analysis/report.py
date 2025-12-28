import sys

def print_report(results, output_file=None):
    """
    Prints analysis results to stdout and optionally to a file.
    """
    lines = []
    lines.append("=== Log Analysis Report ===")
    lines.append("")
    
    # Failed Logins
    lines.append("--- Failed Login Attempts ---")
    if results['failed_logins']:
        for ip, users in results['failed_logins'].items():
            count = len(users)
            unique_users = set(users)
            lines.append(f"IP: {ip} | Attempts: {count} | Users: {', '.join(unique_users)}")
    else:
        lines.append("No failed login attempts detected.")
    lines.append("")

    # Port Scans
    lines.append("--- Potential Port Scans ---")
    if results['port_scans']:
        for ip, ports in results['port_scans'].items():
             lines.append(f"Source IP: {ip} | Target Ports: {len(ports)} | Ports: {', '.join(sorted(ports, key=int)[:10])}{'...' if len(ports)>10 else ''}")
    else:
        lines.append("No port scan patterns detected.")
    lines.append("")

    # Suspicious Activity
    lines.append("--- Suspicious Activity ---")
    if results['suspicious_activity']:
        for line, reason in results['suspicious_activity']:
            lines.append(f"[{reason}] {line}")
    else:
        lines.append("No other suspicious activity detected.")
    lines.append("")
    
    report_content = "\n".join(lines)
    
    # Print to Console
    print(report_content)
    
    # Write to File if requested
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report_content)
            print(f"\nReport saved to {output_file}")
        except IOError as e:
            print(f"\nError saving report: {e}", file=sys.stderr)
