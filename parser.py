import argparse
import sys
import os
from log_analysis.analyzer import LogAnalyzer
from log_analysis.report import print_report

def main():
    parser = argparse.ArgumentParser(description="Log File Analyser - Detect security threats in system logs.")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--output", "-o", help="Path to save the analysis report")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.logfile):
        print(f"Error: Log file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)
        
    print(f"Analyzing {args.logfile}...")
    
    analyzer = LogAnalyzer()
    
    try:
        with open(args.logfile, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                analyzer.process_line(line)
    except Exception as e:
        print(f"Error reading log file: {e}", file=sys.stderr)
        sys.exit(1)
        
    results = analyzer.get_results()
    print_report(results, args.output)

if __name__ == "__main__":
    main()
