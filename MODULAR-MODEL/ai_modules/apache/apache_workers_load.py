import re
from datetime import datetime

def load_sample_logs():
    """Load sample Apache logs for testing."""
    return [
        '127.0.0.1 - - [14/Jan/2025:10:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:56:10 +0000] "GET /api/data HTTP/1.1" 503 0 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:57:50 +0000] "POST /login HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:58:20 +0000] "GET /dashboard HTTP/1.1" 503 0 "-" "Mozilla/5.0"',
    ]

def parse_log_line(log_line):
    """Parse a single log line into its components."""
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
    )
    match = log_pattern.match(log_line)
    if match:
        return match.groupdict()
    return None

def analyze_logs(logs):
    """Analyze Apache logs and identify high workload conditions."""
    high_workload_count = 0
    high_workload_threshold = 2  # Example threshold for high workload
    
    for log in logs:
        parsed_log = parse_log_line(log)
        if parsed_log:
            status = int(parsed_log['status'])
            if status == 503:  # HTTP 503 indicates server is overloaded
                high_workload_count += 1

    if high_workload_count >= high_workload_threshold:
        notify_high_workload(high_workload_count)
    else:
        print("Apache workload is within normal limits.")

def notify_high_workload(count):
    """Notify user of high Apache workload."""
    print(f"ALERT: Apache workers load is too high. {count} instances of overload detected.")

def main():
    """Main function to run the module."""
    print("Loading sample logs...")
    logs = load_sample_logs()
    print("Analyzing logs...")
    analyze_logs(logs)

if __name__ == "__main__":
    main()