import re
from datetime import datetime

def load_sample_logs():
    """Load sample Apache logs for testing."""
    return [
        '127.0.0.1 - - [14/Jan/2025:10:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:56:10 +0000] "GET /api/data HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:57:50 +0000] "POST /login HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:58:20 +0000] "GET /dashboard HTTP/1.1" 200 5120 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:59:30 +0000] "GET /api/data HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
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
    """Analyze Apache logs and identify high traffic conditions."""
    traffic_count = 0
    high_traffic_threshold = 5  # Example threshold for high traffic

    for log in logs:
        parsed_log = parse_log_line(log)
        if parsed_log:
            traffic_count += 1

    if traffic_count >= high_traffic_threshold:
        notify_high_traffic(traffic_count)
    else:
        print("Apache traffic is within normal limits.")

def notify_high_traffic(count):
    """Notify user of high Apache traffic."""
    print(f"ALERT: High traffic detected on the server. {count} requests processed.")

def main():
    """Main function to run the module."""
    print("Loading sample logs...")
    logs = load_sample_logs()
    print("Analyzing logs...")
    analyze_logs(logs)

if __name__ == "__main__":
    main()
