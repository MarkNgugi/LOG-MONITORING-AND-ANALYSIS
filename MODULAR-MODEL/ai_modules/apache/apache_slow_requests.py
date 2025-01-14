import re
from datetime import datetime

def load_sample_logs():
    """Load sample Apache logs for testing."""
    return [
        '127.0.0.1 - - [14/Jan/2025:10:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0" 0.123',
        '127.0.0.1 - - [14/Jan/2025:10:56:10 +0000] "GET /api/data HTTP/1.1" 200 2048 "-" "Mozilla/5.0" 5.678',
        '127.0.0.1 - - [14/Jan/2025:10:57:50 +0000] "POST /login HTTP/1.1" 200 1024 "-" "Mozilla/5.0" 0.456',
        '127.0.0.1 - - [14/Jan/2025:10:58:20 +0000] "GET /dashboard HTTP/1.1" 200 512 "-" "Mozilla/5.0" 10.234',
    ]

def parse_log_line(log_line):
    """Parse a single log line into its components."""
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)" (?P<response_time>\d+\.\d+)'  # Added response_time
    )
    match = log_pattern.match(log_line)
    if match:
        return match.groupdict()
    return None

def analyze_logs_for_slow_requests(logs):
    """Analyze Apache logs and identify slow requests."""
    slow_request_count = 0
    slow_request_threshold = 5.0  # Threshold in seconds for slow requests

    for log in logs:
        parsed_log = parse_log_line(log)
        if parsed_log:
            response_time = float(parsed_log['response_time'])
            if response_time > slow_request_threshold:
                slow_request_count += 1

    if slow_request_count > 0:
        notify_slow_requests(slow_request_count)
    else:
        print("All requests are within acceptable response times.")

def notify_slow_requests(count):
    """Notify user of slow Apache requests."""
    print(f"ALERT: Detected {count} slow requests exceeding the response time threshold.")

def main():
    """Main function to run the module."""
    print("Loading sample logs...")
    logs = load_sample_logs()
    print("Analyzing logs for slow requests...")
    analyze_logs_for_slow_requests(logs)

if __name__ == "__main__":
    main()
