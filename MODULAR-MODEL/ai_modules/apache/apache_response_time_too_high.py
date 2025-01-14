import re
from datetime import datetime

def load_sample_logs():
    """Load sample Apache logs for testing."""
    return [
        '127.0.0.1 - - [14/Jan/2025:10:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024 250 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:56:10 +0000] "GET /api/data HTTP/1.1" 200 0 1200 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:57:50 +0000] "POST /login HTTP/1.1" 200 2048 800 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:58:20 +0000] "GET /dashboard HTTP/1.1" 200 0 1500 "-" "Mozilla/5.0"',
    ]

def parse_log_line(log_line):
    """Parse a single log line into its components."""
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+) (?P<response_time>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
    )
    match = log_pattern.match(log_line)
    if match:
        return match.groupdict()
    return None

def analyze_logs(logs):
    """Analyze Apache logs and identify high response time conditions."""
    high_response_time_count = 0
    high_response_time_threshold = 1000  # Threshold for high response time in milliseconds

    for log in logs:
        parsed_log = parse_log_line(log)
        if parsed_log:
            response_time = int(parsed_log['response_time'])
            if response_time > high_response_time_threshold:
                high_response_time_count += 1

    if high_response_time_count > 0:
        notify_high_response_time(high_response_time_count)
    else:
        print("Apache response times are within normal limits.")

def notify_high_response_time(count):
    """Notify user of high Apache response times."""
    print(f"ALERT: Apache response time is too high. {count} instances of high response time detected.")

def main():
    """Main function to run the module."""
    print("Loading sample logs...")
    logs = load_sample_logs()
    print("Analyzing logs...")
    analyze_logs(logs)

if __name__ == "__main__":
    main()
