import re
from datetime import datetime

def load_sample_logs():
    """Load sample Apache logs for testing."""
    return [
        '127.0.0.1 - - [14/Jan/2025:10:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:56:10 +0000] "GET /api/data HTTP/1.1" 503 0 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:57:50 +0000] "POST /login HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:58:20 +0000] "GET /dashboard HTTP/1.1" 503 0 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:10:59:30 +0000] "GET /error HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
        '127.0.0.1 - - [14/Jan/2025:11:00:00 +0000] "GET /error HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
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
    """Analyze Apache logs and identify high error rate conditions."""
    error_count = 0
    total_count = 0
    error_rate_threshold = 0.5  # threshold for high error rate (50%)

    for log in logs:
        parsed_log = parse_log_line(log)
        if parsed_log:
            total_count += 1
            status = int(parsed_log['status'])
            if 500 <= status < 600:  # HTTP 5xx indicates server errors
                error_count += 1

    if total_count > 0:
        error_rate = error_count / total_count
        if error_rate >= error_rate_threshold:
            notify_high_error_rate(error_rate, error_count, total_count)
        else:
            print("Apache error rate is within normal limits.")
    else:
        print("No logs to analyze.")

def notify_high_error_rate(error_rate, error_count, total_count):
    """Notify user of high Apache error rate."""
    print(f"ALERT: Apache error rate is too high. {error_count}/{total_count} errors detected ({error_rate:.2%} error rate).")

def main():
    """Main function to run the module."""
    print("Loading sample logs...")
    logs = load_sample_logs()
    print("Analyzing logs...")
    analyze_logs(logs)

if __name__ == "__main__":
    main()
