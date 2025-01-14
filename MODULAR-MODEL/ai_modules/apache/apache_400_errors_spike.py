import re
from datetime import datetime, timedelta

# Sample Apache logs (you can add more entries for testing)
sample_logs = [
    '192.168.1.1 - - [10/Jan/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 400 232 "-" "Mozilla/5.0"',
    '192.168.1.2 - - [10/Jan/2025:10:01:00 +0000] "GET /login HTTP/1.1" 404 232 "-" "Mozilla/5.0"',
    '192.168.1.3 - - [10/Jan/2025:10:02:00 +0000] "GET /about HTTP/1.1" 200 232 "-" "Mozilla/5.0"',
    '192.168.1.4 - - [10/Jan/2025:10:03:00 +0000] "GET /contact HTTP/1.1" 400 232 "-" "Mozilla/5.0"',
    '192.168.1.1 - - [10/Jan/2025:10:04:00 +0000] "GET /index.html HTTP/1.1" 400 232 "-" "Mozilla/5.0"',
    '192.168.1.5 - - [10/Jan/2025:10:05:00 +0000] "GET /login HTTP/1.1" 400 232 "-" "Mozilla/5.0"',
]

# Function to parse logs and extract response codes
def parse_log(log):
    pattern = r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<request>.*?)" (?P<status_code>\d{3})'
    match = re.match(pattern, log)
    if match:
        return match.group('timestamp'), int(match.group('status_code'))
    return None, None

# Function to check for spikes in 400-series errors
def check_400_errors_spike(logs, time_window_minutes=5, threshold=2):
    error_counts = {}
    spike_alert = False

    for log in logs:
        timestamp, status_code = parse_log(log)
        if timestamp and status_code and 400 <= status_code < 500:
            # Convert timestamp to datetime for easier comparison
            timestamp = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
            time_window_start = timestamp - timedelta(minutes=time_window_minutes)
            # Count errors in the time window
            error_counts[time_window_start] = error_counts.get(time_window_start, 0) + 1

    # Check for spike
    for time, count in error_counts.items():
        if count >= threshold:
            spike_alert = True
            break

    if spike_alert:
        print("Alert: Apache400ErrorsSpike - Spike in 400-series errors detected!")
    else:
        print("No spike in 400-series errors detected.")

# Test the module with sample logs
check_400_errors_spike(sample_logs)
