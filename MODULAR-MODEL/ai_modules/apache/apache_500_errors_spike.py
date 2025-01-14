import re
from collections import deque
from datetime import datetime, timedelta

# Sample logs for testing purposes
sample_logs = [
    "127.0.0.1 - - [14/Jan/2025:12:00:00 +0000] \"GET /index.html HTTP/1.1\" 500 1024",
    "127.0.0.1 - - [14/Jan/2025:12:01:00 +0000] \"GET /about.html HTTP/1.1\" 200 512",
    "127.0.0.1 - - [14/Jan/2025:12:02:00 +0000] \"GET /contact.html HTTP/1.1\" 500 1024",
    "127.0.0.1 - - [14/Jan/2025:12:03:00 +0000] \"GET /index.html HTTP/1.1\" 500 1024",
    "127.0.0.1 - - [14/Jan/2025:12:05:00 +0000] \"GET /error.html HTTP/1.1\" 500 1024",
    "127.0.0.1 - - [14/Jan/2025:12:07:00 +0000] \"GET /about.html HTTP/1.1\" 200 512",
    "127.0.0.1 - - [14/Jan/2025:12:08:00 +0000] \"GET /contact.html HTTP/1.1\" 500 1024",
]

# Function to parse logs and extract 500-series errors
def parse_logs(logs):
    error_logs = []
    for log in logs:
        match = re.search(r'\[(.*?)\] ".*" (\d{3}) \d+', log)
        if match and 500 <= int(match.group(2)) < 600:
            error_logs.append(datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z"))
    return error_logs

# Function to detect spikes in 500-series errors
def detect_spike(error_logs, time_window=5, threshold=3):
    recent_errors = deque()
    for log_time in error_logs:
        recent_errors.append(log_time)
        # Remove logs outside the time window
        while recent_errors and recent_errors[0] < log_time - timedelta(minutes=time_window):
            recent_errors.popleft()
        
        # Trigger alert if spike is detected
        if len(recent_errors) >= threshold:
            return True
    return False

# Main function to test the module
def check_apache500_error_spike(logs):
    error_logs = parse_logs(logs)
    if detect_spike(error_logs):
        print("Alert: Apache500ErrorsSpike - Spike in 500-series errors detected!")
    else:
        print("No spike detected in 500-series errors.")

# Run the module with sample logs
check_apache500_error_spike(sample_logs)
