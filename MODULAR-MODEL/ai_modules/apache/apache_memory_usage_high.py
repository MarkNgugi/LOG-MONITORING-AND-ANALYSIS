import re

# Sample logs that simulate memory usage issues in Apache logs
sample_logs = [
    "apache_error_log: [Mon Jan 10 18:00:00.000000 2025] [core:notice] [pid 12345:tid 140479534676992] AH00094: Command line: '/usr/sbin/apache2 -X' - Memory Usage: 90%",
    "apache_error_log: [Mon Jan 11 19:00:00.000000 2025] [core:notice] [pid 12346:tid 140479534676993] AH00094: Command line: '/usr/sbin/apache2 -X' - Memory Usage: 85%",
    "apache_error_log: [Mon Jan 12 20:00:00.000000 2025] [core:notice] [pid 12347:tid 140479534676994] AH00094: Command line: '/usr/sbin/apache2 -X' - Memory Usage: 95%",
    "apache_error_log: [Mon Jan 13 21:00:00.000000 2025] [core:notice] [pid 12348:tid 140479534676995] AH00094: Command line: '/usr/sbin/apache2 -X' - Memory Usage: 92%",
]

# Alert threshold (percentage)
MEMORY_USAGE_THRESHOLD = 90

def detect_memory_alert(logs):
    for log in logs:
        # Search for memory usage information in the log
        match = re.search(r'Memory Usage: (\d+)%', log)
        if match:
            memory_usage = int(match.group(1))
            if memory_usage >= MEMORY_USAGE_THRESHOLD:
                # If memory usage exceeds the threshold, trigger an alert
                print(f"ALERT: High memory usage detected! {memory_usage}% in log: {log}")

# Test the module with sample logs
detect_memory_alert(sample_logs)
