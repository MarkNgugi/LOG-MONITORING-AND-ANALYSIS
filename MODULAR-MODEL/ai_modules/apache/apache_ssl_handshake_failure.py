import re

# Sample logs for testing
sample_logs = [
    '192.168.0.1 - - [14/Jan/2025:14:32:20 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
    '192.168.0.2 - - [14/Jan/2025:14:33:05 +0000] "GET / HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
    '192.168.0.3 - - [14/Jan/2025:14:34:15 +0000] "GET /login HTTP/1.1" 400 512 "-" "Mozilla/5.0"',
    'ssl_error: SSL handshake failed at 192.168.0.4 - - [14/Jan/2025:14:35:00 +0000] "GET /secure HTTP/1.1" 400 1024 "-" "Mozilla/5.0"',
    'ssl_error: SSL handshake error at 192.168.0.5 - - [14/Jan/2025:14:36:10 +0000] "GET /login HTTP/1.1" 400 2048 "-" "Mozilla/5.0"',
]

# Function to detect SSL handshake failure
def detect_ssl_handshake_failure(logs):
    ssl_failure_pattern = re.compile(r'ssl_error.*SSL handshake.*', re.IGNORECASE)
    
    alerts = []
    for log in logs:
        if ssl_failure_pattern.search(log):
            alerts.append(f"Alert: ApacheSSLHandshakeFailure - SSL handshake failure detected in log: {log}")
    
    return alerts

# Main function to run the detection
def run_ssl_handshake_detection():
    alerts = detect_ssl_handshake_failure(sample_logs)
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No SSL handshake failures detected.")

# Run the module
if __name__ == "__main__":
    run_ssl_handshake_detection()
