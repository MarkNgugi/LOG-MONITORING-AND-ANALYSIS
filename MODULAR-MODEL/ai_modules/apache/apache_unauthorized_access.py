import re

# Sample Apache logs (replace with real log lines or add more samples)
sample_logs = [
    '192.168.1.1 - - [14/Jan/2025:10:00:00 +0000] "GET /restricted-area HTTP/1.1" 401 234 "-" "Mozilla/5.0"',
    '192.168.1.2 - - [14/Jan/2025:10:05:00 +0000] "GET /public HTTP/1.1" 200 567 "-" "Mozilla/5.0"',
    '192.168.1.3 - - [14/Jan/2025:10:10:00 +0000] "POST /login HTTP/1.1" 401 123 "http://example.com/login" "Mozilla/5.0"',
    '192.168.1.4 - - [14/Jan/2025:10:15:00 +0000] "GET /admin HTTP/1.1" 403 456 "-" "Mozilla/5.0"',
]

def detect_unauthorized_access(logs):
    # Define the regex pattern to extract status codes from the logs (401 for unauthorized)
    unauthorized_pattern = r'"\S+ (\S+) \S+" (\d{3}) \S+'
    unauthorized_logs = []

    for log in logs:
        match = re.search(unauthorized_pattern, log)
        if match:
            status_code = match.group(2)
            if status_code == "401":
                unauthorized_logs.append(log)
    
    return unauthorized_logs

def notify_user(unauthorized_logs):
    if unauthorized_logs:
        print("Apache Unauthorized Access Alert!")
        for log in unauthorized_logs:
            print(f"Alert: Unauthorized access detected: {log}")
    else:
        print("No unauthorized access detected.")

# Main function to run the detection and notification
def run_unauthorized_access_detection():
    unauthorized_logs = detect_unauthorized_access(sample_logs)
    notify_user(unauthorized_logs)

# Test the module
if __name__ == "__main__":
    run_unauthorized_access_detection()
