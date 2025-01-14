import re

# Sample logs representing Apache proxy errors
sample_logs = [
    "proxy: error reading status line from remote server",
    "proxy: error processing request",
    "proxy: No protocol handler was valid for the URL",
    "proxy: connection to backend failed",
    "proxy: failed to connect to backend server",
    "proxy: timeout while connecting to backend",
]

# Function to detect Apache Proxy Errors
def detect_apache_proxy_error(logs):
    proxy_error_patterns = [
        "proxy: error reading status line",
        "proxy: error processing request",
        "proxy: No protocol handler",
        "proxy: connection to backend failed",
        "proxy: failed to connect to backend server",
        "proxy: timeout while connecting to backend",
    ]
    
    detected_errors = []
    
    for log in logs:
        for pattern in proxy_error_patterns:
            if re.search(pattern, log, re.IGNORECASE):
                detected_errors.append(f"Proxy error detected: {log}")
    
    return detected_errors

# Function to notify the user when an Apache Proxy error is detected
def notify_user(errors):
    if errors:
        print("Apache Proxy Errors Detected:")
        for error in errors:
            print(f"- {error}")
    else:
        print("No Apache Proxy Errors detected.")

# Main function to run the module
def run_module():
    detected_errors = detect_apache_proxy_error(sample_logs)
    notify_user(detected_errors)

# Run the module
if __name__ == "__main__":
    run_module()
