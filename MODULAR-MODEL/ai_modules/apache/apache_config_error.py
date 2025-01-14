import re

# Sample Apache error logs with configuration errors
sample_logs = [
    "[Sun Jan 14 12:00:00.000000 2025] [core:alert] [pid 1234:tid 5678] (2)No such file or directory: AH02291: Cannot access directory '/nonexistent/directory' for multi:///.htpasswd",
    "[Sun Jan 14 12:05:00.000000 2025] [core:warn] [pid 1235:tid 5679] (22)Invalid argument: AH00092: Configuration error",
    "[Sun Jan 14 12:10:00.000000 2025] [core:error] [pid 1236:tid 5680] (13)Permission denied: AH01630: Could not open password file: /etc/apache2/.htpasswd",
    "[Sun Jan 14 12:15:00.000000 2025] [core:alert] [pid 1237:tid 5681] Configuration error: Syntax error in .htaccess file"
]

def detect_apache_config_error(logs):
    error_pattern = re.compile(r"(AH[0-9]{5}: .+configuration error|syntax error|permission denied)", re.IGNORECASE)
    alerts = []
    
    for log in logs:
        if error_pattern.search(log):
            alerts.append(f"ApacheConfigError Alert: {log}")
    
    if alerts:
        return alerts
    else:
        return "No configuration errors detected."

# Run the module and check for alerts
alerts = detect_apache_config_error(sample_logs)
for alert in alerts:
    print(alert)
