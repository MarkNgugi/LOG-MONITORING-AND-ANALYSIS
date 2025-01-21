import os
import sys
import django
from datetime import datetime, timedelta
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert

def detect_auth_failures(log_lines, time_window_minutes=5, max_failed_attempts=3):
    failed_attempts = {}
    alerts = []

    for line in log_lines:
        try:
            print(f"Processing log line: {line}")
            parts = line.split(" ", 5)
            timestamp_str = parts[0]
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")

            repeat_match = re.search(r"message repeated (\d+) times", line)
            if "authentication failure" in line and "gdm-password" in line:
                user_match = re.search(r"user=([\w]+)", line)
                if user_match:
                    user = user_match.group(1).strip()
                    print(f"Authentication failure detected for user: {user}")

                    if user not in failed_attempts:
                        failed_attempts[user] = []

                    repeat_count = int(repeat_match.group(1)) if repeat_match else 1
                    failed_attempts[user].extend([timestamp] * repeat_count)

            for user in failed_attempts:
                failed_attempts[user] = [t for t in failed_attempts[user] if t > timestamp - timedelta(minutes=time_window_minutes)]
                if len(failed_attempts[user]) >= max_failed_attempts:
                    alert = Alert(
                        alert_title="Repeated Authentication Failures",
                        timestamp=timestamp,
                        hostname="ubuntu",
                        message=f"Detected {len(failed_attempts[user])} repeated authentication failures for user '{user}' within {time_window_minutes} minutes.",
                        severity="Medium",
                        user=None,
                    )
                    alert.save()
                    print(f"Alert saved for user: {user}")
                    alerts.append({
                        "alert_title": alert.alert_title,
                        "timestamp": alert.timestamp,
                        "hostname": alert.hostname,
                        "message": alert.message,
                        "severity": alert.severity,
                        "user": user,
                    })
                    alerts.append(alert) 
                    failed_attempts[user] = []

        except Exception as e:
            print(f"Error processing log line: {line}, Error: {e}")

    return alerts


# Sample logs
sample_auth_logs = [
    "2025-01-21T14:29:44.636231+03:00 ubuntu gdm-password]: pam_unix(gdm-password:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=mark",
    "2025-01-21T14:29:52.445852+03:00 ubuntu gdm-password]: message repeated 2 times: [ pam_unix(gdm-password:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=mark]",
]

detected_auth_alerts = detect_auth_failures(sample_auth_logs)
print(f"{len(detected_auth_alerts)} auth failure alert(s) detected:")
for alert in detected_auth_alerts:
    print(alert)
