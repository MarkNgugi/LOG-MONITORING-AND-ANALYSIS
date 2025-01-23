import os
import sys
import django
from datetime import datetime, timedelta
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User

def detect(log_lines, time_window_minutes=5, max_failed_attempts=3):
    """
    Detects multiple failed sudo attempts and NTP synchronization failures within a short period.
    """
    failed_attempts = {}
    alerts = []

    for line in log_lines:
        try:            
            print(f"Processing log line: {line}")
            
            parts = line.split(" ", 5)
            timestamp_str = parts[0]
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")
            
            if "authentication failure" in line and "sudo" in line:                
                user = line.split("user=")[-1].split(" ")[0].strip()
                print(f"Authentication failure detected for user: {user}")
                key = user
                
                if key not in failed_attempts:
                    failed_attempts[key] = []

                failed_attempts[key].append(timestamp)

            elif "incorrect password attempts" in line:                
                match_user = re.search(r"sudo:\s+(\w+)\s*:", line)
                match_failed_attempts = re.search(r"\b(\d+)\s+incorrect password attempts", line)

                if match_user and match_failed_attempts:
                    user = match_user.group(1).strip()
                    num_failed = int(match_failed_attempts.group(1))
                    key = user
                    
                    if key not in failed_attempts:
                        failed_attempts[key] = []
                    
                    failed_attempts[key].extend([timestamp] * num_failed)

            if key in failed_attempts:
                print(f"Failed attempts for {key}: {failed_attempts[key]}")
            
            for user in failed_attempts:
                failed_attempts[user] = [t for t in failed_attempts[user] if t > timestamp - timedelta(minutes=time_window_minutes)]
                
                if len(failed_attempts[user]) >= max_failed_attempts:
                    alert = {
                        "alert_title": "Multiple Failed Sudo Attempts",
                        "timestamp": timestamp,
                        "hostname": "ubuntu",  
                        "message": f"Detected {len(failed_attempts[user])} failed sudo attempts for user '{user}' within {time_window_minutes} minutes.",
                        "severity": "High",
                        "user": user,
                    }
                    alerts.append(alert)                    
                    failed_attempts[user] = []

            if "ntpd" in line and ("synchronization error" in line or "time sync failure" in line):
                alert = {
                    "alert_title": "Time Sync Failure",
                    "timestamp": timestamp,
                    "hostname": "ubuntu",  
                    "message": "NTP synchronization failure detected. This may lead to timing issues in system operations.",
                    "severity": "Critical",
                    "user": "system",
                }
                alerts.append(alert)

        except Exception as e:
            print(f"Error processing log line: {line}, Error: {e}")

    return alerts


def create_alerts(alerts):
    """
    Creates alerts in the database using the provided alert data.

    Args:
        alerts (list[dict]): A list of dictionaries containing alert details.
    """
    try:        
        default_user = User.objects.first()
        if not default_user:
            raise ValueError("No default user found in the database.")

        for alert_data in alerts:
            Alert.objects.create(
                alert_title=alert_data["alert_title"],
                timestamp=alert_data["timestamp"],
                hostname=alert_data["hostname"],
                message=alert_data["message"],
                severity=alert_data["severity"],
                user=default_user,
            )
            print(f"Alert created: {alert_data['alert_title']} for user '{alert_data['user']}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")


if __name__ == "__main__":
    
    sample_logs = [
        "2025-01-20T17:05:21.665037+03:00 ubuntu sudo: pam_unix(sudo:auth): authentication failure; logname=smilex uid=1000 euid=0 tty=/dev/pts/9 ruser=smilex rhost=  user=smilex",
        "2025-01-20T17:05:33.240157+03:00 ubuntu sudo:   smilex : 3 incorrect password attempts ; TTY=pts/9 ; PWD=/home/smilex/Desktop ; USER=root ; COMMAND=/usr/bin/ls /root",
        "2025-01-20T18:20:10.123456+03:00 ubuntu ntpd[1234]: synchronization error: clock offset too high",
        "2025-01-20T18:25:45.654321+03:00 ubuntu ntpd[1234]: time sync failure detected"
    ]

    detected_alerts = detect(sample_logs)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
        
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")