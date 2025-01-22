import os
import sys
import django
from datetime import datetime, timedelta
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User

def detect_account_lockouts(log_lines, time_window_minutes=5, max_failed_attempts=1):
    """
    Detects user account lockouts caused by too many failed login attempts.
    """
    failed_attempts = {}
    alerts = []

    # Get the current year
    current_year = datetime.now().year

    for line in log_lines:
        try:
            print(f"Processing log line: {line}")
            
            parts = line.split(" ", 5)
            timestamp_str = parts[0] + " " + parts[1] + " " + parts[2]  # Add the year part for the timestamp
            timestamp_str = timestamp_str + " " + str(current_year)  # Add the current year
            
            # Parse timestamp with the year added
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            
            # Detect failed password attempts
            if "Failed password" in line:
                match_user = re.search(r"Failed password for (\w+) from", line)
                if match_user:
                    user = match_user.group(1).strip()
                    print(f"Failed login attempt detected for user: {user}")
                    key = user

                    if key not in failed_attempts:
                        failed_attempts[key] = []

                    failed_attempts[key].append(timestamp)

            # Detect account lockout message
            elif "User account has been locked" in line:
                match_user = re.search(r"User account has been locked due to too many failed logins for (\w+)", line)
                if match_user:
                    user = match_user.group(1).strip()
                    print(f"Account lockout detected for user: {user}")
                    key = user

                    # Check if lockout happened within the defined time window
                    if key in failed_attempts:
                        # Filter failed attempts within the time window
                        recent_attempts = [
                            attempt for attempt in failed_attempts[key]
                            if (timestamp - attempt).total_seconds() <= time_window_minutes * 60
                        ]

                        print(f"User: {user}, Recent attempts within {time_window_minutes} minutes: {len(recent_attempts)}")

                        # Check if the number of recent attempts meets or exceeds the threshold
                        if len(recent_attempts) >= max_failed_attempts:
                            alert = {
                                "alert_title": "User Account Lockout Detected",
                                "timestamp": timestamp,
                                "hostname": "ubuntu",  
                                "message": f"User '{user}' account was locked due to too many failed login attempts within {time_window_minutes} minutes.",
                                "severity": "High",
                                "user": user,
                            }
                            alerts.append(alert)
                        else:
                            print(f"Not enough failed attempts for user: {user} to trigger an alert.")
                    else:
                        print(f"No failed attempts recorded for user: {user}.")
        except Exception as e:
            print(f"Error processing line: {e}")
    
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
    finally:
        pass  # Add any cleanup logic here if needed


if __name__ == "__main__":

    sample_logs = [
        "Jan 22 14:15:23 ubuntu sshd[12345]: Failed password for username from 192.168.1.2 port 22 ssh2",
        "Jan 22 14:15:26 ubuntu sshd[12345]: User account has been locked due to too many failed logins for username",
    ]

    detected_alerts = detect_account_lockouts(sample_logs)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)

        create_alerts(detected_alerts)
    else:
        print("No account lockouts detected.")
