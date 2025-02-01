import os
import sys
import django
from datetime import datetime, timedelta
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect(log_lines, time_window_minutes=5, max_failed_attempts=3):
    """
    Detects multiple failed SSH authentication attempts using unrecognized keys.
    """
    failed_attempts = {}
    alerts = []

    for log in log_lines:
        try:            
            print(f"Processing log: {log.message}")
            
            timestamp_str = log.timestamp
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")
            
            if "Failed publickey" in log.message:                
                user = log.user
                ip_address = re.search(r"from (\S+)", log.message).group(1)
                key_info = re.search(r"ssh2: (\S+)", log.message).group(1)

                print(f"Unrecognized SSH Key Attempt detected: User '{user}' from IP '{ip_address}' using key {key_info}")

                if user not in failed_attempts:
                    failed_attempts[user] = []

                failed_attempts[user].append(timestamp)

            if user in failed_attempts:
                print(f"Failed attempts for {user}: {failed_attempts[user]}")
                        
            for user in failed_attempts:
                failed_attempts[user] = [t for t in failed_attempts[user] if t > timestamp - timedelta(minutes=time_window_minutes)]
                                
                if len(failed_attempts[user]) >= max_failed_attempts:
                    alert = {
                        "alert_title": "Use of Unrecognized SSH Key Authentication",
                        "timestamp": timestamp,
                        "hostname": log.hostname,  
                        "message": f"Detected {len(failed_attempts[user])} failed SSH login attempts for user '{user}' using unrecognized keys from IP '{ip_address}' within {time_window_minutes} minutes.",
                        "severity": "Medium",
                        "user": user,
                    }
                    alerts.append(alert)                    
                    failed_attempts[user] = []

        except Exception as e:
            print(f"Error processing log: {log.message}, Error: {e}")

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
    # Query LinuxLog for relevant logs
    log_lines = LinuxLog.objects.filter(log_type='authlog').order_by('-timestamp')[:100]  # Fetch the last 100 auth logs

    detected_alerts = detect(log_lines)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
                
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")
