import os
import sys
import django
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect(time_window_minutes=5, max_failed_attempts=3):
    """
    Detects multiple failed SSH login attempts within a short period using logs from the LinuxLog model.
    """
    failed_attempts = {}
    alerts = []

    # Get failed login attempts from 'authlog' type logs containing 'Failed password'
    log_lines = LinuxLog.objects.filter(log_type='authlog', message__icontains="Failed password")
    
    for log in log_lines:
        try:
            # Assuming log.timestamp is in ISO 8601 format
            timestamp_str = log.timestamp
            message = log.message
            user = log.user
            source_ip = message.split("from")[1].split("port")[0].strip()
            
            print(f"Parsing log entry: {log}")
            print(f"Extracted: timestamp='{timestamp_str}', user='{user}', source_ip='{source_ip}'")
            
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")
            key = (user, source_ip)
            
            if key not in failed_attempts:
                failed_attempts[key] = []
            
            failed_attempts[key].append(timestamp)
            
            # Retain only attempts within the time window
            failed_attempts[key] = [t for t in failed_attempts[key] if t > timestamp - timedelta(minutes=time_window_minutes)]
            
            print(f"Failed attempts for {key}: {failed_attempts[key]}")

            if len(failed_attempts[key]) >= max_failed_attempts:
                alert = {
                    "alert_title": "Multiple Failed SSH Login Attempts",
                    "timestamp": timestamp,
                    "hostname": log.hostname,
                    "message": f"Detected {len(failed_attempts[key])} failed login attempts for user '{user}' from IP '{source_ip}' within {time_window_minutes} minutes.",
                    "severity": "High",
                    "user": user,
                }
                alerts.append(alert)
                # Clear attempts for the user after an alert is created
                failed_attempts[key] = []

        except Exception as e:
            print(f"Error processing log entry: {log}, Error: {e}")
    
    return alerts


def create_alerts(alerts):
    """
    Creates alerts in the database using the provided alert data.

    Args:
        alerts (list[dict]): A list of dictionaries containing alert details.
    """
    try:
        # Assume a default user exists; replace with logic to find the user if needed
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
    # Detect alerts based on the logs from the LinuxLog model
    detected_alerts = detect()
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)

        # Store the alerts in the database
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")
