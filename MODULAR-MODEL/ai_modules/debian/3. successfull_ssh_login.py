import os
import sys
import django
from datetime import datetime, timedelta
import re
from django.db.models import Q  # Import Q for OR filtering

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect(time_window_minutes=100):
    """
    Detects successful SSH login attempts using logs from the LinuxLog model.
    """
    successful_logins = []
    alerts = []

    # Get successful login attempts from 'authlog' type logs containing 'Accepted password'
    log_lines = LinuxLog.objects.filter(
        log_type="authlog",
        processed=False  # Only fetch unprocessed logs
    ).filter(
        Q(message__icontains="Accepted password") | Q(message__icontains="session opened")
    )
    
    for log in log_lines:
        try:
            timestamp_str = log.timestamp
            message = log.message
            user = log.user if log.user else "Unknown"
            source_ip = None

            # Pattern 1: Standard SSH Successful Login
            match_ssh = re.search(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)", message)
            
            # Pattern 2: Session Opened for User
            match_session = re.search(r"session opened for user (\S+) by (\S+) from (\d+\.\d+\.\d+\.\d+)", message)
            
            if match_ssh:
                user = match_ssh.group(1)
                source_ip = match_ssh.group(2)
            elif match_session:
                user = match_session.group(1)
                source_ip = match_session.group(3)
            
            if not source_ip:
                continue
            
            print(f"Parsing log entry: {log}")
            print(f"Extracted: timestamp='{timestamp_str}', user='{user}', source_ip='{source_ip}'")
            
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
            
            alert = {
                "alert_title": "Successful SSH Login",
                "timestamp": timestamp,
                "hostname": log.hostname,
                "message": f"User '{user}' successfully logged in from IP '{source_ip}'.",
                "severity": "Medium",
                "user": user,
                "log_source_name": log.log_source_name,  # Include log_source_name in the alert
                "connection": "linux",
            }
            alerts.append(alert)

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
                log_source_name=alert_data["log_source_name"],  # Include log_source_name in the alert
                connection=alert_data["connection"]
            )
            print(f"Alert created: {alert_data['alert_title']} for user '{alert_data['user']}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")

if __name__ == "__main__":
    detected_alerts = detect()
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")