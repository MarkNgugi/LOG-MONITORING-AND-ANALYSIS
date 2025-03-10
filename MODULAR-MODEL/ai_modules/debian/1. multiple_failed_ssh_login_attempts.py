import os
import sys
import django
from datetime import datetime, timedelta
import re
from django.db.models import Q  # Import Q for OR filtering

# Set up Django environment
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect(time_window_minutes=100, max_failed_attempts=1):
    """
    Detects multiple failed SSH login attempts within a short period using logs from the LinuxLog model.
    Only fetches logs that have not been processed (processed=False).
    """
    failed_attempts = {}
    alerts = []

    # Get failed login attempts from 'authlog' type logs containing 'Failed password' or 'incorrect password attempts'
    log_lines = LinuxLog.objects.filter(
        log_type="authlog",
        processed=False  # Only fetch unprocessed logs
    ).filter(
        Q(message__icontains="Failed password") | Q(message__icontains="incorrect password attempts")
    )
    
    for log in log_lines:
        try:
            timestamp_str = log.timestamp
            message = log.message
            user = log.user if log.user else "Unknown"
            source_ip = None

            # Pattern 1: Standard SSH Failed Password Attempt
            match_ssh = re.search(r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)", message)
            
            # Pattern 2: sudo executing SSH with incorrect password attempts
            match_sudo_ssh = re.search(r"(\S+) : \d+ incorrect password attempts .* COMMAND=/usr/bin/ssh .*@(\d+\.\d+\.\d+\.\d+)", message)
            
            if match_ssh:
                user = match_ssh.group(1)
                source_ip = match_ssh.group(2)
            elif match_sudo_ssh:
                user = match_sudo_ssh.group(1)
                source_ip = match_sudo_ssh.group(2)
            
            if not source_ip:
                continue
            
            print(f"Parsing log entry: {log}")
            print(f"Extracted: timestamp='{timestamp_str}', user='{user}', source_ip='{source_ip}'")
            
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
            key = (user, source_ip)
            
            if key not in failed_attempts:
                failed_attempts[key] = []
            
            failed_attempts[key].append(timestamp)
            
            # Retain only attempts within the time window
            failed_attempts[key] = [t for t in failed_attempts[key] if t > timestamp - timedelta(minutes=time_window_minutes)]
            
            print(f"Failed attempts for {key}: {failed_attempts[key]}")
            
            if len(failed_attempts[key]) >= max_failed_attempts:
                alert = {
                    "alert_title": "Failed SSH Login Attempts",
                    "timestamp": timestamp,
                    "hostname": log.hostname,
                    "message": f"Detected {len(failed_attempts[key])} failed login attempts for user '{user}' from IP '{source_ip}' within {time_window_minutes} minutes.",
                    "severity": "High",
                    "user": user,
                    "log_source_name": log.log_source_name,  # Include log_source_name in the alert
                    "connection": "linux",
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
        
        # Mark the processed logs as processed
        log_ids = [log.id for log in LinuxLog.objects.filter(log_type="authlog", processed=False)]
        LinuxLog.objects.filter(id__in=log_ids).update(processed=True)
        print(f"Marked {len(log_ids)} log(s) as processed.")
    else:
        print("No alerts detected.")