import os
import sys
import django
import re
from datetime import datetime
from django.db.models import Q

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect():
    """
    Detects Disk Space Warnings using logs from the LinuxLog model.
    """
    disk_space_warnings = []
    patterns = [
        r"kernel:.*No space left on device",
        r"kernel:.*EXT4-fs warning.*",
        r"kernel:.*EXT4-fs error.*",
        r"systemd.*No space left on device",
        r"CRON.*FAILED.*No space left on device",
        r"No space left on device",
        r"Disk usage.*(9[0-9]|100)%"
    ]
    
    log_lines = LinuxLog.objects.filter(
        log_type__in=["kernlog", "syslog", "authlog", "cronlog"]
    ).filter(
        Q(message__iregex="|".join(patterns))
    )
    
    for log in log_lines:
        try:
            timestamp_str = log.timestamp
            message = log.message
            hostname = log.hostname if log.hostname else "Unknown"
            
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
            severity = "High" if "No space left on device" in message else "Medium"
            
            alert = {
                "alert_title": "Disk Space Warning",
                "timestamp": timestamp,
                "hostname": hostname,
                "message": message,
                "severity": severity,
                "log_source_name": log.log_source_name,  # Include log_source_name in the alert
            }
            disk_space_warnings.append(alert)
        except Exception as e:
            print(f"Error processing log entry: {log}, Error: {e}")
    
    return disk_space_warnings

def create_alerts(alerts):
    """
    Creates alerts in the database using the provided alert data.
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
            )
            print(f"Alert created: {alert_data['alert_title']} for hostname '{alert_data['hostname']}'")
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
