import os
import sys
import django
from datetime import datetime
import re
from django.db.models import Q  # Import Q for OR filtering

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect(time_window_minutes=100):
    """
    Detects Kernel Panic events using logs from the LinuxLog model.
    """
    kernel_panics = []
    alerts = []

    # Get kernel log entries that may indicate a kernel panic
    log_lines = LinuxLog.objects.filter(log_type="kernlog").filter(
        Q(message__icontains="Kernel panic - not syncing") |
        Q(message__icontains="Oops:") |
        Q(message__icontains="BUG:") |
        Q(message__icontains="general protection fault") |
        Q(message__icontains="stack overflow in task") |
        Q(message__icontains="hard lockup on CPU") |
        Q(message__icontains="soft lockup")
    )
    
    for log in log_lines:
        try:
            timestamp_str = log.timestamp
            message = log.message
            hostname = log.hostname if log.hostname else "Unknown"

            # Extract relevant kernel panic details
            match_panic = re.search(r"kernel: .*Kernel panic - not syncing", message)
            match_oops = re.search(r"kernel: .*Oops: [0-9]+ \[#.*\]", message)
            match_bug = re.search(r"kernel: .*BUG: .*", message)
            match_fault = re.search(r"kernel: .*general protection fault", message)

            if match_panic or match_oops or match_bug or match_fault:
                print(f"Parsing log entry: {log}")
                print(f"Extracted: timestamp='{timestamp_str}', hostname='{hostname}'")
                
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
                
                alert = {
                    "alert_title": "Kernel Panic Detected",
                    "timestamp": timestamp,
                    "hostname": hostname,
                    "message": f"Kernel Panic detected on '{hostname}'. Log: {message}",
                    "severity": "High",
                    "user": "System",
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
            print(f"Alert created: {alert_data['alert_title']} for system '{alert_data['hostname']}'")
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
        print("No Kernel Panic alerts detected.")