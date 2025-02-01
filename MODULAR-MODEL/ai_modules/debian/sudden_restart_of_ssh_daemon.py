import os
import sys
import django
from datetime import datetime
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import LinuxLog, Alert, User

def detect_ssh_restarts(log_lines):
    """
    Detects SSH service restarts or reloads based on commands in logs.
    """
    ssh_restart_patterns = [
        r"service ssh restart",
        r"systemctl restart ssh",
        r"systemctl reload ssh"
    ]
    
    alerts = []
    for line in log_lines:
        try:
            print(f"Processing log entry: {line.timestamp} - {line.command}")
            
            if not line.command:
                continue

            for pattern in ssh_restart_patterns:
                if re.search(pattern, line.command, re.IGNORECASE):
                    alert = {
                        "alert_title": "SSH Service Restart/Reload Detected",
                        "timestamp": line.timestamp,
                        "hostname": line.hostname,
                        "message": f"Detected SSH service restart or reload command: {line.command}",
                        "severity": "Medium",
                        "user": line.user if line.user else "Unknown",
                    }
                    alerts.append(alert)
                    print(f"Alert detected: {alert}")
                    break  # No need to check other patterns once matched
        except Exception as e:
            print(f"Error processing log entry: {line}, Error: {e}")
    
    return alerts

def create_alerts(alerts):
    """
    Creates alerts in the database.
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
            print(f"Alert created: {alert_data['alert_title']}")
    except Exception as e:
        print(f"Failed to create alerts: {e}")

if __name__ == "__main__":
    # Fetch logs from the database
    log_entries = LinuxLog.objects.filter(command__isnull=False).order_by("-timestamp")[:100]  # Adjust query as needed
    detected_alerts = detect_ssh_restarts(log_entries)
    
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
        
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")
