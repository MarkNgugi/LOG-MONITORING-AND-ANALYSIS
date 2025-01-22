import os
import sys
import django
from datetime import datetime
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User

def detect_ssh_restarts(log_lines):
    """
    Detects SSH service restarts in system logs.
    """
    ssh_restart_pattern = [
        r"Stopping ssh.service - OpenBSD Secure Shell server",
        r"Stopped ssh.service - OpenBSD Secure Shell server",
        r"Starting ssh.service - OpenBSD Secure Shell server",
        r"Started ssh.service - OpenBSD Secure Shell server"
    ]
    
    restart_sequence = []
    alerts = []

    for line in log_lines:
        try:
            print(f"Processing log line: {line}")
            
            parts = line.split(" ", 5)
            timestamp_str = parts[0]
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")

            for pattern in ssh_restart_pattern:
                if re.search(pattern, line):
                    restart_sequence.append((timestamp, pattern))
                    break

            if len(restart_sequence) >= 4:                
                expected_order = ssh_restart_pattern
                actual_order = [event[1] for event in restart_sequence[-4:]]
                
                if actual_order == expected_order:
                    alert = {
                        "alert_title": "SSH Service Restart Detected",
                        "timestamp": restart_sequence[-1][0],
                        "hostname": "ubuntu",  
                        "message": "Detected a restart of the SSH service.",
                        "severity": "Medium",
                    }
                    alerts.append(alert)
                    print(f"SSH Restart Detected: {alert}")                    
                    restart_sequence = []

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
            print(f"Alert created: {alert_data['alert_title']}")
    except Exception as e:
        print(f"Failed to create alerts: {e}")


if __name__ == "__main__":
    
    sample_logs = [
        "2025-01-22T13:35:13.843920+03:00 ubuntu systemd[1]: Stopping ssh.service - OpenBSD Secure Shell server...",
        "2025-01-22T13:35:13.844039+03:00 ubuntu systemd[1]: ssh.service: Deactivated successfully.",
        "2025-01-22T13:35:13.844287+03:00 ubuntu systemd[1]: Stopped ssh.service - OpenBSD Secure Shell server.",
        "2025-01-22T13:35:13.856307+03:00 ubuntu systemd[1]: Starting ssh.service - OpenBSD Secure Shell server...",
        "2025-01-22T13:35:13.902490+03:00 ubuntu systemd[1]: Started ssh.service - OpenBSD Secure Shell server.",
    ]

    detected_alerts = detect_ssh_restarts(sample_logs)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
        
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")
