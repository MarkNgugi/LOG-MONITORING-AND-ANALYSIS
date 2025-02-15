import os
import sys
import django
from datetime import datetime
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect_sudoers_access(log_lines):
    """
    Detects access or attempts to access the sudoers file based on log patterns.
    """
    alerts = []
    
    for line in log_lines:
        try:
            print(f"Processing log line: {line}")
            timestamp_str = line.timestamp
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")
            
            # Pattern 1: Syntax error while trying to access /etc/sudoers (No access granted)
            if "/etc/sudoers" in line.message and "syntax error" in line.message:
                alert = {
                    "alert_title": "Attempt to Access sudoers Denied",
                    "timestamp": timestamp,
                    "hostname": line.hostname,
                    "message": "An attempt to access /etc/sudoers was detected but was denied due to an incorrect password.",
                    "severity": "Medium",
                    "user": line.user if line.user else "Unknown",
                    "log_source_name": line.log_source_name,  # Include log_source_name in the alert
                }
                alerts.append(alert)
                print(f"Alert created: {alert}")
            
            # Pattern 2: 3 incorrect password attempts while trying to edit sudoers
            elif "3 incorrect password attempts" in line.message and re.search(r"/usr/bin/\w+ sudoers", line.command):
                editor = line.command.split("/usr/bin/")[-1].split(" ")[0]  # Extracting the editor used
                alert = {
                    "alert_title": "Failed Sudoers Access Attempt",
                    "timestamp": timestamp,
                    "hostname": line.hostname,
                    "message": f"Detected 3 incorrect password attempts while trying to edit sudoers using {editor}.",
                    "severity": "High",
                    "user": line.user if line.user else "Unknown",
                    "log_source_name": line.log_source_name,  # Include log_source_name in the alert
                }
                alerts.append(alert)
                print(f"Alert created: {alert}")
            
            # Pattern 3: Successful access to sudoers file
            elif re.search(r"/usr/bin/\w+ sudoers", line.command) and "3 incorrect password attempts" not in line.message and "syntax error" not in line.message:
                editor = line.command.split("/usr/bin/")[-1].split(" ")[0]  # Extracting the editor used
                alert = {
                    "alert_title": "Sudoers File Accessed",
                    "timestamp": timestamp,
                    "hostname": line.hostname,
                    "message": f"User '{line.user}' accessed the sudoers file using {editor}.",
                    "severity": "Informational",
                    "user": line.user if line.user else "Unknown",
                    "log_source_name": line.log_source_name,  # Include log_source_name in the alert
                    "connection": "linux",
                }
                alerts.append(alert)
                print(f"Alert created: {alert}")

        except Exception as e:
            print(f"Error processing log line: {line.message}, Error: {e}")

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
            print(f"Alert recorded: {alert_data['alert_title']} for user '{alert_data['user']}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")

if __name__ == "__main__":
    # Fetch LinuxLog entries related to sudoers file access or attempts
    log_lines = LinuxLog.objects.filter(log_type='authlog',processed=False).order_by('-timestamp')[:2]
    detected_alerts = detect_sudoers_access(log_lines)
    
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
        
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")
