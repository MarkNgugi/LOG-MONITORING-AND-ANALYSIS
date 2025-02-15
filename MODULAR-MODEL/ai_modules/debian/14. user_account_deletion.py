import os
import sys
import django
from datetime import datetime
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect_user_deletion(log_lines):
    """
    Detects user deletion events by checking the service and message fields.
    """
    alerts = []
    
    for line in log_lines:
        try:
            print(f"Processing log line: {line}")
            timestamp_str = line.timestamp
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")
            
            # Check if the service is "userdel" and the message contains "delete user"
            if line.service == "userdel" and "delete user" in line.message.lower():
                # Extract the username from the message
                match = re.search(r"delete user '(\w+)'", line.message)
                if match:
                    username = match.group(1)  # The deleted username
                    
                    # Create an alert for the user deletion
                    alert = {
                        "alert_title": f"User Account Deleted: {username}",
                        "timestamp": timestamp,
                        "hostname": line.hostname,
                        "message": f"Detected deletion of user account '{username}'.",
                        "severity": "High",
                        "log_source_name": line.log_source_name,  # Include log_source_name in the alert
                        "connection": "linux",
                    }
                    alerts.append(alert)
                    print(f"User Deletion Detected: {alert}")
                
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
            print(f"Alert created: {alert_data['alert_title']}")
    except Exception as e:
        print(f"Failed to create alerts: {e}")

if __name__ == "__main__":    
    log_lines = LinuxLog.objects.filter(log_type='authlog',processed=False).order_by('-timestamp')[:2]  # Fetch the last 100 authlog entries
    
    detected_alerts = detect_user_deletion(log_lines)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
        
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")