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
    Detects user deletion events by checking the message field for specific patterns.
    """
    alerts = []
    
    for line in log_lines:
        try:
            print(f"Processing log line: {line}")
            timestamp_str = line.timestamp
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")
            
            # Check the message field for user deletion logs
            if line.message:
                # Pattern 1: accounts-daemon: request by ... delete user 'newusername' (1002)
                pattern1 = r"accounts-daemon: .* delete user '(\w+)'"
                match1 = re.search(pattern1, line.message)
                
                if match1:
                    username = match1.group(1)  # The deleted username
                    
                    alert = {
                        "alert_title": f"User Deletion Detected: {username}",
                        "timestamp": timestamp,
                        "hostname": line.hostname,
                        "message": f"Detected deletion of user '{username}'.",
                        "severity": "High",
                    }
                    alerts.append(alert)
                    print(f"User Deletion Detected: {alert}")
                
                # Pattern 2: userdel[30053]: delete user 'newusername'
                pattern2 = r"userdel\[\d+\]: delete user '(\w+)'"
                match2 = re.search(pattern2, line.message)
                
                if match2:
                    username = match2.group(1)  # The deleted username
                    
                    alert = {
                        "alert_title": f"User Deletion Detected: {username}",
                        "timestamp": timestamp,
                        "hostname": line.hostname,
                        "message": f"Detected deletion of user '{username}'.",
                        "severity": "High",
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
            )
            print(f"Alert created: {alert_data['alert_title']}")
    except Exception as e:
        print(f"Failed to create alerts: {e}")

if __name__ == "__main__":
    # Fetch LinuxLog entries related to auth logs (since user deletion commands are typically in auth logs)
    log_lines = LinuxLog.objects.filter(log_type='authlog').order_by('-timestamp')[:100]  # Fetch the last 100 authlog entries
    
    detected_alerts = detect_user_deletion(log_lines)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
        
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")