import os
import sys
import django
from datetime import datetime, timedelta
from django.utils import timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, WindowsLog

def detect_group_enumeration():
    """
    Detects group enumeration events (Event ID 4798) and creates alerts.
    """
    alerts = []
        
    group_enumeration_events = WindowsLog.objects.filter(event_id=4798)
    
    for log in group_enumeration_events:
        try:
            timestamp = log.timestamp
            
            alert = {
                "alert_title": "User Group Membership Enumerated",
                "timestamp": timestamp,
                "hostname": log.computer,  
                "message": f"User '{log.log_user}''s local group membership was enumerated, possibly indicative of reconnaissance activity.",
                "severity": "Medium",  
                "user": log.log_user, 
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
            )
            print(f"Alert created: {alert_data['alert_title']} for user '{alert_data['user']}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")

if __name__ == "__main__":    
    detected_alerts = detect_group_enumeration()
    
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
                
        create_alerts(detected_alerts)
    else:
        print("No group membership enumeration alerts detected.")
