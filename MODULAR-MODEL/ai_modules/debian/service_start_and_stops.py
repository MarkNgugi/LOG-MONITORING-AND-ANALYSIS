import os
import sys
import django
from datetime import datetime
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect_service_events(log_lines):
    """
    Detects service start and stop events for specific services by checking the command field.
    """
    services = ["systemd", "cron", "rsyslog", "NetworkManager", "apache2", "nginx", "postgresql", "fail2ban", "ufw"]
    event_patterns = {
        "start": r"/usr/sbin/service (\w+) (start|restart|enable)",
        "stop": r"/usr/sbin/service (\w+) (stop|disable)",
    }
    
    alerts = []
    
    for line in log_lines:
        try:
            print(f"Processing log line: {line}")
            timestamp_str = line.timestamp
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")
            
            # Check the command field for service start/stop patterns
            if line.command:
                for event, pattern in event_patterns.items():
                    match = re.search(pattern, line.command, re.IGNORECASE)
                    if match:
                        service_name = match.group(1)
                        action = match.group(2)
                        
                        if service_name in services:
                            alert = {
                                "alert_title": f"{service_name.capitalize()} Service {action.capitalize()} Detected",
                                "timestamp": timestamp,
                                "hostname": line.hostname,
                                "message": f"Detected {action.lower()} of service '{service_name}'.",
                                "severity": "Medium",
                            }
                            alerts.append(alert)
                            print(f"Service {action.capitalize()} Detected: {alert}")
                        
        except Exception as e:
            print(f"Error processing log line: {line.command}, Error: {e}")
    
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
    # Fetch LinuxLog entries related to auth logs (since commands are typically in auth logs)
    log_lines = LinuxLog.objects.filter(log_type='authlog').order_by('-timestamp')[:100]  # Fetch the last 100 authlog entries
    
    detected_alerts = detect_service_events(log_lines)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
        
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")