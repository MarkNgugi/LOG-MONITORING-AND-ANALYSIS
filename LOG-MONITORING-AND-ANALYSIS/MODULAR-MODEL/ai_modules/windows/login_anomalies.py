import os
import sys
import django
from datetime import datetime, timedelta

# Add the Django project root (where manage.py is located) to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
sys.path.append(project_root)

# Set the Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import LogEntry
from log_management_app.models import Anomaly, Alert

def detect_anomalies_and_alerts():
    # Fetch all LogEntry records from the database where source is 'Windows'
    windows_logs = LogEntry.objects.filter(source__icontains='windows')

    for log in windows_logs:
        message = log.message.lower()

        # Check for common login anomalies
        if "failed login" in message or "account locked" in message:
            # Save anomaly
            Anomaly.objects.create(
                source_name=log.source,
                anomaly="Login Anomaly Detected",
                detected_at=datetime.now()
            )
            print(f"Anomaly detected in log from {log.source}: {log.message}")

        # Check for alerts based on critical login-related keywords
        if "unauthorized access" in message or "privilege escalation" in message:
            # Determine alert level
            alert_level = 'high' if 'privilege escalation' in message else 'medium'
            Alert.objects.create(
                alert_title="Security Alert",
                alert_desc=log.message[:100],
                alert_level=alert_level,
                detected_at=datetime.now()
            )
            print(f"Alert detected in log from {log.source}: {log.message}")

if __name__ == '__main__':
    detect_anomalies_and_alerts()
