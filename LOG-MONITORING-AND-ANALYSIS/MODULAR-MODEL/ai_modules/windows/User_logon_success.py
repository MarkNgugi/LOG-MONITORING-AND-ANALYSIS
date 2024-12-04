import os
import sys
import django

# Set up project path and Django settings
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
sys.path.append(project_root)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import LogEntry, Alert
from user_management_app.models import User

def detect_alerts(user):
    """Detect successful login events and create alerts."""
    # Filter logs for successful login event (e.g., event_id 4624)
    logs = LogEntry.objects.filter(processed=False, source='Security', user=user).order_by('TimeCreated')[:100]

    successful_logins = 0

    for log in logs:
        if log.event_id == 4624:  # Event ID for successful login
            successful_logins += 1

            # Determine the severity dynamically (can be adjusted as per your logic)
            if successful_logins == 1:
                severity = 'Low'  # First successful login
            elif successful_logins <= 3:
                severity = 'Medium'  # 2-3 successful logins
            else:
                severity = 'High'  # More than 3 successful logins

            # Create an alert for successful logins
            Alert.objects.create(
                alert_title='SUCCESSFUL LOGIN',
                timestamp=log.TimeCreated,
                host=log.source,
                message=log.message,
                severity=severity,  
                user=user
            )
            print(f"Alert created: {log.message}")

        log.processed = True  # Mark log as processed
        log.save()

    # Optionally, log the number of successful logins
    print(f"User {user} has had {successful_logins} successful logins.")

