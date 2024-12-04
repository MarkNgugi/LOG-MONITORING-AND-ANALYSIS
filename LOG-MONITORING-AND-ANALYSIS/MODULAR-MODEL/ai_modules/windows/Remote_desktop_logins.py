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
    """Detect remote desktop logins (Event ID 4624 with Logon Type 10) and create alerts."""
    # Filter logs for remote interactive logon (Event ID 4624 and Logon Type 10)
    logs = LogEntry.objects.filter(processed=False, source='Security', event_id=4624, user=user).order_by('TimeCreated')[:100]

    remote_desktop_logins = 0

    for log in logs:
        print(f"Processing log: Event ID={log.event_id}, Message={log.message}")

        # Check if the log message contains 'Logon Type: 10' for Remote Desktop login
        if 'Logon Type: 10' in log.message:
            remote_desktop_logins += 1

            # Create an alert for remote desktop logins
            Alert.objects.create(
                alert_title='REMOTE DESKTOP LOGIN', 
                timestamp=log.TimeCreated,
                host=log.source,
                message=log.message,
                severity='Medium',  # Severity can be adjusted based on your logic
                user=user
            )
            print(f"Alert created: {log.message}")

        # Mark log as processed
        log.processed = True
        log.save()

    # Optionally, log the number of remote desktop logins
    print(f"User {user} has had {remote_desktop_logins} remote desktop logins.")
