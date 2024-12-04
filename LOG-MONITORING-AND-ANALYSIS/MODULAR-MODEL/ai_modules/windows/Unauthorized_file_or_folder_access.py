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
    """Detect unauthorized file or folder access (Event ID 4663) and create alerts."""
    # Filter logs for Event ID 4663 - Unauthorized file or folder access
    logs = LogEntry.objects.filter(processed=False, source='Security', event_id=4663, user=user).order_by('TimeCreated')[:100]

    unauthorized_access = 0

    for log in logs:
        # Debugging: Print log message to check content
        print(f"Processing log: Event ID={log.event_id}, Message={log.message}")

        # Checking if the message contains "Access Denied" or "Denied"
        if 'Denied' in log.message or 'Access Denied' in log.message:
            print(f"Debug: Detected potential unauthorized access in log: {log.message}")

            # Increment unauthorized access count
            unauthorized_access += 1

            # Create an alert for unauthorized file or folder access
            Alert.objects.create(
                alert_title='UNAUTHORIZED FILE/FOLDER ACCESS',
                timestamp=log.TimeCreated,
                host=log.source,
                message=log.message,
                severity='High',  # Severity can be adjusted based on your logic
                user=user
            )
            print(f"Alert created: {log.message}")

        # Mark log as processed
        log.processed = True
        log.save()

    # Optionally, log the number of unauthorized access attempts
    print(f"User {user} has had {unauthorized_access} unauthorized file/folder access attempts.")
