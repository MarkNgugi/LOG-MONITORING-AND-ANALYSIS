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
    """Detect event log cleared events (Event ID 1102) and create alerts."""
    # Filter logs for Event ID 1102 - Event log cleared
    logs = LogEntry.objects.filter(processed=False, source='Security', event_id=1102, user=user).order_by('TimeCreated')[:100]

    cleared_event_logs = 0

    for log in logs:
        # Debugging: Print log message to check content
        print(f"Processing log: Event ID={log.event_id}, Message={log.message}")

        # Check if the message contains "Event log cleared"
        if 'Event log cleared' in log.message:
            print(f"Debug: Detected event log cleared: {log.message}")

            # Increment cleared event log count
            cleared_event_logs += 1

            # Create an alert for event log cleared
            Alert.objects.create(
                alert_title='EVENT LOG CLEARED',
                timestamp=log.TimeCreated,
                host=log.source,
                message=log.message,
                severity='Critical',  # Severity can be adjusted based on your logic
                user=user
            )
            print(f"Alert created: {log.message}")

        # Mark log as processed
        log.processed = True
        log.save()

    # Optionally, log the number of cleared event logs
    print(f"User {user} has had {cleared_event_logs} event logs cleared.")
