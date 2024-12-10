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
    """Detect hardware failures (Event ID 41 or 6008) and create alerts."""
    # Filter logs for Event IDs 41 and 6008 (Unexpected shutdowns)
    logs = LogEntry.objects.filter(processed=False, source='Security').filter(
        event_id__in=[41, 6008], user=user
    ).order_by('TimeCreated')[:100]

    hardware_failures = 0

    for log in logs:
        # Debugging: Print log message to check content
        print(f"Processing log: Event ID={log.event_id}, Message={log.message}")

        # Checking for hardware failure event
        if log.event_id == 41 or log.event_id == 6008:
            print(f"Debug: Detected hardware failure event in log: {log.message}")

            # Increment hardware failure count
            hardware_failures += 1

            # Create an alert for hardware failure
            Alert.objects.create(
                alert_title='HARDWARE FAILURE (UNEXPECTED SHUTDOWN)',
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

    # Optionally, log the number of hardware failures
    print(f"User {user} has had {hardware_failures} hardware failure events.")
