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
    """Detect system shutdowns and restarts (Event ID 1074) and create alerts."""
    # Filter logs for Event ID 1074 - System shutdown or restart
    logs = LogEntry.objects.filter(processed=False, source='Security', event_id=1074, user=user).order_by('TimeCreated')[:100]

    shutdown_or_restart = 0

    for log in logs:
        # Debugging: Print log message to check content
        print(f"Processing log: Event ID={log.event_id}, Message={log.message}")

        # Checking if the message contains "shutdown" or "restart"
        if 'shutdown' in log.message.lower() or 'restart' in log.message.lower():
            print(f"Debug: Detected shutdown or restart in log: {log.message}")

            # Increment shutdown or restart count
            shutdown_or_restart += 1

            # Create an alert for shutdown or restart
            Alert.objects.create(
                alert_title='SYSTEM SHUTDOWN OR RESTART',
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

    # Optionally, log the number of shutdown or restart events
    print(f"User {user} has had {shutdown_or_restart} system shutdown/restart events.")
