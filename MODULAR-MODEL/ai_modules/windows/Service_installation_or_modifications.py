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
    """Detect service installations or modifications (Event ID 7045) and create alerts."""
    # Filter logs for Event ID 7045 - Service installed or modified
    logs = LogEntry.objects.filter(processed=False, source='Security', event_id=7045, user=user).order_by('TimeCreated')[:100]

    service_installations = 0

    for log in logs:
        # Debugging: Print log message to check content
        print(f"Processing log: Event ID={log.event_id}, Message={log.message}")

        # Check if the message contains "A new service was installed"
        if 'A new service was installed' in log.message or 'service installation' in log.message:
            print(f"Debug: Detected service installation or modification: {log.message}")

            # Increment service installation count
            service_installations += 1

            # Create an alert for service installation or modification
            Alert.objects.create(
                alert_title='SERVICE INSTALLATION/MODIFICATION',
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

    # Optionally, log the number of service installations or modifications
    print(f"User {user} has had {service_installations} service installations/modifications.")
