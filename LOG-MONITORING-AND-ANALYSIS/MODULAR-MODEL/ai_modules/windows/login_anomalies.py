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
from django.db import connection, transaction

def detect_alerts(user):
    """Detect failed login attempts based on event IDs and create alerts."""
    # Fetch logs for the user and filter for event IDs 4625 and 4648
    logs = LogEntry.objects.filter(user=user, source='Security', event_id__in=[4625, 4648], processed=False).order_by('TimeCreated')[:100]
    print(f"Fetched logs: {logs}")
 
    failed_login_attempts = 0

    for log in logs:
        print(f"Processing log: Event ID={log.event_id}, Message={log.message}")

        # Check for failed login attempts using specific event IDs
        if log.event_id == 4625:  # Event ID for failed login attempts
            failed_login_attempts += 1
            severity = 'High' if failed_login_attempts > 3 else 'Medium'

            # Check if an alert already exists for this log
            existing_alert = Alert.objects.filter(
                alert_title='FAILED LOGIN ATTEMPT',
                message=log.message,
                user=user
            ).first()

            if not existing_alert:
                # Create an alert for failed login attempts if one doesn't already exist
                Alert.objects.create(
                    alert_title='FAILED LOGIN ATTEMPT',
                    timestamp=log.TimeCreated,
                    host=log.source,
                    message=log.message,
                    severity=severity,
                    user=user
                )
                print(f"Alert created: {log.message}")

        # Mark log as processed
        with transaction.atomic():
            log.processed = True
            log.save()

    # Optionally, handle the case of too many failed logins
    if failed_login_attempts > 5:
        print(f"User {user} has too many failed login attempts.")
        # Send email or take further action (e.g., disable account, notify admin)

    print(connection.queries[-1])  # Print the last query Django executed

# Example: detect_alerts(user_instance)
