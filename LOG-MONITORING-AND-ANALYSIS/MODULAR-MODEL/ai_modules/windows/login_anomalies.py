import os
import sys
import django

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
sys.path.append(project_root)

# Set the Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import *


def detect_alerts(user):
    """Detect alerts from unprocessed logs."""
    logs = LogEntry.objects.filter(processed=False, source='Security', user=user).order_by('TimeCreated')[:100]

    failed_login_attempts = 0

    for log in logs:
        if 'Failed login attempt' in log.message:
            failed_login_attempts += 1
            severity = 'High' if failed_login_attempts > 3 else 'Medium'

            # Create an alert for failed logins
            Alert.objects.create(
                alert_title='FAILED LOGIN ATTEMPT',
                timestamp=log.TimeCreated,
                host=log.source,
                message=log.message,
                severity=severity,
                user=user
            )
            print(f"Alert created: {log.message}")

        log.processed = True  # Mark as processed
        log.save()

    # Optionally, handle the case of too many failed logins
    if failed_login_attempts > 5:
        # Take further action (e.g., notify admin, block user, etc.)
        print(f"User {user} has too many failed login attempts.")
        # Add further logic here as needed

# Call the function to detect alerts for a user
# For example: detect_alerts('username')
