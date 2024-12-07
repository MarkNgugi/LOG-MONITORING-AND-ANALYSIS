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
    """Detect suspicious PowerShell activity based on Event IDs 4103 and 4104."""
    
    # Filter logs for PowerShell script block logging events (Event IDs 4103, 4104)
    logs = LogEntry.objects.filter(processed=False, source='Security', event_id__in=[4103, 4104], user=user).order_by('TimeCreated')[:100]

    suspicious_activity_count = 0

    for log in logs:
        # Debugging: Print log message to check content
        print(f"Processing log: Event ID={log.event_id}, Message={log.message}")

        # Check for suspicious activity in PowerShell commands (e.g., obfuscated scripts, base64 encoded commands)
        if 'Invoke-Expression' in log.message or 'IEX' in log.message or 'Base64' in log.message:
            print(f"Debug: Detected suspicious PowerShell activity: {log.message}")

            # Increment suspicious activity count
            suspicious_activity_count += 1

            # Create an alert for suspicious PowerShell activity
            Alert.objects.create(
                alert_title='SUSPICIOUS POWERSHELL ACTIVITY',
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

    # Optionally, log the number of suspicious activities detected
    print(f"User {user} has had {suspicious_activity_count} suspicious PowerShell activities detected.")
