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
    """Detect audit policy changes and create alerts."""
    # Filter logs for Audit Policy Change (Event ID 4719)
    logs = LogEntry.objects.filter(processed=False, source='Security', event_id=4719, user=user).order_by('TimeCreated')[:100]

    for log in logs:
        print(f"Processing log: Event ID={log.event_id}, Message={log.message}")

        # Create an alert for audit policy changes
        Alert.objects.create(
            alert_title='AUDIT POLICY CHANGE',
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

    print(f"Processed {len(logs)} audit policy change logs.")

