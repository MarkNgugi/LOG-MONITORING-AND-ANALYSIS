# MODULAR-MODEL/ai_modules/windows/login_anomalies.py
import os
import sys
import django

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
sys.path.append(project_root)

# Set the Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import *

def detect_alerts():
    """Detect alerts from unprocessed logs."""
    logs = LogEntry.objects.filter(processed=False, source='Security').order_by('TimeCreated')[:100]

    for log in logs:
        if 'Failed login attempt' in log.message:
            # Create an alert for failed logins
            Alert.objects.create(
                alert_title='FAILED LOGIN ATTEMPT',
                timestamp=log.TimeCreated,
                host=log.source,
                message=log.message,
                severity='High',
            )
            print(f"Alert created: {log.message}")

        log.processed = True  # Mark as processed
        log.save()


