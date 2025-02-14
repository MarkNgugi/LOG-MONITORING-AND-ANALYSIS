import os
import sys
import django
import re
from datetime import datetime
from django.db.models import Q

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

# Patterns for detecting account lockout events
LOCKOUT_PATTERNS = [
    r"sudo: .*Account locked due to too many failed login attempts for (\S+)",
    r"faillock.*User (\S+) has been locked due to .* failed login attempts",
    r"pam_tally.*account temporarily locked",
    r"sshd.*Failed password.*Connection closed",
    r"systemd.*User (\S+) locked due to failed logins"
]

def detect():
    """
    Detects account lockout events using logs from the LinuxLog model.
    """
    lockout_alerts = []

    # Query logs for possible account lockout events
    log_entries = LinuxLog.objects.filter(
        log_type="authlog",
        processed=False  # Only fetch unprocessed logs
    ).filter(
        Q(message__icontains="Account locked") |
        Q(message__icontains="failed login attempts") |
        Q(message__icontains="pam_tally") |
        Q(message__icontains="sshd")
    )

    for log in log_entries:
        try:
            timestamp_str = log.timestamp
            message = log.message
            hostname = log.hostname if log.hostname else "Unknown"
            user = "Unknown"

            # Check if message matches any lockout pattern
            for pattern in LOCKOUT_PATTERNS:
                match = re.search(pattern, message)
                if match:
                    user = match.group(1) if match.groups() else "Unknown"
                    break

            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")

            alert = {
                "alert_title": "Account Lockout Detected",
                "timestamp": timestamp,
                "hostname": hostname,
                "message": f"User '{user}' account has been locked due to failed login attempts.",
                "severity": "High",
                "user": user,
                "log_source_name": log.log_source_name,  # Include log_source_name in the alert
            }
            lockout_alerts.append(alert)

        except Exception as e:
            print(f"Error processing log entry: {log}, Error: {e}")

    return lockout_alerts

def create_alerts(alerts):
    """
    Creates alerts in the database using the provided alert data.
    """
    try:
        default_user = User.objects.first()
        if not default_user:
            raise ValueError("No default user found in the database.")

        for alert_data in alerts:
            Alert.objects.create(
                alert_title=alert_data["alert_title"],
                timestamp=alert_data["timestamp"],
                hostname=alert_data["hostname"],
                message=alert_data["message"],
                severity=alert_data["severity"],
                user=default_user,
                log_source_name=alert_data["log_source_name"],  # Include log_source_name in the alert
            )
            print(f"Alert created: {alert_data['alert_title']} for user '{alert_data['user']}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")

if __name__ == "__main__":
    detected_alerts = detect()
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
        create_alerts(detected_alerts)
    else:
        print("No account lockouts detected.")
