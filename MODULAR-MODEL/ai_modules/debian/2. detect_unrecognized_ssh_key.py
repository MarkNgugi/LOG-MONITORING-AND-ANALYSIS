import os
import sys
import django
from datetime import datetime
import re

# Set up Django environment
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect_failed_publickey():
    """
    Detects failed SSH public key authentication attempts by analyzing logs from the LinuxLog model.
    """
    alerts = []

    # Get logs related to failed SSH public key authentication
    log_lines = LinuxLog.objects.filter(
        log_type="authlog",
        message__icontains="Failed publickey"
    )

    for log in log_lines:
        try:
            timestamp_str = log.timestamp
            message = log.message
            user = log.user if log.user else "Unknown"
            source_ip = None

            # Extract source IP and user from the log message
            match = re.search(r"Failed publickey for (\S+) from (\d+\.\d+\.\d+\.\d+)", message)
            if match:
                user = match.group(1)
                source_ip = match.group(2)
            else:
                continue  # Skip logs that don't match the pattern

            print(f"Parsing log entry: {log}")
            print(f"Extracted: timestamp='{timestamp_str}', user='{user}', source_ip='{source_ip}'")

            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")

            # Create an alert for failed SSH public key authentication
            alert = {
                "alert_title": "Use of Unrecognized SSH Key",
                "timestamp": timestamp,
                "hostname": log.hostname,
                "message": f"Detected use of Unrecognized SSH Key from user '{user}' from IP '{source_ip}'.",
                "severity": "High",
                "user": user,
            }
            alerts.append(alert)

        except Exception as e:
            print(f"Error processing log entry: {log}, Error: {e}")

    return alerts


def create_alerts(alerts):
    """
    Creates alerts in the database using the provided alert data.

    Args:
        alerts (list[dict]): A list of dictionaries containing alert details.
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
            )
            print(f"Alert created: {alert_data['alert_title']} for user '{alert_data['user']}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")


if __name__ == "__main__":
    # Detect failed SSH public key authentication attempts
    detected_alerts = detect_failed_publickey()
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)

        # Store the alerts in the database
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")