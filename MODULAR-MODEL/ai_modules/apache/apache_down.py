import os
import sys
import django
from datetime import datetime
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, ApacheLog

# Shutdown patterns to detect Apache shutdown events
shutdown_patterns = [
    r'AH00430: Apache.*shutting down',  # Specific shutdown pattern
    r'AH00094: Command line:.*-k shutdown',  # Command line shutdown
    r'Apache.*DOWN',  # Generic "Apache down" pattern
    r'AH00492:.*SIGWINCH.*shutting down gracefully'  # SIGWINCH graceful shutdown pattern
]

def detect_apache_shutdown(log_lines):
    """
    Detects Apache shutdown events in the provided log lines based on the shutdown patterns.

    Args:
        log_lines (QuerySet): A QuerySet of ApacheLog objects.

    Returns:
        list: A list of dictionaries containing alert details for detected shutdown events.
    """
    alerts = []

    for log in log_lines:
        try:
            if log.error_message:  # Check if the error_message field is not empty
                for pattern in shutdown_patterns:
                    if re.search(pattern, log.error_message, re.IGNORECASE):
                        alert = {
                            "alert_title": "Apache Shutdown Detected",
                            "timestamp": datetime.now(),  # Use current time for the alert
                            "hostname": log.log_source_name,  # Use the log source name as hostname
                            "message": f"Apache shutdown detected: {log.error_message}",
                            "severity": "High",
                            "user": None,  # Will be set to the default user when creating the alert
                        }
                        alerts.append(alert)
                        break  # Stop checking other patterns if a match is found
        except Exception as e:
            print(f"Error processing log line: {log.error_message}, Error: {e}")

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
            print(f"Alert created: {alert_data['alert_title']} - {alert_data['message']}")
    except Exception as e:
        print(f"Failed to create alerts: {e}")


if __name__ == "__main__":
    # Fetch ApacheLog entries related to error logs
    log_lines = ApacheLog.objects.filter(log_type='error').order_by('-timestamp')[:100]  # Fetch the last 100 error logs

    detected_alerts = detect_apache_shutdown(log_lines)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)

        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")