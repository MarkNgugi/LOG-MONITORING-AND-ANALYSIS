import os
import sys
import django
from datetime import datetime
from django.utils.timezone import make_aware

# Set up Django environment
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ALERTING.settings')
django.setup()

from log_management_app.models import Alert, User, LinuxLog

def detect_system_events(log_lines):
    """
    Detects system reboots and shutdowns from LinuxLog entries.

    Args:
        log_lines (QuerySet): A QuerySet of LinuxLog objects.

    Returns:
        list: A list of dictionaries containing alert details.
    """
    alerts = []

    for line in log_lines:
        try:
            print(f"Processing log line: {line.message}")

            # Check for system reboot or shutdown messages
            if "System is rebooting" in line.message:
                alert = {
                    "alert_title": "System Reboot Detected",
                    "timestamp": make_aware(datetime.strptime(line.timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")),
                    "hostname": line.hostname,
                    "message": "System is rebooting.",
                    "severity": "Medium",
                    "user": line.user if line.user else "System",
                }
                alerts.append(alert)
                print(f"System reboot detected: {line.message}")

            elif "System is powering down" in line.message:
                alert = {
                    "alert_title": "System Shutdown Detected",
                    "timestamp": make_aware(datetime.strptime(line.timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")),
                    "hostname": line.hostname,
                    "message": "System is powering down.",
                    "severity": "Medium",
                    "user": line.user if line.user else "System",
                }
                alerts.append(alert)
                print(f"System shutdown detected: {line.message}")

        except Exception as e:
            print(f"Error processing log line: {line.message}, Error: {e}")

    return alerts


def create_alerts(alerts):
    """
    Creates alerts in the database using the provided alert data.

    Args:
        alerts (list[dict]): A list of dictionaries containing alert details.
    """
    try:
        # Fetch the default user (or any user) to associate with the alert
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
            print(f"Alert created: {alert_data['alert_title']} for host '{alert_data['hostname']}'")

    except Exception as e:
        print(f"Failed to create alerts: {e}")


if __name__ == "__main__":
    # Fetch LinuxLog entries related to system events (syslog or authlog)
    log_lines = LinuxLog.objects.filter(log_type__in=['syslog', 'authlog']).order_by('-timestamp')[:100]  # Fetch the last 100 logs

    # Detect system reboots and shutdowns
    detected_alerts = detect_system_events(log_lines)

    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)

        # Create alerts in the database
        create_alerts(detected_alerts)
    else:
        print("No system reboot or shutdown alerts detected.")