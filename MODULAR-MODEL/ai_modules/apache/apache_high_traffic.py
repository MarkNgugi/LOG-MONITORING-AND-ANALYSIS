import os
import sys
import django
from datetime import datetime, timedelta
from django.db.models.signals import post_save
from django.dispatch import receiver

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, ApacheLog

# Global variables to store logs and counts for the sliding window
log_window = []
max_status_codes_threshold = 10  # Threshold for high traffic
time_window_minutes = 1  # Time window in minutes

@receiver(post_save, sender=ApacheLog)
def process_log_in_real_time(sender, instance, **kwargs):
    """
    Processes each new log entry in real-time using Django's post_save signal.
    """
    try:
        # Parse the timestamp from the log entry
        timestamp_str = instance.timestamp
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")

        # Add the log to the sliding window
        log_window.append((timestamp, instance))

        # Remove logs that are older than 1 minute
        current_time = datetime.now()
        while log_window and (current_time - log_window[0][0]) > timedelta(minutes=time_window_minutes):
            log_window.pop(0)

        # Count logs with 2xx, 3xx, 4xx, or 5xx status codes in the last 1 minute
        status_code_count = 0
        for log_timestamp, log in log_window:
            if log.response_code and str(log.response_code).startswith(('2', '3', '4', '5')):
                status_code_count += 1

        # Check if the count exceeds the threshold
        if status_code_count > max_status_codes_threshold:
            alert = {
                "alert_title": "Apache High Traffic",
                "timestamp": timestamp,
                "hostname": instance.log_source_name,  # Use the log source name as hostname
                "message": f"Detected {status_code_count} logs with status codes 2xx, 3xx, 4xx, or 5xx within 1 minute.",
                "severity": "High",
                "user": None,  # Will be set to the default user when creating the alert
            }
            create_alerts([alert])

    except Exception as e:
        print(f"Error processing log entry: {instance.timestamp}, Error: {e}")


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
    # Start monitoring logs in real-time
    print("Monitoring Apache logs in real-time...")