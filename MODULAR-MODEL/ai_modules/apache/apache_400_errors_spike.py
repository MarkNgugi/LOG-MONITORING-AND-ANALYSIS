import os
import sys
import django
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, ApacheLog

def detect_4xx_spike(log_lines, time_window_minutes=1, max_4xx_errors=10):
    """
    Detects spikes in 4xx status codes within a short period.
    """
    error_counts = {}
    alerts = []

    for line in log_lines:
        try:
            print(f"Processing log line: {line}")

            # Parse the timestamp (assuming it's stored as a string in ISO 8601 format)
            timestamp_str = line.timestamp
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")

            # Check if the response code is a 4xx error
            if line.response_code and 400 <= line.response_code < 500:
                client_ip = line.client_ip
                key = client_ip

                if key not in error_counts:
                    error_counts[key] = []

                error_counts[key].append(timestamp)

            # Clean up old timestamps outside the time window
            for ip in error_counts:
                error_counts[ip] = [t for t in error_counts[ip] if t > timestamp - timedelta(minutes=time_window_minutes)]

                # Check if the number of 4xx errors exceeds the threshold
                if len(error_counts[ip]) >= max_4xx_errors:
                    alert = {
                        "alert_title": "Apache 4xx Errors Spike",
                        "timestamp": timestamp,
                        "hostname": line.log_source_name,  # Assuming log_source_name is the hostname
                        "message": f"Detected {len(error_counts[ip])} 4xx errors from IP '{ip}' within {time_window_minutes} minute(s).",
                        "severity": "Medium",
                        "user": None,  # You can associate this with a user if needed
                    }
                    alerts.append(alert)
                    error_counts[ip] = []  # Reset the count after triggering an alert

        except Exception as e:
            print(f"Error processing log line: {line}, Error: {e}")

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
            print(f"Alert created: {alert_data['alert_title']} for IP '{alert_data.get('user', 'N/A')}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")


if __name__ == "__main__":
    # Fetch ApacheLog entries related to access logs
    log_lines = ApacheLog.objects.filter(log_type='access').order_by('-timestamp')[:100]  # Fetch the last 100 access logs

    detected_alerts = detect_4xx_spike(log_lines)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)

        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")