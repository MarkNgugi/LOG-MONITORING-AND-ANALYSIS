import os
import sys
import django
from datetime import datetime, timedelta

# Add the project directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

# Set the settings module for Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

# Import models
from log_management_app.models import Alert, User

def detect(log_lines, time_window_minutes=5, max_failed_attempts=3):
    """
    Detects multiple failed SSH login attempts within a short period.
    """
    failed_attempts = {}
    alerts = []

    for line in log_lines:
        if "Failed password" in line and "sshd" in line:
            try:
                # Extract the timestamp, hostname, and user
                parts = line.split(" ", 5)
                timestamp_str = parts[0]
                hostname = parts[4]
                user = line.split("invalid user")[-1].split("from")[0].strip()
                source_ip = line.split("from")[1].split("port")[0].strip()

                # Debugging output
                print(f"Parsing log line: {line}")
                print(f"Extracted: timestamp='{timestamp_str}', hostname='{hostname}', user='{user}', source_ip='{source_ip}'")

                # Parse the timestamp
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")
                key = (user, source_ip)

                # Initialize failed attempts for this user and IP
                if key not in failed_attempts:
                    failed_attempts[key] = []

                # Add the current timestamp
                failed_attempts[key].append(timestamp)

                # Remove attempts outside the time window
                failed_attempts[key] = [t for t in failed_attempts[key] if t > timestamp - timedelta(minutes=time_window_minutes)]

                # Debugging output
                print(f"Failed attempts for {key}: {failed_attempts[key]}")

                # Check if the threshold is exceeded
                # Check if the threshold is met or exceeded
                if len(failed_attempts[key]) >= max_failed_attempts:
                    alert = {
                        "alert_title": "Multiple Failed SSH Login Attempts",
                        "timestamp": timestamp,
                        "hostname": hostname,
                        "message": f"Detected {len(failed_attempts[key])} failed login attempts for user '{user}' from IP '{source_ip}' within {time_window_minutes} minutes.",
                        "severity": "High",
                        "user": user,
                    }
                    alerts.append(alert)
                    # Clear attempts for the user after an alert is created
                    failed_attempts[key] = []

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
        # Assume a default user exists; replace with logic to find the user if needed
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
    # Sample logs provided by the user
    sample_logs = [
        "2025-01-20T16:19:49.040080+03:00 ubuntu sshd[181502]: Invalid user wronguser from 192.168.15.243 port 40030",
        "2025-01-20T16:19:54.267943+03:00 ubuntu sshd[181502]: pam_unix(sshd:auth): check pass; user unknown",
        "2025-01-20T16:19:54.268460+03:00 ubuntu sshd[181502]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.15.243",
        "2025-01-20T16:19:55.907980+03:00 ubuntu sshd[181502]: Failed password for invalid user wronguser from 192.168.15.243 port 40030 ssh2",
        "2025-01-20T16:19:57.076163+03:00 ubuntu sshd[181502]: pam_unix(sshd:auth): check pass; user unknown",
        "2025-01-20T16:19:59.127539+03:00 ubuntu sshd[181502]: Failed password for invalid user wronguser from 192.168.15.243 port 40030 ssh2",
        "2025-01-20T16:20:03.844286+03:00 ubuntu sshd[181502]: pam_unix(sshd:auth): check pass; user unknown",
        "2025-01-20T16:20:06.387045+03:00 ubuntu sshd[181502]: Failed password for invalid user wronguser from 192.168.15.243 port 40030 ssh2",
        "2025-01-20T16:20:07.154185+03:00 ubuntu sshd[181502]: Connection closed by invalid user wronguser 192.168.15.243 port 40030 [preauth]",
        "2025-01-20T16:20:07.155050+03:00 ubuntu sshd[181502]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.15.243",
    ]

    # Detect alerts
    detected_alerts = detect(sample_logs)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)

        # Store the alerts in the database
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")
