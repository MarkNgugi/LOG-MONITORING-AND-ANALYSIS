import os
import sys
import django
from datetime import datetime, timedelta
import re
from django.utils.timezone import make_aware
from dateutil import parser
from django.utils.timezone import make_aware

from django.utils.timezone import is_aware

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User


def detect_ssh_connection_spikes(log_lines, time_window_minutes=1, max_connections=10):
    connection_attempts = {}
    alerts = []

    for line in log_lines:
        try:
            print(f"Processing log line: {line}")
            
            parts = line.split(" ", 5)
            timestamp_str = parts[0]
            timestamp = parser.parse(timestamp_str)  
            
            if not is_aware(timestamp):
                timestamp = make_aware(timestamp)

            if "Accepted publickey for" in line or "Accepted password for" in line:
                match_ip = re.search(r"from\s+([\d.]+)", line)
                if match_ip:
                    ip_address = match_ip.group(1).strip()
                    print(f"SSH connection detected from IP: {ip_address}")

                    if ip_address not in connection_attempts:
                        connection_attempts[ip_address] = []

                    connection_attempts[ip_address].append(timestamp)
            
            for ip in list(connection_attempts.keys()):
                connection_attempts[ip] = [
                    t for t in connection_attempts[ip]
                    if t > timestamp - timedelta(minutes=time_window_minutes)
                ]

                if len(connection_attempts[ip]) >= max_connections:
                    alert = {
                        "alert_title": "High Number of SSH Connections Detected",
                        "timestamp": timestamp,
                        "hostname": "ubuntu",
                        "message": f"Detected {len(connection_attempts[ip])} SSH connections from IP '{ip}' within {time_window_minutes} minute(s).",
                        "severity": "High",
                        "ip_address": ip,
                    }
                    alerts.append(alert)
                    connection_attempts[ip] = []

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
            print(f"Alert created: {alert_data['alert_title']} for IP '{alert_data['ip_address']}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")


if __name__ == "__main__":
    sample_logs = [
        "2025-01-20T17:05:21.665037+03:00 ubuntu sshd[12345]: Accepted publickey for user from 192.168.1.2 port 22 ssh2",
        "2025-01-20T17:05:25.240157+03:00 ubuntu sshd[12346]: Accepted password for user from 192.168.1.2 port 22 ssh2",
        "2025-01-20T17:05:30.240157+03:00 ubuntu sshd[12347]: Accepted password for user from 192.168.1.2 port 22 ssh2",
        "2025-01-20T17:05:35.240157+03:00 ubuntu sshd[12348]: Accepted password for user from 192.168.1.2 port 22 ssh2",
        "2025-01-20T17:05:40.240157+03:00 ubuntu sshd[12349]: Accepted password for user from 192.168.1.2 port 22 ssh2",
        "2025-01-20T17:05:45.240157+03:00 ubuntu sshd[12350]: Accepted password for user from 192.168.1.2 port 22 ssh2",
        "2025-01-20T17:05:50.240157+03:00 ubuntu sshd[12351]: Accepted password for user from 192.168.1.2 port 22 ssh2",
        "2025-01-20T17:05:55.240157+03:00 ubuntu sshd[12352]: Accepted password for user from 192.168.1.2 port 22 ssh2",
        "2025-01-20T17:06:00.240157+03:00 ubuntu sshd[12353]: Accepted password for user from 192.168.1.2 port 22 ssh2",
        "2025-01-20T17:06:05.240157+03:00 ubuntu sshd[12354]: Accepted password for user from 192.168.1.2 port 22 ssh2",
    ]

    detected_alerts = detect_ssh_connection_spikes(sample_logs)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)

        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")
