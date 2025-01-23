import os
import sys
import django
from datetime import datetime
import ipaddress
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User

# Define expected IP ranges
EXPECTED_IP_RANGES = [
    ipaddress.IPv4Network("192.168.0.0/24"),
    ipaddress.IPv4Network("10.0.0.0/8")
]

def is_ip_unusual(ip):
    """Checks if an IP address is outside the expected ranges."""
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return not any(ip_obj in network for network in EXPECTED_IP_RANGES)
    except ValueError:
        return False

def detect(log_lines):
    """
    Detects root login from unusual IP addresses.
    """
    alerts = []

    for line in log_lines:
        try:
            print(f"Processing log line: {line}")

            # Extract timestamp and check for root login
            parts = line.split(" ", 5)
            timestamp_str = parts[0]
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")

            if "Accepted" in line and "root" in line:
                match_ip = re.search(r"from ([\d.]+) port", line)
                
                if match_ip:
                    ip = match_ip.group(1)
                    if is_ip_unusual(ip):
                        alert = {
                            "alert_title": "Successful Root Login from Unusual IP",
                            "timestamp": timestamp,
                            "hostname": "ubuntu",
                            "message": f"Root login detected from unusual IP address: {ip}.",
                            "severity": "Critical",
                            "ip": ip,
                        }
                        alerts.append(alert)
                        print(f"Alert detected: {alert}")

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
            print(f"Alert created: {alert_data['alert_title']} for IP '{alert_data['ip']}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")

if __name__ == "__main__":
    sample_logs = [
        "2025-01-20T17:05:21.665037+03:00 ubuntu sshd[12345]: Accepted password for root from 203.0.113.5 port 22 ssh2",
        "2025-01-20T17:10:21.665037+03:00 ubuntu sshd[12345]: Accepted password for root from 192.168.1.10 port 22 ssh2",
    ]

    detected_alerts = detect(sample_logs)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)

        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")