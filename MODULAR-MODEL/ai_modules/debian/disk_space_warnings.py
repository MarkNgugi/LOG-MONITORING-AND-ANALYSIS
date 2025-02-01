import os
import sys
import django
from datetime import datetime, timedelta
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User

def detect(log_lines, time_window_minutes=5, max_failed_attempts=3):
    """
    Detects multiple failed sudo attempts, successful root logins from unusual IPs, 
    and high disk usage alerts within a short period.
    """
    failed_attempts = {}
    alerts = []

    unusual_ips = ["192.168.1.100", "10.0.0.200"]  # Example unusual IPs

    for line in log_lines:
        try:            
            print(f"Processing log line: {line}")
            
            parts = line.split(" ", 5)
            timestamp_str = parts[0]
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+03:00")

            # Detect multiple failed sudo attempts
            if "authentication failure" in line and "sudo" in line:                
                user = line.split("user=")[-1].split(" ")[0].strip()
                print(f"Authentication failure detected for user: {user}")
                key = user
                
                if key not in failed_attempts:
                    failed_attempts[key] = []

                failed_attempts[key].append(timestamp)

            elif "incorrect password attempts" in line:                
                match_user = re.search(r"sudo:\s+(\w+)\s*:", line)
                match_failed_attempts = re.search(r"\b(\d+)\s+incorrect password attempts", line)

                if match_user and match_failed_attempts:
                    user = match_user.group(1).strip()
                    num_failed = int(match_failed_attempts.group(1))
                    key = user
                    
                    if key not in failed_attempts:
                        failed_attempts[key] = []
                    
                    failed_attempts[key].extend([timestamp] * num_failed)

            # Detect successful root login from unusual IP
            if "Accepted publickey for root" in line or "Accepted password for root" in line:
                match_ip = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                if match_ip:
                    ip_address = match_ip.group(1)
                    if ip_address in unusual_ips:
                        alert = {
                            "alert_title": "Successful Root Login from Unusual IP",
                            "timestamp": timestamp,
                            "hostname": "ubuntu",  
                            "message": f"Root login detected from unusual IP address {ip_address}.",
                            "severity": "High",
                            "user": "root",
                        }
                        alerts.append(alert)

            # Detect disk usage exceeding threshold
            if "disk usage" in line and "critical" in line:
                match_partition = re.search(r"partition\s+(\S+)", line)
                match_usage = re.search(r"usage\s+(\d+)%", line)
                if match_partition and match_usage:
                    partition = match_partition.group(1)
                    usage = int(match_usage.group(1))
                    if usage > 90:
                        alert = {
                            "alert_title": "High Disk Usage",
                            "timestamp": timestamp,
                            "hostname": "ubuntu",  
                            "message": f"Disk usage on partition {partition} is at {usage}%, exceeding 90%.",
                            "severity": "Critical",
                            "user": "system",
                        }
                        alerts.append(alert)

            if key in failed_attempts:
                print(f"Failed attempts for {key}: {failed_attempts[key]}")
            
            for user in failed_attempts:
                failed_attempts[user] = [t for t in failed_attempts[user] if t > timestamp - timedelta(minutes=time_window_minutes)]
                
                if len(failed_attempts[user]) >= max_failed_attempts:
                    alert = {
                        "alert_title": "Multiple Failed Sudo Attempts",
                        "timestamp": timestamp,
                        "hostname": "ubuntu",  
                        "message": f"Detected {len(failed_attempts[user])} failed sudo attempts for user '{user}' within {time_window_minutes} minutes.",
                        "severity": "High",
                        "user": user,
                    }
                    alerts.append(alert)                    
                    failed_attempts[user] = []

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
            print(f"Alert created: {alert_data['alert_title']} for user '{alert_data['user']}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")


if __name__ == "__main__":
    
    sample_logs = [

    ]

    detected_alerts = detect(sample_logs)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)
        
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")