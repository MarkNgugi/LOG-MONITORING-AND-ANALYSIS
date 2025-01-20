import os
import sys
import django

# Add the project directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

# Set the settings module for Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')  # Correct path to settings.py
django.setup()

# Now you can import models from log_management_app
from log_management_app.models import *

# Your existing detection logic...
def detect(log_lines):
    """Detects 'permission denied' errors in cron job logs.

    Args:
        log_lines (list of str): List of log entries to analyze.

    Returns:
        dict: Details of the detected alert or None if no issue is found.
    """
    for line in log_lines:
        if "CRON" in line and "permission denied" in line:
            try:
                # Split the line to extract relevant details
                timestamp, host, _, details = line.split(" ", 3)

                # Try to extract the user from the details
                user = details.split(":")[0].split("(")[1][:-1]  # Extract user inside parentheses
                message = details.split(": ", 1)[1]  # Extract the error message

                # Prepare alert details
                return {
                    "alert_title": "Cron Job Failure",
                    "timestamp": timestamp,
                    "host": host,
                    "message": message,
                    "severity": "Low",
                    "user": user,
                }
            except IndexError:
                # If an IndexError occurs, print the log line and skip it
                print(f"Skipping malformed log line: {line}")
                continue
    return None



def create_alert(alert_data):
    """Creates an alert in the database using the provided alert data.

    Args:
        alert_data (dict): A dictionary containing alert details.
    """
    try:
        # Assume a default user exists; replace with logic to find the user if needed
        default_user = User.objects.first()
        if not default_user:
            raise ValueError("No default user found in the database.")

        # Create the alert
        Alert.objects.create(
            alert_title=alert_data["alert_title"],
            timestamp=alert_data["timestamp"],
            host=alert_data["host"],
            message=alert_data["message"],
            severity=alert_data["severity"],
            user=default_user,
        )
        print("Alert created successfully!")
    except Exception as e:
        print(f"Failed to create alert: {e}")

if __name__ == "__main__":
    # Example usage
    sample_logs = [
        "2025-01-18T21:15:01.654321+03:00 ubuntu CRON[134567]: (user123) CMD (/usr/local/bin/backup.sh)",
        "2025-01-18T21:15:01.654999+03:00 ubuntu CRON[134567]: error: permission denied: /usr/local/bin/backup.sh",
    ]

    alert_details = detect(sample_logs)
    if alert_details:
        print("Cron Job Failures detected!")
        print(f"Details: {alert_details}")

        # Store the alert in the database
        create_alert(alert_details)
    else:
        print("No issues detected.")
