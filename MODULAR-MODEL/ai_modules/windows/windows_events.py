import os
import sys
import django
from datetime import datetime
from django.db.models import Q

# Set up Django environment
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

from log_management_app.models import Alert, User, WindowsLog

# Mapping of Event IDs to Alert Details
EVENT_ID_TO_ALERT = {
    4624: {
        "alert_title": "Successful Logon",
        "category": "Authentication",
        "severity": "Low",
        "description": "Indicates a successful logon to the system.",
    },
    4625: {
        "alert_title": "Failed Logon",
        "category": "Authentication",
        "severity": "High",
        "description": "Records failed logon attempts, including invalid username or password.",
    },
    4634: {
        "alert_title": "Logoff",
        "category": "Authentication",
        "severity": "Low",
        "description": "Indicates a user logoff event.",
    },
    4647: {
        "alert_title": "User Initiated Logoff",
        "category": "Authentication",
        "severity": "Low",
        "description": "Indicates that a user initiated a logoff from the system.",
    },
    4672: {
        "alert_title": "Special Privileges Assigned to New Logon",
        "category": "Authentication",
        "severity": "Medium",
        "description": "Indicates when a user logs on with special privileges, like an administrator.",
    },
    4688: {
        "alert_title": "A New Process Has Been Created",
        "category": "System",
        "severity": "Medium",
        "description": "Shows when a new process starts on the machine, useful for detecting suspicious processes.",
    },
    4740: {
        "alert_title": "Account Locked Out",
        "category": "Authentication",
        "severity": "High",
        "description": "Indicates that an account has been locked out due to repeated failed login attempts.",
    },
    4768: {
        "alert_title": "A Kerberos Authentication Ticket (TGT) Request Failed",
        "category": "Authentication",
        "severity": "High",
        "description": "Indicates that a user or machine failed to request a Kerberos ticket, potentially signaling authentication issues or attack attempts.",
    },
    4771: {
        "alert_title": "Kerberos Pre-authentication Failed",
        "category": "Authentication",
        "severity": "High",
        "description": "Indicates a failed Kerberos pre-authentication attempt, which can point to brute force or other attack attempts.",
    },
    4798: {
        "alert_title": "A User's Local Group Membership Was Enumerated",
        "category": "Reconnaissance",
        "severity": "Medium",
        "description": "Indicates when a user's group membership is enumerated, which could be indicative of reconnaissance activity by an attacker.",
    },
    6005: {
        "alert_title": "The Event Log Service Has Started",
        "category": "System",
        "severity": "Low",
        "description": "Indicates the system has started logging, typically after a reboot or system startup.",
    },
    6006: {
        "alert_title": "The Event Log Service Has Stopped",
        "category": "System",
        "severity": "Medium",
        "description": "Indicates that the event log service has stopped, which could be a sign of a system shutdown or malicious activity.",
    },
    6008: {
        "alert_title": "The Previous System Shutdown Was Unexpected",
        "category": "System",
        "severity": "Medium",
        "description": "Indicates an unexpected shutdown, which can be used to detect crashes or power failures.",
    },
    41: {
        "alert_title": "Kernel Power (Unexpected Shutdown)",
        "category": "System",
        "severity": "High",
        "description": "Indicates that the system was unexpectedly shut down, including hardware or power failures.",
    },
    1102: {
        "alert_title": "Audit Log Cleared",
        "category": "Authentication",
        "severity": "Critical",
        "description": "Indicates when the audit log is cleared, which could be a sign of tampering or malicious activity.",
    },
    7000: {
        "alert_title": "Service Failed to Start",
        "category": "System",
        "severity": "High",
        "description": "Indicates that a service failed to start, which could signal issues with system services or a potential attack targeting specific services.",
    },
    7031: {
        "alert_title": "Service Terminated Unexpectedly",
        "category": "System",
        "severity": "High",
        "description": "Indicates that a service has terminated unexpectedly, often a clue to instability, or an application crash.",
    },
    55: {
        "alert_title": "The File System Structure on Disk Is Corrupt",
        "category": "System",
        "severity": "High",
        "description": "Indicates file system corruption, which can be a sign of hardware failure or malicious tampering.",
    },
    4616: {
        "alert_title": "System Time Changed",
        "category": "System",
        "severity": "Medium",
        "description": "The system time was changed.",
    },
    5025: {
        "alert_title": "Windows Firewall Service Stopped",
        "category": "System",
        "severity": "High",
        "description": "The Windows Firewall Service has been stopped.",
    },
    5030: {
        "alert_title": "Windows Firewall Service Failed to Start",
        "category": "System",
        "severity": "High",
        "description": "The Windows Firewall Service failed to start.",
    },
    4673: {
        "alert_title": "A Privileged Service Was Called",
        "category": "Security",
        "severity": "Medium",
        "description": "A privileged service was called.",
    },
    4674: {
        "alert_title": "An Operation Was Attempted on a Privileged Object",
        "category": "Security",
        "severity": "Medium",
        "description": "An operation was attempted on a privileged object.",
    },
    4660: {
        "alert_title": "An Object Was Deleted",
        "category": "Security",
        "severity": "Medium",
        "description": "An object was deleted.",
    },
}


def detect_windows_alerts(log_lines):
    """
    Detects alerts based on Windows event IDs.
    """
    alerts = []

    for log in log_lines:
        event_id = log.event_id
        if event_id in EVENT_ID_TO_ALERT:
            alert_data = EVENT_ID_TO_ALERT[event_id]
            alert = {
                "alert_title": alert_data["alert_title"],
                "timestamp": log.timestamp,
                "hostname": log.hostname,
                "message": f"{alert_data['description']} Event ID: {event_id}",
                "severity": alert_data["severity"],
                "user": log.user,
            }
            alerts.append(alert)

    return alerts


def create_alerts(alerts):
    """
    Creates alerts in the database using the provided alert data.
    """
    try:
        for alert_data in alerts:
            Alert.objects.create(
                alert_title=alert_data["alert_title"],
                timestamp=alert_data["timestamp"],
                hostname=alert_data["hostname"],
                message=alert_data["message"],
                severity=alert_data["severity"],
                user=alert_data["user"],
            )
            print(f"Alert created: {alert_data['alert_title']} for user '{alert_data['user']}'")
    except Exception as e:
        print(f"Failed to create alerts: {e}")


if __name__ == "__main__":
    # Fetch WindowsLog entries
    log_lines = WindowsLog.objects.all().order_by('-timestamp')[:100]  # Fetch the last 100 logs

    # Detect alerts
    detected_alerts = detect_windows_alerts(log_lines)
    if detected_alerts:
        print(f"{len(detected_alerts)} alert(s) detected:")
        for alert in detected_alerts:
            print(alert)

        # Create alerts in the database
        create_alerts(detected_alerts)
    else:
        print("No alerts detected.")