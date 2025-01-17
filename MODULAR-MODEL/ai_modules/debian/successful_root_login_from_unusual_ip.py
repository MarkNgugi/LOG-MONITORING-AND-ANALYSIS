"""Successful Root Login from Unusual IP
Category: Authentication
Level: Critical
Description: Root login from an IP address outside the expected range, signaling a potential compromise.
"""

def detect(log_lines):
    """Detects the alert or anomaly in the provided log lines.

    Args:
        log_lines (list of str): List of log entries to analyze.

    Returns:
        bool: True if the alert or anomaly is detected, otherwise False.
    """
    # TODO: Implement detection logic based on the log content
    for line in log_lines:
        if "<add specific condition here>":
            return True
    return False

if __name__ == "__main__":
    # Example usage
    sample_logs = [
        "Sample log entry 1",
        "Sample log entry 2",
        "Sample log entry 3"
    ]
    if detect(sample_logs):
        print("Successful Root Login from Unusual IP detected!")
    else:
        print("No issues detected.")
