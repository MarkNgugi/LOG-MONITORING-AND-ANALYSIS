from datetime import datetime, timedelta
import collections

# Sample Apache logs (with failed login attempts)
sample_logs = [
    {'client_ip': '192.168.1.1', 'status_code': 401, 'timestamp': '2025-01-14T10:00:00'},
    {'client_ip': '192.168.1.1', 'status_code': 401, 'timestamp': '2025-01-14T10:05:00'},
    {'client_ip': '192.168.1.1', 'status_code': 401, 'timestamp': '2025-01-14T10:10:00'},
    {'client_ip': '192.168.1.2', 'status_code': 401, 'timestamp': '2025-01-14T10:15:00'},
    {'client_ip': '192.168.1.1', 'status_code': 200, 'timestamp': '2025-01-14T10:20:00'},
    {'client_ip': '192.168.1.1', 'status_code': 401, 'timestamp': '2025-01-14T10:25:00'},
]

# Function to detect brute force attack
def detect_brute_force_attack(logs, threshold=3, time_window=10):
    ip_attempts = collections.defaultdict(list)

    for log in logs:
        if log['status_code'] == 401:  # Consider failed login attempts
            ip_attempts[log['client_ip']].append(datetime.fromisoformat(log['timestamp']))

    for ip, attempts in ip_attempts.items():
        attempts.sort()
        for i in range(len(attempts) - threshold + 1):
            if (attempts[i + threshold - 1] - attempts[i]) <= timedelta(minutes=time_window):
                return f"Brute force attack detected from IP {ip}."
    return "No brute force attack detected."

# Run the module with sample logs
alert = detect_brute_force_attack(sample_logs)
print(alert)
