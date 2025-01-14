import re
from datetime import datetime, timedelta

# Sample logs to test
sample_logs = [
    "SSL Certificate expired for domain example.com on 2025-02-01",
    "SSL Certificate nearing expiry for domain example2.com, expiring on 2025-01-20",
    "SSL handshake failed for domain example3.com, certificate expired",
    "Access granted to example.com with SSL certificate valid until 2025-06-15"
]

# Function to check for certificate expiry
def check_ssl_expiry(logs):
    # Define the alert threshold (e.g., 30 days before expiry)
    expiry_threshold = timedelta(days=30)
    alert_message = "ApacheCertificateExpiry: SSL certificate nearing expiry"
    
    for log in logs:
        # Look for expiry date in log
        match = re.search(r"expiring on (\d{4}-\d{2}-\d{2})", log)
        if match:
            expiry_date = datetime.strptime(match.group(1), '%Y-%m-%d')
            remaining_days = (expiry_date - datetime.now()).days
            if remaining_days <= expiry_threshold.days:
                print(f"{alert_message} - {log} (Expires in {remaining_days} days)")

# Run the module
if __name__ == "__main__":
    check_ssl_expiry(sample_logs)
