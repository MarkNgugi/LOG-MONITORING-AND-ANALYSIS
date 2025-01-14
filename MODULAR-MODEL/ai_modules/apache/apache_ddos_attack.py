import re
from collections import Counter
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Sample Apache access logs (now with more than 10 requests for one IP)
sample_logs = [
    "192.168.1.1 - - [14/Jan/2025:13:12:59 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:00 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:01 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:02 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:03 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:04 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:05 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:06 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:07 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:08 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:09 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.1 - - [14/Jan/2025:13:13:10 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.2 - - [14/Jan/2025:13:13:11 +0000] \"GET / HTTP/1.1\" 200 2326",
    "192.168.1.3 - - [14/Jan/2025:13:13:12 +0000] \"GET / HTTP/1.1\" 200 2326",
]

def detect_ddos_attack(logs):
    """
    Function to detect possible DDOS attack based on IP request frequency.
    A DDOS attack is suspected if an IP address makes more than 10 requests in a short time frame.
    """
    ip_addresses = [log.split()[0] for log in logs]
    ip_counts = Counter(ip_addresses)
    
    print(f"IP counts: {ip_counts}")  # Debug print to check IP counts

    # If any IP address appears more than 10 times, trigger DDOS alert
    for ip, count in ip_counts.items():
        if count > 10:
            print(f"ApacheDDOSAttack: Possible DDOS attack detected from IP {ip} with {count} requests.")
            notify_user(ip, count)
            return True
    return False

def notify_user(ip, count):
    """
    Function to notify the user. This could be extended to email, SMS, etc.
    Here, we are simply printing a message.
    """
    message = f"DDOS attack detected from IP {ip}. It made {count} requests in a short time span."
    print(message)

    # Example: Send an email (if you have SMTP setup)
    send_email_notification(message)

def send_email_notification(message):
    """
    Example function to send an email notification.
    """
    sender_email = "your_email@example.com"
    receiver_email = "receiver@example.com"
    password = "your_email_password"
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "DDOS Attack Alert"
    msg.attach(MIMEText(message, 'plain'))

    try:
        with smtplib.SMTP("smtp.example.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        print("Notification sent!")
    except Exception as e:
        print(f"Error sending email: {e}")

# Run the detection on sample logs
detect_ddos_attack(sample_logs)
