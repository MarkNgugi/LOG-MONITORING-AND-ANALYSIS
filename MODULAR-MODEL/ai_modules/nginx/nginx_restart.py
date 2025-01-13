import logging
import re


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  
    ]
)

def check_apache_status(log_content):
    try:
        # Regular expression to match restart-related messages
        restart_patterns = [
            r'AH00489:.*configured -- resuming normal operations'  # Apache restart pattern (resuming normal operations)
        ]

        # Check if any restart patterns are found
        for pattern in restart_patterns:
            if re.search(pattern, log_content, re.IGNORECASE):
                logging.info("ALERT: Apache has restarted!")
                return

        logging.info("Apache appears to be running normally.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":

    sample_logs = [
        "[Mon Jan 13 17:18:37.229196 2025] [mpm_event:notice] [pid 86069:tid 127316587001728] AH00489: Apache/2.4.58 (Ubuntu) configured -- resuming normal operations"
    ]

    for log in sample_logs:
        check_apache_status(log)  
