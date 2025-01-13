import logging
import re


logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # show logs in the terminal
    ]
)


def check_apache_status(log_content):
    try:
        # Regular expression to match shutdown-related messages
        shutdown_patterns = [
            r'AH00430: Apache.*shutting down',  # Specific shutdown pattern
            r'AH00094: Command line:.*-k shutdown',  # Command line shutdown
            r'Apache.*DOWN',  # Generic "Apache down" pattern
            r'AH00492:.*SIGWINCH.*shutting down gracefully'  # SIGWINCH graceful shutdown pattern
        ]


        # Check if any shutdown patterns are found
        for pattern in shutdown_patterns:
            if re.search(pattern, log_content, re.IGNORECASE):
                logging.error("ALERT: Apache is DOWN!")
                return

        logging.info("Apache appears to be running normally.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    
    sample_logs = [
        
        # Log indicating Apache is shutting down gracefully
        "[Mon Jan 13 17:59:27.435556 2025] [mpm_event:notice] [pid 86838:tid 123604213835648] AH00492: caught SIGWINCH, shutting down gracefully",

        
    ]

    for log in sample_logs:
        check_apache_status(log)  
