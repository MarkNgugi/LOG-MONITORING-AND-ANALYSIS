from celery import shared_task
import subprocess
from log_management_app.models import LinuxLog, WindowsLog

@shared_task
def process_debian_logs(id):
    log = LinuxLog.objects.get(id=id)
    if not log.processed:  # Only process if not already processed
        log_message = log.message

        # Call all Debian AI modules
        debian_scripts = [
            'service_start_stops_restarts.py'
            'sudden_restart_of_ssh_daemon.py'
        ]
        
        for script in debian_scripts:
            script_path = f"MODULAR-MODEL/ai_modules/debian/{script}"
            subprocess.run(["python3", script_path, log_message], check=True)

        # Mark the log as processed
        log.processed = True
        log.save()

    return f"Processed Debian logs {id}"

@shared_task
def process_windows_logs(id):
    log = WindowsLog.objects.get(id=id)
    if not log.processed:  # Only process if not already processed
        log_message = log.message

        # Call all Windows AI modules (modify as needed)
        windows_scripts = [
            "windows_events.py",        
            # Add more scripts
        ]

        for script in windows_scripts:
            script_path = f"MODULAR-MODEL/ai_modules/windows/{script}"
            subprocess.run(["python3", script_path, log_message], check=True)

        # Mark the log as processed
        log.processed = True
        log.save()

    return f"Processed Windows logs {id}"