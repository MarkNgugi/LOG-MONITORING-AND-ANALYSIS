import logging
from celery import shared_task
import subprocess
from django.db import transaction
from log_management_app.models import LinuxLog, WindowsLog

logger = logging.getLogger(__name__)

@shared_task
def process_debian_logs(id):
    logger.info(f"Starting processing for LinuxLog (ID: {id})")
    with transaction.atomic():
        # Lock the log row to prevent concurrent updates
        log = LinuxLog.objects.select_for_update().get(id=id)
        logger.info(f"Retrieved LinuxLog (ID: {id}, processed: {log.processed})")
        if not log.processed:  # Only process if not already processed
            logger.info(f"Processing LinuxLog (ID: {id})")
            log_message = log.message

            # Call all Debian AI modules
            debian_scripts = [
                '1. multiple_failed_ssh_login_attempts.py',  
                '2. detect_unrecognized_ssh_key.py',
                '3. successfull_ssh_login.py',
                '4. system_reboots_or_shutdowns.py',
                '5. disk_space_warnings.py',
                '6. sudoers_file_access.py',
                '7. cron_job_executed.py',
                '8. user_account_lockouts.py',
                '9. failed_sudo_attempts.py',
                '10. SSHPublicKeyAuthSuccess.py',
                '11. service_start_stops_restarts.py',
                '12. kernel_panic.py',
                '13. user_account_creation.py',
                '14. user_account_deletion.py',
            ]
            
            for script in debian_scripts:
                script_path = f"MODULAR-MODEL/ai_modules/debian/{script}"
                try:
                    subprocess.run(["python3", script_path, log_message], check=True)
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error running script {script}: {e}")

            # Mark the log as processed using update to avoid triggering post_save
            LinuxLog.objects.filter(id=id).update(processed=True)
            logger.info(f"LinuxLog (ID: {id}) marked as processed.")
        else:
            logger.info(f"LinuxLog (ID: {id}) is already processed. Skipping...")

    return f"Processed Debian logs {id}"

@shared_task
def process_windows_logs(id):
    logger.info(f"Starting processing for WindowsLog (ID: {id})")
    with transaction.atomic():
        # Lock the log row to prevent concurrent updates
        log = WindowsLog.objects.select_for_update().get(id=id)
        logger.info(f"Retrieved WindowsLog (ID: {id}, processed: {log.processed})")
        if not log.processed:  # Only process if not already processed
            logger.info(f"Processing WindowsLog (ID: {id})")
            log_message = log.message

            # Call all Windows AI modules (modify as needed)
            windows_scripts = [
                "windows_events.py",  # Example script
                # Add more scripts as needed
            ]

            for script in windows_scripts:
                script_path = f"MODULAR-MODEL/ai_modules/windows/{script}"
                try:
                    subprocess.run(["python3", script_path, log_message], check=True)
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error running script {script}: {e}")

            # Mark the log as processed
            log.processed = True
            log.save()
            logger.info(f"WindowsLog (ID: {id}) marked as processed.")
        else:
            logger.info(f"WindowsLog (ID: {id}) is already processed. Skipping...")

    return f"Processed Windows logs {id}"