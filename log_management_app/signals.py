import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import LinuxLog, WindowsLog
from alerts_and_notifications_app.tasks import process_debian_logs,process_windows_logs

logger = logging.getLogger(__name__)

@receiver(post_save, sender=LinuxLog)
def trigger_debian_ai_modules(sender, instance, created, **kwargs):
    logger.info(f"Signal triggered for LinuxLog (ID: {instance.id}, created: {created})")
    if created:  # Only trigger if a new log is created
        logger.info(f"Triggering Celery task for new LinuxLog (ID: {instance.id})")
        process_debian_logs.delay(instance.id)  # Delay the task to Celery  

@receiver(post_save, sender=WindowsLog)
def trigger_windows_ai_modules(sender, instance, created, **kwargs):
    logger.info(f"Signal triggered for WindowsLog (ID: {instance.id}, created: {created})")
    if created:  # Only trigger if a new log is created
        logger.info(f"Triggering Celery task for new WindowsLog (ID: {instance.id})")
        process_windows_logs.delay(instance.id)  # Delay the task to Celery