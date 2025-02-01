from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import LinuxLog, WindowsLog
from alerts_and_notifications_app.tasks import process_debian_logs, process_windows_logs


@receiver(post_save, sender=LinuxLog)
def trigger_debian_ai_modules(sender, instance, created, **kwargs):
    if created and not instance.processed:  # Only trigger if a new log is added and not processed
        process_debian_logs.delay(instance.id)

@receiver(post_save, sender=WindowsLog)
def trigger_windows_ai_modules(sender, instance, created, **kwargs):
    if created and not instance.processed:  # Only trigger if a new log is added and not processed
        process_windows_logs.delay(instance.id)