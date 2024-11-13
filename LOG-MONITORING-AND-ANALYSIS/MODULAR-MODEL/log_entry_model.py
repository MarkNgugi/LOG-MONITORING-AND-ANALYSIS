from datetime import datetime
from django.db import models  # Import Django's ORM for database operations

class LogEntry(models.Model):  # Make LogEntry a Django model
    source = models.CharField(max_length=100)
    timestamp = models.DateTimeField()
    log_level = models.CharField(max_length=50)
    message = models.TextField()

    def save(self, *args, **kwargs):
        # Override the save method to handle any custom logic if needed
        super().save(*args, **kwargs)  # Save to the Django database

    @staticmethod
    def fetch_logs(source, start_time=None):
        # You can implement this to fetch logs from the database if needed
        return LogEntry.objects.filter(source=source, timestamp__gte=start_time)
