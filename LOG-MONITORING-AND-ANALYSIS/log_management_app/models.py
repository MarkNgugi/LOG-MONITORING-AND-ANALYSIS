from django.db import models

class LogType(models.Model):
    name = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return self.name

class WindowsLogSource(models.Model):
    INGESTION_MTD = [
        ('powershell', 'Powershell'),
    ]

    log_source_name = models.CharField(max_length=100)
    log_type = models.ManyToManyField(LogType)
    log_format = models.CharField(max_length=50, default='JSON')
    ingestion_mtd = models.CharField(max_length=30, choices=INGESTION_MTD, default='powershell')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name
