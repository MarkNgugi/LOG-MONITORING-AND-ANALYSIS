from django.db import models

class WindowsLogSource(models.Model):
    LOG_TYPES = [
        ('All', 'All'),
        ('Application', 'Application logs'),
        ('Security', 'Security logs'),
        ('Setup', 'Setup logs'),
        ('System', 'System Logs'),
    ]

    INGESTION_MTD = [
        ('powershell', 'powershell'),
    ]

    log_source_name = models.CharField(max_length=100)
    log_type = models.CharField(max_length=20, choices=LOG_TYPES)
    log_format = models.CharField(max_length=50)
    ingestion_mtd = models.CharField(max_length=30, choices=INGESTION_MTD, default='Powershell')
    # collection_interval = models.CharField(max_length=50, default=5)
    # log_retention_period = models.CharField(max_length=100,default=5)


    def __str__(self):
        return self.log_source_name




