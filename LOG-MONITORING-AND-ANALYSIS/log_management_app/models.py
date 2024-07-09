from django.db import models

class WindowsLogSource(models.Model):
    LOG_TYPES = [
        ('All', 'All'),
        ('Application', 'Application logs'),
        ('Security', 'Security logs'),
        ('Setup', 'Setup logs'),
        ('System', 'System Logs'),
    ]

    MACHINE_TYPE = [
        ('Single machine', 'Single machine'),
        ('Group policy machine', 'Group policy machine'),
    ]

    log_source_name = models.CharField(max_length=100)
    log_type = models.CharField(max_length=20, choices=LOG_TYPES)
    log_format = models.CharField(max_length=50)
    machine_type = models.CharField(max_length=30, choices=MACHINE_TYPE, default='Single machine')
    collection_interval = models.CharField(max_length=50, default=5)
    log_retention_period = models.CharField(max_length=100,default=5)
    winrm_username = models.CharField(max_length=100,default='username')
    winrm_password = models.CharField(max_length=100,default='....')
    winrm_host = models.CharField(max_length=100,default='windows')
    winrm_port = models.IntegerField(default=5985)

    def __str__(self):
        return self.log_source_name



