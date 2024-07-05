from django.db import models

class WindowsLogSource(models.Model):
    LOG_TYPES = [
        ('All', 'All'),
        ('Application', 'Application logs'),
        ('Security', 'Security logs'),
        ('Setup', 'Setup logs'),
        ('System', 'System Logs'),
    ]

    INGESTION_METHODS = [
        ('WindowsEventForwarding', 'Windows Event Forwarding'),
        ('PowerShellScripts', 'Windows PowerShell Commands'),
        ('RemoteEventLogMonitoring', 'Windows Event Log Subscription'),
        ('WMI', 'WEF Group Policy'),
    ]

    log_source_name = models.CharField(max_length=100)
    log_type = models.CharField(max_length=20, choices=LOG_TYPES)
    log_format = models.CharField(max_length=50)
    ingestion_method = models.CharField(max_length=30, choices=INGESTION_METHODS, default='WindowsEventForwarding')
    collection_interval = models.CharField(max_length=50, default=5)
    log_retention_period = models.CharField(max_length=100,default=5)
    kerberos_spn = models.CharField(max_length=100, help_text="Service Principal Name",null=True)
    kerberos_realm = models.CharField(max_length=100, help_text="Kerberos Realm",null=True)
    kerberos_keytab = models.FileField(upload_to='keytabs/', help_text="Upload Keytab File",null=True)


    def __str__(self):
        return self.log_source_name
