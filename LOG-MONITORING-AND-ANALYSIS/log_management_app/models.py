from django.db import models
from django.utils import timezone

class LogType(models.Model):
    name = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return self.name

class WindowsLogSource(models.Model):
    INGESTION_MTD = [
        ('powershell', 'Powershell'),
        # Add other ingestion methods if needed
    ]

    COLLECTION_INTERVAL_CHOICES = [
        ('5m', 'Every 5 minutes'),
        ('15m', 'Every 15 minutes'),
        ('30m', 'Every 30 minutes'),
        ('1h', 'Every 1 hour'),
        ('6h', 'Every 6 hours'),
        ('12h', 'Every 12 hours'),
        ('24h', 'Every 24 hours'),
    ]

    RETENTION_POLICY_CHOICES = [
        ('7d', '7 days'),
        ('14d', '14 days'),
        ('30d', '30 days'),
        ('60d', '60 days'),
        ('90d', '90 days'),
        ('180d', '180 days'),
        ('365d', '365 days'),
    ]

    SOURCE_STATUS_CHOICES = [
        ('Online', 'Active'),
        ('Offline', 'Inactive'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255,default='localhost',null=True)
    description = models.TextField(blank=True, null=True)
    log_type = models.ManyToManyField(LogType)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_mtd = models.CharField(max_length=50,default='Log streaming')
    # timestamp = models.DateTimeField(auto_now_add=True)
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    ingestion_mtd = models.CharField(max_length=30, choices=INGESTION_MTD, default='powershell')
    comments = models.TextField(blank=True, null=True)
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name
    

class LogFileType(models.TextChoices):
    TEXT = 'text', 'Text'
    CSV = 'csv', 'CSV'
    JSON = 'json', 'JSON'
    XML = 'xml', 'XML'

class LogCollectionFrequency(models.TextChoices):
    EVERY_5_MINUTES = '5', 'Every 5 minutes'
    EVERY_15_MINUTES = '15', 'Every 15 minutes'
    HOURLY = '60', 'Hourly'
    DAILY = '1440', 'Daily'

class LogEncoding(models.TextChoices):
    UTF_8 = 'utf-8', 'UTF-8'
    UTF_16 = 'utf-16', 'UTF-16'
    ISO_8859_1 = 'iso-8859-1', 'ISO-8859-1'
    ASCII = 'ascii', 'ASCII'

class RotationPolicy(models.TextChoices):
    BY_SIZE = 'size', 'By Size'
    BY_DATE = 'date', 'By Date'
    BY_SIZE_AND_DATE = 'size_date', 'By Size and Date'

  

class WindowsFileLogSource(models.Model):

    RETENTION_POLICY_CHOICES = [
        ('7d', '7 days'),
        ('14d', '14 days'),
        ('30d', '30 days'),
        ('60d', '60 days'),
        ('90d', '90 days'),
        ('180d', '180 days'),
        ('365d', '365 days'),
    ]  

    COLLECTION_INTERVAL_CHOICES = [
        ('5m', 'Every 5 minutes'),
        ('15m', 'Every 15 minutes'),
        ('30m', 'Every 30 minutes'),
        ('1h', 'Every 1 hour'),
        ('6h', 'Every 6 hours'),
        ('12h', 'Every 12 hours'),
        ('24h', 'Every 24 hours'), 
    ]

    SOURCE_STATUS_CHOICES = [
        ('Online', 'Active'),
        ('Offline', 'Inactive'),
    ]    

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255,default='localhost',null=True)
    ingestion_mtd = models.CharField(max_length=30, default='powershell')
    log_file_path = models.CharField(max_length=255)
    log_file_type = models.CharField(max_length=10, choices=LogFileType.choices) #change to checkboxes
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_mtd = models.CharField(max_length=50,default='Files streaming')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    file_size_limit = models.PositiveIntegerField()  # in MB
    activate = models.BooleanField(default=True)
    log_encoding = models.CharField(max_length=10, choices=LogEncoding.choices)
    rotation_policy = models.CharField(max_length=15, choices=RotationPolicy.choices)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

class WindowsPerfLogs(models.Model): 

    SOURCE_STATUS_CHOICES = [
        ('Online', 'Active'),
        ('Offline', 'Inactive'),
    ]  

    COLLECTION_INTERVAL_CHOICES = [
        ('5m', 'Every 5 minutes'),
        ('15m', 'Every 15 minutes'),
        ('30m', 'Every 30 minutes'),
        ('1h', 'Every 1 hour'),
        ('6h', 'Every 6 hours'),
        ('12h', 'Every 12 hours'),
        ('24h', 'Every 24 hours'), 
    ]

    RETENTION_POLICY_CHOICES = [
        ('7d', '7 days'),
        ('14d', '14 days'),
        ('30d', '30 days'),
        ('60d', '60 days'),
        ('90d', '90 days'),
        ('180d', '180 days'),
        ('365d', '365 days'),
    ] 

    log_source_name = models.CharField(max_length=100,default='log_source')
    hostname_ip_address = models.CharField(max_length=255,default='localhost',null=True)
    performance_metrics = models.ManyToManyField(
        'PerformanceMetric',
        verbose_name="Performance Metrics",
        help_text="Select the metrics to collect",
    )
    ingestion_mtd = models.CharField(max_length=30, default='powershell')
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50,default='perf logs')
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    # retention_period = models.PositiveIntegerField(verbose_name="Data Retention Period (days)")

    def __str__(self):
        return self.log_source_name

class PerformanceMetric(models.Model):
    name = models.CharField(max_length=100, verbose_name="Metric Name")
    
    def __str__(self):
        return self.name


class WindowsActiveDirectoryLogSource(models.Model):

    SOURCE_STATUS_CHOICES = [
        ('Online', 'Active'),
        ('Offline', 'Inactive'),
    ]  

    COLLECTION_INTERVAL_CHOICES = [
        ('5m', 'Every 5 minutes'),
        ('15m', 'Every 15 minutes'),
        ('30m', 'Every 30 minutes'),
        ('1h', 'Every 1 hour'),
        ('6h', 'Every 6 hours'),
        ('12h', 'Every 12 hours'),
        ('24h', 'Every 24 hours'), 
    ]

    RETENTION_POLICY_CHOICES = [
        ('7d', '7 days'),
        ('14d', '14 days'),
        ('30d', '30 days'),
        ('60d', '60 days'),
        ('90d', '90 days'),
        ('180d', '180 days'),
        ('365d', '365 days'),
    ]     

    log_source_name = models.CharField(max_length=100, verbose_name="Log Source Name")
    domain_name = models.CharField(max_length=100, verbose_name="Domain Name")
    hostname_ip_address = models.CharField(max_length=255,default='localhost',null=True)
    ingestion_mtd = models.CharField(max_length=30, default='powershell')
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_mtd = models.CharField(max_length=50,default='AD logs')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    

    def __str__(self):
        return self.log_source_name


#APPLICATION LOGS MODELS

class WebserverLogFileUpload(models.Model):
    source_name = models.CharField(max_length=100)
    file_type = models.CharField(max_length=50)
    upload_date = models.DateTimeField(auto_now_add=True)
    log_file_description = models.TextField()
    file = models.FileField(upload_to='uploads/',null=True)

    def __str__(self):

        return self.source_name
    

#testing model

class SecurityLog(models.Model):
    event_id = models.IntegerField(default=0)
    timestamp = models.DateTimeField(default=timezone.now)
    message = models.TextField(null=True)

    def __str__(self):
        return f"Event ID: {self.event_id} at {self.timestamp}"


        return self.source_name 

