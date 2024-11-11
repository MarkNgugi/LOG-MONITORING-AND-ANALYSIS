from django.db import models
from django.utils import timezone 
from user_management_app.models import User

 

class UploadedLog(models.Model):
    file = models.FileField(upload_to='uploaded_logs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

class LogEntry(models.Model):
    timestamp = models.DateTimeField()
    log_level = models.CharField(max_length=50)
    message = models.TextField()
    source = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

# class Anomaly(models.Model):
#     severity = models.CharField(max_length=50)
#     description = models.TextField()
#     log_entry = models.ForeignKey(LogEntry, on_delete=models.CASCADE)
#     detected_at = models.DateTimeField(auto_now_add=True)

#====================WINDOWS LOGS MODELS START=======================    

class WindowsLogType(models.Model): 
    LOG_TYPE_CHOICES = [
        ('system', 'System'),
        ('security', 'Security'),
        ('setup', 'Setup'),
        ('application', 'Application'), 
    ]

    name = models.CharField(max_length=20, choices=LOG_TYPE_CHOICES, unique=True)

    def __str__(self):
        return self.name



class WindowsLogSource(models.Model):
    INGESTION_MTD = [
        ('powershell', 'Powershell'),
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
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    description = models.TextField(blank=True, null=True)
    log_type = models.ManyToManyField(WindowsLogType)
    os_type=models.CharField(max_length=50,default='Windows')
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')
    collection_interval = models.CharField(max_length=10, default='Real-time')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    ingestion_mtd = models.CharField(max_length=30, choices=INGESTION_MTD, default='powershell')    
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name


class WindowsFileLogSource(models.Model):

    INGESTION_MTD = [
        ('powershell', 'Powershell'),
    ]

    LogFormat = [
        ('text', 'Text'),
        ('csv', 'CSV'),
        ('json', 'JSON'),
        ('xml', 'XML'),
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

    ROTATION_POLICY_CHOICES = [
        ('size', 'By Size'),
        ('date', 'By Date'),
        ('size_date', 'By Size and Date'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    ingestion_mtd = models.CharField(max_length=30, default='powershell')
    log_file_path = models.CharField(max_length=255)
    os_type=models.CharField(max_length=50,default='Windows') 
    log_type = models.ManyToManyField(WindowsLogType)
    log_format = models.CharField(max_length=10, choices=LogFormat)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_mtd = models.CharField(max_length=50, default='Files streaming')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    ingestion_mtd = models.CharField(max_length=30, choices=INGESTION_MTD, default='powershell')   
    # file_size_limit = models.PositiveIntegerField()  # in MB
    activate = models.BooleanField(default=True)
    rotation_policy = models.CharField(max_length=15, choices=ROTATION_POLICY_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    # Event IDs: Specific event IDs to filter for.

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

    log_source_name = models.CharField(max_length=100, default='log_source')
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    performance_metrics = models.ManyToManyField(
        'WindowsPerformanceMetric',
        verbose_name="Performance Metrics",
        help_text="Select the metrics to collect",
    )
    ingestion_mtd = models.CharField(max_length=30, default='powershell')
    os_type=models.CharField(max_length=50,default='Windows')
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='perf logs')
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name


class WindowsPerformanceMetric(models.Model):   

    METRIC_CHOICES = [
        ('cpu', 'CPU'),
        ('memory', 'Memory'),
        ('disk', 'Disk'),
        ('network', 'Network'),
        ('system', 'System'),
        ('process', 'Process'),
        ('application', 'Application'),
    ]
    
    # Fields for performance metrics
    name = models.CharField(max_length=100, verbose_name="Metric Name")
    # metric_type = models.CharField(max_length=20, choices=METRIC_CHOICES, verbose_name="Metric Type")
    
    # # CPU Metrics
    # processor_time = models.FloatField(null=True, blank=True, verbose_name="Processor Time (%)")
    # processor_queue_length = models.FloatField(null=True, blank=True, verbose_name="Processor Queue Length")
    # context_switches_per_sec = models.FloatField(null=True, blank=True, verbose_name="Context Switches/sec")
    
    # # Memory Metrics
    # available_mbytes = models.FloatField(null=True, blank=True, verbose_name="Available MBytes")
    # committed_bytes = models.FloatField(null=True, blank=True, verbose_name="Committed Bytes")
    # page_faults_per_sec = models.FloatField(null=True, blank=True, verbose_name="Page Faults/sec")
    
    # # Disk Metrics
    # disk_read_bytes_per_sec = models.FloatField(null=True, blank=True, verbose_name="Disk Read Bytes/sec")
    # disk_write_bytes_per_sec = models.FloatField(null=True, blank=True, verbose_name="Disk Write Bytes/sec")
    # disk_queue_length = models.FloatField(null=True, blank=True, verbose_name="Disk Queue Length")
    
    # # Network Metrics
    # network_interface_bytes_total_per_sec = models.FloatField(null=True, blank=True, verbose_name="Network Interface Bytes Total/sec")
    # packets_per_sec = models.FloatField(null=True, blank=True, verbose_name="Packets/sec")
    # network_interface_output_queue_length = models.FloatField(null=True, blank=True, verbose_name="Network Interface Output Queue Length")
    
    # # System Metrics
    # system_up_time = models.FloatField(null=True, blank=True, verbose_name="System Up Time")
    # system_calls_per_sec = models.FloatField(null=True, blank=True, verbose_name="System Calls/sec")
    # interrupts_per_sec = models.FloatField(null=True, blank=True, verbose_name="Interrupts/sec")
    
    # # Process Metrics
    # process_private_bytes = models.FloatField(null=True, blank=True, verbose_name="Process Private Bytes")
    # process_virtual_bytes = models.FloatField(null=True, blank=True, verbose_name="Process Virtual Bytes")
    # process_cpu_time = models.FloatField(null=True, blank=True, verbose_name="Process CPU Time")
    
    # # Application Metrics
    # application_response_time = models.FloatField(null=True, blank=True, verbose_name="Application Response Time")
    # application_errors = models.IntegerField(null=True, blank=True, verbose_name="Application Errors")
    
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

    log_source_name = models.CharField(max_length=100, default='log_source')
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    domain_name=models.CharField(max_length=200)
    ingestion_mtd = models.CharField(max_length=30, default='powershell')
    os_type=models.CharField(max_length=50,default='Windows')
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='AD logs')
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

#====================WINDOWS LOGS MODELS END============================================

#====================LINUX LOGS MODELS START=========================

class LinuxLogType(models.Model):

    LOG_TYPE_CHOICES = [
        ('system', 'System'),
        ('security', 'Security'),
        ('setup', 'Setup'),
        ('application', 'Application'), 
    ] 

    name = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return self.name


class LinuxLogSource(models.Model):
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

    log_source_name = models.CharField(max_length=100, default='log_source')
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    log_type = models.ManyToManyField(LinuxLogType)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    os_type=models.CharField(max_length=50,default='Linux')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='log streaming')
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name


class LinuxFileLogSource(models.Model):
    LOG_FILE_TYPE = [
        ('text', 'Text'),
        ('csv', 'CSV'),
        ('json', 'JSON'),
        ('xml', 'XML'),
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

    ROTATION_POLICY_CHOICES = [
        ('size', 'By Size'),
        ('date', 'By Date'),
        ('size_date', 'By Size and Date'),
    ]

    log_source_name = models.CharField(max_length=100, default='log_source')
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    log_file_path = models.CharField(max_length=255)
    log_type = models.ManyToManyField(LinuxLogType)
    log_file_type = models.CharField(max_length=10, choices=LOG_FILE_TYPE)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    os_type=models.CharField(max_length=50,default='Linux')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    file_size_limit = models.PositiveIntegerField()  # in MB
    collection_mtd = models.CharField(max_length=50, default='file streaming')
    activate = models.BooleanField(default=True)
    rotation_policy = models.CharField(max_length=15, choices=ROTATION_POLICY_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name


class LinuxPerfLogs(models.Model):
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

    log_source_name = models.CharField(max_length=100, default='log_source')
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    performance_metrics = models.ManyToManyField(
        'LinuxPerformanceMetric',
        verbose_name="Performance Metrics",
        help_text="Select the metrics to collect",
    )
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    os_type=models.CharField(max_length=50,default='Linux')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='perf logs')
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name


class LinuxPerformanceMetric(models.Model):
    name = models.CharField(max_length=100, verbose_name="Metric Name")

    def __str__(self):
        return self.name


class LDAPLogSource(models.Model):
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

    log_source_name = models.CharField(max_length=100, default='log_source')
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    domain_name=models.CharField(max_length=200)
    os_type=models.CharField(max_length=50,default='Linux')
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='AD logs')
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

#====================LINUX LOGS MODELS END=========================

#====================MACOS LOGS MODELS START===============================================

class MacLogType(models.Model):
    name = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return self.name


class MacLogSource(models.Model):
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

    log_source_name = models.CharField(max_length=100, default='log_source')
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    log_type = models.ManyToManyField(MacLogType)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    os_type=models.CharField(max_length=50,default='Mac')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='log streaming')
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name


class MacFileLogSource(models.Model):
    LOG_FILE_TYPE = [
        ('text', 'Text'),
        ('csv', 'CSV'),
        ('json', 'JSON'),
        ('xml', 'XML'),
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

    ROTATION_POLICY_CHOICES = [
        ('size', 'By Size'),
        ('date', 'By Date'),
        ('size_date', 'By Size and Date'),
    ]

    log_source_name = models.CharField(max_length=100, default='log_source')
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    log_file_path = models.CharField(max_length=255)
    log_file_type = models.CharField(max_length=10, choices=LOG_FILE_TYPE)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    os_type=models.CharField(max_length=50,default='Mac')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    file_size_limit = models.PositiveIntegerField()  # in MB
    collection_mtd = models.CharField(max_length=50, default='file streaming')
    activate = models.BooleanField(default=True)
    rotation_policy = models.CharField(max_length=15, choices=ROTATION_POLICY_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name


class MacPerfLogs(models.Model):
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

    log_source_name = models.CharField(max_length=100, default='log_source')
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    performance_metrics = models.ManyToManyField(
        'LinuxPerformanceMetric',
        verbose_name="Performance Metrics",
        help_text="Select the metrics to collect",
    )
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    os_type=models.CharField(max_length=50,default='Mac')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='perf logs')
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name


class MacPerformanceMetric(models.Model):
    name = models.CharField(max_length=100, verbose_name="Metric Name")

    def __str__(self):
        return self.name


class OpenDirLogSource(models.Model):
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

    log_source_name = models.CharField(max_length=100, default='log_source')
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    domain_name=models.CharField(max_length=200)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    os_type=models.CharField(max_length=50,default='Mac')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='AD logs')
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name 

#====================MACOS LOGS MODELS END=========================



#===========================APPLICATION LOGS MODELS START================================

class WebServer(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)

    def __str__(self):
        return self.name 
 

    #=======WEBSERVERS=======

#APACHE START

class ApacheserverLogStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    server_type=models.CharField(max_length=50,default='Apache')
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

class ApacheserverLogFileStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    server_type=models.CharField(max_length=50,default='Apache')
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name  


class ApacheserverPerfLogs(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    server_type=models.CharField(max_length=50,default='Apache')
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name           

class ApacheLogFileUploadForm(models.Model):
    pass


#APACHE END



#NGINX START

class NginxserverLogStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    server_type=models.CharField(max_length=50,default='Nginx')
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

class NginxserverLogFileStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    server_type=models.CharField(max_length=50,default='Nginx')
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name  


class NginxserverPerfLogs(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    server_type=models.CharField(max_length=50,default='Nginx')
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name           

class NginxLogFileUploadForm(models.Model):
    pass


#NGINX END


#IIS START

class IISserverLogStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    server_type=models.CharField(max_length=50,default='IIS')
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

class IISserverLogFileStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    server_type=models.CharField(max_length=50,default='IIS')
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name  


class IISserverPerfLogs(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    server_type=models.CharField(max_length=50,default='IIS')
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name           

class IISLogFileUploadForm(models.Model):
    pass


#IIS END


#TOMCAT START 

class TomcatserverLogStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

class TomcatserverLogFileStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name  


class TomcatserverPerfLogs(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name           

class TomcatLogFileUploadForm(models.Model):
    pass


#TOMCAT END


#LIGHTTPD START  

class LighttpdserverLogStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

class LighttpdserverLogFileStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name  


class LighttpdserverPerfLogs(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    web_server_type = models.CharField(max_length=50, default='Apache')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name           

class LighttpdLogFileUploadForm(models.Model):
    pass


#LIGHTTPD END
 
#MYSQL START

class MysqlLogStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    db_type = models.CharField(max_length=50, default='Mysql')  # Type of web server
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

class MysqlLogFileStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    db_type = models.CharField(max_length=50, default='Mysql')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name  


class MysqlPerfLogs(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    db_type = models.CharField(max_length=50, default='Mysql')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name           

class MysqlLogFileUploadForm(models.Model):
    pass


#MYSQL END

#POSTGRES START

class PostgresLogStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    db_type = models.CharField(max_length=50, default='Postgres')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

class PostgresLogFileStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    db_type = models.CharField(max_length=50, default='Postgres')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name  


class PostgresPerfLogs(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'), 
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    db_type = models.CharField(max_length=50, default='Postgres')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name           

class PostgresLogFileUploadForm(models.Model):
    pass

#POSTGRES END


#MONGODB START

class MongodbLogStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    db_type = models.CharField(max_length=50, default='Mongodb')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name

class MongodbLogFileStream(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'),
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    db_type = models.CharField(max_length=50, default='Mongodb')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name  


class MongodbPerfLogs(models.Model):

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

    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARN', 'WARN'),
        ('ERROR', 'ERROR'), 
    ]

    log_source_name = models.CharField(max_length=100)
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    log_file_path = models.CharField(max_length=255)  # Path to the log file
    log_level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='INFO')  # Level of logs to be collected
    filter_keyword = models.CharField(max_length=100, blank=True, null=True)  # Optional keyword for filtering logs
    log_rotation_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')  # Interval for log rotation
    db_type = models.CharField(max_length=50, default='Mongodb')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')  # Method of log collection
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name           

class MongoLogFileUploadForm(models.Model):
    pass

#MONGODB END

class WindowsAlert(models.Model):
    event_id = models.CharField(max_length=50)
    entry_type=models.CharField(max_length=50)
    provider = models.CharField(max_length=100)
    alert_level = models.CharField(max_length=100)
    message = models.TextField()
    source_name = models.CharField(max_length=100,default="windows")
    timestamp = models.DateTimeField()

    def __str__(self):
        return f"WindowsAlert {self.event_id}: {self.message[:50]}..."


