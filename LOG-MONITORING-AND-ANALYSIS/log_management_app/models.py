from django.db import models
from django.utils import timezone 

#====================WINDOWS LOGS MODELS START=======================

class WindowsLogType(models.Model):
    name = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return self.name


class WindowsLogSource(models.Model):
    INGESTION_MTD = [
        ('powershell', 'Powershell'),
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
    hostname_ip_address = models.CharField(max_length=255, default='localhost', null=True)
    description = models.TextField(blank=True, null=True)
    log_type = models.ManyToManyField(WindowsLogType)
    os_type=models.CharField(max_length=50,default='Windows')
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_mtd = models.CharField(max_length=50, default='Log streaming')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    ingestion_mtd = models.CharField(max_length=30, choices=INGESTION_MTD, default='powershell')
    comments = models.TextField(blank=True, null=True)
    activate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.log_source_name


class WindowsFileLogSource(models.Model):
    LogFileType = [
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
    log_file_type = models.CharField(max_length=10, choices=LogFileType)
    status = models.CharField(max_length=10, choices=SOURCE_STATUS_CHOICES, default='Offline')
    collection_mtd = models.CharField(max_length=50, default='Files streaming')
    retention_policy = models.CharField(max_length=10, choices=RETENTION_POLICY_CHOICES, default='30d')
    collection_interval = models.CharField(max_length=10, choices=COLLECTION_INTERVAL_CHOICES, default='24h')
    file_size_limit = models.PositiveIntegerField()  # in MB
    activate = models.BooleanField(default=True)
    rotation_policy = models.CharField(max_length=15, choices=ROTATION_POLICY_CHOICES)
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

    #=======WEBSERVERS=======

#APACHE

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

    

#testing model

class SecurityLog(models.Model):
    event_id = models.IntegerField(default=0)
    timestamp = models.DateTimeField(default=timezone.now)
    message = models.TextField(null=True)

    def __str__(self):
        return f"Event ID: {self.event_id} at {self.timestamp}"


