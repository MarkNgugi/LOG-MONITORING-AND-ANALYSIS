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
    ingestion_mtd = models.CharField(max_length=30, choices=INGESTION_MTD, default='powershell')
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

class LogFormat(models.TextChoices):
    PLAIN_TEXT = 'plain', 'Plain Text'
    STRUCTURED = 'structured', 'Structured'
    SEMI_STRUCTURED = 'semi_structured', 'Semi-Structured'

class AuthMethod(models.TextChoices):
    NONE = 'none', 'None'
    BASIC_AUTH = 'basic', 'Basic Auth'
    WINDOWS_AUTH = 'windows', 'Windows Authentication'

class WindowsFileLogSource(models.Model):
    log_source_name = models.CharField(max_length=100)
    log_file_path = models.CharField(max_length=255)
    log_file_type = models.CharField(max_length=10, choices=LogFileType.choices)
    collection_frequency = models.CharField(max_length=4, choices=LogCollectionFrequency.choices)
    file_size_limit = models.PositiveIntegerField()  # in MB
    log_encoding = models.CharField(max_length=10, choices=LogEncoding.choices)
    rotation_policy = models.CharField(max_length=15, choices=RotationPolicy.choices)
    log_format = models.CharField(max_length=15, choices=LogFormat.choices)
    auth_method = models.CharField(max_length=10, choices=AuthMethod.choices)
    additional_params = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.log_source_name

class WindowsPerfLogs(models.Model):
    # Fields for the Windows client log source
    client_name = models.CharField(max_length=100, verbose_name="Client Name")
    ip_address = models.GenericIPAddressField(protocol='IPv4', verbose_name="IP Address")
    port_number = models.PositiveIntegerField(verbose_name="Port Number")
    username = models.CharField(max_length=100, verbose_name="Username")
    password = models.CharField(max_length=100, verbose_name="Password")
    performance_metrics = models.ManyToManyField(
        'PerformanceMetric',
        verbose_name="Performance Metrics",
        help_text="Select the metrics to collect",
    )
    collection_interval = models.PositiveIntegerField(verbose_name="Collection Interval (seconds)")
    retention_period = models.PositiveIntegerField(verbose_name="Data Retention Period (days)")
    log_format = models.CharField(max_length=10, choices=[('json', 'JSON'), ('xml', 'XML'), ('csv', 'CSV')], verbose_name="Log Format")
    notifications = models.BooleanField(default=False, verbose_name="Enable Notifications")

    def __str__(self):
        return self.client_name

class PerformanceMetric(models.Model):
    name = models.CharField(max_length=100, verbose_name="Metric Name")
    
    def __str__(self):
        return self.name


class WindowsActiveDirectoryLogSource(models.Model):
    # Fields for the Active Directory log source
    log_source_name = models.CharField(max_length=100, verbose_name="Log Source Name")
    domain_name = models.CharField(max_length=100, verbose_name="Domain Name")
    domain_controller_ip = models.GenericIPAddressField(protocol='IPv4', verbose_name="Domain Controller IP Address")
    port_number = models.PositiveIntegerField(default=389, verbose_name="Port Number")  # Default LDAP port
    username = models.CharField(max_length=100, verbose_name="Username")
    password = models.CharField(max_length=100, verbose_name="Password")
    log_level = models.CharField(max_length=10, choices=[('info', 'INFO'), ('warn', 'WARN'), ('error', 'ERROR')], default='info', verbose_name="Log Level")
    log_format = models.CharField(max_length=10, choices=[('json', 'JSON'), ('xml', 'XML'), ('csv', 'CSV')], default='json', verbose_name="Log Format")
    collection_interval = models.PositiveIntegerField(default=60, verbose_name="Collection Interval (seconds)")
    retention_period = models.PositiveIntegerField(default=7, verbose_name="Retention Period (days)")

    def __str__(self):
        return self.log_source_name
