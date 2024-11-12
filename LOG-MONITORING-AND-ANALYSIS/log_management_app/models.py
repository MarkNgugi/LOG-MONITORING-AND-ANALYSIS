from django.db import models
from django.utils import timezone 
from user_management_app.models import User

 

class WindowsLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='Windows')
    file = models.FileField(upload_to='uploaded_logs/windows/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name
    
class WindowsADLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='WindowsAD')
    file = models.FileField(upload_to='uploaded_logs/windowsAD/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name
    
class LinuxLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='Linux')
    file = models.FileField(upload_to='uploaded_logs/linux/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name    
    
class MacLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='mac')
    file = models.FileField(upload_to='uploaded_logs/mac/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name 

class ApacheLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='apache')
    file = models.FileField(upload_to='uploaded_logs/apache/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name         


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



#===========================APPLICATION LOGS MODELS START================================






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


