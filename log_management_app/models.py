from django.db import models
from django.utils import timezone 
from user_management_app.models import User
from datetime import datetime 
from user_management_app.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authtoken.models import Token  
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

def get_default_user():
    # This can be any user that makes sense as the default
    return User.objects.first()  # Fetch the first user or specify another default user.

 
class WindowsLog(models.Model):
    LOG_TYPE_CHOICES = [
        ('syslog', 'Syslog'),
        ('authlog', 'Authlog'),
    ]    
    log_source_name = models.CharField(max_length=255, null=True, blank=True)
    event_id = models.IntegerField()    
    timestamp = models.DateTimeField()
    log_type = models.CharField(max_length=50, choices=LOG_TYPE_CHOICES, null=True, blank=True) 
    hostname = models.CharField(max_length=255, null=True, blank=True)   
    message = models.TextField(null=True, blank=True)     
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='windows_logs')
    processed = models.BooleanField(default=False)

    def __str__(self):        
        return str(self.event_id) if self.hostname else "No Source Name"

 
class WindowsADLog(models.Model):
    LOG_TYPE_CHOICES = [
        ('syslog', 'Syslog'),
        ('authlog', 'Authlog'),
    ]
    log_source_name = models.CharField(max_length=255, null=True, blank=True)
    event_id = models.IntegerField()    
    timestamp = models.DateTimeField()
    log_type = models.CharField(max_length=50, choices=LOG_TYPE_CHOICES, null=True, blank=True) 
    hostname = models.CharField(max_length=255, null=True, blank=True)   
    message = models.TextField(null=True, blank=True)     
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='windowsAD_logs')

    def __str__(self):        
        return str(self.event_id) if self.hostname else "No Source Name"

class LinuxLog(models.Model):
    # Common fields for both syslogs and auth logs
    LOG_TYPE_CHOICES = [
        ('syslog', 'Syslog'),
        ('authlog', 'Authlog'),
    ]
    log_source_name = models.CharField(max_length=255, null=True, blank=True)
    log_type = models.CharField(max_length=50, choices=LOG_TYPE_CHOICES, null=True)
    timestamp = models.CharField(null=True, blank=True)
    hostname = models.CharField(max_length=255, null=True, blank=True)
    service = models.CharField(max_length=255, null=True, blank=True)
    process_id = models.IntegerField(null=True, blank=True)
    message = models.TextField(null=True, blank=True)

    # Additional fields for syslogs
    log_level = models.CharField(max_length=50, null=True, blank=True)

    # Additional fields for auth logs
    user = models.CharField(max_length=255, null=True, blank=True)
    command = models.TextField(null=True, blank=True)
    pwd = models.CharField(max_length=255, null=True, blank=True)
    session_status = models.CharField(max_length=255, null=True, blank=True)
    uid = models.IntegerField(null=True, blank=True)

    # ForeignKey to the User model
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='linux_logs', null=True, blank=True)
    processed = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Linux Log"
        verbose_name_plural = "Linux Logs"

    def __str__(self):
        return f"{self.log_type} - {self.timestamp} - {self.service} - {self.log_type} - {self.message[:50]}"


class Alert(models.Model):
    alert_title = models.CharField(max_length=100)    
    timestamp = models.DateTimeField()  
    hostname = models.CharField(max_length=100)  
    message = models.TextField(null=True)  
    severity = models.CharField(max_length=100, default="Low")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="alerts_user", null=True, blank=True)    
    log_source_name = models.CharField(max_length=255, null=True, blank=True)
    connection = models.CharField(max_length=255, null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']    

    def __str__(self):
        return self.alert_title

class ApacheLog(models.Model):
   
    LOG_TYPE_CHOICES = [
        ('access', 'Access'),
        ('error', 'Error'),
    ]    
    log_source_name = models.CharField(max_length=255, null=True, blank=True)
    log_type = models.CharField(max_length=50, choices=LOG_TYPE_CHOICES, null=True) 
    client_ip = models.GenericIPAddressField(null=True, blank=True)  
    remote_logname = models.CharField(max_length=100, blank=True, null=True)  
    remote_user = models.CharField(max_length=100, blank=True, null=True)  
    timestamp = models.CharField(null=True, blank=True) 
    request_line = models.CharField(max_length=255, default='none', blank=True)  
    response_code = models.IntegerField(null=True, blank=True)  
    response_size = models.IntegerField(null=True, blank=True)  
    referrer = models.CharField(max_length=255, blank=True, null=True)  
    user_agent = models.CharField(max_length=255, blank=True, null=True)  
    created_at = models.DateTimeField(auto_now_add=True)  
    
    # Fields specific to error logs
    log_level = models.CharField(max_length=50, blank=True, null=True)  
    error_message = models.TextField(blank=True, null=True) 
    process_id = models.IntegerField(null=True, blank=True)        
    module = models.CharField(max_length=255, blank=True, null=True)  

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='apache_logs', null=True, blank=True)

    class Meta:
        ordering = ['-timestamp'] 
        verbose_name = "Apache Log"
        verbose_name_plural = "Apache Logs"

    def __str__(self):
        return f"{self.client_ip if self.client_ip else 'N/A'} - {self.timestamp} -{self.log_type} -{self.response_code if self.response_code else 'N/A'}"


class NginxLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='nginx')
    file = models.FileField(upload_to='uploaded_logs/nginx/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name



class MysqlLog(models.Model):
    LOG_LEVEL_CHOICES = [
        ('System', 'System'),
        ('Warning', 'Warning'),
        ('Error', 'Error'),
        ('Info', 'Info'),
    ]
    log_source_name = models.CharField(max_length=255)
    log_type = models.CharField(max_length=50, default="mysql_error")
    timestamp = models.DateTimeField()
    error_message = models.TextField()    
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="mysql_logs")    

    def __str__(self):
        return f"{self.timestamp} - {self.log_source_name}: {self.error_message[:50]}"


class RedisLog(models.Model):
    LOG_TYPE_CHOICES = [
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('DEBUG', 'Debug'),
        ('', 'Debug'),
    ]

    log_source_name = models.CharField(max_length=255)
    log_type = models.CharField(max_length=50, default="redis")
    timestamp = models.DateTimeField()
    message = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="redis_logs")

    def __str__(self):
        return f"{self.timestamp} - {self.log_source_name}: {self.message[:50]}"      

class IISLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='iis')
    file = models.FileField(upload_to='uploaded_logs/iis/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name        

class MysqlLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='mysql')
    file = models.FileField(upload_to='uploaded_logs/mysql/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name       

class PostgresLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='postgres')
    file = models.FileField(upload_to='uploaded_logs/postgres/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name     

class MongoLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='mongo')
    file = models.FileField(upload_to='uploaded_logs/mongo/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name 
 
 
class LogEntry(models.Model):
    TimeCreated = models.DateTimeField()
    event_id = models.IntegerField()
    LevelDisplayName = models.CharField(max_length=50)
    source = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    processed = models.BooleanField(default=False)  # Tracks if the log has been processed
    batch_id = models.IntegerField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="log_entries_user")


    def __str__(self):
        return f"{self.TimeCreated} - {self.event_id} - {self.source}"
 
 


class CustomToken(Token):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=255, default="token1")

    def __str__(self):
        username = getattr(self.user, 'username', 'Unknown User')
        return f"Token '{self.name}' for {username} created at {self.created_at}"
