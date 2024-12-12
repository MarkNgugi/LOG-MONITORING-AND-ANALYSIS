from django.db import models
from django.utils import timezone 
from user_management_app.models import User
from datetime import datetime 
from user_management_app.models import User

def get_default_user():
    # This can be any user that makes sense as the default
    return User.objects.first()  # Fetch the first user or specify another default user.

 
class WindowsLogFile(models.Model):
    source_name = models.CharField(max_length=20, blank=True, null=True)
    source = models.CharField(max_length=255, default='Windows')
    os_type = models.CharField(max_length=50, default='Windows')
    file = models.FileField(upload_to='uploaded_logs/windows/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='windows_logs')

    def __str__(self):
        # Return 'source_name' or a fallback string if it's None
        return self.source_name if self.source_name else "No Source Name"

    
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
 
class LinuxLog(models.Model):    

    timestamp = models.CharField(max_length=255,null=True)
    event = models.TextField(max_length=50,null=True)
    status = models.CharField(max_length=50, null=True, blank=True)
    log_level = models.CharField(max_length=50, null=True)
    hostname = models.CharField(max_length=255, null=True, blank=True)
    process = models.CharField(max_length=255, null=True, blank=True)
    source = models.CharField(max_length=255, null=True, blank=True)
    message = models.TextField(null=True, blank=True)
    username = models.CharField(max_length=255, null=True, blank=True)
    source_ip = models.CharField(max_length=50, null=True, blank=True)
    
 
    def __str__(self):
        return f"{self.timestamp} - {self.event} - {self.username} - {self.source_ip}"

    class Meta:
        verbose_name = "Linux Log"
        verbose_name_plural = "Linux Logs"

     
class MacLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='mac')
    file = models.FileField(upload_to='uploaded_logs/mac/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name 
 
 
class ApacheLog(models.Model):
    client_ip = models.CharField(max_length=50, null=True, blank=True)
    timestamp = models.CharField(max_length=255, null=True)
    method = models.CharField(max_length=10,null=True, blank=True)
    url = models.TextField(null=True, blank=True)
    protocol = models.TextField(null=True)
    status_code = models.PositiveIntegerField(null=True, blank=True)
    referrer = models.TextField(null=True)
    user_agent = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)    
    
    # Error Log Fields
    error_module = models.CharField(max_length=50,null=True, blank=True)
    process_id = models.PositiveIntegerField(null=True)
    error_message = models.TextField(null=True, blank=True)
    file_path = models.TextField(null=True, blank=True)


    def __str__(self):        
            return f"{self.timestamp} {self.client_ip} {self.method} {self.url}"
        

    class Meta:
        verbose_name = "Apache Log"
        verbose_name_plural = "Apache Logs"

class NginxLogFile(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    os_type=models.CharField(max_length=50,default='nginx')
    file = models.FileField(upload_to='uploaded_logs/nginx/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_name     

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
 

class Alert(models.Model):
    alert_title = models.CharField(max_length=30)    
    timestamp = models.DateTimeField()  
    host = models.CharField(max_length=100)  
    message = models.TextField(null=True)  
    severity = models.CharField(max_length=10, default="None")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="alerts_user")
    


    def __str__(self):
        return self.alert_title
 
 
 