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
    timestamp = models.DateTimeField()
    log_level = models.CharField(max_length=50)
    message = models.TextField()
    source = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

class Anomaly(models.Model):
    source_name=models.CharField(max_length=20, blank=True, null=True)
    anomaly=models.CharField(max_length=30, blank=True, null=True)
    detected_at = models.DateTimeField(auto_now_add=True)



#===========================APPLICATION LOGS MODELS START================================








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


