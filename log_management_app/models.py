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
    return User.objects.first()  

 
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
    processed = models.BooleanField(default=False)

    def __str__(self):        
        return str(self.event_id) if self.hostname else "No Source Name"

class LinuxLog(models.Model):    
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
    
    log_level = models.CharField(max_length=50, null=True, blank=True)    
    user = models.CharField(max_length=255, null=True, blank=True)
    command = models.TextField(null=True, blank=True)
    pwd = models.CharField(max_length=255, null=True, blank=True)
    session_status = models.CharField(max_length=255, null=True, blank=True)
    uid = models.IntegerField(null=True, blank=True)

    
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
 


class Report(models.Model):
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]

    report_title = models.CharField(max_length=255)
    generated_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    generated_at = models.DateTimeField(auto_now_add=True)
    total_logs_processed = models.IntegerField()
    data_sources = models.JSONField(null=True,blank=True)  
    log_summary = models.JSONField(null=True,blank=True)  
    total_alerts_triggered = models.IntegerField()
    alert_severity_distribution = models.JSONField()  
    top_critical_alerts = models.JSONField()  

    def __str__(self):
        return self.report_title


 
