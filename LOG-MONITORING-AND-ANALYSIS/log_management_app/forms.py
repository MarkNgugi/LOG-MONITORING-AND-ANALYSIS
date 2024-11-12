from django import forms
from .models import *

#====================WINDOWS LOGS FORMS START=======================

class WindowsLogUploadForm(forms.ModelForm):
    class Meta:
        model = WindowsLogFile
        fields = ['source_name', 'file']
        widgets = {
            'source_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter log source'
            }),
            'file': forms.ClearableFileInput(attrs={
                'class': 'form-control-file',
                'style': 'display:none;', 
                'id': 'fileInput',         
            }),
        }


class WindowsADLogUploadForm(forms.ModelForm):
    class Meta:
        model = WindowsADLogFile
        fields = ['source_name', 'file']
        widgets = {
            'source_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter log source'
            }),
            'file': forms.ClearableFileInput(attrs={
                'class': 'form-control-file',
                'style': 'display:none;', 
                'id': 'fileInput',         
            }),
        }

#=================================WINDOWS LOGS FORMS END============================================

#================LINUX LOGS FORMS START============================================

class LinuxLogUploadForm(forms.ModelForm):
    class Meta:
        model = LinuxLogFile
        fields = ['source_name', 'file']
        widgets = {
            'source_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter log source'
            }),
            'file': forms.ClearableFileInput(attrs={
                'class': 'form-control-file',
                'style': 'display:none;', 
                'id': 'fileInput',         
            }),
        }

#================LINUX LOGS FORMS END============================================


#================MACOS LOGS FORMS START============================================

class MacLogUploadForm(forms.ModelForm):
    class Meta:
        model = MacLogFile
        fields = ['source_name', 'file']
        widgets = {
            'source_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter log source'
            }),
            'file': forms.ClearableFileInput(attrs={
                'class': 'form-control-file',
                'style': 'display:none;', 
                'id': 'fileInput',         
            }),
        }

#=================================MACOS LOGS FORMS END============================================




#APPLICATION LOGS FORMS
 
#APACHE LOGS FORMS START
class ApacheserverLogStreamForm(forms.ModelForm):
    class Meta:
        model = ApacheserverLogStream
        fields = [
            'log_source_name', 'log_file_path', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),        
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
                        
        }


class ApacheserverLogFileStreamForm(forms.ModelForm):
    class Meta: 
        model = ApacheserverLogFileStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }

class ApacheserverPerfLogForm(forms.ModelForm):
    class Meta:
        model = ApacheserverPerfLogs
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }        

#APACHE LOGS FORMS END        

#NGINX LOGS FORMS START
class NginxserverLogStreamForm(forms.ModelForm):
    class Meta:
        model = NginxserverLogStream
        fields = [
            'log_source_name', 'log_file_path', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),            
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }


class NginxserverLogFileStreamForm(forms.ModelForm):
    class Meta:
        model = NginxserverLogFileStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }

class NginxserverPerfLogForm(forms.ModelForm):
    class Meta:
        model = NginxserverPerfLogs
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }    


#NGINX LOGS FORMS END  


#IIS LOGS FORMS START
class IISserverLogStreamForm(forms.ModelForm):
    class Meta:
        model = IISserverLogStream
        fields = [
            'log_source_name', 'log_file_path', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),       
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
            
        }


class IISserverLogFileStreamForm(forms.ModelForm):
    class Meta:
        model = IISserverLogFileStream 
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }

class IISserverPerfLogForm(forms.ModelForm):
    class Meta:
        model = IISserverPerfLogs
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }   


#IIS LOGS FORMS END  


#TOMCAT LOGS FORMS START
class TomcatserverLogStreamForm(forms.ModelForm):
    class Meta:
        model = TomcatserverLogStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }


class TomcatserverLogFileStreamForm(forms.ModelForm):
    class Meta:
        model = TomcatserverLogStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-select'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-select'}),
            'collection_interval': forms.Select(attrs={'class': 'form-select'}),
            'retention_policy': forms.Select(attrs={'class': 'form-select'}),

            
        }

class TomcatserverPerfLogForm(forms.ModelForm):
    class Meta:
        model = TomcatserverLogStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-select'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-select'}),
            'collection_interval': forms.Select(attrs={'class': 'form-select'}),
            'retention_policy': forms.Select(attrs={'class': 'form-select'}),

            
        }   


#TOMCAT LOGS FORMS END=================================================


#LIGHTTPD LOGS FORMS START 
class LighttpdserverLogStreamForm(forms.ModelForm):
    class Meta:
        model = LighttpdserverLogStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }


class LighttpdserverLogFileStreamForm(forms.ModelForm):
    class Meta:
        model = LighttpdserverLogStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-select'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-select'}),
            'collection_interval': forms.Select(attrs={'class': 'form-select'}),
            'retention_policy': forms.Select(attrs={'class': 'form-select'}),

            
        }

class LighttpdserverPerfLogForm(forms.ModelForm):
    class Meta:
        model = LighttpdserverLogStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-select'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-select'}),
            'collection_interval': forms.Select(attrs={'class': 'form-select'}),
            'retention_policy': forms.Select(attrs={'class': 'form-select'}),

            
        }   


#LIGHTTPD LOGS FORMS END



#MYSQL LOGS FORMS START 
class MysqlLogStreamForm(forms.ModelForm):
    class Meta:
        model = MysqlLogStream
        fields = [
            'log_source_name', 'log_file_path', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),            
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }


class MysqlLogFileStreamForm(forms.ModelForm):
    class Meta:
        model = MysqlLogFileStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }

class MysqlPerfLogForm(forms.ModelForm):
    class Meta:
        model = MysqlPerfLogs
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }   


#MYSQL LOGS FORMS END




#POSTGRES LOGS FORMS START

class PostgresLogStreamForm(forms.ModelForm):
    class Meta:
        model = PostgresLogStream
        fields = [
            'log_source_name', 'log_file_path', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),            
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }


class PostgresLogFileStreamForm(forms.ModelForm):
    class Meta:
        model = PostgresLogFileStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }

class PostgresPerfLogForm(forms.ModelForm):
    class Meta:
        model = PostgresPerfLogs
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        } 

#POSTGRES LOGS FORMS END


#MONGODB LOGS FORMS START

class MongodbLogStreamForm(forms.ModelForm):
    class Meta:
        model = MongodbLogStream
        fields = [
            'log_source_name', 'log_file_path','filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),            
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        }


class MongodbLogFileStreamForm(forms.ModelForm):
    class Meta:
        model = MongodbLogFileStream
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        } 

class MongodbPerfLogForm(forms.ModelForm):
    class Meta:
        model = MongodbPerfLogs
        fields = [
            'log_source_name', 'log_file_path',
            'log_level', 'filter_keyword', 'log_rotation_interval', 
            'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),     
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log file path'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

            
        } 

#MONGODB LOGS FORMS END