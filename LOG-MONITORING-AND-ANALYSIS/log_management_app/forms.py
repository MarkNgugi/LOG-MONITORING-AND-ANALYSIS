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


class ApacheLogUploadForm(forms.ModelForm):
    class Meta:
        model = ApacheLogFile
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

        

class NginxLogUploadForm(forms.ModelForm):
    class Meta:
        model = NginxLogFile
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


class IISLogUploadForm(forms.ModelForm):
    class Meta:
        model = IISLogFile
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