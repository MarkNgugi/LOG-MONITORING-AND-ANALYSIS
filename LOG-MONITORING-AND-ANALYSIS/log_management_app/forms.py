
from django import forms
from .models import *

#====================WINDOWS LOGS FORMS START=======================

class WindowsLogSourceForm(forms.ModelForm):
    log_type = forms.ModelMultipleChoiceField(
        queryset=WindowsLogType.objects.all(),
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = WindowsLogSource 
        fields = [
            'log_source_name', 'description', 'log_type', 'retention_policy',
            
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name', 'required':True}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter description', 'rows': 3}),            
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
        }

 
class WindowsFileLogSourceForm(forms.ModelForm):
    log_type = forms.ModelMultipleChoiceField(
        queryset=WindowsLogType.objects.all()
    )    
    class Meta:
        model = WindowsFileLogSource
        fields = [
            'log_source_name',
            'log_file_path',
            'log_type',
            'collection_interval',            
            'retention_policy',
            'log_format',
            'rotation_policy',
            # 'ingestion_mtd'
            

        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter the path to the log file'}),            
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
            'log_format': forms.Select(attrs={'class': 'form-control'}),                       
            'rotation_policy': forms.Select(attrs={'class': 'form-control'}),
            # 'ingestion_mtd': forms.TextInput(attrs={'class': 'form-control', 'readonly': 'readonly', 'disabled': 'disabled'}),         
        }


class WindowsPerfLogsForm(forms.ModelForm):
    performance_metrics = forms.ModelMultipleChoiceField(
        queryset=WindowsPerformanceMetric.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False
    )
    
    class Meta:
        model = WindowsPerfLogs
        fields = [
            'log_source_name',
            'performance_metrics',
            'collection_interval',
            'retention_policy',
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
        }
        help_texts = {
            'performance_metrics': 'Select the types of metrics to include',
        }


class WindowsActiveDirectoryLogSourceForm(forms.ModelForm): 
    class Meta:
        model = WindowsActiveDirectoryLogSource
        fields = ['log_source_name', 'domain_name', 'collection_interval', 'retention_policy']
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'domain_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter domain name'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
        }

#=================================WINDOWS LOGS FORMS END============================================

#================LINUX LOGS FORMS START============================================

class LinuxLogSourceForm(forms.ModelForm):
    log_type = forms.ModelMultipleChoiceField(
        queryset=LinuxLogType.objects.all(),
        widget=forms.CheckboxSelectMultiple
    )

    class Meta:
        model = LinuxLogSource 
        fields = [
            'log_source_name', 'log_type', 'collection_interval', 'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'log_type': forms.CheckboxSelectMultiple(attrs={'class': 'form-check'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
            
            
        }


class LinuxFileLogSourceForm(forms.ModelForm):
    class Meta:
        model = LinuxFileLogSource
        fields = [
            'log_source_name',
            'log_file_path',
            'log_type',
            'log_file_type',
            'collection_interval',
            'file_size_limit',
            'rotation_policy',
            'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter the path to the log file'}),
            'log_file_type': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
            'file_size_limit': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter size limit in MB'}),
            'rotation_policy': forms.Select(attrs={'class': 'form-control'}),
        }

class LinuxPerfLogsForm(forms.ModelForm):
    performance_metrics = forms.ModelMultipleChoiceField(
        queryset=LinuxPerformanceMetric.objects.all(),
        required=True,
        help_text="Select the metrics to collect"
    )

    class Meta: 
        model = LinuxPerfLogs
        fields = [
            'log_source_name',  
            'performance_metrics', 
            'collection_interval', 
            'retention_policy',
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
        }



class LdapLogSourceForm(forms.ModelForm): 
    class Meta:
        model = LDAPLogSource
        fields = ['log_source_name', 'domain_name', 'collection_interval', 'retention_policy']
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'domain_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter domain name'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
        }

#================LINUX LOGS FORMS END============================================


#================MACOS LOGS FORMS START============================================

class MacLogSourceForm(forms.ModelForm):
    log_type = forms.ModelMultipleChoiceField(
        queryset=MacLogType.objects.all(),
        widget=forms.CheckboxSelectMultiple
    )

    class Meta:
        model = MacLogSource
        fields = [
            'log_source_name', 'log_type', 'collection_interval',
            'retention_policy'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),            
            'log_type': forms.CheckboxSelectMultiple(attrs={'class': 'form-check'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),            
            
        }


class MacFileLogSourceForm(forms.ModelForm):
    class Meta:
        model = MacFileLogSource
        fields = [
            'log_source_name',
            'log_file_path',
            'log_file_type',
            'collection_interval',
            'file_size_limit',
            'rotation_policy',
            'retention_policy'

        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter the path to the log file'}),
            'log_file_type': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
            'file_size_limit': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter size limit in MB'}),            
            'rotation_policy': forms.Select(attrs={'class': 'form-control'}),
        }


class MacPerfLogsForm(forms.ModelForm):
    performance_metrics = forms.ModelMultipleChoiceField(
        queryset=MacPerformanceMetric.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=True,
        help_text="Select the metrics to collect"
    )

    class Meta: 
        model = MacPerfLogs
        fields = [
            'log_source_name',  
            'performance_metrics', 'collection_interval', 'retention_policy', 
            
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'performance_metrics': forms.CheckboxSelectMultiple(attrs={'class': 'form-check'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),

        }


class OpenDirLogSourceForm(forms.ModelForm): 
    class Meta:
        model = OpenDirLogSource
        fields = ['log_source_name', 'domain_name', 'collection_interval', 'retention_policy']
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'domain_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter domain name'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
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