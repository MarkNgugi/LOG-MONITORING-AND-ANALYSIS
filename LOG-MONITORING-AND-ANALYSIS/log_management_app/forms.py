
from django import forms
from .models import *

#====================WINDOWS LOGS FORMS START=======================

class WindowsLogSourceForm(forms.ModelForm):
    log_type = forms.ModelMultipleChoiceField(
        queryset=WindowsLogType.objects.all(),
        widget=forms.CheckboxSelectMultiple
    )

    class Meta:
        model = WindowsLogSource
        fields = [
            'log_source_name', 'description', 'log_type', 'collection_interval',
            'retention_policy', 'ingestion_mtd', 'comments'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter description', 'rows': 3}),
            'log_type': forms.CheckboxSelectMultiple(attrs={'class': 'form-check'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
            'ingestion_mtd': forms.Select(attrs={'class': 'form-control'}),
            'comments': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter comments', 'rows': 3}),

        }

class WindowsFileLogSourceForm(forms.ModelForm):
    class Meta:
        model = WindowsFileLogSource
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


class WindowsPerfLogsForm(forms.ModelForm):
    performance_metrics = forms.ModelMultipleChoiceField(
        queryset=WindowsPerformanceMetric.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=True,
        help_text="Select the metrics to collect"
    )

    class Meta: 
        model = WindowsPerfLogs
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
            'log_source_name', 'log_type', 'collection_interval',
            'retention_policy', 'collection_mtd'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'log_type': forms.CheckboxSelectMultiple(attrs={'class': 'form-check'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
            'collection_mtd': forms.Select(attrs={'class': 'form-control'}),
            
        }


class LinuxFileLogSourceForm(forms.ModelForm):
    class Meta:
        model = LinuxFileLogSource
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


class LinuxPerfLogsForm(forms.ModelForm):
    performance_metrics = forms.ModelMultipleChoiceField(
        queryset=LinuxPerformanceMetric.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=True,
        help_text="Select the metrics to collect"
    )

    class Meta: 
        model = LinuxPerfLogs
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
            'retention_policy', 'collection_mtd'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'log_type': forms.CheckboxSelectMultiple(attrs={'class': 'form-check'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'retention_policy': forms.Select(attrs={'class': 'form-control'}),
            'collection_mtd': forms.Select(attrs={'class': 'form-control'}),
            
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


class ApacheserverLogFileStreamForm(forms.ModelForm):
    class Meta:
        model = ApacheserverLogStream
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

class ApacheserverPerfLogForm(forms.ModelForm):
    class Meta:
        model = ApacheserverLogStream
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

#APACHE LOGS FORMS END        

#NGINX LOGS FORMS START
class NginxserverLogStreamForm(forms.ModelForm):
    class Meta:
        model = NginxserverLogStream
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


class NginxserverLogFileStreamForm(forms.ModelForm):
    class Meta:
        model = NginxserverLogStream
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

class NginxserverPerfLogForm(forms.ModelForm):
    class Meta:
        model = NginxserverLogStream
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


#NGINX LOGS FORMS END  


#IIS LOGS FORMS START
class IISserverLogStreamForm(forms.ModelForm):
    class Meta:
        model = IISserverLogStream
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


class IISserverLogFileStreamForm(forms.ModelForm):
    class Meta:
        model = IISserverLogStream
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

class IISserverPerfLogForm(forms.ModelForm):
    class Meta:
        model = IISserverLogStream
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
            'log_level': forms.Select(attrs={'class': 'form-select'}),
            'filter_keyword': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter filter keyword (optional)'}),
            'log_rotation_interval': forms.Select(attrs={'class': 'form-select'}),
            'collection_interval': forms.Select(attrs={'class': 'form-select'}),
            'retention_policy': forms.Select(attrs={'class': 'form-select'}),

            
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


#TOMCAT LOGS FORMS END