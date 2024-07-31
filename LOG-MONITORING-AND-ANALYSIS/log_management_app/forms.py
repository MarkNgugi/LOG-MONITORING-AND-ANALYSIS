
from django import forms
from .models import WindowsLogSource, LogType, WindowsFileLogSource, WindowsPerfLogs, PerformanceMetric, WindowsActiveDirectoryLogSource, WebserverLogFileUpload


class WindowsLogSourceForm(forms.ModelForm):
    log_type = forms.ModelMultipleChoiceField(
        queryset=LogType.objects.all(),
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
            'log_encoding',
            'rotation_policy',
            'log_format',
            'auth_method',
            'additional_params'
        ]
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'log_file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter the path to the log file'}),
            'log_file_type': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.Select(attrs={'class': 'form-control'}),
            'file_size_limit': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter size limit in MB'}),
            'log_encoding': forms.Select(attrs={'class': 'form-control'}),
            'rotation_policy': forms.Select(attrs={'class': 'form-control'}),
            'log_format': forms.Select(attrs={'class': 'form-control'}),
            'auth_method': forms.Select(attrs={'class': 'form-control'}),
            'additional_params': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Enter any additional parameters'}),
        }


class WindowsPerfLogsForm(forms.ModelForm):
    performance_metrics = forms.ModelMultipleChoiceField(
        queryset=PerformanceMetric.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=True,
        help_text="Select the metrics to collect"
    )

    class Meta:
        model = WindowsPerfLogs
        fields = [
            'client_name', 'ip_address', 'port_number', 'username', 'password', 
            'performance_metrics', 'collection_interval', 'retention_period', 
            'log_format', 'notifications'
        ]
        widgets = {
            'client_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter client name'}),
            'ip_address': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter IP address'}),
            'port_number': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter port number'}),
            'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter username'}),
            'password': forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter password'}),
            'collection_interval': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter interval in seconds'}),
            'retention_period': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter retention period in days'}),
            'log_format': forms.Select(attrs={'class': 'form-control'}),
            'notifications': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

class WindowsActiveDirectoryLogSourceForm(forms.ModelForm):
    class Meta:
        model = WindowsActiveDirectoryLogSource
        fields = ['log_source_name', 'domain_name', 'domain_controller_ip', 'port_number', 'username', 'password', 'log_level', 'log_format', 'collection_interval', 'retention_period']
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter log source name'}),
            'domain_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter domain name'}),
            'domain_controller_ip': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter domain controller IP address'}),
            'port_number': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter port number'}),
            'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter username'}),
            'password': forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter password'}),
            'log_level': forms.Select(attrs={'class': 'form-control'}),
            'log_format': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter collection interval in seconds'}),
            'retention_period': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter retention period in days'}),
        }

#APPLICATION LOGS FORMS

class WebserverLogFileUploadForm(forms.ModelForm):
    class Meta:
        model = WebserverLogFileUpload
        fields = ['source_name', 'file_type', 'log_file_description', 'file']
        widgets = {
            'source_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter source name'}),
            'file_type': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter file type'}),
            'log_file_description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Enter log file description'}),
            
        }

