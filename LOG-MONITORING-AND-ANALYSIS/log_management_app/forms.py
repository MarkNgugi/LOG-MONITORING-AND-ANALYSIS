from django import forms
from .models import WindowsLogSource

class WindowsLogSourceForm(forms.ModelForm):
    class Meta:
        model = WindowsLogSource
        fields = ['log_source_name', 'log_type', 'log_format', 'ingestion_mtd']
        labels = {
            'log_source_name': 'Log Source Name',
            'log_type': 'Log Type',
            'log_format': 'Log Format',
            'ingestion_mtd': 'Ingestion Method',
        }
        widgets = {
            'log_type': forms.Select(choices=WindowsLogSource.LOG_TYPES),
            'ingestion_mtd': forms.Select(choices=WindowsLogSource.INGESTION_MTD),
        }
