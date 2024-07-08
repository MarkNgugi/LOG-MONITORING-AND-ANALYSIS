from django import forms
from .models import WindowsLogSource

class WindowsLogSourceForm(forms.ModelForm):
    class Meta:
        model = WindowsLogSource
        fields = ['log_source_name', 'log_type', 'log_format', 'machine_type', 
                  'collection_interval', 'log_retention_period',
                  ]

        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control'}),
            'log_type': forms.Select(attrs={'class': 'form-control'}),
            'log_format': forms.TextInput(attrs={'class': 'form-control'}),
            'machine_type': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.TextInput(attrs={'class': 'form-control'}),
            'log_retention_period': forms.TextInput(attrs={'class': 'form-control'}),

        }

