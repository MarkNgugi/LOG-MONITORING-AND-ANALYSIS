from django import forms
from .models import WindowsLogSource

class WindowsLogSourceForm(forms.ModelForm):
    class Meta:
        model = WindowsLogSource
        fields = ['log_source_name', 'log_type', 'log_format', 'ingestion_method', 
                  'collection_interval', 'log_retention_period', 'kerberos_spn', 
                  'kerberos_realm', 'kerberos_keytab']

        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control'}),
            'log_type': forms.Select(attrs={'class': 'form-control'}),
            'log_format': forms.TextInput(attrs={'class': 'form-control'}),
            'ingestion_method': forms.Select(attrs={'class': 'form-control'}),
            'collection_interval': forms.TextInput(attrs={'class': 'form-control'}),
            'log_retention_period': forms.TextInput(attrs={'class': 'form-control'}),
            'kerberos_spn': forms.TextInput(attrs={'class': 'form-control'}),
            'kerberos_realm': forms.TextInput(attrs={'class': 'form-control'}),
            'kerberos_keytab': forms.FileInput(attrs={'class': 'form-control'}),
        }

    def clean_kerberos_keytab(self):
        keytab_file = self.cleaned_data.get('kerberos_keytab')
        if keytab_file:
            if not keytab_file.name.endswith('.keytab'):
                raise forms.ValidationError("Please upload a valid Keytab file.")
        return keytab_file
