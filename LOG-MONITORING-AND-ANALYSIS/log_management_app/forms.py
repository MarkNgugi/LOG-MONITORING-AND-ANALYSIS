# from django import forms
# from .models import WindowsLogSource

# class WindowsLogSourceForm(forms.ModelForm):
#     class Meta:
#         model = WindowsLogSource
#         fields = [
#             'log_source_name', 'log_type', 'log_format', 'machine_type',
#             'collection_interval', 'log_retention_period',
#             'winrm_username', 'winrm_password', 'winrm_host', 'winrm_port'
#         ]

#         widgets = {
#             'log_source_name': forms.TextInput(attrs={'class': 'form-control'}),
#             'log_type': forms.Select(attrs={'class': 'form-control'}),
#             'log_format': forms.TextInput(attrs={'class': 'form-control'}),
#             'machine_type': forms.Select(attrs={'class': 'form-control'}),
#             'collection_interval': forms.TextInput(attrs={'class': 'form-control'}),
#             'log_retention_period': forms.TextInput(attrs={'class': 'form-control'}),
#             'winrm_username': forms.TextInput(attrs={'class': 'form-control'}),
#             'winrm_password': forms.PasswordInput(attrs={'class': 'form-control'}),
#             'winrm_host': forms.TextInput(attrs={'class': 'form-control'}),
#             'winrm_port': forms.NumberInput(attrs={'class': 'form-control'}),
#         }


from django import forms
from .models import WindowsLogSource

class WindowsLogSourceForm(forms.ModelForm):
    class Meta:
        model = WindowsLogSource
        fields = ['log_source_name', 'winrm_username', 'winrm_password', 'winrm_host', 'winrm_port']
        widgets = {
            'log_source_name': forms.TextInput(attrs={'class': 'form-control'}),
            'winrm_username': forms.TextInput(attrs={'class': 'form-control'}),
            'winrm_password': forms.PasswordInput(attrs={'class': 'form-control'}),
            'winrm_host': forms.TextInput(attrs={'class': 'form-control'}),
            'winrm_port': forms.NumberInput(attrs={'class': 'form-control'}),
        }

