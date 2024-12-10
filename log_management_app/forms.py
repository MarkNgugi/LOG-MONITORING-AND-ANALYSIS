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

class MysqlLogUploadForm(forms.ModelForm):
    class Meta:
        model = MysqlLogFile
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

class PostgresLogUploadForm(forms.ModelForm):
    class Meta:
        model = PostgresLogFile
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

class MongoLogUploadForm(forms.ModelForm):
    class Meta:
        model = MongoLogFile
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

