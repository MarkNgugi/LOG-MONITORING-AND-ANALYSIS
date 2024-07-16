
from django import forms
from .models import WindowsLogSource, LogType

class WindowsLogSourceForm(forms.ModelForm):
    log_type = forms.ModelMultipleChoiceField(
        queryset=LogType.objects.all(),
        widget=forms.CheckboxSelectMultiple
    )

    class Meta:
        model = WindowsLogSource
        fields = ['log_source_name', 'log_type', 'log_format', 'ingestion_mtd']
