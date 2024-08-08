from django import forms
from .models import User

class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(), min_length=8)
    confirm_password = forms.CharField(widget=forms.PasswordInput(), min_length=8, label='Confirm Password')

    class Meta:
        model = User
        fields = ['username', 'email', 'full_name', 'contact_number', 'role', 'department', 'date_of_birth', 'profile_picture', 'security_question', 'security_answer']
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password != confirm_password:
            self.add_error('confirm_password', 'Passwords do not match')
