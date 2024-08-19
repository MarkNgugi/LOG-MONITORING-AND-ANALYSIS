from django import forms
from .models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ValidationError


class RegistrationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'password1', 'password2']


class LoginForm(AuthenticationForm):
    username = forms.EmailField(widget=forms.EmailInput(attrs={'autofocus': True}))

    class Meta: 
        model = User
        fields = ['username', 'password']        

class UserForm(forms.ModelForm):
    # password = forms.CharField(widget=forms.PasswordInput(), min_length=8)
    # confirm_password = forms.CharField(widget=forms.PasswordInput(), min_length=8, label='Confirm Password')
    role = forms.ChoiceField(choices=User.roles, widget=forms.RadioSelect)

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'contact_number', 'role', 'department', 'date_of_birth', 'profile_picture', 'security_question', 'security_answer']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your username'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email address'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your first name'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your last name'}),
            'contact_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your contact number'}),
            # 'role': forms.Select(attrs={'class': 'form-control'}),
            'department': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your department'}),
            'date_of_birth': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'profile_picture': forms.FileInput(attrs={'class': 'form-control-file'}),
            'security_question': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your security question'}),
            'security_answer': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your security answer'}),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password != confirm_password:
            self.add_error('confirm_password', 'Passwords do not match')

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError('Username taken. Please choose another.')
        return username            
