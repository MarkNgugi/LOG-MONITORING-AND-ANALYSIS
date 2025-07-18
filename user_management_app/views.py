from django.shortcuts import render, redirect
from log_management_app.views import *
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .forms import *
from .models import *
 
 
def custom_login(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('username')  # Email is used as the username
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')  
            else:
                messages.error(request, "Invalid email or password.")
        else:
            messages.error(request, "Invalid email or password.")
    else:
        form = LoginForm()
    
    context={'form':form}
    return render(request, 'baseapp/MAINauth/loginform.html', context)



def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home') 
        else:         
            print(form.errors) 
    else:
        form = RegistrationForm()        

    context = {'form': form}
    return render(request, 'baseapp/MAINauth/register.html', context)

def custom_logout(request):
    logout(request)
    return redirect('login')


@login_required
def accountsettings(request, tab='profile'):
    user = request.user
    
    if request.method == 'POST':
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.email = request.POST.get('email')
        
        # Handle profile picture upload
        if 'profile_picture' in request.FILES:
            # Delete the old profile picture if it exists
            if user.profile_picture:
                user.profile_picture.delete()
            # Save the new profile picture
            user.profile_picture = request.FILES['profile_picture']
            print(f"New profile picture saved: {user.profile_picture}")  # Debugging
        
        user.save()
        messages.success(request, 'Profile updated successfully.')
        return redirect('accountsettings_tab', tab='profile')
    
    context = {'tab': tab, 'user': user}
    return render(request, 'baseapp/accountsettings/accountsettings.html', context)




