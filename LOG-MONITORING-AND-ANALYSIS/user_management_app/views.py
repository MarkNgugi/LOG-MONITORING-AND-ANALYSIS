from django.shortcuts import render, redirect
from log_management_app.views import home
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

def user_list(request):
    users=User.objects.all()
    users=User.objects.exclude(role='Admin')
    context={'users':users}
    return render(request,'baseapp/useraccounts/useraccounts.html',context)

@login_required
@user_passes_test(lambda u: u.is_superuser)  # Only allow superusers to add new users
def add_user(request):
    if request.method == 'POST':
        form = UserForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.save(commit=False)
            password = form.cleaned_data.get('password')
            user.set_password(password)
            user.save()
            messages.success(request, 'User added successfully!')
            return redirect('useraccounts')  # Redirect to a user list view or any other page
    else:
        form = UserForm()
    return render(request, 'baseapp/useraccounts/add_user.html', {'form': form})

 
@login_required
@user_passes_test(lambda u: u.is_superuser)  # Only allow superusers to edit users
def edit_user(request, user_id):
    user = User.objects.get(id=user_id)
    if request.method == 'POST':
        form = UserForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, 'User updated successfully!')
            return redirect('useraccounts')  # Redirect to a user list view or any other page
    else:
        form = UserForm(instance=user)
    return render(request, 'baseapp/useraccounts/edit_user.html', {'form': form, 'user': user})


@login_required 
@user_passes_test(lambda u: u.is_superuser)  # Only allow superusers to delete users
def delete_user(request, user_id):
    user = User.objects.get(id=user_id)
    if request.method == 'POST':
        user.delete()
        messages.success(request, 'User deleted successfully!')
        return redirect('useraccounts')  
    return render(request, 'baseapp/useraccounts/delete_user.html', {'user': user})


def user_profile(request,user_id):
    user = User.objects.get(id=user_id)
    context={'user':user}
    return render(request, 'baseapp/useraccounts/userprofile.html',context)


 


@login_required
def accountsettings(request, tab='profile'):
    user = request.user
    
    if request.method == 'POST':
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.email = request.POST.get('email')
        user.save()
        messages.success(request, 'Profile updated successfully.')
        return redirect('accountsettings_tab', tab='profile')
    
    context = {'tab': tab, 'user': user}
    return render(request, 'baseapp/accountsettings/accountsettings.html', context)


def ip_page(request):
    context={}
    return render(request,'baseapp/accesscontrol/ip.html',context)

def test(request):
    context={}
    return render(request,'baseapp/accesscontrol/test.html',context)


