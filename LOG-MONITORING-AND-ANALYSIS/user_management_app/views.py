from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .forms import *
from .models import *


def user_list(request):
    context={}
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
            return redirect('user_list')  # Redirect to a user list view or any other page
    else:
        form = UserForm()
    return render(request, 'baseapp/user/add_user.html', {'form': form})

def profilesettings(request):
    context={}
    return render(request,'baseapp/profilesettings/profilesettings.html',context)

def accountsecurity(request):
    context={}
    return render(request,'baseapp/profilesettings/accountsettings.html',context)

def profilesecurity(request):
    context={}
    return render(request,'baseapp/profilesettings/profilesecurity.html',context)

def profilenotifications(request):
    context={}
    return render(request,'baseapp/profilesettings/profilenotifications.html',context)

def ip_page(request):
    context={}
    return render(request,'baseapp/accesscontrol/ip.html',context)

def test(request):
    context={}
    return render(request,'baseapp/accesscontrol/test.html',context)


