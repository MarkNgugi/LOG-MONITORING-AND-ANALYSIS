from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .forms import *
from .models import *


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


