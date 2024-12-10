from django.shortcuts import render
from .models import *

#ALERTS



def alertconfig(request):
    context={}
    return render(request,'baseapp/alertconfig/alertconfig.html',context)

def alertconfigpage(request):
    context={}
    return render(request,'baseapp/alertconfig/configpage.html',context)

def contactpoint(request):
    context={}
    return render(request,'baseapp/contactpoints/contactpoint.html',context)

def notification_policy(request):
    context={}
    return render(request,'baseapp/notificationpolicy/notificationpolicies.html',context)

    
 

def scheduledreports(request):
    context={}
    return render(request,'baseapp/scheduledreports/scheduledreports.html',context)

def addscheduledreport(request):
    context={}
    return render(request,'baseapp/scheduledreports/addreport.html',context)
    
def customalerts(request):
    context={}
    return render(request,'baseapp/customalerts/customalerts.html',context)

def notification_settings(request):
    context={}
    return render(request,'baseapp/notificationsettings/notsettings.html',context)