from django.shortcuts import render
from django.http import HttpResponse

def home(request):
    context={}
    return render(request,'baseapp/home.html',context)

def system_windows_logs(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windows.html',context)

def system_windows_logs_form(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windowsform.html',context)