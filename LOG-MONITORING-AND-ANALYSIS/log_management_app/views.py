from django.shortcuts import render
from django.http import HttpResponse

def home(request):
    context={}
    return render(request,'baseapp/home.html',context)

def system_windows_logs(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windows.html',context)

def system_windows_form(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windowsform.html',context)

def application_webserver_logs(request):
    context={}
    return render(request,'baseapp/logsources/applicationlogs/webserver.html',context)

def application_webserver_form(request):
    context={}
    return render(request,'baseapp/logsources/applicationlogs/webserverform.html',context)

def logstreams(request):
    context={}
    return render(request,'baseapp/logstreams/logstreams.html',context)