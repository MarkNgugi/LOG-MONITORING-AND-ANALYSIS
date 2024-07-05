from django.shortcuts import render,redirect
from django.http import HttpResponse
from .forms import WindowsLogSource

def home(request):
    context={}
    return render(request,'baseapp/home.html',context)

def system_windows_logs(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windows.html',context)


def system_windows_logs_form(request):
    if request.method=='POST':
        log_source_form=WindowsLogSource(request.POST)
        if log_source_form.is_valid:
            log_source_form=log_source_form.save()
            return redirect('home')
        
    else:
        log_source_form=WindowsLogSource()
    context={'log_source_form':log_source_form}
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