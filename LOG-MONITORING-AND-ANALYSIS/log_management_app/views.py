from django.shortcuts import render,redirect
from django.http import HttpResponse
from .forms import WindowsLogSourceForm
from .models import WindowsLogSource


def home(request):
    context={}
    return render(request,'baseapp/home.html',context)

def system_os_types(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/OSpage.html',context)

def system_windows_logs(request):
    log_sources=WindowsLogSource.objects.all()
    context={'log_sources':log_sources}
    return render(request,'baseapp/logsources/systemlogs/windows.html',context)


def system_windows_logs_form(request):
    if request.method=='POST':
        log_source_form=WindowsLogSourceForm(request.POST)
        if log_source_form.is_valid:
            log_source_form=log_source_form.save()
            return redirect('ingestionmtd')
        
    else:
        log_source_form=WindowsLogSourceForm()
    context={'log_source_form':log_source_form}
    return render(request,'baseapp/logsources/systemlogs/windowsform.html',context)

def ingestionmtd(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/ingmtd.html',context)

def application_webserver_logs(request):
    context={}
    return render(request,'baseapp/logsources/applicationlogs/webserver.html',context)

def application_webserver_form(request):
    context={}
    return render(request,'baseapp/logsources/applicationlogs/webserverform.html',context)

def logstreams(request):
    context={}
    return render(request,'baseapp/logstreams/logstreams.html',context)

def add_log_source(request):
    if request.method == 'POST':
        form = WindowsLogSourceForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('log_source_list')  
    else:
        form = WindowsLogSourceForm()

    context={'form':form}
    return render(request, 'baseapp/logsources/add_log_source.html',context)

