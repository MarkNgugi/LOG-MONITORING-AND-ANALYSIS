from django.shortcuts import render,redirect
from django.http import HttpResponse
from .forms import WindowsLogSourceForm
from .models import WindowsLogSource
import winrm


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
            return redirect('system_windows_logs')
        
    else:
        log_source_form=WindowsLogSourceForm()
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


def fetch_logs(host, username, password, port=5985):
    session = winrm.Session(f'http://{host}:{port}/wsman', auth=(username, password))
    result = session.run_cmd('powershell Get-EventLog -LogName System')
    
    if result.status_code == 0:
        logs = result.std_out.decode('utf-8')
        return logs
    else:
        raise Exception(f"Failed to fetch logs: {result.std_err.decode('utf-8')}")

def add_log_source(request):
    if request.method == 'POST':
        form = WindowsLogSourceForm(request.POST)
        if form.is_valid():
            log_source = form.save()
            try:
                logs = fetch_logs(
                    log_source.winrm_host,
                    log_source.winrm_username,
                    log_source.winrm_password,
                    log_source.winrm_port
                )
                # Process logs as needed
                print(logs)
                return redirect('success_page')  # Redirect to a success page
            except Exception as e:
                form.add_error(None, str(e))  # Add the error to the form
    else:
        form = WindowsLogSourceForm()
    
    return render(request, 'add_log_source.html', {'form': form})

