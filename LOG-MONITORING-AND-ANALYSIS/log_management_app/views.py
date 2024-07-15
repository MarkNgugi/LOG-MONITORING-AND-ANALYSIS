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


def check_connection(host, username, password, port=5985):
    try:
        session = winrm.Session(f'http://{host}:{port}/wsman', auth=(username, password))
        result = session.run_cmd('echo WinRM connection successful')

        if result.status_code == 0:
            return True, result.std_out.decode('utf-8')
        else:
            return False, result.std_err.decode('utf-8')
    except Exception as e:
        return False, str(e)

def add_log_source(request):
    if request.method == 'POST':
        form = WindowsLogSourceForm(request.POST)
        if form.is_valid():
            log_source = form.save(commit=False)
            success, message = check_connection(
                log_source.winrm_host,
                log_source.winrm_username,
                log_source.winrm_password,
                log_source.winrm_port
            )

            if success:
                form.add_error(None, "Connection successful!")
            else:
                form.add_error(None, f"Connection failed: {message}")

    else:
        form = WindowsLogSourceForm()
    
    return render(request, 'baseapp/logsources/add_log_source.html', {'form': form})


