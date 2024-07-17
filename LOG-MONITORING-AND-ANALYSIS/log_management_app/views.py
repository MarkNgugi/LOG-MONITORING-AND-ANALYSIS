from django.shortcuts import render,redirect
from .forms import WindowsLogSourceForm,WindowsFileLogSourceForm,WindowsPerfLogsForm,WindowsActiveDirectoryLogSourceForm
from .models import WindowsLogSource


def home(request):
    context={}
    return render(request,'baseapp/home.html',context)

def system_os_types(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windows/OSpage.html',context)

def system_windows_logs_table(request):
    log_sources=WindowsLogSource.objects.all()
    context={'log_sources':log_sources}
    return render(request,'baseapp/logsources/systemlogs/windows/windowslogstable.html',context)

#syslogs collectin mtds start
def system_collection_options(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windows/collectionopts.html',context)

#syslogs collectin mtds end

#syslogs forms start
def stream_windows_host_logs(request):
    if request.method=='POST':
        log_source_form=WindowsLogSourceForm(request.POST)
        if log_source_form.is_valid():
            log_source_form=log_source_form.save()
            return redirect('streamsyslogs')
        
    else: 
        log_source_form=WindowsLogSourceForm()
    context={'log_source_form':log_source_form}
    return render(request,'baseapp/logsources/systemlogs/windows/streamsyslogsform.html',context)


def logfilestreams(request):
    if request.method=='POST':
        logfileform=WindowsFileLogSourceForm(request.POST)
        if logfileform.is_valid():
            logfileform=logfileform.save()
            return redirect('streamlogfiles')
    else:
        logfileform=WindowsFileLogSourceForm()
    context={'logfileform':logfileform}
    return render(request,'baseapp/logsources/systemlogs/windows/logfilestreamform.html',context)

def performancelogs(request):
    if request.method=='POST':
        logperf=WindowsPerfLogsForm(request.POST)
        if logperf.is_valid():
            logperf=logperf.save()
            return redirect('collectperflogs')
    else:
        logperf=WindowsPerfLogsForm()
    context={'logperf':logperf}
    return render(request,'baseapp/logsources/systemlogs/windows/perfform.html',context)


def activedirectoryform(request):
    if request.method == 'POST':
        activedirectoryform = WindowsActiveDirectoryLogSourceForm(request.POST)
        if activedirectoryform.is_valid():
            activedirectoryform.save()
            return redirect('activedirectorylogs') 
    else:
        activedirectoryform = WindowsActiveDirectoryLogSourceForm()
    
    context = {'activedirectoryform': activedirectoryform}
    return render(request, 'baseapp/logsources/systemlogs/windows/activedirectoryform.html', context)


#syslogs forms end

#syslogs instructions start
def streamsyslogs(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windows/inst-streamsyslogs.html',context)

def streamlogfiles(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windows/inst-streamlogfiles.html',context)

def collectperflogs(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windows/collectperflogs.html',context)

def activedirectorylogs(request):
    context={}
    return render(request,'baseapp/logsources/systemlogs/windows/inst-activedirectorylogs.html',context)

#syslogs instructions end




def application_webserver_logs(request):
    context={}
    return render(request,'baseapp/logsources/applicationlogs/webserver.html',context)

def application_webserver_form(request):
    context={}
    return render(request,'baseapp/logsources/applicationlogs/webserverform.html',context)

def logstreams(request):
    context={}
    return render(request,'baseapp/logstreams/logstreams.html',context)


