from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import SecurityLogSerializer
from itertools import chain

from django.shortcuts import render,redirect
from .forms import WindowsLogSourceForm,WindowsFileLogSourceForm,WindowsPerfLogsForm,WindowsActiveDirectoryLogSourceForm,WebserverLogFileUploadForm,WindowsFileLogSource, LinuxLogSourceForm
from .models import WindowsLogSource,SecurityLog,WindowsPerfLogs,WindowsActiveDirectoryLogSource
from django.urls import reverse


@api_view(['POST'])
def SecurityLogView(request):
    serializer = SecurityLogSerializer(data=request.data, many=True)

    if serializer.is_valid():
        serializer.save()
        return Response({"message": "Logs received successfully"}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def home(request):
    context={}
    return render(request,'baseapp/home.html',context)

#LOG SOURCES

def logsources(request):
    log_sources_1 = WindowsLogSource.objects.all()
    log_sources_2 = WindowsFileLogSource.objects.all()
    log_sources_3 = WindowsPerfLogs.objects.all()
    log_sources_4 = WindowsActiveDirectoryLogSource.objects.all()

    log_sources = list(chain(log_sources_1, log_sources_2,log_sources_3, log_sources_4))
    context={'log_sources':log_sources}
    return render(request,'baseapp/logsources/logsources.html',context)    


#LOG INGESTION 
def system_os_types(request): 
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/OSpage.html',context)


#syslogs collectin mtds START
def windows_collection_options(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/collectionopts.html',context)

def linux_collection_options(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/linux/collectionopts.html',context)

def macos_collection_options(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/macos/collectionopts.html',context)

#syslogs collectin mtds END

#WINDOWS FORMS START
def stream_windows_host_logs(request):
    if request.method=='POST':
        log_source_form=WindowsLogSourceForm(request.POST)
        if log_source_form.is_valid():
            log_source_form=log_source_form.save()
            return redirect('streamsyslogs')
        
    else: 
        log_source_form=WindowsLogSourceForm() 
    context={
        'log_source_form':log_source_form,
        
        }
    return render(request,'baseapp/logingestion/systemlogs/windows/stream_win_logsform.html',context)


def logfilestreams(request):
    if request.method=='POST':
        logfileform=WindowsFileLogSourceForm(request.POST)
        if logfileform.is_valid():
            logfileform=logfileform.save()
            return redirect('streamlogfiles')
    else:
        logfileform=WindowsFileLogSourceForm() 
    context={'logfileform':logfileform}
    return render(request,'baseapp/logingestion/systemlogs/windows/logfilestreamform.html',context)

def performancelogs(request):
    if request.method=='POST':
        logperf=WindowsPerfLogsForm(request.POST)
        if logperf.is_valid():
            logperf=logperf.save()
            return redirect('collectperflogs')
    else:
        logperf=WindowsPerfLogsForm()
    context={'logperf':logperf}
    return render(request,'baseapp/logingestion/systemlogs/windows/perfform.html',context)


def activedirectoryform(request):
    if request.method == 'POST':
        activedirectoryform = WindowsActiveDirectoryLogSourceForm(request.POST)
        if activedirectoryform.is_valid():
            activedirectoryform.save()
            return redirect('activedirectorylogs') 
    else:
        activedirectoryform = WindowsActiveDirectoryLogSourceForm()
    
    context = {'activedirectoryform': activedirectoryform}
    return render(request, 'baseapp/logingestion/systemlogs/windows/activedirectoryform.html', context)

#WINDOWS FORMS END

#====================LINUX FORMS START============================

def stream_linux_host_logs(request):
    if request.method=='POST':
        log_source_form=LinuxLogSourceForm(request.POST)
        if log_source_form.is_valid():
            log_source_form=log_source_form.save()
            return redirect('home')
        
    else: 
        log_source_form=LinuxLogSourceForm() 
    context={
        'log_source_form':log_source_form,
        
        }
    return render(request,'baseapp/logingestion/systemlogs/linux/linuxlogsform.html',context)



#===============================LINUX FORM END========================================
#syslogs instructions start
def streamsyslogs(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/inst-streamsyslogs.html',context)

def streamlogfiles(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/inst-streamlogfiles.html',context)

def collectperflogs(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/collectperflogs.html',context)

def activedirectorylogs(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/inst-activedirectorylogs.html',context)

#syslogs instructions end



#APPLICATION LOGS START
    #webserver
def application_webserver_logs(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserver.html',context)

def application_webserver_form(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverform.html',context)

def web_server_types(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webservertypes.html',context)

def webserver_collection_options(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/collectionopts.html',context)

def webserver_collection_agents(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/collectionagent.html',context)

#APPLICATION LOGS FORMS
    #webserver forms

def webserverfileupload(request):
    if request.method == 'POST':
        webserverfileuploadform=WebserverLogFileUploadForm(request.POST,request.FILES)
        if webserverfileuploadform.is_valid():
            webserverfileuploadform.save()
            return redirect(reverse('home'))
    else:
        webserverfileuploadform=WebserverLogFileUploadForm()
    
    context={'webserverfileuploadform':webserverfileuploadform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverfileupload.html',context)

    #database

def database_types(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/databases/databasetypes.html',context)


    #caching systems

def cachingsystems_types(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/middleware/cachingsystems.html',context)


#SEARCH

def search(request):
    context={}
    return render(request,'baseapp/search/search.html',context)

#STREAMS

def logstreams(request):
    context={}
    return render(request,'baseapp/logstreams/logstreams.html',context)

#ANOMALIES

def anomaliespage(request):
    context={}
    return render(request,'baseapp/anomalies/anomalies.html',context)

def anomalydetail(request):
    context={}
    return render(request,'baseapp/anomalies/anomalydetail.html',context)

#REPORTS

def reportspage(request):
    context={}
    return render(request,'baseapp/reports/report.html',context)

#INCIDENT RESPONSE

def incidences(request):
    context={}
    return render(request,'baseapp/incidentresponse/incidences.html',context)

def incidentresponse(request):
    context={}
    return render(request,'baseapp/incidentresponse/incidentresponse.html',context)

#LOG RETENTION

def logretention(request):
    context={}
    return render(request,'baseapp/logretention/logretention.html',context)