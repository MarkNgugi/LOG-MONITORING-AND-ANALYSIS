from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import SecurityLogSerializer
from itertools import chain

from django.shortcuts import render,redirect
from .forms import *
from .models import *
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


def logsources(request, os_type=None):
    log_sources_1 = WindowsLogSource.objects.all()
    log_sources_2 = WindowsFileLogSource.objects.all()
    log_sources_3 = WindowsPerfLogs.objects.all()
    log_sources_4 = WindowsActiveDirectoryLogSource.objects.all()

    log_sources_5 = LinuxLogSource.objects.all()
    log_sources_6 = LinuxFileLogSource.objects.all()
    log_sources_7 = LinuxPerfLogs.objects.all()
    log_sources_8 = LDAPLogSource.objects.all()

    log_sources_9 = MacLogSource.objects.all()
    log_sources_10 = MacFileLogSource.objects.all()
    log_sources_11 = MacPerfLogs.objects.all()
    log_sources_12 = OpenDirLogSource.objects.all()

    # Chain all log sources
    all_log_sources = list(chain(
        log_sources_1, log_sources_2, log_sources_3, log_sources_4, 
        log_sources_5, log_sources_6, log_sources_7, log_sources_8,
        log_sources_9, log_sources_10, log_sources_11, log_sources_12
    ))

    # Count each OS type before filtering
    windows_count = len(list(chain(log_sources_1, log_sources_2, log_sources_3, log_sources_4)))
    linux_count = len(list(chain(log_sources_5, log_sources_6, log_sources_7, log_sources_8)))
    mac_count = len(list(chain(log_sources_9, log_sources_10, log_sources_11, log_sources_12)))
    all_count = len(all_log_sources)  # Total count of all log sources

    # Filtering based on os_type
    if os_type == "windows":
        log_sources = list(chain(log_sources_1, log_sources_2, log_sources_3, log_sources_4))
    elif os_type == "linux":
        log_sources = list(chain(log_sources_5, log_sources_6, log_sources_7, log_sources_8))
    elif os_type == "macos":
        log_sources = list(chain(log_sources_9, log_sources_10, log_sources_11, log_sources_12))
    else:
        log_sources = all_log_sources

    context = {
        'log_sources': log_sources,
        'windows_count': windows_count,
        'linux_count': linux_count,
        'mac_count': mac_count,
        'all_count': all_count,
        'os_type': os_type,  # Pass os_type to the template for active tab
    }

    return render(request, 'baseapp/logsources/logsources.html', context)



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
            return redirect('logsources')
        
    else: 
        log_source_form=WindowsLogSourceForm() 
    context={
        'log_source_form':log_source_form,
        
        }
    return render(request,'baseapp/logingestion/systemlogs/windows/stream_win_logsform.html',context)


def windowslogfilestreams(request):
    if request.method=='POST':
        logfileform=WindowsFileLogSourceForm(request.POST)
        if logfileform.is_valid():
            logfileform=logfileform.save()
            return redirect('logsources')
    else:
        logfileform=WindowsFileLogSourceForm() 
    context={'logfileform':logfileform}
    return render(request,'baseapp/logingestion/systemlogs/windows/logfilestreamform.html',context)

def windowsperformancelogs(request):
    if request.method=='POST':
        logperf=WindowsPerfLogsForm(request.POST)
        if logperf.is_valid():
            logperf=logperf.save()
            return redirect('logsources')
    else:
        logperf=WindowsPerfLogsForm()
    context={'logperf':logperf}
    return render(request,'baseapp/logingestion/systemlogs/windows/perfform.html',context)


def activedirectoryform(request):
    if request.method == 'POST':
        activedirectoryform = WindowsActiveDirectoryLogSourceForm(request.POST)
        if activedirectoryform.is_valid():
            activedirectoryform.save()
            return redirect('logsources') 
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
            return redirect('logsources')
        
    else: 
        log_source_form=LinuxLogSourceForm() 
    context={
        'log_source_form':log_source_form,
        
        }
    return render(request,'baseapp/logingestion/systemlogs/linux/stream_linux_logsform.html',context)


def linuxlogfilestreams(request):
    if request.method=='POST':
        logfileform=LinuxFileLogSourceForm(request.POST)
        if logfileform.is_valid():
            logfileform=logfileform.save()
            return redirect('logsources')
    else:
        logfileform=LinuxFileLogSourceForm() 
    context={'logfileform':logfileform}
    return render(request,'baseapp/logingestion/systemlogs/linux/logfilestreamform.html',context)


def linuxperformancelogs(request):
    if request.method=='POST':
        logperf=LinuxPerfLogsForm(request.POST)
        if logperf.is_valid():
            logperf=logperf.save()
            return redirect('logsources')
    else:
        logperf=LinuxPerfLogsForm()
    context={'logperf':logperf}
    return render(request,'baseapp/logingestion/systemlogs/linux/perfform.html',context)


def ldaplogs(request):
    if request.method == 'POST':
        ldapform = LdapLogSourceForm(request.POST)
        if ldapform.is_valid():
            ldapform.save()
            return redirect('logsources') 
    else:
        ldapform = LdapLogSourceForm()
    
    context = {'ldapform': ldapform}
    return render(request, 'baseapp/logingestion/systemlogs/linux/ldapform.html', context)



#===============================LINUX FORM END========================================


#===============================MACOS FORM START========================================

def stream_mac_host_logs(request):
    if request.method=='POST':
        log_source_form=MacLogSourceForm(request.POST)
        if log_source_form.is_valid():
            log_source_form=log_source_form.save()
            return redirect('logsources')
        
    else: 
        log_source_form=MacLogSourceForm() 
    context={
        'log_source_form':log_source_form,
        
        }
    return render(request,'baseapp/logingestion/systemlogs/macos/stream_mac_logsform.html',context)


def maclogfilestreams(request):
    if request.method=='POST':
        logfileform=MacFileLogSourceForm(request.POST)
        if logfileform.is_valid():
            logfileform=logfileform.save()
            return redirect('logsources')
    else:
        logfileform=MacFileLogSourceForm() 
    context={'logfileform':logfileform}
    return render(request,'baseapp/logingestion/systemlogs/macos/logfilestreamform.html',context)


def macperformancelogs(request):
    if request.method=='POST':
        logperf=MacPerfLogsForm(request.POST)
        if logperf.is_valid():
            logperf=logperf.save()
            return redirect('logsources')
    else:
        logperf=MacPerfLogsForm()
    context={'logperf':logperf}
    return render(request,'baseapp/logingestion/systemlogs/macos/perfform.html',context)


def opendirlogs(request):
    if request.method == 'POST':
        opendirform = OpenDirLogSourceForm(request.POST)
        if opendirform.is_valid():
            opendirform.save()
            return redirect('logsources') 
    else:
        opendirform = OpenDirLogSourceForm()
    
    context = {'opendirform': opendirform}
    return render(request, 'baseapp/logingestion/systemlogs/macos/opendirform.html', context)

#===============================MACOS FORM END========================================


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

def web_server_types(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webservertypes.html',context)

def application_webserver_form(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverform.html',context)


def webserver_collection_options(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/collectionopts.html',context)



#APPLICATION LOGS FORMS
    #webserver forms

# def webserverfileupload(request):
#     if request.method == 'POST':
#         webserverfileuploadform=WebserverLogFileUploadForm(request.POST,request.FILES)
#         if webserverfileuploadform.is_valid():
#             webserverfileuploadform.save()
#             return redirect(reverse('home'))
#     else:
#         webserverfileuploadform=WebserverLogFileUploadForm()
    
#     context={'webserverfileuploadform':webserverfileuploadform}
#     return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverfileupload.html',context)



def apacheserverlogstream(request):
    if request.method=='POST':
        apacheform=ApacheserverLogStream(request.POST)
        if apacheform.is_valid():
            apacheform.save()
            return redirect('logsources')
        
    else:
        apacheform=ApacheserverLogStreamForm()
    context={'apacheform':apacheform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/apache/apachestream.html',context)

def apacheserverlogfilestream(request):
    if request.method=='POST':
        apacheform=ApacheserverLogFileStream(request.POST)
        if apacheform.is_valid():
            apacheform.save()
            return redirect('logsources')
        
    else:
        apacheform=ApacheserverLogFileStreamForm()
    context={'apacheform':apacheform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/apache/apachefilestream.html',context)

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