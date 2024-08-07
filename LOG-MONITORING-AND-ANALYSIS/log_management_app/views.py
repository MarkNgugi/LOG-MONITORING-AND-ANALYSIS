from itertools import chain

from django.shortcuts import render,redirect
from .forms import *
from .models import *
from django.urls import reverse


#LOG SOURCES
def home(request):
    context={}
    return render(request,'baseapp/home.html',context)

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



def application_webserver_form(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverform.html',context)


def webserver_collection_options(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/collectionopts.html',context)

def logstreamingwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/logstreamwizard.html',context)

def logfilestreamingwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/logfilestreamwizard.html',context)

def perflogwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/perflogsstreamwizard.html',context)

def logfileuploadwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/logfileuploadwizard.html',context)



#APPLICATION LOGS FORMS
    #webserver forms

def apacheserverlogstream(request):
    if request.method=='POST':
        apacheform=ApacheserverLogStreamForm(request.POST)
        if apacheform.is_valid():
            apacheform.save()
            return redirect('logsources')
        
    else:
        apacheform=ApacheserverLogStreamForm()
    context={'apacheform':apacheform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/apache/apachestream.html',context)

def apacheserverlogfilestream(request):
    if request.method=='POST':
        apacheform=ApacheserverLogFileStreamForm(request.POST) 
        if apacheform.is_valid():
            apacheform.save()
            return redirect('logsources')
        
    else:
        apacheform=ApacheserverLogFileStreamForm()
    context={'apacheform':apacheform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/apache/apachefilestream.html',context)


def apacheserverperflogs(request):
    if request.method=='POST':
        apacheform=ApacheserverPerfLogForm(request.POST)
        if apacheform.is_valid():
            apacheform.save()
            return redirect('logsources')
        
    else:
        apacheform=ApacheserverPerfLogForm()
    context={'apacheform':apacheform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/apache/apacheperflogs.html',context)

def apachefileupload(request):
    if request.method == 'POST':
        webserverfileuploadform=ApacheLogFileUploadForm(request.POST,request.FILES)
        if webserverfileuploadform.is_valid():
            webserverfileuploadform.save()
            return redirect(reverse('home'))
    else:
        webserverfileuploadform=ApacheLogFileUploadForm()
    
    context={'webserverfileuploadform':webserverfileuploadform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverfileupload.html',context)


#APACHE FORMS END


def nginxserverlogstream(request):
    if request.method=='POST':
        nginxform=NginxserverLogStreamForm(request.POST)
        if nginxform.is_valid():
            nginxform.save()
            return redirect('logsources')
        
    else:
        nginxform=NginxserverLogStreamForm()
    context={'nginxform':nginxform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/nginx/nginxstream.html',context)

def nginxserverlogfilestream(request):
    if request.method=='POST':
        nginxform=NginxserverLogFileStreamForm(request.POST) 
        if nginxform.is_valid():
            nginxform.save()
            return redirect('logsources')
        
    else:
        nginxform=NginxserverLogFileStreamForm()
    context={'nginxform':nginxform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/nginx/nginxperflogs.html',context)


def nginxserverperflogs(request):
    if request.method=='POST':
        nginxform=NginxserverPerfLogForm(request.POST)
        if nginxform.is_valid():
            nginxform.save()
            return redirect('logsources')
        
    else:
        nginxform=NginxserverPerfLogForm()
    context={'nginxform':nginxform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/nginx/nginxfilestream.html',context)

def nginxfileupload(request):
    if request.method == 'POST':
        webserverfileuploadform=NginxLogFileUploadForm(request.POST,request.FILES)
        if webserverfileuploadform.is_valid():
            webserverfileuploadform.save()
            return redirect(reverse('home'))
    else:
        webserverfileuploadform=NginxLogFileUploadForm()
    
    context={'webserverfileuploadform':webserverfileuploadform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverfileupload.html',context)


#NGINX FORMS END


def iisserverlogstream(request):
    if request.method=='POST':
        iisform=IISserverLogStreamForm(request.POST)
        if iisform.is_valid():
            iisform.save()
            return redirect('logsources')
        
    else:
        iisform=IISserverLogStreamForm()
    context={'iisform':iisform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/iis/iisstream.html',context)

def iisserverlogfilestream(request):
    if request.method=='POST':
        iisform=IISserverLogFileStreamForm(request.POST) 
        if iisform.is_valid():
            iisform.save()
            return redirect('logsources')
        
    else:
        iisform=NginxserverLogFileStreamForm()
    context={'iisform':iisform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/iis/iisperflogs.html',context)


def iisserverperflogs(request):
    if request.method=='POST':
        iisform=IISserverPerfLogForm(request.POST)
        if iisform.is_valid():
            iisform.save()
            return redirect('logsources')
        
    else:
        iisform=IISserverPerfLogForm()
    context={'iisform':iisform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/iis/iisfilestream.html',context)

def iisfileupload(request):
    if request.method == 'POST':
        webserverfileuploadform=IISLogFileUploadForm(request.POST,request.FILES)
        if webserverfileuploadform.is_valid():
            webserverfileuploadform.save()
            return redirect(reverse('home'))
    else:
        webserverfileuploadform=IISLogFileUploadForm()
    
    context={'webserverfileuploadform':webserverfileuploadform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverfileupload.html',context)


#IIS FORMS END



def tomcatserverlogstream(request):
    if request.method=='POST':
        tomcatform=TomcatserverLogStreamForm(request.POST)
        if tomcatform.is_valid():
            tomcatform.save()
            return redirect('logsources')
        
    else:
        tomcatform=TomcatserverLogStreamForm()
    context={'tomcatform':tomcatform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/tomcat/tomcatstream.html',context)

def tomcatserverlogfilestream(request):
    if request.method=='POST':
        tomcatform=TomcatserverLogFileStreamForm(request.POST) 
        if tomcatform.is_valid():
            tomcatform.save()
            return redirect('logsources')
        
    else:
        tomcatform=TomcatserverLogFileStreamForm()
    context={'tomcatform':tomcatform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/tomcat/tomcatfilestream.html',context)


def tomcatserverperflogs(request):
    if request.method=='POST':
        tomcatform=TomcatserverPerfLogForm(request.POST)
        if tomcatform.is_valid():
            tomcatform.save()
            return redirect('logsources')
        
    else:
        tomcatform=TomcatserverPerfLogForm()
    context={'tomcatform':tomcatform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/tomcat/tomcatperflogs.html',context)

def tomcatfileupload(request):
    if request.method == 'POST':
        webserverfileuploadform=TomcatLogFileUploadForm(request.POST,request.FILES)
        if webserverfileuploadform.is_valid():
            webserverfileuploadform.save()
            return redirect(reverse('home'))
    else:
        webserverfileuploadform=TomcatLogFileUploadForm()
    
    context={'webserverfileuploadform':webserverfileuploadform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverfileupload.html',context)


#TOMCAT FORMS END


def lighttpdserverlogstream(request):
    if request.method=='POST':
        lighttpdform=LighttpdserverLogStreamForm(request.POST)
        if lighttpdform.is_valid():
            lighttpdform.save()
            return redirect('logsources')
        
    else:
        lighttpdform=LighttpdserverLogStreamForm()
    context={'lighttpdform':lighttpdform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/lighttpd/lighttpdstream.html',context)

def lighttpdserverlogfilestream(request):
    if request.method=='POST':
        lighttpdform=LighttpdserverLogFileStreamForm(request.POST) 
        if lighttpdform.is_valid():
            lighttpdform.save()
            return redirect('logsources')
        
    else:
        lighttpdform=LighttpdserverLogFileStreamForm()
    context={'lighttpdform':lighttpdform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/lighttpd/lighttpdfilestream.html',context)


def lighttpdserverperflogs(request):
    if request.method=='POST':
        lighttpdform=LighttpdserverPerfLogForm(request.POST)
        if lighttpdform.is_valid():
            lighttpdform.save()
            return redirect('logsources')
        
    else:
        lighttpdform=LighttpdserverPerfLogForm()
    context={'lighttpdform':lighttpdform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/lighttpd/lighttpdperflogs.html',context)

def lighttpdfileupload(request):
    if request.method == 'POST':
        webserverfileuploadform=LighttpdLogFileUploadForm(request.POST,request.FILES)
        if webserverfileuploadform.is_valid():
            webserverfileuploadform.save()
            return redirect(reverse('home'))
    else:
        webserverfileuploadform=LighttpdLogFileUploadForm()
    
    context={'webserverfileuploadform':webserverfileuploadform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverfileupload.html',context)


#LIGHTTPD FORMS END








    #database

def database_collection_options(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/databases/collectionopts.html',context)

def dblogstreamingwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/databases/logstreamwizard.html',context)

def dblogfilestreamingwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/databases/logfilestreamwizard.html',context)

def dbperflogwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/databases/perflogsstreamwizard.html',context)

def dblogfileuploadwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/databases/logfileuploadwizard.html',context)


#DATABASE FORMS START

def mysqllogstream(request):
    if request.method=='POST':
        mysqlform=MysqlLogStreamForm(request.POST)
        if mysqlform.is_valid():
            mysqlform.save()
            return redirect('logsources')
        
    else:
        mysqlform=MysqlLogStreamForm()
    context={'mysqlform':mysqlform}
    return render(request,'baseapp/logingestion/applicationlogs/databases/mysql/mysqlstream.html',context)

def mysqllogfilestream(request):
    if request.method=='POST':
        mysqlform=MysqlLogFileStreamForm(request.POST) 
        if mysqlform.is_valid():
            mysqlform.save()
            return redirect('logsources')
        
    else:
        mysqlform=MysqlLogFileStreamForm()
    context={'mysqlform':mysqlform}
    return render(request,'baseapp/logingestion/applicationlogs/databases/mysql/mysqlfilestream.html',context)


def mysqlperflogs(request):
    if request.method=='POST':
        mysqlform=MysqlPerfLogForm(request.POST)
        if mysqlform.is_valid():
            mysqlform.save()
            return redirect('logsources')
        
    else:
        mysqlform=MysqlPerfLogForm()
    context={'mysqlform':mysqlform}
    return render(request,'baseapp/logingestion/applicationlogs/databases/mysql/mysqlperflogs.html',context)

def mysqlfileupload(request):
    if request.method == 'POST':
        webserverfileuploadform=MysqlLogFileUploadForm(request.POST,request.FILES)
        if webserverfileuploadform.is_valid():
            webserverfileuploadform.save()
            return redirect(reverse('home'))
    else:
        webserverfileuploadform=MysqlLogFileUploadForm()
    
    context={'webserverfileuploadform':webserverfileuploadform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverfileupload.html',context)


#POSTGRES
def postgreslogstream(request):
    if request.method=='POST':
        postgresform=PostgresLogStreamForm(request.POST)
        if postgresform.is_valid():
            postgresform.save()
            return redirect('logsources')
        
    else:
        postgresform=PostgresLogStreamForm()
    context={'postgresform':postgresform}
    return render(request,'baseapp/logingestion/applicationlogs/databases/postgres/postgresstream.html',context)

def postgreslogfilestream(request):
    if request.method=='POST':
        postgresform=PostgresLogFileStreamForm(request.POST) 
        if postgresform.is_valid():
            postgresform.save()
            return redirect('logsources')
        
    else:
        postgresform=PostgresLogFileStreamForm()
    context={'postgresform':postgresform}
    return render(request,'baseapp/logingestion/applicationlogs/databases/postgres/postgresfilestream.html',context)


def postgresperflogs(request):
    if request.method=='POST':
        postgresform=PostgresPerfLogForm(request.POST)
        if postgresform.is_valid():
            postgresform.save()
            return redirect('logsources')
        
    else:
        postgresform=PostgresPerfLogForm()
    context={'postgresform':postgresform}
    return render(request,'baseapp/logingestion/applicationlogs/databases/postgres/postgresperflogs.html',context)


#MONGO
def mongodblogstream(request):
    if request.method=='POST':
        mongodbform=MongodbLogStreamForm(request.POST)
        if mongodbform.is_valid():
            mongodbform.save()
            return redirect('logsources')
        
    else:
        mongodbform=MongodbLogStreamForm()
    context={'mongodbform':mongodbform}
    return render(request,'baseapp/logingestion/applicationlogs/databases/mongodb/mongodbstream.html',context)

def mongodblogfilestream(request):
    if request.method=='POST':
        mongodbform=MongodbLogFileStreamForm(request.POST) 
        if mongodbform.is_valid():
            mongodbform.save()
            return redirect('logsources')
        
    else:
        mongodbform=MongodbLogFileStreamForm()
    context={'mongodbform':mongodbform}
    return render(request,'baseapp/logingestion/applicationlogs/databases/mongodb/mongodbfilestream.html',context)


def mongodbperflogs(request):
    if request.method=='POST':
        mongodbform=MongodbPerfLogForm(request.POST)
        if mongodbform.is_valid():
            mongodbform.save()
            return redirect('logsources')
        
    else:
        mongodbform=MongodbPerfLogForm()
    context={'mongodbform':mongodbform}
    return render(request,'baseapp/logingestion/applicationlogs/databases/mongodb/mongodbperflogs.html',context)


#DATABASE FORMS END



def alert_history(request): 

    critical_alerts = WindowsAlert.objects.filter(entry_type='Critical')
    high_alerts = WindowsAlert.objects.filter(entry_type__in=['Error', 'FailureAudit', 'Failure Audit'])
    medium_alerts = WindowsAlert.objects.filter(entry_type='Warning')
    low_alerts = WindowsAlert.objects.filter(entry_type__in=['Success Audit', 'SuccessAudit'])


    context = {
        'critical_alerts': critical_alerts,
        'high_alerts': high_alerts,
        'medium_alerts': medium_alerts,
        'low_alerts': low_alerts,
    }

    return render(request, 'baseapp/alerts/alerts.html', context)












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






