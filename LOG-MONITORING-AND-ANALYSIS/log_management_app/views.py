from itertools import chain
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger


from django.shortcuts import render,redirect
from .forms import *
from .models import *
from django.urls import reverse

from .tasks import process_uploaded_log
def upload_log(request):
    if request.method == 'POST':
        form = LogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_log.delay(uploaded_log.id)  # Trigger async processing
            return redirect('home')
    else:
        form = LogUploadForm()
    return render(request, 'baseapp/upload_log.html', {'form': form})

#LOG SOURCES
def home(request):
    context={}
    return render(request,'baseapp/home.html',context)

def logsources(request, os_type=None, server_type=None, db_type=None, network_type=None):
    # Initialize log sources
    system_logs = []
    webserver_logs = []
    database_logs = []
    network_logs = []

    # Querysets for system logs
    log_sources_windows = list(chain(
        WindowsLogSource.objects.all(),
        WindowsFileLogSource.objects.all(),
        WindowsPerfLogs.objects.all(),
        WindowsActiveDirectoryLogSource.objects.all()
    ))

    log_sources_linux = list(chain(
        LinuxLogSource.objects.all(),
        LinuxFileLogSource.objects.all(),
        LinuxPerfLogs.objects.all(),
        LDAPLogSource.objects.all()
    ))

    log_sources_macos = list(chain(
        MacLogSource.objects.all(),
        MacFileLogSource.objects.all(),
        MacPerfLogs.objects.all(),
        OpenDirLogSource.objects.all()
    ))

    # Querysets for web server logs
    apache_logs = list(chain(
        ApacheserverLogStream.objects.all(),
        ApacheserverLogFileStream.objects.all(),
        ApacheserverPerfLogs.objects.all()
    ))

    nginx_logs = list(chain(
        NginxserverLogStream.objects.all(),
        NginxserverLogFileStream.objects.all(),
        NginxserverPerfLogs.objects.all()
    ))

    iis_logs = list(chain(
        IISserverLogStream.objects.all(),
        IISserverLogFileStream.objects.all(),
        IISserverPerfLogs.objects.all()
    ))

    # Querysets for database logs
    mysql_logs = list(chain(
        MysqlLogStream.objects.all(),
        MysqlLogFileStream.objects.all(),
        MysqlPerfLogs.objects.all()
    ))

    postgres_logs = list(chain(
        PostgresLogStream.objects.all(),
        PostgresLogFileStream.objects.all(),
        PostgresPerfLogs.objects.all()
    ))

    mongodb_logs = list(chain(
        MongodbLogStream.objects.all(),
        MongodbLogFileStream.objects.all(),
        MongodbPerfLogs.objects.all()
    ))

    # Querysets for network logs
    firewall_logs = list(chain(

    ))

    switch_logs = list(chain(

    ))

    router_logs = list(chain(

    ))

    # Filtering based on parameters
    if os_type:
        if os_type == 'windows':
            system_logs = log_sources_windows
        elif os_type == 'linux':
            system_logs = log_sources_linux
        elif os_type == 'macos':
            system_logs = log_sources_macos
    else:
        system_logs = list(chain(log_sources_windows, log_sources_linux, log_sources_macos))

    if server_type:
        if server_type == 'apache':
            webserver_logs = apache_logs
        elif server_type == 'nginx':
            webserver_logs = nginx_logs
        elif server_type == 'iis':
            webserver_logs = iis_logs
    else:
        webserver_logs = list(chain(apache_logs, nginx_logs, iis_logs))

    if db_type:
        if db_type == 'mysql':
            database_logs = mysql_logs
        elif db_type == 'postgres':
            database_logs = postgres_logs
        elif db_type == 'mongo':
            database_logs = mongodb_logs
    else:
        database_logs = list(chain(mysql_logs, postgres_logs, mongodb_logs))

    if network_type:
        pass

    else:
        pass

    # Counts for each category
    all_count = len(webserver_logs)
    apache_count = len(apache_logs)
    nginx_count = len(nginx_logs)
    iis_count = len(iis_logs)

    windows_count = len(log_sources_windows)
    linux_count = len(log_sources_linux)
    mac_count = len(log_sources_macos)
    total_system_logs_count = windows_count + linux_count + mac_count

    mysql_count = len(mysql_logs)
    postgres_count = len(postgres_logs)
    mongo_count = len(mongodb_logs)
    total_db_logs_count = mysql_count + postgres_count + mongo_count

    firewall_count = len(firewall_logs)
    switch_count = len(switch_logs)
    router_count = len(router_logs)
    total_network_logs_count = firewall_count + switch_count + router_count

    context = {
        'all_count': all_count,
        'apache_count': apache_count,
        'nginx_count': nginx_count,
        'iis_count': iis_count,
        'windows_count': windows_count,
        'linux_count': linux_count,
        'mac_count': mac_count,
        'total_system_logs_count': total_system_logs_count,
        'mysql_count': mysql_count,
        'postgres_count': postgres_count,
        'mongo_count': mongo_count,
        'total_db_logs_count': total_db_logs_count,
        'firewall_count': firewall_count,
        'switch_count': switch_count,
        'router_count': router_count,
        'total_network_logs_count': total_network_logs_count,
        'log_sources': system_logs,
        'webserver_logs': webserver_logs,
        'database_logs': database_logs,
        'network_logs': network_logs,  # Add network logs to context
        'os_type': os_type,
        'server_type': server_type,
        'db_type': db_type,
        'network_type': network_type,  # Include network_type in context
    }

    return render(request, 'baseapp/logsources/logsources.html', context)





#LOG INGESTION 
def system_os_types(request):  
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/OSpage.html',context)

def windows(request):

    if request.method == 'POST':    
        print(request.POST) 
        log_source_form = WindowsLogSourceForm(request.POST)
        if log_source_form.is_valid():
            log_source = log_source_form.save(commit=False)
            log_source.save()
            log_source_form.save_m2m() 
            return redirect('logsources')
        else:
            print(log_source_form.errors)
 
    else:
        log_source_form = WindowsLogSourceForm()

    context = {
        'log_source_form': log_source_form,
    }    
    
    return render(request,'baseapp/logingestion/systemlogs/windows/windows.html',context)

def windowsAD(request):
    if request.method == 'POST': 
        activedirectoryform = WindowsActiveDirectoryLogSourceForm(request.POST)
        if activedirectoryform.is_valid():
            activedirectoryform.save()
            return redirect('activedirectorylogs') 
    else:
        activedirectoryform = WindowsActiveDirectoryLogSourceForm()
    
    context = {'activedirectoryform': activedirectoryform}        
    return render(request,'baseapp/logingestion/systemlogs/activedirectory/activedirectory.html',context)

def linux(request):
    if request.method=='POST':
        log_source_form=LinuxLogSourceForm(request.POST)
        if log_source_form.is_valid():
            log_source_form=log_source_form.save()
            return redirect('logsources')
        
        else:
            print(log_source_form.errors)
        
    else: 
        log_source_form=LinuxLogSourceForm() 
        
    context={
        'log_source_form':log_source_form,
        
        }    
    return render(request,'baseapp/logingestion/systemlogs/linux/linux.html',context)


def macos(request):
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
    return render(request,'baseapp/logingestion/systemlogs/macos/macos.html',context)


def apache(request):
    if request.method=='POST':
        apacheform=ApacheserverLogStreamForm(request.POST)
        if apacheform.is_valid():
            apacheform.save()
            return redirect('logsources')
        else:
            print(apacheform.errors)
        
    else:
        apacheform=ApacheserverLogStreamForm()
    context={
        'apacheform':apacheform,        
        }    
    
    return render(request,'baseapp/logingestion/applicationlogs/webservers/apache/apache.html',context)

def nginx(request):
    if request.method=='POST':
        nginxform=NginxserverLogStreamForm(request.POST)
        if nginxform.is_valid():
            nginxform.save()
            return redirect('logsources')
        
    else:
        nginxform=NginxserverLogStreamForm()
    context={'nginxform':nginxform}        
    return render(request,'baseapp/logingestion/applicationlogs/webservers/nginx/nginx.html',context)

def iis(request):
    if request.method=='POST':
        iisform=IISserverLogStreamForm(request.POST)
        if iisform.is_valid():
            iisform.save()
            return redirect('logsources')
        
    else:
        iisform=IISserverLogStreamForm()
    context={'iisform':iisform}        
    return render(request,'baseapp/logingestion/applicationlogs/webservers/iis/iis.html',context)


def mysql(request):
    if request.method=='POST':
        print(request.POST)
        mysqlform=MysqlLogStreamForm(request.POST)
        if mysqlform.is_valid():
            mysqlform.save()
            return redirect('logsources')
        else:
            print(mysqlform.errors)
        
    else:
        mysqlform=MysqlLogStreamForm()
    context={'mysqlform':mysqlform}        
    return render(request,'baseapp/logingestion/applicationlogs/databases/mysql/mysql.html',context)

def postgresql(request):
    if request.method=='POST':
        postgresform=PostgresLogStreamForm(request.POST)
        if postgresform.is_valid():
            postgresform.save()
            return redirect('logsources')
        
    else:
        postgresform=PostgresLogStreamForm()
    context={'postgresform':postgresform}        
    return render(request,'baseapp/logingestion/applicationlogs/databases/postgres/postgresql.html',context)

def mongodb(request):
    if request.method=='POST':
        mongodbform=MongodbLogStreamForm(request.POST)
        if mongodbform.is_valid():
            mongodbform.save()
            return redirect('logsources')
        
    else:
        mongodbform=MongodbLogStreamForm()
    context={'mongodbform':mongodbform}        
    return render(request,'baseapp/logingestion/applicationlogs/databases/mongodb/mongodb.html',context)



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
# def stream_windows_host_logs(request):
#     if request.method == 'POST':    
#         log_source_form = WindowsLogSourceForm(request.POST) 
#         if log_source_form.is_valid():
#             log_source = log_source_form.save(commit=False)
#             log_source.save()
#             log_source_form.save_m2m() 
#             return redirect('streamsyslogs')

#     else:
#         log_source_form = WindowsLogSourceForm()

#     context = {
#         'log_source_form': log_source_form,
#     }
#     return render(request, 'baseapp/logingestion/systemlogs/windows/windows.html', context)

 

def windowslogfilestreams(request):
    if request.method=='POST':
        logfileform=WindowsFileLogSourceForm(request.POST)
        if logfileform.is_valid():
            logfileform=logfileform.save()
            return redirect('streamlogfiles')
    else: 
        logfileform=WindowsFileLogSourceForm() 
    context={'logfileform':logfileform}
    return render(request,'baseapp/logingestion/systemlogs/windows/logfilestreamform.html',context)

def windowsperformancelogs(request):
    if request.method == 'POST':
        print(request.POST)  # Print the submitted data to check if performance_metrics is included
        logperf = WindowsPerfLogsForm(request.POST)
        if logperf.is_valid():
            instance = logperf.save(commit=False)            
            instance.save()            
            performance_metrics_ids = logperf.cleaned_data['performance_metrics']            
            performance_metrics = WindowsPerformanceMetric.objects.filter(pk__in=performance_metrics_ids)            
            instance.performance_metrics.set(performance_metrics)            
            instance.save()
            return redirect('collectperflogs')
        else:
            print(logperf.errors)  # Print form errors to see if there's an issue
    else:
        logperf = WindowsPerfLogsForm()
    context = {'logperf': logperf}
    return render(request, 'baseapp/logingestion/systemlogs/windows/perfform.html', context)



# def activedirectoryform(request):
#     if request.method == 'POST': 
#         activedirectoryform = WindowsActiveDirectoryLogSourceForm(request.POST)
#         if activedirectoryform.is_valid():
#             activedirectoryform.save()
#             return redirect('activedirectorylogs') 
#     else:
#         activedirectoryform = WindowsActiveDirectoryLogSourceForm()
    
#     context = {'activedirectoryform': activedirectoryform}
#     return render(request, 'baseapp/logingestion/systemlogs/windows/activedirectoryform.html', context)


def fileuploadform(request):
    context={}
    return render(request, 'baseapp/logingestion/systemlogs/windows/logfileupload.html', context)


#WINDOWS FORMS END

#====================LINUX FORMS START============================

# def stream_linux_host_logs(request):
#     if request.method=='POST':
#         log_source_form=LinuxLogSourceForm(request.POST)
#         if log_source_form.is_valid():
#             log_source_form=log_source_form.save()
#             return redirect('lin_streamsyslogs')
        
#         else:
#             print(log_source_form.errors)
        
#     else: 
#         log_source_form=LinuxLogSourceForm() 

#     context={
#         'log_source_form':log_source_form,
        
#         }
#     return render(request,'baseapp/logingestion/systemlogs/linux/stream_linux_logsform.html',context)

 
def linuxlogfilestreams(request):
    if request.method == 'POST':
        logfileform = LinuxFileLogSourceForm(request.POST)
        if logfileform.is_valid():
            log_source = logfileform.save(commit=False)
            log_source.save()
            logfileform.save_m2m()
            return redirect('lin_streamlogfiles')
    else:
        logfileform = LinuxFileLogSourceForm()
    
    
    all_log_types = LinuxLogType.objects.all()
    
    selected_log_type_ids = logfileform.instance.log_type.values_list('id', flat=True) if logfileform.instance.pk else []

    context = {
        'logfileform': logfileform,
        'selected_log_type_ids': selected_log_type_ids,
        'all_log_types': all_log_types
    }
    
    return render(request, 'baseapp/logingestion/systemlogs/linux/logfilestreamform.html', context)



def linuxperformancelogs(request):
    if request.method=='POST': 
        logperf=LinuxPerfLogsForm(request.POST)
        if logperf.is_valid():
            logperf=logperf.save()
            return redirect('lin_collectperflogs')
        
        else:
            print(logperf.errors)
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

# def stream_mac_host_logs(request):
#     if request.method=='POST':
#         log_source_form=MacLogSourceForm(request.POST)
#         if log_source_form.is_valid():
#             log_source_form=log_source_form.save()
#             return redirect('logsources')
        
#     else: 
#         log_source_form=MacLogSourceForm() 
#     context={
#         'log_source_form':log_source_form,
        
#         }
#     return render(request,'baseapp/logingestion/systemlogs/macos/stream_mac_logsform.html',context)


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

#===========================INSTRUCTIONS START==================================
#syslogs instructions start

    #windows
def win_streamsyslogs(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/inst-streamsyslogs.html',context)

def win_streamlogfiles(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/inst-streamlogfiles.html',context)

def win_collectperflogs(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/inst-perflogs.html',context)

def activedirectorylogs(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/windows/inst-activedirectorylogs.html',context)

    #linux
def lin_streamsyslogs(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/linux/inst-streamsyslogs.html',context)

def lin_streamlogfiles(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/linux/inst-streamlogfiles.html',context)

def lin_collectperflogs(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/linux/inst-perflogs.html',context)

def ldaplogs(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/linux/inst-ldaplogs.html',context)

#syslogs instructions end


#=========================INSTRUCTIONS START==================================


#===========================APPLICATION LOGS START===============================
    #webserver



def application_webserver_form(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverform.html',context)


def webserver_collection_options(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/collectionopts.html',context)

def logstreamingwizard(request):
    webservers = WebServer.objects.all()
    context={'webservers':webservers}
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
    # webservers = WebServer.objects.all()
    if request.method=='POST':
        apacheform=ApacheserverLogStreamForm(request.POST)
        if apacheform.is_valid():
            apacheform.save()
            return redirect('logsources')
        else:
            print(apacheform.errors)
        
    else:
        apacheform=ApacheserverLogStreamForm()
    context={
        'apacheform':apacheform,
        # 'webservers':webservers
        }
    return render(request,'baseapp/logingestion/applicationlogs/webservers/apache/apachestream.html',context)

def apacheserverlogfilestream(request):
    if request.method=='POST':
        apachefileform=ApacheserverLogFileStreamForm(request.POST) 
        if apachefileform.is_valid():
            apachefileform.save()
            return redirect('logsources')
        else:
            print(apachefileform.errors)        
        
    else:
        apachefileform=ApacheserverLogFileStreamForm()
    context={'apachefileform':apachefileform}
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


# def nginxserverlogstream(request):
#     if request.method=='POST':
#         nginxform=NginxserverLogStreamForm(request.POST)
#         if nginxform.is_valid():
#             nginxform.save()
#             return redirect('logsources')
        
#     else:
#         nginxform=NginxserverLogStreamForm()
#     context={'nginxform':nginxform}
#     return render(request,'baseapp/logingestion/applicationlogs/webservers/nginx/nginxstream.html',context)

def nginxserverlogfilestream(request):
    if request.method=='POST':
        nginxform=NginxserverLogFileStreamForm(request.POST) 
        if nginxform.is_valid():
            nginxform.save()
            return redirect('logsources')
        
    else: 
        nginxform=NginxserverLogFileStreamForm()
    context={'nginxform':nginxform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/nginx/nginxfilestream.html',context)


def nginxserverperflogs(request):
    if request.method=='POST':
        nginxform=NginxserverPerfLogForm(request.POST)
        if nginxform.is_valid():
            nginxform.save()
            return redirect('logsources')
        
    else:
        nginxform=NginxserverPerfLogForm()
    context={'nginxform':nginxform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/nginx/nginxperflogs.html',context)

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


# def iisserverlogstream(request):
#     if request.method=='POST':
#         iisform=IISserverLogStreamForm(request.POST)
#         if iisform.is_valid():
#             iisform.save()
#             return redirect('logsources')
        
#     else:
#         iisform=IISserverLogStreamForm()
#     context={'iisform':iisform}
#     return render(request,'baseapp/logingestion/applicationlogs/webservers/iis/iisstream.html',context)

def iisserverlogfilestream(request):
    if request.method=='POST':
        iisform=IISserverLogFileStreamForm(request.POST) 
        if iisform.is_valid():
            iisform.save()
            return redirect('logsources')
        
    else:
        iisform=NginxserverLogFileStreamForm()
    context={'iisform':iisform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/iis/iisfilestream.html',context)


def iisserverperflogs(request):
    if request.method=='POST':
        iisform=IISserverPerfLogForm(request.POST)
        if iisform.is_valid():
            iisform.save()
            return redirect('logsources')
        
    else:
        iisform=IISserverPerfLogForm()
    context={'iisform':iisform}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/iis/iisperflogs.html',context)

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

#MYSQL
# def mysqllogstream(request):
#     if request.method=='POST':
#         mysqlform=MysqlLogStreamForm(request.POST)
#         if mysqlform.is_valid():
#             mysqlform.save()
#             return redirect('logsources')
        
#     else:
#         mysqlform=MysqlLogStreamForm()
#     context={'mysqlform':mysqlform}
#     return render(request,'baseapp/logingestion/applicationlogs/databases/mysql/mysqlstream.html',context)

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
# def postgreslogstream(request):
#     if request.method=='POST':
#         postgresform=PostgresLogStreamForm(request.POST)
#         if postgresform.is_valid():
#             postgresform.save()
#             return redirect('logsources')
        
#     else:
#         postgresform=PostgresLogStreamForm()
#     context={'postgresform':postgresform}
#     return render(request,'baseapp/logingestion/applicationlogs/databases/postgres/postgresstream.html',context)
 
def postgreslogfilestream(request):
    if request.method=='POST':
        postgresform=PostgresLogFileStreamForm(request.POST) 
        if postgresform.is_valid():
            postgresform.save()
            return redirect('logsources')
        
    else:
        postgresform=PostgresLogFileStreamForm()
    context={'postgresform':postgresform}
    return render(request,'baseapp/logingestion/applicationlogs/databases/postgres/postresfilestream.html',context)


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
# def mongodblogstream(request):
#     if request.method=='POST':
#         mongodbform=MongodbLogStreamForm(request.POST)
#         if mongodbform.is_valid():
#             mongodbform.save()
#             return redirect('logsources')
        
#     else:
#         mongodbform=MongodbLogStreamForm()
#     context={'mongodbform':mongodbform}
#     return render(request,'baseapp/logingestion/applicationlogs/databases/mongodb/mongodbstream.html',context)

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


#=========================================DATABASE FORMS END=========================================================



def alert_history(request): 

    critical_alerts = WindowsAlert.objects.filter(entry_type='Critical')
    high_alerts = WindowsAlert.objects.filter(entry_type__in=['Error', 'FailureAudit', 'Failure Audit'])
    medium_alerts = WindowsAlert.objects.filter(entry_type='Warning')
    low_alerts = WindowsAlert.objects.filter(entry_type__in=['Success Audit', 'SuccessAudit', 'Information'])


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






