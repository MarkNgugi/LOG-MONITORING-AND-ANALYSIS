from itertools import chain
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from .forms import *
from .models import *
from django.urls import reverse
from .tasks import *
 

def log_history(request):
    logs = LogEntry.objects.filter(user=request.user).order_by('-TimeCreated')
    context = {'logs': logs}
    return render(request, 'baseapp/logs/logs.html', context)


#LOG SOURCES
def home(request):
    context={'user':request.user}
    return render(request,'baseapp/home.html',context)

def logsources(request, os_type=None, server_type=None, db_type=None,):    
    # Initialize log sources
    system_logs = []
    webserver_logs = []
    database_logs = []    

    # Querysets for system logs
    log_sources_windows = list(chain(
        WindowsLogFile.objects.filter(user=request.user),        
    ))

    log_sources_linux = list(chain(
        LinuxLogFile.objects.all(),

    ))

    log_sources_macos = list(chain(
        MacLogFile.objects.all(),
    ))

    # Querysets for web server logs
    apache_logs = list(chain(
        ApacheLogFile.objects.all(),

    ))

    nginx_logs = list(chain(
        NginxLogFile.objects.all(),

    ))

    iis_logs = list(chain(
        IISLogFile.objects.all(),

    ))

    # Querysets for database logs
    mysql_logs = list(chain(
        MysqlLogFile.objects.all(),

    ))

    postgres_logs = list(chain(
        PostgresLogFile.objects.all(),

    ))

    mongodb_logs = list(chain(
        MongoLogFile.objects.all(),

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
        'log_sources': system_logs,
        'webserver_logs': webserver_logs,
        'database_logs': database_logs,        
        'os_type': os_type,
        'server_type': server_type,
        'db_type': db_type,        
    }

    return render(request, 'baseapp/logsources/logsources.html', context)

 
 


#LOG INGESTION 
def system_os_types(request):  
    context={}
    return render(request,'baseapp/logingestion/OSpage.html',context)

@login_required
def windows_log_upload(request):
    if request.method == 'POST':
        form = WindowsLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save(commit=False)
            uploaded_log.user = request.user  
            uploaded_log.save()  
            process_uploaded_windows_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = WindowsLogUploadForm()
        
    return render(request, 'baseapp/logingestion/systemlogs/windows/windows.html', {'form': form})

def windowsAD_log_upload(request):
    if request.method == 'POST':
        form = WindowsADLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_AD_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = WindowsADLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/systemlogs/activedirectory/activedirectory.html', context)
    

def linux_log_upload(request):
    if request.method == 'POST':
        form = LinuxLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_linux_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = LinuxLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/systemlogs/linux/linux.html', context)


def mac_log_upload(request):
    if request.method == 'POST':
        form = MacLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_mac_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = MacLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/systemlogs/macos/macos.html', context)

 
def apache_log_upload(request):
    if request.method == 'POST':
        form = ApacheLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_apache_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = ApacheLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/applicationlogs/webservers/apache/apache.html', context)

def nginx_log_upload(request):
    if request.method == 'POST':
        form = NginxLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_nginx_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = NginxLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/applicationlogs/webservers/nginx/nginx.html', context)

def iis_log_upload(request):
    if request.method == 'POST':
        form = IISLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_iis_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = IISLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/applicationlogs/webservers/iis/iis.html', context)



def mysql_log_upload(request):
    if request.method == 'POST':
        form = MysqlLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_mysql_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = MysqlLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/applicationlogs/databases/mysql/mysql.html', context)

def postgres_log_upload(request):
    if request.method == 'POST':
        form = PostgresLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_postgres_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = PostgresLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/applicationlogs/databases/postgres/postgresql.html', context)

def mongo_log_upload(request):
    if request.method == 'POST':
        form = MongoLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_mongo_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = MongoLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/applicationlogs/databases/mongodb/mongodb.html', context)





#=========================================DATABASE FORMS END=========================================================


#SEARCH

def search(request):
    context={}
    return render(request,'baseapp/search/search.html',context)

#STREAMS

def logstreams(request):
    context={}
    return render(request,'baseapp/logstreams/logstreams.html',context)

#ANOMALIES

def alert_history(request): 

    alerts = Alert.objects.filter(user=request.user)
    context = {'alerts': alerts,}

    return render(request, 'baseapp/alerts/alerts.html', context)

def alertdetail(request,id):
    alert = Alert.objects.filter(id=id)
    context={'alert':alert}

    return render(request,'baseapp/alerts/alertdetails.html',context)

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






