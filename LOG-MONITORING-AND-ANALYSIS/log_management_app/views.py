from itertools import chain
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render,redirect
from .forms import *
from .models import *
from django.urls import reverse
from .tasks import *
 

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
        WindowsLogFile.objects.all(),        
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
    return render(request,'baseapp/logingestion/OSpage.html',context)

def windows_log_upload(request):
    if request.method == 'POST':
        form = WindowsLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_windows_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('home')
    else:
        form = WindowsLogUploadForm()
    return render(request, 'baseapp/logingestion/systemlogs/windows/windows.html', {'form': form})

def windowsAD_log_upload(request):
    if request.method == 'POST':
        form = WindowsADLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_AD_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('home')
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
            return redirect('home')
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
            return redirect('home')
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
            return redirect('home')
    else:
        form = ApacheLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/applicationlogs/webservers/apache/apache.html', context)

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






#===========================APPLICATION LOGS START===============================
    #webserver



def application_webserver_form(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/webserverform.html',context)


def webserver_collection_options(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/collectionopts.html',context)



def logfilestreamingwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/logfilestreamwizard.html',context)

def perflogwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/perflogsstreamwizard.html',context)

def logfileuploadwizard(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/logfileuploadwizard.html',context)




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






