from django.urls import path
from . import views
from .views import SecurityLogView

urlpatterns = [

    path('api/logs/', views.SecurityLogView, name='security_logs'),
    path('upload/', views.webserverfileupload, name='upload_file'),

    path('home/',views.home,name='home'),

#LOG SOURCES

    path('home/log-sources',views.logsources,name='logsources'),

#SEARCH

    path('home/search',views.search,name='search'),

#LOG INGESTION 

    #SYSTEM LOGS
        #Windows 
    path('home/system-logs/os-types/',views.system_os_types,name='system_os_types'),

    path('home/windows/collection-options/',views.windows_collection_options,name='windows_collection_options'),
    path('home/unixlinux/collection-options/',views.linux_collection_options,name='linux_collection_options'),
    path('home/macos/unixlinux/collection-options/',views.macos_collection_options,name='macos_collection_options'),
   
        #windows collection forms
    path('home/logs-source/system/windows/streamlogs/', views.stream_windows_host_logs, name='stream_windows_host_logs'),
    path('home/windows/logfilestreams/',views.windowslogfilestreams,name='windowslogfilestreams'),
    path('home/windows/performancelogs/',views.windowsperformancelogs,name='windowsperformancelogs'),
    path('home/activedirectory/',views.activedirectoryform,name='activedirectoryform'),


        #linux collection forms
    path('home/linux/form/',views.stream_linux_host_logs,name='stream_linux_host_logs'),
    path('home/linux/logfilestreams/',views.linuxlogfilestreams,name='linuxlogfilestreams'),
    path('home/linux/performancelogs/',views.linuxperformancelogs,name='linuxperformancelogs'),
    path('home/ldap/',views.ldaplogs,name='ldaplogs'),    




        #instructions
    path('home/syslogs-instructions/',views.streamsyslogs,name='streamsyslogs'),
    path('home/syslogsfiles-instructions/',views.streamlogfiles,name='streamlogfiles'),
    path('home/performance-instructions/',views.collectperflogs,name='collectperflogs'),
    path('home/activedirectory-instructions/',views.activedirectorylogs,name='activedirectorylogs'),






    #APPLICATION LOGS

        #WEBSERVERS
    path('home/logs-source/application/webserver/', views.application_webserver_logs, name='application_webserver_logs'),
    path('home/logs-source/application/webserverform/', views.application_webserver_form, name='application_webserver_form'),

    path('home/webserver-types/',views.web_server_types,name='web_server_types'), 
    path('home/webcollection-options/',views.webserver_collection_options,name='webserver_collection_options'),
    path('home/webcollection-agent/',views.webserver_collection_agents,name='webserver_collection_agents'),

        #collection forms
    path('home/webserver/fileupload/',views.webserverfileupload,name='webserverfileupload'),


        #DATABASES
    path('home/database-types/',views.database_types,name='database_types'), 


        #CACHING SYSTEMS

    path('home/cachingsystems-types/',views.cachingsystems_types,name='cachingsystems_types'),


    #LOG STREAMS
    path('home/log-streams/', views.logstreams, name='logstreams'),    


    #ANOMALIES
    path('home/anomalies/',views.anomaliespage,name='anomaliespage'),
    path('home/anomalydetail/',views.anomalydetail,name='anomalydetail'),


    #REPORTS 
    path('home/reports/',views.reportspage,name='reportspage'),


    #INCIDENT RESPONSE 
    path('home/incidences/',views.incidences,name='incidences'),
    path('home/incidentresponse/',views.incidentresponse,name='incidentresponse'),

    #LOG RETENTION
    path('home/logretention/',views.logretention,name='logretention'),


]