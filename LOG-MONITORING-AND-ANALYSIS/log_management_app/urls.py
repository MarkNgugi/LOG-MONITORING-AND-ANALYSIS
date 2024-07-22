from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.webserverfileupload, name='upload_file'),

    path('home/',views.home,name='home'),

    #LOG SOURCES
    #SYSTEM LOGS
        #Windows urls
    path('home/system-logs/os-types/',views.system_os_types,name='system_os_types'),
    path('home/logs-source/system/windows/', views.system_windows_logs_table, name='system_windows_logs_table'),
    path('home/collection-options/',views.system_collection_options,name='system_collection_options'),
   
    #collection forms
    path('home/logs-source/system/windows/streamlogs/', views.stream_windows_host_logs, name='stream_windows_host_logs'),
    path('home/logfilestreams/',views.logfilestreams,name='logfilestreams'),
    path('home/performancelogs/',views.performancelogs,name='performancelogs'),
    path('home/activedirectory/',views.activedirectoryform,name='activedirectoryform'),

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
    path('home2/log-streams',views.home,)
    

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)