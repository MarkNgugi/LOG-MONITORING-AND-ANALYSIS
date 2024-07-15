from django.urls import path
from . import views

urlpatterns=[

    path('home/',views.home,name='home'),

    #LOG SOURCES
    #system log source 
        #Windows urls
    path('home/system-logs/os-types/',views.system_os_types,name='system_os_types'),
    path('home/logsource/',views.add_log_source,name='add_log_source'),
    path('home/logs-source/system/windows/', views.system_windows_logs, name='system_windows_logs'),
    path('home/logs-source/system/windows/add-log-source-and-ingestion/', views.system_windows_logs_form, name='system_windows_logs_form'),
    path('home/ingestion-mtd/',views.ingestionmtd,name='ingestionmtd'),

    #application log sources
    path('home/logs-source/application/webserver/', views.application_webserver_logs, name='application_webserver_logs'),
    path('home/logs-source/application/webserverform/', views.application_webserver_form, name='application_webserver_form'),

    #LOG STREAMS
    path('home/log-streams/', views.logstreams, name='logstreams'),
    path('home2/log-streams',views.home,)
    

]