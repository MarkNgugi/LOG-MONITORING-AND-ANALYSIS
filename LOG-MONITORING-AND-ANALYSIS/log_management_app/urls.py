from django.urls import path
from . import views

urlpatterns=[

    path('home/',views.home,name='home'),

    #LOG SOURCES
    #system log source 
    path('home/logs-source/system/windows/', views.system_windows_logs, name='system_windows_logs'),
    path('home/logs-source/system/windowsform/', views.system_windows_form, name='system_windows_form'),

    #application log sources
    path('home/logs-source/application/webserver/', views.application_webserver_logs, name='application_webserver_logs'),
    path('home/logs-source/application/webserverform/', views.application_webserver_form, name='application_webserver_form'),

    #LOG STREAMS
    path('home/log-streams/', views.logstreams, name='logstreams'),
    

]