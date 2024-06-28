from django.urls import path
from . import views

urlpatterns=[

    path('home/',views.home,name='home'),

    #LOG SOURCES
    #system log source 
    path('logs-source/system/windows/', views.system_windows_logs, name='system_windows_logs'),
    path('logs-source/system/windowsform/', views.system_windows_logs_form, name='system_windows_logs_form'),

    #application log sources

]