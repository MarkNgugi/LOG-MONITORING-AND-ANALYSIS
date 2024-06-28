from django.urls import path
from . import views

urlpatterns=[

    path('home/',views.home,name='home'),

    #LOG SOURCES
    #system log source
    path('logs/system/windows/', views.system_windows_logs, name='system_windows_logs'),

    #application log sources
]