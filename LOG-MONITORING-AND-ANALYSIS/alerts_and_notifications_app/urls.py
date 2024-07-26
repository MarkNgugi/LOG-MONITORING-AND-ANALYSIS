from django.urls import path
from . import views

urlpatterns=[

    #ALERTS
    path('alerts-config/',views.alertconfig,name='alertconfig'),
    path('alerts-history/',views.alertspage,name='alertspage'),
    path('scheduled-reports/',views.scheduledreports,name='scheduledreports'), 
    path('add-scheduled-reports/',views.addscheduledreport,name='addscheduledreport'),
    path('custom-alerts/',views.customalerts,name='customalerts'),
    path('not-settings/',views.notification_settings,name='notification_settings'),
]