from django.urls import path
from . import views

urlpatterns=[

    #ALERTS
    path('alerts-config-list/',views.alertconfig,name='alertconfig'),
    path('new-alert-rule/',views.alertconfigpage,name='alertconfigpage'),
    # path('alerts-history/',views.alert_history,name='alert_history'),


    path('scheduled-reports/',views.scheduledreports,name='scheduledreports'), 
    path('add-scheduled-reports/',views.addscheduledreport,name='addscheduledreport'),
    path('custom-alerts/',views.customalerts,name='customalerts'),
    path('not-settings/',views.notification_settings,name='notification_settings'),
]