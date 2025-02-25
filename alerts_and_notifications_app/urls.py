from django.urls import path
from . import views

urlpatterns=[

    #ALERTS
    path('alerts-config-list/',views.alertconfig,name='alertconfig'),
    path('new-alert-rule/',views.alertconfigpage,name='alertconfigpage'),
    # path('alerts-history/',views.alert_history,name='alert_history'),
    path('alerting/contact-points/',views.contactpoint,name='contactpoint'),
    path('alerting/notification-policies/',views.notification_policy,name='notification-policies'),



    path('generated-reports/',views.scheduledreports,name='gen_reports'), 
    path('add-reports/',views.addscheduledreport,name='addreport'),
    path('report/<int:report_id>/', views.report_detail, name='report_detail'),
    path('addscheduledreport/', views.addscheduledreport, name='addscheduledreport'),
    path('report/<int:report_id>/', views.report_detail, name='report_detail'),

    path('custom-alerts/',views.customalerts,name='customalerts'), 
    path('not-settings/',views.notification_settings,name='notification_settings'),
] 