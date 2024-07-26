from django.urls import path
from . import views

urlpatterns=[

    #ALERTS
    path('alerts-history/',views.alertspage,name='alertspage'),
    path('scheduled-reports/',views.scheduledreports,name='scheduledreports'), 
    path('add-scheduled-reports/',views.addscheduledreport,name='addscheduledreport'),
]