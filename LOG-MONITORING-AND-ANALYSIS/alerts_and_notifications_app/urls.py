from django.urls import path
from . import views

urlpatterns=[

    #ALERTS
    path('alerts-history/',views.alertspage,name='alertspage'),
]