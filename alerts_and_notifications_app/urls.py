from django.urls import path
from . import views

urlpatterns=[

    path('generated-reports/',views.scheduledreports,name='gen_reports'), 
    path('add-reports/',views.addscheduledreport,name='addreport'),
    path('report/<int:report_id>/', views.report_detail, name='report_detail'),
    path('addscheduledreport/', views.addscheduledreport, name='addscheduledreport'),
    path('report/<int:report_id>/', views.report_detail, name='report_detail'),

] 