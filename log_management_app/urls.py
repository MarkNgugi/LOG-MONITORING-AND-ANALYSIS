from django.urls import path
from . import views
from .views import *

from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

urlpatterns = [    

    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('home/',views.home,name='home'),    
    path('search/',views.logs_search,name='search'),    

 
#LOG SOURCES

    path('log-sources/', views.logsources, name='logsources'),
    path('log-sources/os/<str:os_type>/', views.logsources, name='logsources_os'),
    path('log-sources/os/<str:os_type>/<str:log_source_name>/<str:hostname>/', views.sourceinfo, name='sourceinfo'),
    path('log-sources/server/<str:server_type>/', views.logsources, name='logsources_server'),
    path('log-sources/db/<str:db_type>/', views.logsources, name='logsources_db'),    

      
    path('home/system-logs/os-types/',views.system_os_types,name='system_os_types'),

    path('home/system-logs/os-types/windows-explorer/',views.windows_log_upload,name='windows'),
    path('home/system-logs/os-types/windows-explorer/',views.windowsAD_log_upload,name='windowsAD'),
    path('home/system-logs/os-types/linux-explorer/',views.linux_log_upload,name='linux'),
    path('home/system-logs/linuxmetrics/',views.linux_info,name='linuxinfo'),
    
    path('home/system-logs/os-types/ad-explorer/',views.windowsAD_log_upload,name='activedirectory'),

    
    path('home/alert-detail/<int:id>/',views.alertdetail,name='alertdetail'),

    path('home/reports/',views.reportspage,name='reportspage'),

    path('alerts-history/',views.alert_history,name='alert_history'),
    path('alerts/delete/<int:alert_id>/', views.delete_alert, name='delete_alert'),

    path('api/linux/logs/', views.LinuxLogView.as_view(), name='linux-log-upload'),
    

    path('api/get-user-id/', views.get_user_id, name='get_user_id'),

    
]