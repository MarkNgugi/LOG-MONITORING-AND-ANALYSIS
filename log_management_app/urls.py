from django.urls import path
from . import views
from .views import *

from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

urlpatterns = [    

    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Custom Token Generation Endpoint
    # path('api/generate-token/', GenerateTokenView.as_view(), name='generate_token'),
    path('api/generate-token/', generate_token, name='generate_token'),
    path('execute/<str:filename>', ExecuteScriptView.as_view(), name='execute-script'),

    path('home/',views.home,name='home'),    

 
#LOG SOURCES

    path('log-sources/', views.logsources, name='logsources'),
    path('log-sources/os/<str:os_type>/', views.logsources, name='logsources_os'),
    path('log-sources/os/<str:os_type>/<str:log_source_name>/<str:hostname>/', views.sourceinfo, name='sourceinfo'),
    path('log-sources/server/<str:server_type>/', views.logsources, name='logsources_server'),
    path('log-sources/db/<str:db_type>/', views.logsources, name='logsources_db'),    

#SEARCH
  
    path('home/search',views.search,name='search'),

#LOG INGESTION 
      
    path('home/system-logs/os-types/',views.system_os_types,name='system_os_types'),

    path('home/system-logs/os-types/windows-explorer/',views.windows_log_upload,name='windows'),
    path('home/system-logs/os-types/windows-explorer/',views.windowsAD_log_upload,name='windowsAD'),
    path('home/system-logs/os-types/linux-explorer/',views.linux_log_upload,name='linux'),
    path('home/system-logs/linuxmetrics/',views.linux_info,name='linuxinfo'),
    
    path('home/system-logs/os-types/ad-explorer/',views.windowsAD_log_upload,name='activedirectory'),
    
    path('home/system-logs/os-types/apache-explorer/',views.apache_log_upload,name='apache'),
    path('home/webserver-logs/apachemetrics/',views.apache_info,name='apacheinfo'),
    

    path('home/system-logs/os-types/nginx-explorer/',views.nginx_log_upload,name='nginx'),
    path('home/webserver-logs/nginxmetrics/',views.nginx_info,name='nginxinfo'),

    path('home/system-logs/os-types/iis-explorer/',views.iis_log_upload,name='iis'),

    # path('home/system-logs/os-types/mysql-explorer/',views.mysql_log_upload,name='mysql'),
    # path('home/system-logs/os-types/postgresql-explorer/',views.postgres_log_upload,name='postgresql'),
    # path('home/system-logs/os-types/mongodb-explorer/',views.mongo_log_upload,name='mongodb'),    



    #LOG STREAMS
    path('home/log-streams/', views.logstreams, name='logstreams'),    


    #ANOMALIES
    
    path('home/alert-detail/<int:id>/',views.alertdetail,name='alertdetail'),


    #REPORTS 
    path('home/reports/',views.reportspage,name='reportspage'),


    #INCIDENT RESPONSE 
    path('home/incidences/',views.incidences,name='incidences'),
    path('home/incidentresponse/',views.incidentresponse,name='incidentresponse'),

    #LOG RETENTION
    path('home/logretention/',views.logretention,name='logretention'),


    path('alerts-history/',views.alert_history,name='alert_history'),

    path('api/linux/logs/', views.LinuxLogView.as_view(), name='linux-log-upload'),
    path('api/apache/logs/', views.ApacheLogView.as_view(), name='apache-log-upload'),
    path('api/mysql/logs/', views.MysqlLogView.as_view(), name='mysql-log-upload'),
    path('api/redis/logs/', RedisLogView.as_view(), name='redis-logs'),
    

    path('api/get-user-id/', views.get_user_id, name='get_user_id'),

    
]