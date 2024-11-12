from django.urls import path
from . import views


urlpatterns = [    

    path('home/',views.home,name='home'),


#LOG SOURCES

    path('log-sources/', views.logsources, name='logsources'),
    path('log-sources/os/<str:os_type>/', views.logsources, name='logsources_os'),
    path('log-sources/server/<str:server_type>/', views.logsources, name='logsources_server'),
    path('log-sources/db/<str:db_type>/', views.logsources, name='logsources_db'),
    path('log-sources/network/<str:network_type>/', views.logsources, name='logsources_network'),

    

#SEARCH

    path('home/search',views.search,name='search'),

#LOG INGESTION 

    #SYSTEM LOGS        
    path('home/system-logs/os-types/',views.system_os_types,name='system_os_types'),

    path('home/system-logs/os-types/windows-explorer/',views.windows_log_upload,name='windows'),
    path('home/system-logs/os-types/linux-explorer/',views.linux_log_upload,name='linux'),
    path('home/system-logs/os-types/macos-explorer/',views.mac_log_upload,name='macos'),
    path('home/system-logs/os-types/ad-explorer/',views.windowsAD_log_upload,name='activedirectory'),

    path('home/system-logs/os-types/apache-explorer/',views.apache_log_upload,name='apache'),
    path('home/system-logs/os-types/nginx-explorer/',views.nginx_log_upload,name='nginx'),
    path('home/system-logs/os-types/iis-explorer/',views.iis_log_upload,name='iis'),

    path('home/system-logs/os-types/mysql-explorer/',views.mysql,name='mysql'),
    path('home/system-logs/os-types/postgresql-explorer/',views.postgresql,name='postgresql'),
    path('home/system-logs/os-types/mongodb-explorer/',views.mongodb,name='mongodb'),    


        #collection forms
    # path('home/webserver/fileupload/',views.webserverfileupload,name='webserverfileupload'),
    # path('home/db/mysql',views.mysqllogstream,name='mysqllogstream'),
    path('home/db/mysqlfile',views.mysqllogfilestream,name='mysqllogfilestream'),
    path('home/db/mysqlperf',views.mysqlperflogs,name='mysqlperflogs'),

 
    # path('home/db/postgres',views.postgreslogstream,name='postgreslogstream'),
    path('home/db/postgresfile',views.postgreslogfilestream,name='postgreslogfilestream'),
    path('home/db/postgresperf',views.postgresperflogs,name='postgresperflogs'),
 
    # path('home/db/mongo',views.mongodblogstream,name='mongodblogstream'),
    path('home/db/mongofile',views.mongodblogfilestream,name='mongodblogfilestream'),
    path('home/db/mongoperf',views.mongodbperflogs,name='mongodbperflogs'),

        #CACHING SYSTEMS

    path('home/cachingsystems-types/',views.cachingsystems_types,name='cachingsystems_types'),


    #LOG STREAMS
    path('home/log-streams/', views.logstreams, name='logstreams'),    


    #ANOMALIES
    path('home/anomalies/',views.anomaliespage,name='anomaliespage'),
    path('home/anomalydetail/',views.anomalydetail,name='anomalydetail'),


    #REPORTS 
    path('home/reports/',views.reportspage,name='reportspage'),


    #INCIDENT RESPONSE 
    path('home/incidences/',views.incidences,name='incidences'),
    path('home/incidentresponse/',views.incidentresponse,name='incidentresponse'),

    #LOG RETENTION
    path('home/logretention/',views.logretention,name='logretention'),


    path('alerts-history/',views.alert_history,name='alert_history'),

    
]