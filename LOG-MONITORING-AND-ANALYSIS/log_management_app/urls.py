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
        #Windows 
    path('home/system-logs/os-types/',views.system_os_types,name='system_os_types'),

    path('home/system-logs/os-types/windows-explorer/',views.windows,name='windows'),
    path('home/system-logs/os-types/linux-explorer/',views.linux,name='linux'),
    path('home/system-logs/os-types/macos-explorer/',views.macos,name='macos'),
    path('home/system-logs/os-types/ad-explorer/',views.windowsAD,name='activedirectory'),

    path('home/system-logs/os-types/apache-explorer/',views.apache,name='apache'),
    path('home/system-logs/os-types/nginx-explorer/',views.nginx,name='nginx'),
    path('home/system-logs/os-types/iis-explorer/',views.iis,name='iis'),

    path('home/system-logs/os-types/mysql-explorer/',views.mysql,name='mysql'),
    path('home/system-logs/os-types/postgresql-explorer/',views.postgresql,name='postgresql'),
    path('home/system-logs/os-types/mongodb-explorer/',views.mongodb,name='mongodb'),    



    path('home/windows/collection-options/',views.windows_collection_options,name='windows_collection_options'),
    path('home/unixlinux/collection-options/',views.linux_collection_options,name='linux_collection_options'),
    path('home/macos/unixlinux/collection-options/',views.macos_collection_options,name='macos_collection_options'),
   
        #windows collection forms
    # path('home/logs-source/system/windows/streamlogs/', views.stream_windows_host_logs, name='stream_windows_host_logs'),
    path('home/windows/logfilestreams/',views.windowslogfilestreams,name='windowslogfilestreams'),
    path('home/windows/performancelogs/',views.windowsperformancelogs,name='windowsperformancelogs'),
    # path('home/activedirectory/',views.activedirectoryform,name='activedirectoryform'),
    path('home/fileuploag/',views.fileuploadform,name='fileuploadform'),
 

        #linux collection forms 
    # path('home/linux/form/',views.stream_linux_host_logs,name='stream_linux_host_logs'),
    path('home/linux/logfilestreams/',views.linuxlogfilestreams,name='linuxlogfilestreams'),
    path('home/linux/performancelogs/',views.linuxperformancelogs,name='linuxperformancelogs'),
    path('home/ldap/',views.ldaplogs,name='ldaplogs'),    

        #macos collection forms
    # path('home/mac/form/',views.stream_mac_host_logs,name='stream_mac_host_logs'),
    path('home/mac/logfilestreams/',views.maclogfilestreams,name='maclogfilestreams'),
    path('home/mac/performancelogs/',views.macperformancelogs,name='macperformancelogs'),
    path('home/opendir/',views.opendirlogs,name='opendirlogs'), 




        #instructions
            #windows
    path('home/syslogs-instructions/',views.win_streamsyslogs,name='streamsyslogs'),
    path('home/syslogsfiles-instructions/',views.win_streamlogfiles,name='streamlogfiles'),
    path('home/performance-instructions/',views.win_collectperflogs,name='collectperflogs'),
    path('home/activedirectory-instructions/',views.activedirectorylogs,name='activedirectorylogs'),

            #linux
    path('home/linuxlogs-instructions/',views.lin_streamsyslogs,name='lin_streamsyslogs'),
    path('home/linuxlogsfiles-instructions/',views.lin_streamlogfiles,name='lin_streamlogfiles'),
    path('home/linuxperformance-instructions/',views.lin_collectperflogs,name='lin_collectperflogs'),
    # path('home/activedirectory-instructions/',views.ldaplogs,name='activedirectorylogs'),    






    #APPLICATION LOGS

        #WEBSERVERS

    path('home/webcollection-options/',views.webserver_collection_options,name='webserver_collection_options'), 

    path('home/webcollection-options/logstreaming/',views.logstreamingwizard,name='logstreamingwizard'),        
    path('home/webcollection-options/Logfilestreaming/',views.logfilestreamingwizard,name='logfilestreamingwizard'),  
    path('home/webcollection-options/perflogs/',views.perflogwizard,name='perflogwizard'),
    path('home/webcollection-options/fileupload/',views.logfileuploadwizard,name='logfileuploadwizard'),
    

    path('home/logs-source/application/webserverform/', views.application_webserver_form, name='application_webserver_form'),

    
    
    # path('home/webcollection-agent/',views.webserver_collection_agents,name='webserver_collection_agents'),
 
        #collection forms
    # path('home/webserver/fileupload/',views.webserverfileupload,name='webserverfileupload'),
    path('home/webserver/apache',views.apacheserverlogstream,name='apacheserverlogstream'),
    path('home/webserver/apachefile',views.apacheserverlogfilestream,name='apacheserverlogfilestream'),
    path('home/webserver/apacheperf',views.apacheserverperflogs,name='apacheserverperflogs'),

    path('home/webserver/nginx',views.nginxserverlogstream,name='nginxserverlogstream'),
    path('home/webserver/nginxfile',views.nginxserverlogfilestream,name='nginxserverlogfilestream'),
    path('home/webserver/nginxperf',views.nginxserverperflogs,name='nginxserverperflogs'),

    path('home/webserver/iis',views.iisserverlogstream,name='iisserverlogstream'),
    path('home/webserver/iisfile',views.iisserverlogfilestream,name='iisserverlogfilestream'),
    path('home/webserver/iisperf',views.iisserverperflogs,name='iisserverperflogs'),

    path('home/webserver/tomcat',views.tomcatserverlogstream,name='tomcatserverlogstream'),
    path('home/webserver/tomcatfile',views.tomcatserverlogfilestream,name='tomcatserverlogfilestream'),
    path('home/webserver/tomcatperf',views.tomcatserverperflogs,name='tomcatserverperflogs'),


    path('home/webserver/lighttpd',views.lighttpdserverlogstream,name='lighttpdserverlogstream'),
    path('home/webserver/lighttpdfile',views.lighttpdserverlogfilestream,name='lighttpdserverlogfilestream'),
    path('home/webserver/lighttpdperf',views.lighttpdserverperflogs,name='lighttpdserverperflogs'),    

 


        #DATABASES
    path('home/databsecollection-options/',views.database_collection_options,name='database_collection_options'), 

    path('home/databaecollection-options/db/logstreaming/',views.dblogstreamingwizard,name='dblogstreamingwizard'),        
    path('home/databasecollection-options/db/Logfilestreaming/',views.dblogfilestreamingwizard,name='dblogfilestreamingwizard'),  
    path('home/databasecollection-options/db/perflogs/',views.dbperflogwizard,name='dbperflogwizard'),
    path('home/databasecollection-options/db/fileupload/',views.dblogfileuploadwizard,name='dblogfileuploadwizard'), 


        #collection forms
    # path('home/webserver/fileupload/',views.webserverfileupload,name='webserverfileupload'),
    path('home/db/mysql',views.mysqllogstream,name='mysqllogstream'),
    path('home/db/mysqlfile',views.mysqllogfilestream,name='mysqllogfilestream'),
    path('home/db/mysqlperf',views.mysqlperflogs,name='mysqlperflogs'),


    path('home/db/postgres',views.postgreslogstream,name='postgreslogstream'),
    path('home/db/postgresfile',views.postgreslogfilestream,name='postgreslogfilestream'),
    path('home/db/postgresperf',views.postgresperflogs,name='postgresperflogs'),
 
    path('home/db/mongo',views.mongodblogstream,name='mongodblogstream'),
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