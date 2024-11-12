from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(WindowsLogFile)
admin.site.register(WindowsADLogFile)
admin.site.register(LogEntry)
# admin.site.register(Anomaly)


admin.site.register(LinuxLogFile)

admin.site.register(MacLogFile) 


admin.site.register(WebServer)
admin.site.register(ApacheserverLogStream)
admin.site.register(ApacheserverLogFileStream)
admin.site.register(ApacheserverPerfLogs)

admin.site.register(NginxserverLogStream)
admin.site.register(NginxserverLogFileStream)
admin.site.register(NginxserverPerfLogs)

admin.site.register(IISserverLogStream)
admin.site.register(IISserverLogFileStream)
admin.site.register(IISserverPerfLogs)

admin.site.register(TomcatserverLogStream)
admin.site.register(TomcatserverLogFileStream)
admin.site.register(TomcatserverPerfLogs)

admin.site.register(LighttpdserverLogStream)
admin.site.register(LighttpdserverLogFileStream)
admin.site.register(LighttpdserverPerfLogs)

admin.site.register(MysqlLogStream)
admin.site.register(MysqlLogFileStream)
admin.site.register(MysqlPerfLogs)

admin.site.register(PostgresLogStream)
admin.site.register(PostgresLogFileStream)
admin.site.register(PostgresPerfLogs)

admin.site.register(MongodbLogStream)
admin.site.register(MongodbLogFileStream)
admin.site.register(MongodbPerfLogs)

admin.site.register(WindowsAlert)











