from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(WindowsLogFile)
admin.site.register(WindowsADLogFile)
admin.site.register(LogEntry)
# admin.site.register(Anomaly)


admin.site.register(LinuxLogFile)
admin.site.register(MacLogFile) 

admin.site.register(ApacheLogFile)
admin.site.register(NginxLogFile)
admin.site.register(IISLogFile)


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











