from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(WindowsLog)
admin.site.register(WindowsADLogFile)
admin.site.register(LogEntry)
# admin.site.register(Anomaly)

admin.site.register(LinuxLogFile)
admin.site.register(LinuxLog)

admin.site.register(MacLogFile) 

admin.site.register(ApacheLog)

admin.site.register(NginxLogFile)
admin.site.register(NginxLog)

admin.site.register(IISLogFile)

admin.site.register(MysqlLogFile)
admin.site.register(PostgresLogFile)
admin.site.register(MongoLogFile)

admin.site.register(Alert)
admin.site.register(CustomToken)


 

 







