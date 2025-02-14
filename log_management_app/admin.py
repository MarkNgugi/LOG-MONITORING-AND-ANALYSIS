from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(WindowsLog)
admin.site.register(WindowsADLog)
admin.site.register(LogEntry)
# admin.site.register(Anomaly)

admin.site.register(LinuxLog)

admin.site.register(ApacheLog)

admin.site.register(NginxLogFile)
admin.site.register(MysqlLog)

admin.site.register(RedisLog)

admin.site.register(MysqlLogFile)
admin.site.register(PostgresLogFile)
admin.site.register(MongoLogFile)

admin.site.register(Alert)
admin.site.register(CustomToken)







