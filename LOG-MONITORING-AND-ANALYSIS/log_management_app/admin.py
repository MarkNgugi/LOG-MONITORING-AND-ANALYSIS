from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(WindowsLogSource)
admin.site.register(LogType)
admin.site.register(WebserverLogFileUpload)
admin.site.register(SecurityLog)
admin.site.register(WindowsFileLogSource)
admin.site.register(WindowsPerfLogs)
admin.site.register(PerformanceMetric)
admin.site.register(WindowsActiveDirectoryLogSource)

