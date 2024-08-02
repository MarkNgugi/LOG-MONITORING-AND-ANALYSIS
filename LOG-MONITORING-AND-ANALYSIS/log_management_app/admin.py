from django.contrib import admin
from .models import *
# Register your models here.



admin.site.register(WindowsLogType)
admin.site.register(WindowsLogSource) 
admin.site.register(WindowsFileLogSource)
admin.site.register(WindowsPerfLogs)
admin.site.register(WindowsPerformanceMetric)
admin.site.register(WindowsActiveDirectoryLogSource)


admin.site.register(LinuxLogType) 
admin.site.register(LinuxLogSource)
admin.site.register(LinuxFileLogSource)
admin.site.register(LinuxPerformanceMetric)
admin.site.register(LinuxPerfLogs)
admin.site.register(LDAPLogSource)

admin.site.register(MacLogType) 
admin.site.register(MacLogSource)
admin.site.register(MacFileLogSource)
admin.site.register(MacPerfLogs)
admin.site.register(MacPerformanceMetric)
admin.site.register(OpenDirLogSource)


admin.site.register(ApacheserverLogStream)
admin.site.register(ApacheserverLogFileStream)
admin.site.register(ApacheserverPerfLogs)


admin.site.register(SecurityLog)





