from django.contrib import admin
from .models import *

admin.site.register(WindowsLog)
admin.site.register(WindowsADLog)
admin.site.register(LinuxLog)
admin.site.register(Alert)
admin.site.register(Report)







