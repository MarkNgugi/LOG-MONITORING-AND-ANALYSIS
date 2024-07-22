from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(WindowsLogSource)
admin.site.register(LogType)
admin.site.register(WebserverLogFileUpload)
