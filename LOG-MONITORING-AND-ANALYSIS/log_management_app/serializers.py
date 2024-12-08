from rest_framework import serializers
from .models import *

# class SecurityLogSerializer(serializers.ModelSerializer):
#     class Meta:
#         model=SecurityLog
#         fields='__all__'


class LinuxLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogEntry
        fields = '__all__'





    