import json
from datetime import datetime
from rest_framework import serializers
from .models import *


class ApacheLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApacheLog
        fields = [
            'log_type',  
            'client_ip',
            'remote_logname',
            'remote_user',
            'timestamp',
            'request_line',
            'response_code',
            'response_size',
            'referrer',
            'user_agent',
            'log_level',
            'error_message',
            'process_id',            
            'module',
        ]


from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class LinuxLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = LinuxLog
        fields = [
            'log_type',
            'timestamp',
            'hostname',
            'service',
            'process_id',
            'message',
            'log_level',  # Only for syslogs
            'user',  # Only for auth logs
            'command',  # Only for auth logs
            'pwd',  # Only for auth logs
            'session_status',  # Only for auth logs
            'uid',  # Only for auth logs
            'owner',  # ForeignKey to the User model
        ]

    def to_internal_value(self, data):        
        user_id = data.pop('user_id', None)
        
        validated_data = super().to_internal_value(data)

        if user_id:
            try:                
                user = User.objects.get(id=user_id)
                validated_data['owner'] = user  
            except User.DoesNotExist:
                raise serializers.ValidationError({'user_id': 'Invalid user ID'})

        return validated_data

    

# class ApacheLogSerializer(serializers.Serializer):
#     source_name = serializers.CharField(allow_null=False, required=True)
#     logs = serializers.ListField(child=serializers.JSONField(), required=True)  # List of logs

#     def create(self, validated_data):
#         source_name = validated_data.get('source_name')
#         logs_data = validated_data.get('logs')

#         # Fetch or create the source
#         source, _ = ApacheSourceInfo.objects.get_or_create(source_name=source_name)

#         logs = []
#         for log in logs_data:
#             timestamp = log.get('timestamp')
#             if timestamp:
#                 try:
#                     timestamp = datetime.strptime(timestamp, "%a %b %d %H:%M:%S").replace(year=datetime.now().year)
#                 except ValueError:
#                     raise serializers.ValidationError("Invalid timestamp format. Expected format: Thu Dec 12 12:01:21")

#             log_entry = ApacheLog.objects.create(
#                 source=source,
#                 client_ip=log.get('client_ip'),
#                 remote_logname=log.get('remote_logname'),
#                 remote_user=log.get('remote_user'),
#                 timestamp=timestamp,
#                 request_line=log.get('request_line'),
#                 response_code=log.get('response_code'),
#                 response_size=log.get('response_size'),
#                 referrer=log.get('referrer'),
#                 user_agent=log.get('user_agent'),
#             )
#             logs.append(log_entry)

#         return logs



class NginxLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = NginxLog
        fields = [
            'log_type',
            'client_ip',
            'remote_logname',
            'remote_user',
            'timestamp',
            'request_line',
            'response_code',
            'response_size',
            'referrer',
            'user_agent',
            'log_level',
            'error_message',
            'process_id',
            'module',
        ]