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
        ]
    

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



class NginxLogSerializer(serializers.Serializer):
    timestamp = serializers.CharField(allow_null=True, required=False)
    client_ip = serializers.CharField(allow_null=True, required=False)
    method = serializers.CharField(allow_null=True, required=False)
    url = serializers.CharField(allow_null=True, required=False)
    protocol = serializers.CharField(allow_null=True, required=False)
    status_code = serializers.CharField(allow_null=True, required=False)
    referrer = serializers.CharField(allow_null=True, required=False)
    user_agent = serializers.CharField(allow_null=True, required=False)

    error_module = serializers.CharField(allow_null=True, required=False)
    process_id = serializers.IntegerField(allow_null=True, required=False)
    error_message = serializers.CharField(allow_null=True, required=False)
    file_path = serializers.CharField(allow_null=True, required=False)

    

    def create(self, validated_data):
        logs = []
        if isinstance(validated_data, list):
            for log in validated_data:
                # If log is a string, try to parse it as JSON
                if isinstance(log, str):
                    if log.strip():
                        try:
                            log = json.loads(log)
                        except json.JSONDecodeError:
                            raise serializers.ValidationError("Invalid JSON format in log data.")
                    else:
                        raise serializers.ValidationError("Empty log data received.")
                
                # Handle timestamp
                timestamp = log.get('timestamp')
                if timestamp:
                    try:
                        timestamp = datetime.strptime(timestamp, "%a %b %d %H:%M:%S").replace(year=datetime.now().year)
                    except ValueError:
                        raise serializers.ValidationError("Invalid timestamp format. Expected format: Thu Dec 12 12:01:21")
                else:
                    raise serializers.ValidationError("Missing timestamp.")
                
                # Check for critical missing fields
                if log.get('client_ip') is None:
                    raise serializers.ValidationError("Missing client_ip.")
                if log.get('error_message') is None:
                    raise serializers.ValidationError("Missing error_message.")
                
                # Create ApacheLog object
                log_entry = NginxLog.objects.create(
                    timestamp=timestamp,
                    client_ip=log.get('client_ip'),
                    method=log.get('method'),
                    url=log.get('url'),
                    status_code=log.get('status_code'),
                    referrer=log.get('referrer'),
                    user_agent=log.get('user_agent'),
                    error_module=log.get('error_module'),
                    process_id=log.get('process_id'),
                    error_message=log.get('error_message'),
                    file_path=log.get('file_path'),                    
                )
                logs.append(log_entry)
        else:
            raise serializers.ValidationError("Expected a list of log data.")

        return logs 