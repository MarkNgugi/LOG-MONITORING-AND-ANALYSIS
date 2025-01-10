import json
from datetime import datetime
from rest_framework import serializers
from .models import *


class ApacheLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApacheLog
        fields = '__all__' 

class LinuxLogSerializer(serializers.Serializer):
    timestamp = serializers.CharField(allow_null=True, required=False)
    event = serializers.CharField(allow_null=True, required=False)
    status = serializers.CharField(allow_null=True, required=False)
    log_level = serializers.CharField(allow_null=True, required=False)
    hostname = serializers.CharField(allow_null=True, required=False)
    process = serializers.CharField(allow_null=True, required=False)
    source = serializers.CharField(allow_null=True, required=False)
    message = serializers.CharField(allow_null=True, required=False)
    username = serializers.CharField(allow_null=True, required=False)
    source_ip = serializers.CharField(allow_null=True, required=False)



    def create(self, validated_data):
        logs = []
        for log in validated_data:
            if isinstance(log, str):
                if log.strip():
                    try:
                        log = json.loads(log)
                    except json.JSONDecodeError:
                        raise serializers.ValidationError("Invalid JSON format in log data.")
                else:
                    raise serializers.ValidationError("Empty log data received.")
            
            timestamp = log.get('timestamp')
            if timestamp:
                try:
                    timestamp = datetime.strptime(timestamp, "%b %d %H:%M:%S").replace(year=datetime.now().year)
                except ValueError:
                    raise serializers.ValidationError("Invalid timestamp format.")
            else:
                raise serializers.ValidationError("Missing timestamp.")
            
            log_entry = LinuxLog.objects.create(
                timestamp=timestamp,
                hostname=log.get('hostname'),
                event=log.get('event'),
                status=log.get('status'),
                log_level=log.get('log_level'),
                process=log.get('process'),
                source=log.get('source'),
                message=log.get('message'),
                username=log.get('username'),
                source_ip=log.get('source_ip')
            )
            logs.append(log_entry)

        return logs
    

class ApacheLogSerializer(serializers.Serializer):
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
                log_entry = ApacheLog.objects.create(
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