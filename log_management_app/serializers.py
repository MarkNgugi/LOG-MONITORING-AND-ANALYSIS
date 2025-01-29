import json
from datetime import datetime
from rest_framework import serializers
from .models import *
from django.contrib.auth import get_user_model


User = get_user_model()

class ApacheLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApacheLog
        fields = [
            'log_source_name',
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
            'owner',  
        ]

    def to_internal_value(self, data):
        # Extract user_id from the incoming data
        user_id = data.pop('user_id', None)
        
        # Validate the rest of the data using the parent class method
        validated_data = super().to_internal_value(data)

        # If user_id is provided, fetch the User instance and assign it to the owner field
        if user_id:
            try:
                user = User.objects.get(id=user_id)
                validated_data['owner'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError({'user_id': 'Invalid user ID'})

        return validated_data


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
            'log_source_name',
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




class MysqlLogSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=False)

    class Meta:
        model = MysqlLog
        fields = [
            'log_source_name',
            'log_type',
            'timestamp',
            'error_message',
            'owner',  # Include owner field for user association
        ]

    def to_internal_value(self, data):
        user_id = data.pop('user_id', None)
        validated_data = super().to_internal_value(data)

        if user_id:
            try:
                user = User.objects.get(id=user_id)
                validated_data['owner'] = user  # Assign the User instance directly
            except User.DoesNotExist:
                raise serializers.ValidationError({'user_id': 'Invalid user ID'})

        return validated_data


class RedisLogSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=False)

    class Meta:
        model = RedisLog
        fields = [
            'log_source_name',
            'log_type',
            'timestamp',
            'message',
            'owner',
        ]

    def to_internal_value(self, data):
        # Extract user_id from the incoming data
        user_id = data.pop('user_id', None)

        # Validate the rest of the data using the parent class method
        validated_data = super().to_internal_value(data)

        # If user_id is provided, fetch the User instance and assign it to the owner field
        if user_id:
            try:
                user = User.objects.get(id=user_id)
                validated_data['owner'] = user  # Assign the User instance directly
            except User.DoesNotExist:
                raise serializers.ValidationError({'user_id': 'Invalid user ID'})

        return validated_data
