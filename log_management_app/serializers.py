import json
from datetime import datetime
from rest_framework import serializers
from .models import *
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








