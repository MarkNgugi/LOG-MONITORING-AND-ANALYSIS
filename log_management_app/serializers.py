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

    def validate(self, data):
        # Ensure required fields are valid
        if 'TimeCreated' not in data:
            raise serializers.ValidationError("TimeCreated is required.")
        if 'event_id' not in data:
            raise serializers.ValidationError("Event ID is required.")
        return data





    