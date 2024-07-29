from rest_framework import serializers
from .models import SecurityLog

class SecurityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model=SecurityLog
        fields='__all__'

    