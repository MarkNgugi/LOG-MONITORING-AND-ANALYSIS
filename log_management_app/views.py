from itertools import chain
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from .forms import *
from .models import *
from django.urls import reverse
from .tasks import *
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import *
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view
from django.shortcuts import get_object_or_404
 
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from .models import Token  
from django.utils.timezone import now, timedelta

import logging
 
class GenerateTokenView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request):
        user = request.user
        token_name = request.data.get('name')

        if not token_name:
            return Response({'error': 'Token name is required.'}, status=400)

        # Try to get the existing token with the same name
        token, created = CustomToken.objects.get_or_create(user=user, name=token_name)

        # If token is newly created, set the creation time
        if created:
            token.created_at = now()
            token.save()

        # Check if the token has expired (10 seconds expiration time)
        if now() - token.created_at > timedelta(seconds=1000):
            # If expired, delete the old token and generate a new one
            token.delete()
            token = CustomToken.objects.create(user=user, name=token_name)  # Create a new token

        # Return the (new or valid) token
        return Response({'access_token': token.key})

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import json
from rest_framework.authtoken.models import Token

@csrf_exempt
@login_required
def generate_token(request):
    if request.method == 'POST':
        user = request.user
        data = json.loads(request.body)
        name = data.get('name')

        if not name:
            return JsonResponse({'error': 'Name is required'}, status=400)

        # Create or update the token
        token, created = CustomToken.objects.get_or_create(user=user, defaults={'name': name})
        if not created:  # Token already exists
            token.name = name  # Update the name field
            token.save()

        return JsonResponse({'access_token': token.key, 'name': token.name})
    return JsonResponse({'error': 'Invalid request'}, status=400)

 

from django.http import HttpResponse, HttpResponseForbidden, Http404
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.views import APIView
from django.conf import settings
from .models import CustomToken
import os

class ExecuteScriptView(APIView):
    authentication_classes = [TokenAuthentication]  # Use token-based authentication

    def get(self, request, filename):
        # Get the token from the request headers
        token_key = request.headers.get('Authorization', '').split(' ')[-1]
        try:
            # Validate the token
            token = CustomToken.objects.get(key=token_key)
            if not token or (timezone.now() - token.created_at > timedelta(seconds=1000)):
                raise AuthenticationFailed("Token is invalid or expired.")                
        except CustomToken.DoesNotExist:
            raise AuthenticationFailed("Invalid token.")

        # Build the file path
        file_path = os.path.join(settings.BASE_DIR, 'protected_files', filename)
        if not os.path.exists(file_path):
            raise Http404("File not found.")

        # Read the file content
        with open(file_path, 'r') as file:
            script_content = file.read()

        # Return the script content as plain text
        return HttpResponse(script_content, content_type="text/plain")


@login_required
def get_user_id(request):
    return JsonResponse({"user_id": request.user.id})

def log_history(request):
    logs = LogEntry.objects.filter(user=request.user).order_by('-TimeCreated')
    context = {'logs': logs}
    return render(request, 'baseapp/logs/logs.html', context)


#LOG SOURCES
def home(request):
    context={'user':request.user}
    return render(request,'baseapp/home.html',context)

from itertools import chain
from django.db.models import Max

def logsources(request, os_type=None):
    # Querysets for system logs
    log_sources_windows = WindowsLog.objects.filter(user=request.user)
    log_sources_windows_ad = WindowsADLog.objects.filter(user=request.user)
    log_sources_linux = LinuxLog.objects.filter(owner=request.user)

    # Filtering based on parameters
    if os_type:
        if os_type == 'windows':
            log_sources = log_sources_windows.values('log_source_name', 'hostname').annotate(last_collected=Max('timestamp'))
        elif os_type == 'windowsAD':
            log_sources = log_sources_windows_ad.values('log_source_name', 'hostname').annotate(last_collected=Max('timestamp'))
        elif os_type == 'linux':
            log_sources = log_sources_linux.values('log_source_name', 'hostname').annotate(last_collected=Max('timestamp'))
    else:
        # Combine all log sources if no os_type is specified
        log_sources = list(chain(
            log_sources_windows.values('log_source_name', 'hostname').annotate(last_collected=Max('timestamp')),
            log_sources_windows_ad.values('log_source_name', 'hostname').annotate(last_collected=Max('timestamp')),
            log_sources_linux.values('log_source_name', 'hostname').annotate(last_collected=Max('timestamp'))
        ))

    # Counts for each category
    windows_count = log_sources_windows.count()
    windows_ad_count = log_sources_windows_ad.count()
    linux_count = log_sources_linux.count()
    total_system_logs_count = windows_count + windows_ad_count + linux_count

    context = {
        'windows_count': windows_count,
        'windows_ad_count': windows_ad_count,
        'linux_count': linux_count,
        'total_system_logs_count': total_system_logs_count,
        'log_sources': log_sources,  # Pass the filtered log_sources to the template
        'os_type': os_type,
    }

    return render(request, 'baseapp/logsources/logsources.html', context)



from django.db.models import Count

def sourceinfo(request, os_type, log_source_name, hostname):
    # Fetch the log source based on os_type, log_source_name, and hostname
    if os_type == 'windows':
        log_source = get_object_or_404(WindowsLog, log_source_name=log_source_name, hostname=hostname, user=request.user)
        recent_logs = WindowsLog.objects.filter(log_source_name=log_source_name, hostname=hostname, user=request.user).order_by('-timestamp')[:10]
        total_logs = WindowsLog.objects.filter(log_source_name=log_source_name, hostname=hostname, user=request.user).count()
    elif os_type == 'windowsAD':
        log_source = get_object_or_404(WindowsADLog, log_source_name=log_source_name, hostname=hostname, user=request.user)
        recent_logs = WindowsADLog.objects.filter(log_source_name=log_source_name, hostname=hostname, user=request.user).order_by('-timestamp')[:10]
        total_logs = WindowsADLog.objects.filter(log_source_name=log_source_name, hostname=hostname, user=request.user).count()
    elif os_type == 'linux':
        log_sources = LinuxLog.objects.filter(log_source_name=log_source_name, hostname=hostname, owner=request.user)
        
        if log_sources.exists():
            log_source = log_sources.first()  # Get the first object
        else:
            return HttpResponse("Log source not found", status=404)
        
        recent_logs = log_sources.order_by('-timestamp')[:10]
        total_logs = log_sources.count()
    else:
        # Handle invalid os_type
        return HttpResponse("Invalid OS type", status=400)

    # Fetch the number of alerts for the selected log source
    total_alerts = Alert.objects.filter(log_source_name=log_source_name, hostname=hostname, user=request.user).count()

    context = {
        'log_source': log_source,
        'recent_logs': recent_logs,  # Pass the last 10 logs to the template
        'os_type': os_type,
        'total_logs': total_logs,  # Pass the total number of logs
        'total_alerts': total_alerts,  # Pass the total number of alerts
    }

    return render(request, 'baseapp/logsources/sourceinfo.html', context)


#LOG INGESTION 
def system_os_types(request):  
    context={}
    return render(request,'baseapp/logingestion/OSpage.html',context)

@login_required
def windows_log_upload(request):
    context = {}
    return render(request, 'baseapp/logingestion/systemlogs/windows/windows.html', context)

def windowsAD_log_upload(request):
    context = {}
    return render(request, 'baseapp/logingestion/systemlogs/activedirectory/activedirectory.html', context)
    

def linux_log_upload(request):
    context = {} 
    return render(request, 'baseapp/logingestion/systemlogs/linux/linux.html', context)



logger = logging.getLogger(__name__)

class LinuxLogView(APIView):
    def post(self, request, *args, **kwargs):
        logger.debug(f"Incoming request data: {request.data}")
        logs = request.data if isinstance(request.data, list) else [request.data]

        if not logs:
            return Response(
                {"error": "No logs provided or invalid format."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = LinuxLogSerializer(data=logs, many=True, context={'request': request})
        if serializer.is_valid():
            try:
                serializer.save()
                skipped_logs = len(logs) - len(serializer.validated_data)
                message = f"Logs processed successfully. Skipped {skipped_logs} invalid entries." if skipped_logs > 0 else "Logs processed successfully."
                return Response({"message": message}, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error saving logs: {str(e)}")
                return Response(
                    {"error": "Error saving logs", "details": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            logger.error(f"Serializer validation errors: {serializer.errors}")
            return Response(
                {"error": "Validation failed", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )




            
def linux_info(request):
    context={}
    return render(request,'baseapp/logingestion/systemlogs/linux/linuxinfo.html',context)


def apache_log_upload(request):
    context={}
    return render(request, 'baseapp/logingestion/applicationlogs/webservers/apache/apache.html',context)





logger = logging.getLogger(__name__)

class ApacheLogView(APIView):
    def post(self, request, *args, **kwargs):
        logger.debug(f"Incoming request data: {request.data}")
        logs = request.data if isinstance(request.data, list) else [request.data]

        if not logs:
            return Response(
                {"error": "No logs provided or invalid format."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Pass the request context to the serializer
        serializer = ApacheLogSerializer(data=logs, many=True, context={'request': request})
        if serializer.is_valid():
            try:
                serializer.save()
                skipped_logs = len(logs) - len(serializer.validated_data)
                message = f"Logs processed successfully. Skipped {skipped_logs} invalid entries." if skipped_logs > 0 else "Logs processed successfully."
                return Response({"message": message}, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error saving logs: {str(e)}")
                return Response(
                    {"error": "Error saving logs", "details": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            logger.error(f"Serializer validation errors: {serializer.errors}")
            return Response(
                {"error": "Validation failed", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

  

@api_view(['POST'])
def create_apache_log(request):
    if request.method == 'POST':
        serializer = ApacheLogSerializer(data=request.data)  # Validates and converts the data

        if serializer.is_valid():
            # Save the log entry to the ApacheLog model
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  




def apache_info(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/apache/apacheinfo.html',context)





def nginx_log_upload(request):
    if request.method == 'POST':
        form = NginxLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_nginx_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = NginxLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/applicationlogs/webservers/nginx/nginx.html', context)



logger = logging.getLogger(__name__)

class MysqlLogView(APIView):
    def post(self, request, *args, **kwargs):
        # Log incoming request data for debugging
        logger.debug(f"Incoming request data: {request.data}")

        # Ensure logs are processed as a list
        logs = request.data if isinstance(request.data, list) else [request.data]

        # Check if logs are provided
        if not logs:
            return Response(
                {"error": "No logs provided or invalid format."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Add user_id to each log entry if not already present
        for log in logs:
            if 'user_id' not in log:
                log['user_id'] = request.user.id  # Use the authenticated user's ID

        # Pass the request context to the serializer
        serializer = MysqlLogSerializer(data=logs, many=True, context={'request': request})

        # Validate and save logs
        if serializer.is_valid():
            try:
                serializer.save()
                skipped_logs = len(logs) - len(serializer.validated_data)
                message = f"Logs processed successfully. Skipped {skipped_logs} invalid entries." if skipped_logs > 0 else "Logs processed successfully."
                return Response({"message": message}, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error saving logs: {str(e)}")
                return Response(
                    {"error": "Error saving logs", "details": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            logger.error(f"Serializer validation errors: {serializer.errors}")
            return Response(
                {"error": "Validation failed", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )



class RedisLogView(APIView):
    def post(self, request, *args, **kwargs):
        # Log incoming request data for debugging
        logger.debug(f"Incoming request data: {request.data}")

        # Ensure logs are processed as a list
        logs = request.data if isinstance(request.data, list) else [request.data]

        # Check if logs are provided
        if not logs:
            return Response(
                {"error": "No logs provided or invalid format."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Add user_id to each log entry if not already present
        for log in logs:
            if 'user_id' not in log:
                log['user_id'] = request.user.id  # Use the authenticated user's ID

        # Pass the request context to the serializer
        serializer = RedisLogSerializer(data=logs, many=True, context={'request': request})

        # Validate and save logs
        if serializer.is_valid():
            try:
                serializer.save()
                skipped_logs = len(logs) - len(serializer.validated_data)
                message = f"Logs processed successfully. Skipped {skipped_logs} invalid entries." if skipped_logs > 0 else "Logs processed successfully."
                return Response({"message": message}, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error saving logs: {str(e)}")
                return Response(
                    {"error": "Error saving logs", "details": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            logger.error(f"Serializer validation errors: {serializer.errors}")
            return Response(
                {"error": "Validation failed", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

def nginx_info(request):
    context={}
    return render(request,'baseapp/logingestion/applicationlogs/webservers/nginx/nginxinfo.html',context)

def iis_log_upload(request):
    if request.method == 'POST':
        form = IISLogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save()
            process_uploaded_iis_logs.delay(uploaded_log.id)  # Trigger async processing
            return redirect('logsources')
    else:
        form = IISLogUploadForm()

    context={'form':form}        
    return render(request, 'baseapp/logingestion/applicationlogs/webservers/iis/iis.html', context)












#=========================================DATABASE FORMS END=========================================================


#SEARCH

def search(request):
    context={}
    return render(request,'baseapp/search/search.html',context)

#STREAMS

def logstreams(request):
    context={}
    return render(request,'baseapp/logstreams/logstreams.html',context)

#ANOMALIES

def alert_history(request):
    alerts = Alert.objects.filter(user=request.user)
    
    # Dynamically determine os_type based on the log source
    for alert in alerts:
        if 'windows' in alert.connection.lower():
            alert.os_type = 'windows'
        elif 'linux' in alert.connection.lower():
            alert.os_type = 'linux'
        else:
            alert.os_type = 'windowsAD'  # Default or adjust as needed

    context = {
        'alerts': alerts,
    }

    return render(request, 'baseapp/alerts/alerts.html', context)

def alertdetail(request,id):
    alert = Alert.objects.filter(id=id)
    context={'alert':alert}

    return render(request,'baseapp/alerts/alertdetails.html',context)

#REPORTS

def reportspage(request):
    context={}
    return render(request,'baseapp/reports/report.html',context)

#INCIDENT RESPONSE

def incidences(request):
    context={}
    return render(request,'baseapp/incidentresponse/incidences.html',context)

def incidentresponse(request):
    context={}
    return render(request,'baseapp/incidentresponse/incidentresponse.html',context)

#LOG RETENTION

def logretention(request):
    context={}
    return render(request,'baseapp/logretention/logretention.html',context)






