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
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import json
from rest_framework.authtoken.models import Token
import logging
from django.http import HttpResponse, HttpResponseForbidden, Http404
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.views import APIView
import os
from itertools import chain
from django.db.models import Max
from django.db.models import Count


@login_required
def get_user_id(request):
    return JsonResponse({"user_id": request.user.id})


def home(request):
    # Calculate total logs
    total_windows_logs = WindowsLog.objects.count()
    total_ad_logs = WindowsADLog.objects.count()
    total_linux_logs = LinuxLog.objects.count()
    total_logs = total_windows_logs + total_ad_logs + total_linux_logs

    # Calculate processed logs
    processed_logs = (
        WindowsLog.objects.filter(processed=True).count() +
        WindowsADLog.objects.filter(processed=True).count() +
        LinuxLog.objects.filter(processed=True).count()
    )

    # Calculate alerts triggered
    total_alerts = Alert.objects.count()
    total_sys_alerts = Alert.objects.all()

    # Calculate total log sources
    windows_log_sources = WindowsLog.objects.values_list('log_source_name', flat=True).distinct()
    windows_ad_log_sources = WindowsADLog.objects.values_list('log_source_name', flat=True).distinct()
    linux_log_sources = LinuxLog.objects.values_list('log_source_name', flat=True).distinct()
    total_log_sources = len(set(windows_log_sources) | set(windows_ad_log_sources) | set(linux_log_sources))

    # Calculate alerts for each system
    windows_alerts = Alert.objects.filter(log_source_name__icontains="Windows").count()
    ad_alerts = Alert.objects.filter(log_source_name__icontains="Active Directory").count()
    linux_alerts = Alert.objects.filter(connection__icontains="linux").count()

    # Calculate percentage of alerts for each system
    windows_alert_percentage = (windows_alerts / total_alerts * 100) if total_alerts > 0 else 0
    ad_alert_percentage = (ad_alerts / total_alerts * 100) if total_alerts > 0 else 0
    linux_alert_percentage = (linux_alerts / total_alerts * 100) if total_alerts > 0 else 0

    # Fetch the last 10 reports
    recent_reports = Report.objects.order_by('-generated_at')[:10]

    # Add metrics to the context
    context = {
        'user': request.user,
        'total_logs': total_logs,
        'total_sys_alerts': total_sys_alerts,
        'processed_logs': processed_logs,
        'alerts_triggered': total_alerts,
        'total_log_sources': total_log_sources,
        'total_windows_logs': total_windows_logs,
        'total_ad_logs': total_ad_logs,
        'total_linux_logs': total_linux_logs,
        'windows_alerts': windows_alerts,
        'ad_alerts': ad_alerts,
        'linux_alerts': linux_alerts,
        'windows_alert_percentage': round(windows_alert_percentage, 2),
        'ad_alert_percentage': round(ad_alert_percentage, 2),
        'linux_alert_percentage': round(linux_alert_percentage, 2),
        'recent_reports': recent_reports,  # Add recent reports to the context
    }

    return render(request, 'baseapp/home.html', context)



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


from django.core.paginator import Paginator
from django.shortcuts import render
from .models import LinuxLog
from django.http import HttpResponse
import csv
from django.db.models import Q

def logs_search(request):
    # Get all filter parameters
    filters = {
        'log_type': request.GET.get('log_type', ''),
        'log_level': request.GET.get('log_level', ''),
        'hostname': request.GET.get('hostname', ''),
        'service': request.GET.get('service', ''),
        'user': request.GET.get('user', ''),
        'process_id': request.GET.get('process_id', '')
    }

    # Start with all logs
    logs = LinuxLog.objects.all().order_by('-timestamp')

    # Apply filters only if they exist in request.GET
    if filters['log_type']:
        logs = logs.filter(log_type=filters['log_type'])
    
    if filters['log_level']:
        logs = logs.filter(log_level=filters['log_level'])
    
    if filters['hostname']:
        logs = logs.filter(hostname__icontains=filters['hostname'])
    
    if filters['service']:
        logs = logs.filter(service__icontains=filters['service'])
    
    if filters['user']:
        logs = logs.filter(user__icontains=filters['user'])
    
    if filters['process_id']:
        logs = logs.filter(process_id=filters['process_id'])

    # Get counts for quick stats
    syslog_count = LinuxLog.objects.filter(log_type='syslog').count()
    authlog_count = LinuxLog.objects.filter(log_type='authlog').count()
    error_count = LinuxLog.objects.filter(log_level='error').count()
    user_activity_count = LinuxLog.objects.filter(user__isnull=False).count()

    # Handle CSV export
    if request.GET.get('export') == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="linux_logs_export.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Timestamp', 'Type', 'Hostname', 'Service', 'Process ID', 'User', 'Message', 'Level'])
        
        for log in logs:
            writer.writerow([
                log.timestamp,
                log.get_log_type_display(),
                log.hostname,
                log.service,
                log.process_id,
                log.user,
                log.message,
                log.log_level,
            ])
        
        return response

    # Pagination
    paginator = Paginator(logs, 25)  # Show 25 logs per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Get the query parameters without page for pagination links
    query_params = request.GET.copy()
    if 'page' in query_params:
        del query_params['page']
    query_params = query_params.urlencode()

    context = {
        'logs': page_obj,
        'syslog_count': syslog_count,
        'authlog_count': authlog_count,
        'error_count': error_count,
        'user_activity_count': user_activity_count,
        'query_params': query_params,
    }

    return render(request, 'baseapp/search/search.html', context)


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


def delete_alert(request, alert_id):
    # Fetch the alert to be deleted
    alert = get_object_or_404(Alert, id=alert_id, user=request.user)

    # Delete the alert
    alert.delete()

    # Add a success message
    messages.success(request, 'Alert deleted successfully.')

    # Redirect to the alert history page
    return redirect('alert_history')

#REPORTS

def reportspage(request):
    context={}
    return render(request,'baseapp/reports/report.html',context)
