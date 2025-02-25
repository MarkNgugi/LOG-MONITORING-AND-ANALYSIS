from django.shortcuts import render
from .models import *
from log_management_app.models import *
import json
from django.shortcuts import render, get_object_or_404

#ALERTS



def alertconfig(request):
    context={}
    return render(request,'baseapp/alertconfig/alertconfig.html',context)

def alertconfigpage(request):
    context={}
    return render(request,'baseapp/alertconfig/configpage.html',context)

def contactpoint(request):
    context={}
    return render(request,'baseapp/contactpoints/contactpoint.html',context)

def notification_policy(request):
    context={}
    return render(request,'baseapp/notificationpolicy/notificationpolicies.html',context)

    
   

def scheduledreports(request):
    reports = Report.objects.all()
    context={'reports':reports}
    return render(request,'baseapp/scheduledreports/scheduledreports.html',context)


from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.core.serializers.json import DjangoJSONEncoder
import json
from datetime import datetime
from log_management_app.models import WindowsLog, WindowsADLog, LinuxLog, Alert


def addscheduledreport(request):
    if request.method == 'POST':
        # Debug: Print the POST data
        print(request.POST)

        # Get form data
        report_title = request.POST.get('reportName')
        selected_log_source = request.POST.get('logSources')

        # Debug: Print the retrieved values
        print(f"Report Title: {report_title}")
        print(f"Selected Log Source: {selected_log_source}")

        # Ensure report_title is not None or empty
        if not report_title:
            return JsonResponse({'error': 'Report title is required'}, status=400)

        # Get the current user
        generated_by = request.user

        # Fetch logs based on the selected log source
        if selected_log_source == 'Windows':
            logs = WindowsLog.objects.filter(log_source_name=selected_log_source)
        elif selected_log_source == 'Windows AD':
            logs = WindowsADLog.objects.filter(log_source_name=selected_log_source)
        elif selected_log_source == 'Linux':
            logs = LinuxLog.objects.filter(log_source_name=selected_log_source)
        else:
            logs = []

        # Calculate total logs processed
        total_logs_processed = len(logs)

        # Fetch alerts related to the selected log source
        alerts = Alert.objects.filter(log_source_name=selected_log_source)
        total_alerts_triggered = len(alerts)

        # Calculate alert severity distribution
        severity_distribution = {
            'Critical': alerts.filter(severity='Critical').count(),
            'High': alerts.filter(severity='High').count(),
            'Medium': alerts.filter(severity='Medium').count(),
            'Low': alerts.filter(severity='Low').count(),
        }

        # Get top 5 critical alerts
        top_critical_alerts = list(alerts.filter(severity='Critical').values('alert_title', 'timestamp', 'hostname', 'message')[:5])

        # Create the report
        report = Report(
            report_title=report_title,
            generated_by=generated_by,
            total_logs_processed=total_logs_processed,
            data_sources=[selected_log_source],
            log_summary={selected_log_source: total_logs_processed},
            total_alerts_triggered=total_alerts_triggered,
            alert_severity_distribution=severity_distribution,
            top_critical_alerts=top_critical_alerts,
        )
        report.save()

        return redirect('report_detail', report_id=report.id)

    # For GET requests, populate the log sources dropdown
    windows_log_sources = list(WindowsLog.objects.values_list('log_source_name', flat=True).distinct())
    windows_ad_log_sources = list(WindowsADLog.objects.values_list('log_source_name', flat=True).distinct())
    linux_log_sources = list(LinuxLog.objects.values_list('log_source_name', flat=True).distinct())
    all_log_sources = list(set(windows_log_sources + windows_ad_log_sources + linux_log_sources))

    context = {
        'all_log_sources': json.dumps(all_log_sources),
    }
    return render(request, 'baseapp/scheduledreports/addreport.html', context)



def report_detail(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    context = {
        'report': report,
    }
    return render(request, 'baseapp/scheduledreports/report_detail.html', context)
    
def customalerts(request):
    context={}
    return render(request,'baseapp/customalerts/customalerts.html',context)

def notification_settings(request):
    context={}
    return render(request,'baseapp/notificationsettings/notsettings.html',context)