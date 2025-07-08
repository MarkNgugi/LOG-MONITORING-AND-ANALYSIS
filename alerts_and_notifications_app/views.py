from django.shortcuts import render
from .models import *
from log_management_app.models import *
import json
from django.shortcuts import render, get_object_or_404
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.core.serializers.json import DjangoJSONEncoder
import json
from datetime import datetime
from log_management_app.models import WindowsLog, WindowsADLog, LinuxLog, Alert

#remove this view later
def alerts(request):
    context = {}
    return render(request, "home/templates/mark.html",context)

#ALERTS
def scheduledreports(request):
    reports = Report.objects.all()
    context={'reports':reports}
    return render(request,'baseapp/scheduledreports/scheduledreports.html',context)


def delete_report(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    report.delete()
    return redirect('gen_reports')

def addscheduledreport(request):
    if request.method == 'POST':
        report_title = request.POST.get('reportName')
        selected_log_source = request.POST.get('logSources')

        if not report_title:
            return JsonResponse({'error': 'Report title is required'}, status=400)

        # Get Linux logs for selected source
        logs = LinuxLog.objects.filter(log_source_name=selected_log_source)
        total_logs_processed = logs.count()

        # Get alerts for selected source
        alerts = Alert.objects.filter(log_source_name=selected_log_source)
        total_alerts_triggered = alerts.count()

        # Severity distribution (Critical, High, Low, Info)
        severity_distribution = {
            'Critical': alerts.filter(severity='Critical').count(),
            'High': alerts.filter(severity='High').count(),
            'Low': alerts.filter(severity='Low').count(),
            'Info': alerts.filter(severity='Info').count(),
        }

        # Prepare top critical alerts with proper timestamp formatting
        top_critical_alerts = []
        for alert in alerts.filter(severity='Critical').order_by('-timestamp')[:5]:
            top_critical_alerts.append({
                'alert_title': alert.alert_title,
                'timestamp': alert.timestamp.strftime("%b. %d, %Y, %I:%M %p"),
                'hostname': alert.hostname,
                'message': alert.message,
                'log_source_name': alert.log_source_name
            })

        # Create and save report
        report = Report(
            report_title=report_title,
            generated_by=request.user,
            total_logs_processed=total_logs_processed,
            data_sources=[selected_log_source],
            log_summary={selected_log_source: total_logs_processed},
            total_alerts_triggered=total_alerts_triggered,
            alert_severity_distribution=severity_distribution,
            top_critical_alerts=top_critical_alerts,
        )
        report.save()

        return redirect('gen_reports',)

    # GET request - get distinct Linux log sources ordered by name
    linux_log_sources = LinuxLog.objects.exclude(log_source_name__isnull=True)\
                                       .exclude(log_source_name__exact='')\
                                       .order_by('log_source_name')\
                                       .values_list('log_source_name', flat=True)\
                                       .distinct()

    return render(request, 'baseapp/scheduledreports/addreport.html', {
        'all_log_sources': list(linux_log_sources)
    })


from django.db.models import Q

def report_detail(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    
    # Get data sources from the report - handle different formats
    data_sources = []
    if report.data_sources:
        if isinstance(report.data_sources, list):
            data_sources = [str(src).strip(" '\"[]") for src in report.data_sources]
        elif isinstance(report.data_sources, str):
            data_sources = [src.strip(" '\"[]") for src in report.data_sources.split(',')]
    
    data_sources = [src for src in data_sources if src]
    
    # Fetch all matching alerts (not just critical) for accurate total count
    all_matching_alerts = Alert.objects.all()
    if data_sources:
        query = Q()
        for source in data_sources:
            query |= Q(log_source_name__icontains=source)
        all_matching_alerts = all_matching_alerts.filter(query)
    
    # Get critical alerts from the matching set
    critical_alerts = all_matching_alerts.filter(severity="Critical").order_by('-timestamp')[:5]
    
    # Calculate actual counts
    total_alerts = all_matching_alerts.count()
    severity_distribution = {
        'Critical': all_matching_alerts.filter(severity="Critical").count(),
        'High': all_matching_alerts.filter(severity="High").count(),
        'Low': all_matching_alerts.filter(severity="Low").count(),
        'Info': all_matching_alerts.filter(severity="Info").count(),
    }
    
    context = {
        'report': report,
        'critical_alerts': critical_alerts,
        'actual_total_alerts': total_alerts,
        'actual_severity_distribution': severity_distribution,
    }
    return render(request, 'baseapp/scheduledreports/report_detail.html', context)
