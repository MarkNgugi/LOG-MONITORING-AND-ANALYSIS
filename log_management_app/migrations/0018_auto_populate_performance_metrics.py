
from django.db import migrations

def create_performance_metrics(apps, schema_editor):
    PerformanceMetric = apps.get_model('log_management_app', 'PerformanceMetric')
    performance_metrics = ['CPU Usage', 'Memory Usage', 'Disk Usage', 'Network Throughput', 'Disk I/O', 'Page File Usage','Thread Count', 'Handle Count', 'Process Count']
    for metric in performance_metrics:
        PerformanceMetric.objects.create(name=metric)

class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0015_performancemetric_windowsperflogs'),  
    ]

    operations = [
        migrations.RunPython(create_performance_metrics),
    ]
