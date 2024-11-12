import csv
from celery import shared_task
from .models import *

@shared_task
def process_uploaded_windows_logs(log_id):
    uploaded_log = WindowsLogFile.objects.get(id=log_id)
    with open(uploaded_log.file.path, 'r') as log_file:
        reader = csv.DictReader(log_file)
        for row in reader:
            LogEntry.objects.create(
                timestamp=row['timestamp'],
                log_level=row['log_level'],
                message=row['message'],
                source=row.get('source', 'unknown')
            )

@shared_task
def process_uploaded_AD_logs(log_id):
    uploaded_log = WindowsADLogFile.objects.get(id=log_id)
    with open(uploaded_log.file.path, 'r') as log_file:
        reader = csv.DictReader(log_file)
        for row in reader:
            LogEntry.objects.create(
                timestamp=row['timestamp'],
                log_level=row['log_level'],
                message=row['message'],
                source=row.get('source', 'unknown')
            )