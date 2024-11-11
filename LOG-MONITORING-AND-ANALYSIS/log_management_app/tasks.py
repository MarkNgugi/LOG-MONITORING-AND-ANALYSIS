import csv
from celery import shared_task
from .models import UploadedLog, LogEntry

@shared_task
def process_uploaded_log(log_id):
    uploaded_log = UploadedLog.objects.get(id=log_id)
    with open(uploaded_log.file.path, 'r') as log_file:
        reader = csv.DictReader(log_file)
        for row in reader:
            LogEntry.objects.create(
                timestamp=row['timestamp'],
                log_level=row['log_level'],
                message=row['message'],
                source=row.get('source', 'unknown')
            )
