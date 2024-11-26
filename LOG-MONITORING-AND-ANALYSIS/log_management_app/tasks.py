import csv
from celery import shared_task
from .models import *


@shared_task
def process_uploaded_windows_logs(log_id):
    uploaded_log = WindowsLogFile.objects.get(id=log_id)
    user = uploaded_log.user  # Get the user who uploaded the log
    with open(uploaded_log.file.path, 'r') as log_file:
        reader = csv.DictReader(log_file)
        for row in reader:
            # Parse TimeCreated to datetime object
            time_created = datetime.strptime(row['TimeCreated'], '%Y-%m-%d %H:%M:%S')
            LogEntry.objects.create(
                TimeCreated=time_created,
                event_id=int(row['Id']),
                LevelDisplayName=row['LevelDisplayName'],
                message=row['Message'],
                source=row.get('ProviderName', 'unknown'),
                user=user  # Link the log to the user
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

@shared_task
def process_uploaded_linux_logs(log_id):
    uploaded_log = LinuxLogFile.objects.get(id=log_id)
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
def process_uploaded_mac_logs(log_id):
    uploaded_log = MacLogFile.objects.get(id=log_id)
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
def process_uploaded_apache_logs(log_id):
    uploaded_log = ApacheLogFile.objects.get(id=log_id)
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
def process_uploaded_nginx_logs(log_id):
    uploaded_log = NginxLogFile.objects.get(id=log_id)
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
def process_uploaded_iis_logs(log_id):
    uploaded_log = IISLogFile.objects.get(id=log_id)
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
def process_uploaded_mysql_logs(log_id):
    uploaded_log = MysqlLogFile.objects.get(id=log_id)
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
def process_uploaded_postgres_logs(log_id):
    uploaded_log = PostgresLogFile.objects.get(id=log_id)
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
def process_uploaded_mongo_logs(log_id):
    uploaded_log = MongoLogFile.objects.get(id=log_id)
    with open(uploaded_log.file.path, 'r') as log_file:
        reader = csv.DictReader(log_file)
        for row in reader:
            LogEntry.objects.create(
                timestamp=row['timestamp'],
                log_level=row['log_level'],
                message=row['message'],
                source=row.get('source', 'unknown')
            )                                       