from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
app = Celery('LOG_MONITORING_AND_ANALYSIS')
broker_connection_retry_on_startup = True
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
app.conf.task_default_retry_delay = 0  # No retries
app.conf.task_default_max_retries = 0  # No retries

app.conf.task_acks_late = True
app.conf.task_reject_on_worker_lost = True
