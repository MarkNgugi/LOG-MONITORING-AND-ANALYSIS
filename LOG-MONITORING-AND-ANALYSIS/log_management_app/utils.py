from datetime import datetime
from .models import LogEntry
from django.db import transaction

def fetch_unprocessed_logs(batch_size=100):
    """Fetch unprocessed logs for batch processing."""
    return LogEntry.objects.filter(processed=False).order_by('TimeCreated')[:batch_size]

def process_logs_in_batch(batch_size=100):
    """Process unprocessed logs in batches."""
    with transaction.atomic():
        # Lock unprocessed logs for this transaction
        logs = LogEntry.objects.select_for_update().filter(processed=False).order_by('TimeCreated')[:batch_size]
        
        if not logs.exists():
            print("No new logs to process.")
            return

        # Assign a unique batch ID
        batch_id = create_batch_id()

        for log in logs:
            try:
                analyze_log(log)  # Analyze each log entry
                log.processed = True
                log.batch_id = batch_id
                log.save()
            except Exception as e:
                print(f"Error processing log {log.id}: {e}")
        
        print(f"Processed batch {batch_id}")

def create_batch_id():
    """Generate a unique batch ID."""
    return int(datetime.utcnow().timestamp())
 