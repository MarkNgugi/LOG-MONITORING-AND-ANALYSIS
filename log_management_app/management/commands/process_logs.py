from django.core.management.base import BaseCommand
from pymongo import MongoClient
from log_management_app.models import WindowsAlert
from django.conf import settings
from datetime import datetime
from django.utils import timezone
import re

class Command(BaseCommand):
    help = 'Fetch logs from MongoDB and store them in Django models'

    def get_mongo_client(self):
        print(f"Connecting to MongoDB at {settings.MONGODB_SETTINGS['host']}")
        return MongoClient(settings.MONGODB_SETTINGS['host'])

    def fetch_logs_from_collection(self, collection_name):
        client = self.get_mongo_client()
        db = client[settings.MONGODB_SETTINGS['db']]
        collection = db[collection_name]
        log_count = collection.count_documents({})
        print(f"Fetched {log_count} logs from {collection_name}")
        return collection.find()

    def convert_to_datetime(self, date_str):
        """ Convert /Date(1723051981501)/ to a timezone-aware Python datetime object. """
        timestamp = int(re.search(r'\d+', date_str).group())
        dt = datetime.fromtimestamp(timestamp / 1000)
        return timezone.make_aware(dt, timezone.get_current_timezone())

    def process_and_store_logs(self):
        collections = ['systemlogs', 'applicationlogs', 'securitylogs']
        
        for collection_name in collections:
            logs = self.fetch_logs_from_collection(collection_name)
            
            for log in logs:
                # Debug print to see log details
                print(f"Processing log: {log}")

                # Skip documents where required fields are missing
                if (log.get('LevelDisplayName') is None or 
                    log.get('Message') is None or 
                    log.get('TimeCreated') is None):
                    print(f"Skipping log due to missing fields: {log}")
                    continue

                # Convert the TimeCreated field to a timezone-aware datetime object
                try:
                    timestamp = self.convert_to_datetime(log.get('TimeCreated'))
                except ValueError:
                    print(f"Skipping log due to invalid date format: {log}")
                    continue

                # Create a WindowsAlert instance for valid documents
                try:
                    WindowsAlert.objects.create(
                        event_id=log.get('Id'),
                        entry_type=log.get('LevelDisplayName'),
                        provider=log.get('ProviderName'),
                        alert_level=log.get('LevelDisplayName'),  # Assuming alert_level is the same as entry_type
                        message=log.get('Message'),
                        timestamp=timestamp,
                        source_name="windows"  # Assuming source_name is the collection name
                    )
                    print(f"Inserted log into WindowsAlert: {log}")
                except IntegrityError as e:
                    print(f"IntegrityError: {e} - Log details: {log}")

    def handle(self, *args, **options):
        self.process_and_store_logs()
        self.stdout.write(self.style.SUCCESS('Successfully processed and stored logs'))
