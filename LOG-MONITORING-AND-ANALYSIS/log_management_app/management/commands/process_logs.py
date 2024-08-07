# log_management_app/management/commands/process_logs.py
from django.core.management.base import BaseCommand
from pymongo import MongoClient
from log_management_app.models import WindowsAlert
from django.conf import settings

class Command(BaseCommand):
    help = 'Fetch logs from MongoDB and store them in Django models'

    def get_mongo_client(self):
        return MongoClient(settings.MONGODB_SETTINGS['host'])

    def fetch_logs_from_collection(self, collection_name):
        client = self.get_mongo_client()
        db = client[settings.MONGODB_SETTINGS['db']]
        collection = db[collection_name]
        return collection.find()

    def process_and_store_logs(self):
        collections = ['systemlogs', 'applicationlogs', 'securitylogs']
        
        for collection_name in collections:
            logs = self.fetch_logs_from_collection(collection_name)
            
            for log in logs:
                WindowsAlert.objects.create(
                    event_id=log.get('Id'),
                    entry_type=log.get('LevelDisplayName'),
                    provider=log.get('ProviderName'),
                    message=log.get('Message'),
                    timestamp=log.get('Timecreated'),
                    source_name=collection_name  # Assuming source_name is the collection name
                )

    def handle(self, *args, **options):
        self.process_and_store_logs()
        self.stdout.write(self.style.SUCCESS('Successfully processed and stored logs'))
