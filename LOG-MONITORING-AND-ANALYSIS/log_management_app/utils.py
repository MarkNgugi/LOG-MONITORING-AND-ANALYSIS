# utils.py
from pymongo import MongoClient
from django.conf import settings
from log_management_app.models import WindowsAlert


def get_mongo_client():
    return MongoClient(settings.MONGODB_SETTINGS['host'])

def fetch_logs_from_collection(collection_name):
    client = get_mongo_client()
    db = client[settings.MONGODB_SETTINGS['db']]
    collection = db[collection_name]
    return collection.find()

def process_and_store_logs():
    collections = ['systemlogs', 'applicationlogs', 'securitylogs']
    
    for collection_name in collections:
        logs = fetch_logs_from_collection(collection_name)
        
        for log in logs:
            WindowsAlert.objects.create(
                event_id=log.get('Id'),
                entry_type=log.get('LevelDisplayName'),
                provider=log.get('ProviderName'),
                message=log.get('Message'),
                timestamp=log.get('Timecreated'),
                source_name=collection_name  # Assuming source_name is the collection name
            )

if __name__ == "__main__":
    process_and_store_logs()
