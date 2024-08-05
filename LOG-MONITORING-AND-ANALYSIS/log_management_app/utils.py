# utils.py
from pymongo import MongoClient
from django.conf import settings
from .models import Alert
import json

# Load Event ID to Alert Level mapping from a JSON file
def load_event_id_config():
    with open('log_management_app/configs/windows/event_ids_config.json', 'r') as file:
        return json.load(file)

def get_mongo_client():
    return MongoClient(settings.MONGODB_SETTINGS['host'])

def fetch_logs_from_mongo():
    client = get_mongo_client()
    db = client[settings.MONGODB_SETTINGS['db']]
    collection = db['logstest']
    return collection.find()

def categorize_log(log_entry, event_id_config):
    event_id = log_entry.get('event_id')
    
    # Determine the alert level based on the event_id_config
    alert_level = event_id_config.get(event_id, 'Unknown')  # Default to 'Unknown' if not found
    
    return alert_level

def process_and_store_logs():
    logs = fetch_logs_from_mongo()
    event_id_config = load_event_id_config()
    
    for log in logs:
        alert_level = categorize_log(log, event_id_config)
        Alert.objects.create(
            event_id=log.get('event_id'),
            description=log.get('description'),
            alert_level=alert_level,
            source_name=log.get('source_name'),
            timestamp=log.get('timestamp'),
        )
