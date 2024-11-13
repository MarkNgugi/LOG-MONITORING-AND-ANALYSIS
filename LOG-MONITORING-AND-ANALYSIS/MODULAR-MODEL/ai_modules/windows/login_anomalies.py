import os
import sys
import django

# Add the Django project root (where manage.py is located) to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
sys.path.append(project_root)

# Set the Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
django.setup()

# Import the LogEntry model from the log_management_app
from log_management_app.models import LogEntry

def print_items():
    items = LogEntry.objects.all()  # Fetch all LogEntry records from the database
    for item in items:
        print(item)  # Print the string representation defined in __str__()

if __name__ == '__main__':
    print_items()
