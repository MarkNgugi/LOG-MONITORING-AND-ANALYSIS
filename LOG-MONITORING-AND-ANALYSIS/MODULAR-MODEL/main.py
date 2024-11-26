import os
import sys
import importlib
from django.core.wsgi import get_wsgi_application

# Set up Django environment
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LOG_MONITORING_AND_ANALYSIS.settings')
application = get_wsgi_application()

from tasks.schedule_analysis import schedule_tasks
from user_management_app.models import User

MODULE_DIR = 'ai_modules'

def run_all_modules(user):
    """Run detection modules for all logs."""
    # Ensure the user passed is valid
    if user is None:
        print("No user found. Exiting...")
        return

    users = User.objects.filter(id=user.id)

    for os_name in os.listdir(MODULE_DIR):
        os_path = os.path.join(MODULE_DIR, os_name)
        if os.path.isdir(os_path):
            for module_file in os.listdir(os_path):
                if module_file.endswith(".py"):
                    module_name = f"{MODULE_DIR}.{os_name}.{module_file[:-3]}"
                    module = importlib.import_module(module_name)
                    if hasattr(module, "detect_alerts"):
                        print(f"Running {module_name}")

                        for user in users:
                            print(f"Running alert detection for user: {user}")
                            module.detect_alerts(user)

if __name__ == "__main__":
    # Example: Retrieve the first user in the database
    user = User.objects.first()  # Get the first user; you can modify this logic
    if user:
        print(f"Running detection for user: {user}")
        run_all_modules(user)  # Pass the user to the function

        # Schedule tasks (pass the user argument as well)
        schedule_tasks(run_all_modules, user=user)
    else:
        print("No user found.")
