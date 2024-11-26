import os
import importlib
from tasks.schedule_analysis import schedule_tasks
from ..user_management_app.models import User

import sys

# Add the project root to the Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(project_root)

MODULE_DIR = 'ai_modules'

def run_all_modules():
    """Run detection modules for all logs."""
    # Get users from the database or choose a specific user
    users = User.objects.all()  # You can filter specific users if needed, or use one user

    for os_name in os.listdir(MODULE_DIR):
        os_path = os.path.join(MODULE_DIR, os_name)
        if os.path.isdir(os_path):
            for module_file in os.listdir(os_path):
                if module_file.endswith(".py"):
                    module_name = f"{MODULE_DIR}.{os_name}.{module_file[:-3]}"
                    module = importlib.import_module(module_name)
                    if hasattr(module, "detect_alerts"):
                        print(f"Running {module_name}")
                        
                        # Loop through users and call detect_alerts for each
                        for user in users:
                            print(f"Running alert detection for user: {user}")
                            module.detect_alerts(user)  # Pass the user argument to detect_alerts

if __name__ == "__main__":
    run_all_modules()
    schedule_tasks(run_all_modules)
