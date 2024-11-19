# MODULAR-MODEL/main.py
import os
import importlib
from tasks.schedule_analysis import schedule_tasks

MODULE_DIR = 'ai_modules'

def run_all_modules():
    """Run detection modules for all logs."""
    for os_name in os.listdir(MODULE_DIR):
        os_path = os.path.join(MODULE_DIR, os_name)
        if os.path.isdir(os_path):
            for module_file in os.listdir(os_path):
                if module_file.endswith(".py"):
                    module_name = f"{MODULE_DIR}.{os_name}.{module_file[:-3]}"
                    module = importlib.import_module(module_name)
                    if hasattr(module, "detect_alerts"):
                        print(f"Running {module_name}")
                        module.detect_alerts()

if __name__ == "__main__":
    run_all_modules()
    schedule_tasks(run_all_modules)
 