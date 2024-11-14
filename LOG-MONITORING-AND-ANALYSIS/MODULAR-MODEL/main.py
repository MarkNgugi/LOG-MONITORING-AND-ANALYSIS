import os
import importlib
from tasks.schedule_analysis import schedule_tasks

# Directory where AI modules are located
MODULE_DIR = 'ai_modules'

def run_all_modules():
    # Loop through each OS folder and each module in that folder
    for os_name in os.listdir(MODULE_DIR):
        os_path = os.path.join(MODULE_DIR, os_name)
        if os.path.isdir(os_path):
            for module_file in os.listdir(os_path):
                if module_file.endswith(".py"):
                    module_name = f"{MODULE_DIR}.{os_name}.{module_file[:-3]}"  
                    module = importlib.import_module(module_name)
                    if hasattr(module, "detect_anomalies_and_alerts"):
                        print(f"Running {module_name}")
                        module.detect_anomalies_and_alerts()

if __name__ == "__main__":
    # Run all detection modules
    run_all_modules()
    
    # Schedule periodic tasks, passing the `run_all_modules` function
    schedule_tasks(run_all_modules)
