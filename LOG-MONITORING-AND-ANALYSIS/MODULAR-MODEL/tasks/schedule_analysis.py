import time
from datetime import datetime

def schedule_tasks(task_function, interval=10):  
    while True:
        print(f"Running scheduled tasks at {datetime.now()}")
        task_function()
        time.sleep(interval)
