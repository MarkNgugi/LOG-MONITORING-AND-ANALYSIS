import time
from datetime import datetime

def schedule_tasks(task_function, interval=10):
    """Run the given task function at fixed intervals."""
    while True:
        print(f"Running scheduled tasks at {datetime.now()}")
        task_function()
        time.sleep(interval)
