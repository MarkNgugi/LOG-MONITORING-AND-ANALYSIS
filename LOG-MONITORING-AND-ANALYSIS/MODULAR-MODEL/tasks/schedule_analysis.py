import time
from datetime import datetime

def schedule_tasks(task_function, user, interval=10):
    """Run the given task function at fixed intervals, passing the user argument."""
    while True:
        print(f"Running scheduled tasks at {datetime.now()}")
        task_function(user)  # Pass the user argument to the task function
        time.sleep(interval)
