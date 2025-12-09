import psutil

def get_cpu_info():
    """
        Placeholder for psutil related utilities.
        Used in main.py for system monitoring and resource management.
    """
    cpu_info = {
        "physical_cores": psutil.cpu_count(logical=False),
        "total_cores": psutil.cpu_count(logical=True),
        "max_frequency": psutil.cpu_freq().max,
        "min_frequency": psutil.cpu_freq().min,
        "current_frequency": psutil.cpu_freq().current,
        "cpu_usage_per_core": psutil.cpu_percent(percpu=True),
        "total_cpu_usage": psutil.cpu_percent(),
    }
    return cpu_info