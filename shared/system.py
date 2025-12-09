"""
    Shared utility functions for system information retrieval.
"""
import platform

def get_system_info():
    """Retrieve basic system information."""
    system_info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }
    return system_info

def get_os():
    """
        Returns a value based on the current operating system.
        Used in main.py as a switch case for different OS-specific implementations.
    """
    operating_system = platform.system()
    switcher = {
        "Windows": "This is Windows OS",
        "Linux": "This is Linux OS",
        "Darwin": "This is macOS",
    }
    return switcher.get(operating_system, "Unknown Operating System")