"""
    Main entry point for the Asset Auditing tool
"""
from shared.system import get_system_info, get_os
from shared.hardware import get_cpu_info
from collectors.mac import get_mac_network_info


def main():
    """
        Idea of this eventually is to store results based on an OS switch into a large dict then use formatter.py to generate a report.
        Right now using it to test individual collectors.
    """

    system_info = get_system_info()
    print("\nSystem Information:")
    for key, value in system_info.items():
        print(f"{key}: {value}")

    cpu_info = get_cpu_info()
    print("\nCPU Information:")
    for key, value in cpu_info.items():
        print(f"{key}: {value}")

    for network in get_mac_network_info():
        print(f"\nNetwork Interface:")
        for key, value in network.items():
            print(f"{key}: {value}")
    


if __name__ == "__main__":
    main()
    