"""
    Main entry point for the Asset Auditing tool
"""
from shared.system import get_system_info, get_os, get_user_information
from shared.hardware import get_cpu_info, get_disk_info, get_battery_info
from collectors.mac import get_mac_network_info, check_mac_firewall_status, check_mac_filevault_status
from reports.formatter import print_disk_info
from core.report import write_json_report

from shared.network import get_net_addr

import os, pwd, subprocess

def main():
    """
        Idea of this eventually is to store results based on an OS switch into a large dict then use formatter.py to generate a report.
        Right now using it to test individual collectors.
    """

    print(get_net_addr())

    system_info = get_system_info()
    print("\nSystem Information:")
    for key, value in system_info.items():
        print(f"{key}: {value}")

    cpu_info = get_cpu_info()
    print("\nCPU Information:")
    for key, value in cpu_info.items():
        print(f"{key}: {value}")

    disk_info = get_disk_info()
    print_disk_info(disk_info)

    for network in get_mac_network_info():
        print(f"\nNetwork Interface:")
        for key, value in network.items():
            print(f"{key}: {value}")

    users = get_user_information()
    print("\nUser Information:")
    for user in users:
        print(f"User: {user.name}, Terminal: {user.terminal}, Host: {user.host}, Started: {user.started} Root?: {os.getuid() == 0}")

    users = pwd.getpwall()
    for u in users:
        if u.pw_uid == 0:
            print(u.pw_name, u.pw_uid, u.pw_dir, u.pw_shell)

    report = {}
    report["firewall"] = check_mac_firewall_status()
    report["filevault"] = check_mac_filevault_status()

    json_path = write_json_report(report, "results/audit_report.json")
    print(f"Wrote {json_path}")

    

if __name__ == "__main__":
    main()
    