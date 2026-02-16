"""
    Report formatting functions
"""

def print_helper(print_line, dict_item):
    print(f"\n{print_line}:")
    for value in dict_item:
        print(f"\n{dict_item}: {value}")



def print_disk_info(disk_info):
    print("\nPartitions:")
    text = "\n".join(str(part) for part in disk_info)
    print(text)

    for disk in disk_info:
        if "USB" in disk.mountpoint:
            print(f"USB Volume detected at partition {disk.mountpoint}")
        else:
            print(f"No USB device {disk.mountpoint}.")

    return disk_info


def disk_check(disk_info):

   pass