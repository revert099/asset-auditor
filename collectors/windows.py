import wmi

def get_windows_operating_system_info():
    """
        Retrieve Windows operating system information using WMI.
        Identity and Context - Who/What is this Windows machine.

        Returns:
            dict: A dictionary containing OS information.
    """
    c = wmi.WMI()
    os_info = c.Win32_OperatingSystem()[0]
    system_info = {
        "os_name": os_info.Caption,
        "os_version": os_info.Version,
        "architecture": os_info.OSArchitecture,
        "bios": os_info.BIOSVersion,
        "system_product": os_info.SystemProduct,
        "manufacturer": os_info.Manufacturer,
        "build_number": os_info.BuildNumber,
    }
    return system_info

def get_windows_file_system_info():
    """Retrieve Windows file system information using WMI."""
    c = wmi.WMI()
    file_systems = []
    for fs in c.Win32_LogicalDisk():
        fs_info = {
            "system_directory": fs.SystemDirectory,
            "device_id": fs.DeviceID,
            "file_system": fs.FileSystem,
            "size": fs.Size,
            "free_space": fs.FreeSpace,
            "volume_name": fs.VolumeName,
        }
        file_systems.append(fs_info)
    return file_systems

def get_windows_users():
    """Retrieve Windows user account information using WMI."""
    c = wmi.WMI()
    num_users = c.NumberOfUsers
    # Get user account details
    users = []               # list to hold user account details
    for user in c.Win32_UserAccount():  # iterate through user accounts
        user_info = {
            "name": user.Name,
            "full_name": user.FullName,
            "status": user.Status,
            "sid": user.SID,
            "disabled": user.Disabled,
        }
        users.append(user_info)
    return num_users, users


def get_windows_hardware_details():
    """
        Retrieve Windows hardware details using WMI.
        Hardware and Capacity - What is inside this Windows machine.
    """

    c = wmi.WMI()
    # Initialise hardware details dictionary
    hardware_details = {
        "cpu": [],
        "memory": [],
        "disk_drives": [],
        "network_adapters": [],
    }

    # Get CPU details
    for cpu in c.Win32_Processor():
        cpu_info = {
            "name": cpu.Name,
            "manufacturer": cpu.Manufacturer,
            "max_clock_speed": cpu.MaxClockSpeed,
            "number_of_cores": cpu.NumberOfCores,
        }
        hardware_details["cpu"].append(cpu_info)

    # Get RAM details
    for mem in c.Win32_PhysicalMemory():
        mem_info = {
            "capacity": mem.Capacity,
            "speed": mem.Speed,
            "manufacturer": mem.Manufacturer,
        }
        hardware_details["memory"].append(mem_info)

    # Get Logical Disk details
    for l_disk in c.Win32_LogicalDisk():
        disk_info = {
            "device_id": l_disk.DeviceID,
            "file_system": l_disk.FileSystem,
            "size": l_disk.Size,
            "free_space": l_disk.FreeSpace,
        }
        hardware_details["disk_drives"].append(disk_info)

    # Get Physical Disk details
    for disk in c.Win32_DiskDrive():
        disk_info = {
            "model": disk.Model,
            "size": disk.Size,
            "interface_type": disk.InterfaceType,
        }
        hardware_details["disk_drives"].append(disk_info)

    # Get Network Adapter details
    for adapter in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        adapter_info = {
            "description": adapter.Description,
            "mac_address": adapter.MACAddress,
            "ip_address": adapter.IPAddress,
        }
        hardware_details["network_adapters"].append(adapter_info)

    return hardware_details

def get_windows_security_details():
    """Retrieve Windows security details using WMI."""
    c = wmi.WMI()
    security_details = {
        "antivirus_products": [],
        "firewall_enabled": None,
    }
    # Get Antivirus details
    for av in c.Win32_AntivirusProduct():
        av_info = {
            "name": av.DisplayName,
            "version": av.Version,
            "product_state": av.ProductState,
        }
        security_details["antivirus_products"].append(av_info)

    # Get Firewall details
    for fw in c.Win32_FirewallProduct():
        security_details["firewall_enabled"] = fw.Enabled

    return security_details
