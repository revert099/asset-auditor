"""
    macOS specific collectors and utilities.
""" 

import platform # used for OS detection, Hardware information
import objc  # used for macOS-specific system calls
import SystemConfiguration


def get_mac_network_info():
    """Retrieve macOS network information using pyobjc."""

    network_info = []
    networks = SystemConfiguration.SCNetworkInterfaceCopyAll()

    for network in networks:
        interface_info = {
            "name": SystemConfiguration.SCNetworkInterfaceGetLocalizedDisplayName(network),
            "type": SystemConfiguration.SCNetworkInterfaceGetInterfaceType(network),
            "bsd_name": SystemConfiguration.SCNetworkInterfaceGetBSDName(network),
        }
        network_info.append(interface_info)

    return network_info
    

