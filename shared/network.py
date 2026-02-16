import psutil
from typing import Any

from typing import Any
import psutil
import socket

def _family_to_label(fam: object) -> str:
    """
    Convert address family to a readable label for JSON output.
    (psutil returns platform-specific family values.)
    """
    try:
        if fam == socket.AF_INET:
            return "IPv4"
        if fam == socket.AF_INET6:
            return "IPv6"
    except Exception:
        pass

    # MAC address family differs by OS (AF_LINK on mac/BSD, AF_PACKET on Linux)
    # We’ll label these generically as MAC when we see common names.
    name = getattr(fam, "name", None)
    if isinstance(name, str) and ("LINK" in name or "PACKET" in name):
        return "MAC"

    # Fallback: string form
    return str(fam)


def get_net_addr() -> list[dict[str, Any]]:
    """
    Returns JSON-friendly network interface inventory combining:
      - psutil.net_if_addrs(): IPs + MACs per interface
      - psutil.net_if_stats(): up/down, speed, duplex, MTU (where available)
    """
    results: list[dict[str, Any]] = []

    if_addr = psutil.net_if_addrs()   # dict[str, list[snicaddr]]
    if_stats = psutil.net_if_stats()  # dict[str, snicstats]

    for iface_name, addr_list in if_addr.items():
        stats = if_stats.get(iface_name)

        iface_record: dict[str, Any] = {
            "name": iface_name,
            "stats": None if stats is None else {
                "isup": stats.isup,
                "duplex": getattr(stats.duplex, "name", str(stats.duplex)),
                "speed_mbps": stats.speed,
                "mtu": stats.mtu,
            },
            "addresses": []
        }

        for a in addr_list:
            iface_record["addresses"].append({
                "family": _family_to_label(a.family),
                "address": a.address,
                "netmask": getattr(a, "netmask", None),
                "broadcast": getattr(a, "broadcast", None),
                "ptp": getattr(a, "ptp", None),
            })

        results.append(iface_record)

    return results

def get_net_():
    pass










"""FYI

    What you can’t do cleanly cross-platform with only psutil

These usually require OS-native commands (so you’d still keep them behind the same shared interface, but platform branches inside):

3) Default gateway / routing table
	•	macOS/Linux: netstat -rn or route -n / ip route
	•	Windows: route print or PowerShell cmdlets

4) DNS servers
	•	macOS: scutil --dns
	•	Windows: ipconfig /all or PowerShell (Get-DnsClientServerAddress)
	•	Linux: /etc/resolv.conf or resolvectl status (systemd-resolved)

5) Wi-Fi SSID / security type
	•	macOS: airport -I (or system_profiler SPAirPortDataType)
	•	Windows: netsh wlan show interfaces
	•	Linux: nmcli or iw dev

6) VPN detection (best-effort)

Cross-platform heuristic via interface names + routes, but “real” detection tends to be OS-specific.

"""