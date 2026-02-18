from typing import Any
import psutil
import socket

def _family_to_label(fam: object) -> str:
    """
    Convert a psutil "address family" value into a human-readable label.

    Why this exists:
      - psutil returns families as platform-specific values (enums / ints)
      - For client/audit JSON, it's nicer to see "IPv4", "IPv6", "MAC"

    Common families you’ll see:
      - AF_INET   -> IPv4
      - AF_INET6  -> IPv6
      - AF_LINK   -> MAC (macOS/BSD)
      - AF_PACKET -> MAC (Linux)
    """
    # socket.AF_INET / socket.AF_INET6 are stable cross-platform constants
    try:
        if fam == socket.AF_INET:
            return "IPv4"
        if fam == socket.AF_INET6:
            return "IPv6"
    except Exception:
        # Very defensive: if comparing fails for any reason, just continue
        pass

    # MAC address family differs per OS. Sometimes the family is an Enum
    # whose .name contains "AF_LINK" (macOS/BSD) or "AF_PACKET" (Linux).
    name = getattr(fam, "name", None)
    if isinstance(name, str) and ("LINK" in name or "PACKET" in name):
        return "MAC"

    # Fallback: store whatever representation we got. This avoids crashing
    # and still preserves useful information for later debugging.
    return str(fam)

def _laddr_ip_port(laddr: Any) -> tuple[str | None, int | None]:
    """
    laddr can be:
      - a tuple: (ip, port)
      - a namedtuple with .ip and .port
    """
    if not laddr:
        return None, None
    ip = getattr(laddr, "ip", None)
    port = getattr(laddr, "port", None)
    if ip is not None and port is not None:
        return ip, port
    # fall back to tuple indexing
    try:
        return laddr[0], laddr[1]
    except Exception:
        return None, None


def get_net_addr() -> list[dict[str, Any]]:
    """
    Return a JSON-friendly inventory of network interfaces.

    This is "inventory" data (facts), not a security PASS/FAIL check.

    Data sources:
      - psutil.net_if_addrs():
          Returns a dict mapping interface name -> list of address entries.
          Each address entry may include:
            * family   (IPv4/IPv6/MAC family)
            * address  (IP string or MAC string)
            * netmask/broadcast/ptp (sometimes present, platform-dependent)

      - psutil.net_if_stats():
          Returns a dict mapping interface name -> a stats entry containing:
            * isup   (True/False)
            * duplex (enum/int)
            * speed  (Mbps, can be 0 or unknown)
            * mtu    (integer, can be 0 or unknown)

    Output shape (per interface):
      {
        "name": "en0",
        "stats": { "isup": true, "duplex": "...", "speed_mbps": 1000, "mtu": 1500 },
        "addresses": [
          { "family": "MAC",  "address": "aa:bb:cc:...", ... },
          { "family": "IPv4", "address": "192.168.1.10", "netmask": "...", ... },
          { "family": "IPv6", "address": "fe80::....", ... }
        ]
      }
    """
    results: list[dict[str, Any]] = []

    # net_if_addrs(): dict[str, list[snicaddr]]
    # Example:
    #   {
    #     "en0": [snicaddr(...), snicaddr(...), ...],
    #     "lo0": [...],
    #   }
    if_addr = psutil.net_if_addrs()

    # net_if_stats(): dict[str, snicstats]
    # Example:
    #   {
    #     "en0": snicstats(isup=True, duplex=..., speed=1000, mtu=1500),
    #     "lo0": snicstats(...),
    #   }
    if_stats = psutil.net_if_stats()

    # Outer loop: iterate interfaces by name.
    # iface_name is a string like "en0", "lo0", "Wi-Fi", "Ethernet".
    # addr_list is a list of address entries for that interface.
    for iface_name, addr_list in if_addr.items():
        # Stats are a separate dict. Some interfaces might not have stats,
        # so we use .get() and handle None.
        stats = if_stats.get(iface_name)

        # Build the record for THIS interface.
        iface_record: dict[str, Any] = {
            # The interface name is the key that ties everything together.
            "name": iface_name,

            # Stats can be missing, especially for odd/virtual interfaces.
            # We store None rather than crashing.
            "stats": None if stats is None else {
                # True/False if the interface is currently up.
                "isup": stats.isup,

                # Duplex may be an enum/int. Use .name if present, otherwise str().
                "duplex": getattr(stats.duplex, "name", str(stats.duplex)),

                # Link speed in Mbps. Often 0/unknown on some adapters.
                "speed_mbps": stats.speed,

                # MTU size. Sometimes 0/unknown depending on platform.
                "mtu": stats.mtu,
            },

            # Each interface can have multiple address entries:
            # MAC + IPv4 + IPv6, sometimes multiple IPv6 or multiple IPv4.
            "addresses": [],
        }

        # Inner loop: iterate the address entries for THIS interface.
        # These entries have fields like family/address/netmask/broadcast/ptp.
        for a in addr_list:
            iface_record["addresses"].append({
                # Convert family enum/int into a readable label.
                "family": _family_to_label(a.family),

                # The actual IP or MAC string.
                "address": a.address,

                # These fields exist only sometimes. getattr keeps it safe.
                "netmask": getattr(a, "netmask", None),
                "broadcast": getattr(a, "broadcast", None),
                "ptp": getattr(a, "ptp", None),
            })

        # Add this interface to the output list.
        results.append(iface_record)

    return results


def get_listening_ports() -> dict[str, Any]:
    """
    Best-effort exposure snapshot (shared/psutil-only):
      - TCP listeners: status == CONN_LISTEN
      - UDP bound sockets: type == SOCK_DGRAM and laddr has a port

    Important:
      - On macOS, psutil.net_connections() may raise AccessDenied unless run as sudo/root.
      - This function must NEVER crash the whole audit; it returns a structured error.
    """
    tcp_results: list[dict[str, Any]] = []
    udp_results: list[dict[str, Any]] = []

    # ---- Step 1: Acquire connections (this is the privileged call) ----
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as e:
        # Return a JSON-friendly structure your report builder can store.
        return {
            "tcp": [],
            "udp": [],
            "not_checked": True,
            "error": f"{type(e).__name__}: {e}",
            "remediation": "Run the audit with elevated privileges (sudo/root) to enumerate system-wide listening sockets."
        }
    except OSError as e:
        # Some platforms may raise OSError for other reasons (rare).
        return {
            "tcp": [],
            "udp": [],
            "not_checked": True,
            "error": f"{type(e).__name__}: {e}",
            "remediation": "Could not enumerate sockets due to an OS error. Try running as sudo/root and re-test."
        }

    # ---- Step 2: Parse and categorise results ----
    for c in conns:
        ip, port = _laddr_ip_port(c.laddr)
        if port is None:
            continue

        fam = _family_to_label(c.family)
        pid = c.pid

        # Best-effort process name (may fail even when conns succeeded)
        proc_name = None
        if pid is not None:
            try:
                proc_name = psutil.Process(pid).name()
            except Exception:
                proc_name = None

        # TCP listener
        if c.type == socket.SOCK_STREAM and c.status == psutil.CONN_LISTEN:
            tcp_results.append({
                "ip": ip,
                "port": port,
                "family": fam,
                "pid": pid,
                "process_name": proc_name,
            })
            continue

        # UDP bound socket (no LISTEN state for UDP)
        if c.type == socket.SOCK_DGRAM:
            udp_results.append({
                "ip": ip,
                "port": port,
                "family": fam,
                "pid": pid,
                "process_name": proc_name,
            })

    return {
        "tcp": tcp_results,
        "udp": udp_results,
        "not_checked": False,
        "error": None,
        "remediation": None
    }