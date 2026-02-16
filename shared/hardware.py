import psutil # https://pypi.org/project/psutil/
from typing import Any

# -----------------------------
# CPU Information
# -----------------------------
def get_cpu_info():
    """
    Return CPU information in a JSON-friendly dict.

    Notes:
      - cpu_freq() can return None on some platforms/VMs.
      - cpu_percent() without an interval is a quick snapshot (may be 0.0 on first call).
    """
    freq = psutil.cpu_freq()
    cpu_times = psutil.cpu_times()

    return {
        "physical_cores": psutil.cpu_count(logical=False),
        "total_cores": psutil.cpu_count(logical=True),
        "frequency_mhz": None if freq is None else {
            "max": freq.max,
            "min": freq.min,
            "current": freq.current,
        },
        "usage_percent": {
            "per_core": psutil.cpu_percent(percpu=True),
            "total": psutil.cpu_percent(),
        },
        "cpu_times": cpu_times._asdict() if cpu_times else None,
    }


# -----------------------------
# Battery Information
# -----------------------------
def get_battery_info():
    """
    Return battery information in a JSON-friendly dict, or None if not present.

    Notes:
      - Many desktops and some VMs return None.
    """
    b = psutil.sensors_battery()
    if not b:
        return None

    # asdict fields commonly include: percent, secsleft, power_plugged
    return b._asdict()


# -----------------------------
# Memory Information
# -----------------------------
def get_memory_info():
    """
    Return memory information in a JSON-friendly dict.
    """
    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()

    return {
        "virtual_memory": vm._asdict() if vm else None,
        "swap_memory": sm._asdict() if sm else None,
    }

# Disk Information
def get_disk_info() -> list[dict[str, Any]]:
    """
    Return a clean, JSON-friendly list where each item contains:
      - partition details (device, mountpoint, fstype, opts)
      - usage details (total, used, free, percent)
    If disk_usage fails for a mount (permissions, removable media, pseudo FS),
    we store the error and continue.
    """
    results: list[dict[str, Any]] = []
    partitions = psutil.disk_partitions(all=False)

    for p in partitions:
        record: dict[str, Any] = {
            "device": p.device,
            "mountpoint": p.mountpoint,
            "fstype": p.fstype,
            "opts": p.opts,
        }

        try:
            u = psutil.disk_usage(p.mountpoint)
            record["usage"] = {
                "total": u.total,
                "used": u.used,
                "free": u.free,
                "percent": u.percent,
            }
        except Exception as e:
            record["usage"] = None
            record["error"] = f"{type(e).__name__}: {e}"

        results.append(record)

    return results


# -----------------------------
# One-call hardware bundle
# -----------------------------
def get_hardware_info():
    """
    Convenience wrapper so main.py can call one function.
    """
    return {
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "battery": get_battery_info(),
        "disk": get_disk_info(),  
    }