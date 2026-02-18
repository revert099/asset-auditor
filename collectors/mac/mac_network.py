from collectors.mac import run_cmd
from typing import Any

def get_mac_default_route() -> dict[str, Any]:
    """
    macOS: default route (gateway + primary interface) via `route -n get default`.
    Returns a JSON-friendly dict with parsed fields + evidence.
    """
    rc, stdout, stderr = run_cmd(["route", "-n", "get", "default"])

    evidence = {
        "cmd": "route -n get default",
        "rc": rc,
        "stdout": stdout,
        "stderr": stderr,
    }

    if rc != 0:
        return {
            "not_checked": True,
            "error": stderr or stdout or "route command failed",
            "remediation": "Run with appropriate permissions and ensure the route command is available.",
            "gateway": None,
            "interface": None,
            "flags": None,
            "evidence": evidence,
        }

    # Keys we want to extract from the stdout
    fields = {"gateway:": "gateway", "interface:": "interface", "flags:": "flags"}
    parsed: dict[str, Any] = {"gateway": None, "interface": None, "flags": None}

    # Parse line-by-line (route output is key: value style)
    for line in stdout.splitlines():
        s = line.strip()
        for prefix, out_key in fields.items():
            if s.startswith(prefix):
                # Split only this line at the first ":" and take the value part.
                # Example: "gateway: 192.168.1.1" -> "192.168.1.1"
                parts = s.split(":", 1)
                parsed[out_key] = parts[1].strip() if len(parts) == 2 else None

    return {
        "destination": "default",
        "not_checked": False,
        "error": None,
        "remediation": None,
        **parsed,
        "evidence": evidence,
    }


def get_mac_dns_config() -> dict[str, Any]:
    """
    macOS DNS resolver inventory via `scutil --dns`.
    Returns nameservers + search domains (deduped, order-preserving) plus evidence.
    """
    rc, stdout, stderr = run_cmd(["scutil", "--dns"])

    evidence = {
        "cmd": "scutil --dns",
        "rc": rc,
        "stdout": stdout,
        "stderr": stderr,
    }

    if rc != 0:
        return {
            "not_checked": True,
            "error": stderr or stdout or "scutil --dns failed",
            "remediation": "Ensure scutil is available and run with appropriate permissions.",
            "nameservers": [],
            "search_domains": [],
            "evidence": evidence,
        }

    nameservers: list[str] = []
    search_domains: list[str] = []

    for line in stdout.splitlines():
        s = line.strip()

        # Example: "nameserver[0] : 1.1.1.1"
        if s.startswith("nameserver[") and ":" in s:
            value = s.split(":", 1)[1].strip()
            if value and value not in nameservers:
                nameservers.append(value)
            continue

        # Example: "search domain[0] : corp.example.com"
        if s.startswith("search domain[") and ":" in s:
            value = s.split(":", 1)[1].strip()
            if value and value not in search_domains:
                search_domains.append(value)
            continue

    return {
        "nameservers": nameservers,
        "search_domains": search_domains,
        "not_checked": False,
        "error": None,
        "remediation": None,
        "evidence": evidence,
    }


def get_mac_proxy_config() -> dict[str, Any]:
    """
    macOS proxy configuration via `scutil --proxy`.

    Returns a JSON-friendly dict with:
      - http/https/socks proxy settings (enabled/host/port)
      - PAC settings (enabled/url)
      - exceptions list (best-effort)
      - evidence (cmd/rc/stdout/stderr)
    """
    rc, stdout, stderr = run_cmd(["scutil", "--proxy"])

    evidence = {
        "cmd": "scutil --proxy",
        "rc": rc,
        "stdout": stdout,
        "stderr": stderr,
    }

    if rc != 0:
        return {
            "not_checked": True,
            "error": stderr or stdout or "scutil --proxy failed",
            "remediation": "Ensure scutil is available and run with appropriate permissions.",
            "http": {"enabled": None, "host": None, "port": None},
            "https": {"enabled": None, "host": None, "port": None},
            "socks": {"enabled": None, "host": None, "port": None},
            "pac": {"enabled": None, "url": None},
            "exceptions": [],
            "evidence": evidence,
        }

    # ---- 1) Parse simple "Key : Value" pairs into a dict ----
    kv: dict[str, str] = {}
    lines = stdout.splitlines()

    for line in lines:
        s = line.strip()
        # scutil output is generally "Key : Value"
        if ":" not in s:
            continue
        key, val = s.split(":", 1)
        key = key.strip()
        val = val.strip()
        if key:
            kv[key] = val

    # ---- 2) Small helpers to convert types ----
    def _bool_from_01(v: str | None) -> bool | None:
        if v is None:
            return None
        if v == "1":
            return True
        if v == "0":
            return False
        return None

    def _int_or_none(v: str | None) -> int | None:
        if v is None:
            return None
        try:
            return int(v)
        except Exception:
            return None

    # ---- 3) Build structured output ----
    http_enabled = _bool_from_01(kv.get("HTTPEnable"))
    https_enabled = _bool_from_01(kv.get("HTTPSEnable"))
    socks_enabled = _bool_from_01(kv.get("SOCKSEnable"))

    pac_enabled = _bool_from_01(kv.get("ProxyAutoConfigEnable"))
    pac_url = kv.get("ProxyAutoConfigURLString")

    # ---- 4) Best-effort ExceptionsList parsing ----
    # scutil sometimes prints ExceptionsList on one line, sometimes as a block/array.
    # MVP approach:
    #   - if there’s a scalar line "ExceptionsList : ..." capture it
    #   - plus: capture quoted items inside the block if present (best-effort)
    exceptions: list[str] = []
    in_exceptions_block = False

    for line in lines:
        s = line.strip()

        # Start of the ExceptionsList section
        if s.startswith("ExceptionsList"):
            # Could be "ExceptionsList : <array> {"
            # or "ExceptionsList : something"
            in_exceptions_block = True

            # If there is a value on the same line after ":", try to parse it lightly
            if ":" in s:
                tail = s.split(":", 1)[1].strip()
                # If it's a simple single token (not an array opener), capture it
                # (rare, but harmless)
                if tail and not tail.startswith("<array>"):
                    exceptions.append(tail)
            continue

        # If we're in the ExceptionsList block, try to extract items.
        if in_exceptions_block:
            # End of array block often contains "}"
            if s.startswith("}"):
                in_exceptions_block = False
                continue

            # Common formats in the block:
            #   0 : localhost
            #   1 : 127.0.0.1
            #   2 : *.local
            #
            # We'll capture text after ":" when it looks like "N : value"
            if ":" in s:
                tail = s.split(":", 1)[1].strip()
                if tail and tail not in exceptions:
                    exceptions.append(tail)

    return {
        "http": {
            "enabled": http_enabled,
            "host": kv.get("HTTPProxy"),
            "port": _int_or_none(kv.get("HTTPPort")),
        },
        "https": {
            "enabled": https_enabled,
            "host": kv.get("HTTPSProxy"),
            "port": _int_or_none(kv.get("HTTPSPort")),
        },
        "socks": {
            "enabled": socks_enabled,
            "host": kv.get("SOCKSProxy"),
            "port": _int_or_none(kv.get("SOCKSPort")),
        },
        "pac": {
            "enabled": pac_enabled,
            "url": pac_url,
        },
        "exceptions": exceptions,
        "not_checked": False,
        "error": None,
        "remediation": None,
        "evidence": evidence,
    }