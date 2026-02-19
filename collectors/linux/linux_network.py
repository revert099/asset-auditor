from helpers.unix import run_cmd, get_evidence
import os
from typing import Any

# -----------------------------
# 1) Default route / gateway
# -----------------------------
def get_linux_default_route() -> dict[str, Any]:
    """
    Linux: default route (gateway + primary interface).

    Primary command (modern Linux):
      - ip route show default

    Fallback commands (older systems):
      - route -n
      - netstat -rn

    Output (MVP):
      {
        "gateway": "192.168.1.1",
        "interface": "eth0",
        "not_checked": False,
        "error": None,
        "remediation": None,
        "evidence": {...}
      }

    Notes:
      - ip route output is NOT key:value.
        Typical: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
        Parse tokens after "via" (gateway) and "dev" (interface).
    """
    # Try modern command first
    cmd = ["ip", "route", "show", "default"]
    rc, stdout, stderr = run_cmd(cmd)
    evidence = get_evidence(cmd, rc, stdout, stderr)

    gateway: str | None = None
    iface: str | None = None

    if rc == 0 and stdout.strip():
        # Usually one line; still handle multiple lines safely.
        for line in stdout.splitlines():
            s = line.strip()
            if not s:
                continue
            tokens = s.split()

            # Find "via <gateway>"
            if "via" in tokens:
                i = tokens.index("via")
                if i + 1 < len(tokens):
                    gateway = tokens[i + 1]

            # Find "dev <iface>"
            if "dev" in tokens:
                i = tokens.index("dev")
                if i + 1 < len(tokens):
                    iface = tokens[i + 1]

            # If we got something, no need to keep scanning lines.
            if gateway or iface:
                break

        return {
            "gateway": gateway,
            "interface": iface,
            "not_checked": False,
            "error": None,
            "remediation": None,
            "evidence": evidence,
        }

    # Fallback #1: route -n
    # Typical lines include:
    #   Destination Gateway     Genmask ... Iface
    #   0.0.0.0     192.168.1.1 0.0.0.0 ... eth0
    cmd2 = ["route", "-n"]
    rc2, out2, err2 = run_cmd(cmd2)
    evidence2 = get_evidence(cmd2, rc2, out2, err2)

    if rc2 == 0 and out2.strip():
        for line in out2.splitlines():
            s = line.strip()
            if not s or s.lower().startswith("destination") or s.lower().startswith("kernel"):
                continue
            parts = s.split()
            # Heuristic: default route row often has Destination 0.0.0.0 or "default"
            # Columns: Destination Gateway Genmask Flags Metric Ref Use Iface
            if len(parts) >= 8 and (parts[0] == "0.0.0.0" or parts[0].lower() == "default"):
                gateway = parts[1]
                iface = parts[-1]
                break

        return {
            "gateway": gateway,
            "interface": iface,
            "not_checked": False,
            "error": None,
            "remediation": None,
            "evidence": evidence2,
        }

    # Fallback #2: netstat -rn
    # Typical includes a "default" row:
    #   default  192.168.1.1  ...  eth0
    cmd3 = ["netstat", "-rn"]
    rc3, out3, err3 = run_cmd(cmd3)
    evidence3 = get_evidence(cmd3, rc3, out3, err3)

    if rc3 == 0 and out3.strip():
        for line in out3.splitlines():
            s = line.strip()
            if not s:
                continue
            parts = s.split()
            if len(parts) >= 3 and parts[0].lower() == "default":
                gateway = parts[1]
                # Interface column varies; usually last column is iface
                iface = parts[-1]
                break

        return {
            "gateway": gateway,
            "interface": iface,
            "not_checked": False,
            "error": None,
            "remediation": None,
            "evidence": evidence3,
        }

    # If everything failed
    return {
        "gateway": None,
        "interface": None,
        "not_checked": True,
        "error": stderr or stdout or err2 or out2 or err3 or out3 or "Could not determine default route",
        "remediation": "Ensure iproute2 is installed (ip command) or provide route/netstat; run with appropriate permissions.",
        "evidence": {
            "primary": evidence,
            "fallback_route": evidence2,
            "fallback_netstat": evidence3,
        },
    }


# -----------------------------
# 2) DNS configuration
# -----------------------------
def get_linux_dns_config() -> dict[str, Any]:
    """
    Linux: DNS configuration (nameservers + search domains).

    Preferred (systemd-resolved environments):
      - resolvectl status

    Fallback:
      - parse /etc/resolv.conf

    Output:
      {
        "source": "resolvectl" | "resolv.conf",
        "nameservers": ["1.1.1.1", "8.8.8.8"],
        "search_domains": ["corp.example.com"],
        "not_checked": False,
        "error": None,
        "remediation": None,
        "evidence": {...}
      }

    Notes:
      - /etc/resolv.conf may point to a stub resolver (e.g. 127.0.0.53).
        That’s still useful; you can treat it as "local stub" later in scoring.
    """
    nameservers: list[str] = []
    search_domains: list[str] = []

    # Try resolvectl first
    cmd = ["resolvectl", "status"]
    rc, stdout, stderr = run_cmd(cmd)
    evidence = get_evidence(cmd, rc, stdout, stderr)

    if rc == 0 and stdout.strip():
        # resolvectl format varies, but common lines include:
        #   DNS Servers: 1.1.1.1 8.8.8.8
        #   DNS Domain: corp.example.com
        for line in stdout.splitlines():
            s = line.strip()

            # DNS Servers: <ip> <ip> ...
            if s.startswith("DNS Servers:"):
                tail = s.split(":", 1)[1].strip()
                for tok in tail.split():
                    if tok and tok not in nameservers:
                        nameservers.append(tok)

            # DNS Domain: <domain> (sometimes multiple)
            if s.startswith("DNS Domain:"):
                tail = s.split(":", 1)[1].strip()
                for tok in tail.split():
                    if tok and tok not in search_domains:
                        search_domains.append(tok)

            # Some versions show "Domains:" or "Search Domains:"
            if s.startswith("Domains:") or s.startswith("Search Domains:"):
                tail = s.split(":", 1)[1].strip()
                for tok in tail.split():
                    if tok and tok not in search_domains:
                        search_domains.append(tok)

        return {
            "source": "resolvectl",
            "nameservers": nameservers,
            "search_domains": search_domains,
            "not_checked": False,
            "error": None,
            "remediation": None,
            "evidence": evidence,
        }

    # Fallback: /etc/resolv.conf
    path = "/etc/resolv.conf"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception as e:
        return {
            "source": None,
            "nameservers": [],
            "search_domains": [],
            "not_checked": True,
            "error": f"{type(e).__name__}: {e}",
            "remediation": "Could not read /etc/resolv.conf; run with appropriate permissions or check file existence.",
            "evidence": {"resolvectl": evidence, "resolv_conf_path": path},
        }

    # Parse resolv.conf style:
    #   nameserver 1.1.1.1
    #   search corp.example.com example.com
    #   domain corp.example.com
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue

        if s.startswith("nameserver"):
            parts = s.split()
            if len(parts) >= 2:
                ns = parts[1]
                if ns not in nameservers:
                    nameservers.append(ns)

        if s.startswith("search"):
            parts = s.split()
            for dom in parts[1:]:
                if dom and dom not in search_domains:
                    search_domains.append(dom)

        if s.startswith("domain"):
            parts = s.split()
            if len(parts) >= 2:
                dom = parts[1]
                if dom not in search_domains:
                    search_domains.append(dom)

    return {
        "source": "resolv.conf",
        "nameservers": nameservers,
        "search_domains": search_domains,
        "not_checked": False,
        "error": None,
        "remediation": None,
        "evidence": {
            "resolvectl": evidence,
            "resolv_conf_path": path,
            # keep the file content short in evidence if you prefer; or store full text
            "resolv_conf_preview": "\n".join(text.splitlines()[:50]),
        },
    }


# -----------------------------
# 3) Proxy configuration
# -----------------------------
def get_linux_proxy_config() -> dict[str, Any]:
    """
    Linux: proxy configuration (best-effort).

    Linux is not standardised like macOS/Windows for proxies.
    MVP sources (shared, offline, non-invasive):
      - environment variables:
          HTTP_PROXY / HTTPS_PROXY / NO_PROXY
          http_proxy / https_proxy / no_proxy
      - /etc/environment (optional; common place for system-wide env vars)

    Output:
      {
        "http_proxy": "http://proxy:8080" | None,
        "https_proxy": "http://proxy:8080" | None,
        "no_proxy": "localhost,127.0.0.1,..." | None,
        "sources": ["env", "etc_environment"],
        "not_checked": False,
        "error": None,
        "remediation": None,
        "evidence": {...}
      }

    Notes:
      - We DO NOT make any network calls.
      - If you later support desktop proxies (GNOME/KDE), that becomes optional OS/env-specific logic.
    """
    def _get_env_any(*keys: str) -> str | None:
        for k in keys:
            v = os.environ.get(k)
            if v:
                return v.strip()
        return None

    http_proxy = _get_env_any("HTTP_PROXY", "http_proxy")
    https_proxy = _get_env_any("HTTPS_PROXY", "https_proxy")
    no_proxy = _get_env_any("NO_PROXY", "no_proxy")

    sources: list[str] = []
    if http_proxy or https_proxy or no_proxy:
        sources.append("env")

    # Optional: read /etc/environment (common system-wide env file)
    etc_env_path = "/etc/environment"
    etc_env_text = None
    try:
        with open(etc_env_path, "r", encoding="utf-8", errors="replace") as f:
            etc_env_text = f.read()
    except Exception:
        etc_env_text = None

    # Best-effort parse of /etc/environment:
    # Lines like:
    #   http_proxy="http://proxy:8080"
    #   https_proxy=http://proxy:8080
    if etc_env_text:
        for line in etc_env_text.splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")

            if k in ("HTTP_PROXY", "http_proxy") and not http_proxy and v:
                http_proxy = v
                sources.append("etc_environment")
            if k in ("HTTPS_PROXY", "https_proxy") and not https_proxy and v:
                https_proxy = v
                if "etc_environment" not in sources:
                    sources.append("etc_environment")
            if k in ("NO_PROXY", "no_proxy") and not no_proxy and v:
                no_proxy = v
                if "etc_environment" not in sources:
                    sources.append("etc_environment")

    # No true "run_cmd" evidence here since it’s environment/file-based
    evidence = {
        "env_present": {
            "HTTP_PROXY": bool(os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")),
            "HTTPS_PROXY": bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")),
            "NO_PROXY": bool(os.environ.get("NO_PROXY") or os.environ.get("no_proxy")),
        },
        "etc_environment_path": etc_env_path,
        "etc_environment_preview": None if not etc_env_text else "\n".join(etc_env_text.splitlines()[:50]),
    }

    return {
        "http_proxy": http_proxy,
        "https_proxy": https_proxy,
        "no_proxy": no_proxy,
        "sources": sources,
        "not_checked": False,
        "error": None,
        "remediation": None,
        "evidence": evidence,
    }