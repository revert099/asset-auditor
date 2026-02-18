"""
    collectors/mac.py
    macOS specific collectors and utilities.
""" 

import platform # used for OS detection, Hardware information
import objc  # used for macOS-specific system calls
import SystemConfiguration
import Security
from core.models import AuditResult, Finding

import subprocess

SFW = "/usr/libexec/ApplicationFirewall/socketfilterfw" # directory to socketfilterfw binary

def run_cmd(cmd: list[str], timeout_s: int = 10) -> tuple[int, str, str]:
    """
    Run a command and return:
      - return code (rc)
      - stdout (string)
      - stderr (string)

    We capture output so we can store it in the AuditResult.evidence field
    for transparency/debugging (useful for client reports too).
    """

    p = subprocess.run(
        cmd,
        text=True,              # decode output to str instead of bytes
        capture_output=True,    # capture stdout/stderr
        timeout=timeout_s
    )

    # Normalise None → "" and strip whitespace
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def _parse_state(output: str) -> int | None:
    """
    socketfilterfw --getglobalstate prints something like:
      "Firewall is enabled. (State = 1)"
      "Firewall is disabled. (State = 0)"

    We only need the numeric state for decision-making.
    Return:
      1 if enabled
      0 if disabled
      2 if some other state appears (occasionally seen)
      None if we can't interpret the output
    """
    if "State = 1" in output:
        return 1
    if "State = 0" in output:
        return 0
    if "State = 2" in output:
        return 2
    return None


def _parse_on_off(output: str) -> bool | None:
    """
    socketfilterfw --getstealthmode / --getblockall prints wording like
    "Stealth mode enabled" or "Stealth mode disabled".

    We do a simple text match:
      - returns True if it contains "enabled"
      - returns False if it contains "disabled"
      - returns None if neither is present (unexpected wording)
    """
    low = output.lower()
    if "enabled" in low:
        return True
    if "disabled" in low:
        return False
    return None


def check_mac_firewall_status() -> AuditResult:
    """
    macOS Firewall check (Application Firewall / ALF).

    What we do:
      1) Ask for global firewall state (on/off) -> PASS or FAIL
      2) Optionally record stealth mode and "block all" settings
      3) Store all raw command output in evidence (auditability)
      4) Return a AuditResult object that your report builder can score/print
    """
    findings: list[Finding] = []
    evidence: dict = {
        "tool": SFW,
        "notes": "Uses macOS Application Firewall (ALF) via socketfilterfw"
    }

    # ---- 1) Query main firewall state (this is the key control) ----
    rc1, out1, err1 = run_cmd([SFW, "--getglobalstate"])
    evidence["getglobalstate"] = {"rc": rc1, "stdout": out1, "stderr": err1}

    # If command fails, we can't conclude anything.
    # Return NOT_CHECKED (so it doesn't get counted as a hard FAIL).
    if rc1 != 0:
        return AuditResult(
            id="firewall",
            name="Firewall status (macOS Application Firewall)",
            weight=10,
            status="NOT_CHECKED",
            score_factor=0.6,
            evidence=evidence,
            findings=[
                Finding(
                    severity="MEDIUM",
                    title="Could not query firewall state",
                    detail=f"socketfilterfw failed (rc={rc1}). {err1 or out1 or ''}".strip(),
                    remediation="Run as sudo/root and confirm the binary exists at /usr/libexec/ApplicationFirewall/socketfilterfw."
                )
            ],
        )

    # Parse the numeric global state from the output text
    state = _parse_state(out1)

    # We keep parsed values separate from raw outputs
    evidence["parsed"] = {"global_state": state}

    # ---- 2) Query optional settings (nice extra posture signals) ----
    # These are NOT required to determine if firewall is on/off,
    # but are useful in an audit report.
    rc2, out2, err2 = run_cmd([SFW, "--getstealthmode"])
    rc3, out3, err3 = run_cmd([SFW, "--getblockall"])

    evidence["getstealthmode"] = {"rc": rc2, "stdout": out2, "stderr": err2}
    evidence["getblockall"] = {"rc": rc3, "stdout": out3, "stderr": err3}

    # Parse stealth/block_all only if the commands succeeded
    stealth = _parse_on_off(out2) if rc2 == 0 else None
    block_all = _parse_on_off(out3) if rc3 == 0 else None

    evidence["parsed"].update({
        "stealth_mode": stealth,
        "block_all": block_all
    })

    # ---- 3) Decide PASS/WARN/FAIL based on parsed results ----
    #
    # Strong signals:
    #   - State 0 = firewall OFF -> FAIL
    #   - State 1 = firewall ON  -> PASS (optionally WARN if stealth off)
    #
    # If we can't interpret state, we WARN (still collected evidence).
    if state == 0:
        findings.append(
            Finding(
                severity="HIGH",
                title="Firewall is disabled",
                detail="macOS Application Firewall reports State = 0 (off).",
                remediation="Enable Firewall in System Settings → Network → Firewall."
            )
        )
        return AuditResult(
            id="firewall",
            name="Firewall status (macOS Application Firewall)",
            weight=10,
            status="FAIL",
            score_factor=0.0,
            evidence=evidence,
            findings=findings
        )

    if state == 1:
        # Firewall is on. Stealth off isn't necessarily a failure, but it is a
        # small hardening win to enable, so we mark it WARN (optional policy).
        if stealth is False:
            findings.append(
                Finding(
                    severity="LOW",
                    title="Stealth mode is disabled",
                    detail="Firewall is enabled, but stealth mode appears disabled.",
                    remediation="Consider enabling Stealth Mode if appropriate for the environment."
                )
            )
            return AuditResult(
                id="firewall",
                name="Firewall status (macOS Application Firewall)",
                weight=10,
                status="WARN",
                score_factor=0.5,
                evidence=evidence,
                findings=findings
            )

        # Firewall on, stealth either on or unknown → PASS
        return AuditResult(
            id="firewall",
            name="Firewall status (macOS Application Firewall)",
            weight=10,
            status="PASS",
            score_factor=1.0,
            evidence=evidence,
            findings=findings
        )

    # Fallback: state is None or something unexpected (like 2).
    # We captured the outputs, but cannot confidently interpret them.
    findings.append(
        Finding(
            severity="LOW",
            title="Firewall state could not be interpreted",
            detail=f"Unexpected output: {out1!r}",
            remediation="Verify firewall settings manually and expand parsing rules if needed."
        )
    )
    return AuditResult(
        id="firewall",
        name="Firewall status (macOS Application Firewall)",
        weight=10,
        status="WARN",
        score_factor=0.5,
        evidence=evidence,
        findings=findings
    )

def check_mac_filevault_status():
    """
    Placeholder for macOS FileVault disk encryption status check.
    """
    
    rc, out, err = run_cmd(["fdesetup", "status"])
    evidence = {
        "cmd": "fdesetup status",
        "rc": rc,
        "stdout": out,
        "stderr": err
    }
    # return null evidence
    if rc != 0:
        return AuditResult(
            id="filevault",
            name="FileVault disk encryption status",
            weight=20,
            status="NOT_CHECKED",
            score_factor=0.6,
            evidence=evidence,
            findings=[
                Finding(
                    severity="MEDIUM",
                    title="Could not query FileVault status",
                    detail=f"fdesetup failed (rc={rc}). {err or out or ''}".strip(),
                    remediation="Confirm the fdesetup command is available."
                )
            ]
        )

    low = out.lower()
    if "filevault is on" in low:
        return AuditResult(
            id="filevault",
            name="FileVault disk encryption status",
            weight=20,
            status = "PASS",
            score_factor = 1.0,
            evidence=evidence,
            findings = []
        )
    elif "filevault is off" in low:
        return AuditResult(
            id="filevault",
            name="FileVault disk encryption status",
            weight=20,
            status = "FAIL",
            score_factor = 0.0,
            evidence=evidence,
            findings = [
                Finding(
                    severity="CRITICAL",
                    title="FileVault is disabled",
                    detail="FileVault disk encryption is reported as off.",
                    remediation="Enable FileVault in System Settings → Privacy & Security → FileVault."
                )
            ]
        )
    # fallback for unexpected output
    return AuditResult(
        id="filevault",
        name="FileVault disk encryption status",
        weight=20,
        status = "WARN",
        score_factor = 0.5,
        evidence=evidence,
        findings = [
            Finding(
                severity="LOW",
                title="FileVault status could not be interpreted",
                detail=f"Unexpected output: {out!r}",
                remediation="Verify FileVault settings manually and expand parsing rules if needed."
            )
        ]
    )

##################################
##################################
################################__
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

def get_mac_disk_encryption_status():
    """Retrieve macOS disk encryption status using pyobjc."""
    # Placeholder for actual implementation
    return "Not Implemented"