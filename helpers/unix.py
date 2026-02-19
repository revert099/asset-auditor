import subprocess

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

def get_evidence(cmd, rc, stdout, stderr):

    return {
        "cmd": cmd,
        "rc": rc,
        "stdout": stdout,
        "stderr": stderr
    }