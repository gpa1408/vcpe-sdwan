import subprocess
from pathlib import Path

from fastapi import HTTPException


def run_cmd(cmd: list[str]) -> dict:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=5
        )
        return {
            "ok": True,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "cmd": cmd,
        }
    except subprocess.CalledProcessError as e:
        return {
            "ok": False,
            "stdout": e.stdout.strip() if e.stdout else "",
            "stderr": e.stderr.strip() if e.stderr else "",
            "cmd": cmd,
            "returncode": e.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "stdout": "",
            "stderr": "command timed out",
            "cmd": cmd,
            "returncode": -1,
        }


def ensure_interface_exists(name: str) -> None:
    if not Path(f"/sys/class/net/{name}").exists():
        raise HTTPException(status_code=404, detail=f"Interface '{name}' not found")


def read_int_file(path: str | Path) -> int:
    return int(Path(path).read_text().strip())


def build_rule_cmd(action: str, table: str, fwmark=None, priority=None, src=None, dst=None, iif=None, oif=None) -> list[str]:
    cmd = ["ip", "rule", action]

    if priority is not None:
        cmd.extend(["priority", str(priority)])

    if fwmark:
        cmd.extend(["fwmark", str(fwmark)])

    if src:
        cmd.extend(["from", src])

    if dst:
        cmd.extend(["to", dst])

    if iif:
        cmd.extend(["iif", iif])

    if oif:
        cmd.extend(["oif", oif])

    cmd.extend(["table", str(table)])
    return cmd