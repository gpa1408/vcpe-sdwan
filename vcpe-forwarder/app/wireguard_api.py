from fastapi import APIRouter, HTTPException

from app.kernel import ensure_interface_exists, run_cmd
from app.models import (
    WireGuardInterfaceCreateRequest,
    WireGuardInterfaceUpdateRequest,
    WireGuardPeerRequest,
)

router = APIRouter(tags=["wireguard"])


def ensure_wg_exists(name: str) -> None:
    ensure_interface_exists(name)


@router.get("/wireguard/interfaces")
def list_wireguard_interfaces():
    result = run_cmd(["ip", "-d", "link", "show", "type", "wireguard"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "interfaces": result["stdout"].splitlines() if result["stdout"] else []
    }


@router.post("/wireguard/interfaces")
def create_wireguard_interface(req: WireGuardInterfaceCreateRequest):
    # create interface
    result = run_cmd(["ip", "link", "add", "dev", req.name, "type", "wireguard"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    # configure private key
    wg_cmd = ["wg", "set", req.name, "private-key", "/dev/stdin"]
    if req.listen_port is not None:
        wg_cmd.extend(["listen-port", str(req.listen_port)])

    try:
        import subprocess
        p = subprocess.run(
            wg_cmd,
            input=req.private_key,
            text=True,
            capture_output=True,
            timeout=5,
        )
        if p.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail={
                    "ok": False,
                    "cmd": wg_cmd,
                    "stdout": p.stdout.strip(),
                    "stderr": p.stderr.strip(),
                    "returncode": p.returncode,
                },
            )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=500,
            detail={"ok": False, "cmd": wg_cmd, "stderr": "command timed out"},
        )

    # optional address
    if req.address:
        addr_result = run_cmd(["ip", "addr", "add", req.address, "dev", req.name])
        if not addr_result["ok"]:
            raise HTTPException(status_code=500, detail=addr_result)

    # bring interface up
    up_result = run_cmd(["ip", "link", "set", req.name, "up"])
    if not up_result["ok"]:
        raise HTTPException(status_code=500, detail=up_result)

    return {
        "status": "created",
        "interface": req.name,
        "listen_port": req.listen_port,
        "address": req.address,
    }


@router.patch("/wireguard/interfaces/{name}")
def update_wireguard_interface(name: str, req: WireGuardInterfaceUpdateRequest):
    ensure_wg_exists(name)

    if req.private_key is not None or req.listen_port is not None:
        wg_cmd = ["wg", "set", name]
        if req.private_key is not None:
            wg_cmd.extend(["private-key", "/dev/stdin"])
        if req.listen_port is not None:
            wg_cmd.extend(["listen-port", str(req.listen_port)])

        try:
            import subprocess
            p = subprocess.run(
                wg_cmd,
                input=req.private_key or "",
                text=True,
                capture_output=True,
                timeout=5,
            )
            if p.returncode != 0:
                raise HTTPException(
                    status_code=500,
                    detail={
                        "ok": False,
                        "cmd": wg_cmd,
                        "stdout": p.stdout.strip(),
                        "stderr": p.stderr.strip(),
                        "returncode": p.returncode,
                    },
                )
        except subprocess.TimeoutExpired:
            raise HTTPException(
                status_code=500,
                detail={"ok": False, "cmd": wg_cmd, "stderr": "command timed out"},
            )

    if req.address is not None:
        # replace address in a simple way: flush and set one address
        flush_result = run_cmd(["ip", "addr", "flush", "dev", name])
        if not flush_result["ok"]:
            raise HTTPException(status_code=500, detail=flush_result)

        add_result = run_cmd(["ip", "addr", "add", req.address, "dev", name])
        if not add_result["ok"]:
            raise HTTPException(status_code=500, detail=add_result)

    return {"status": "updated", "interface": name}


@router.delete("/wireguard/interfaces/{name}")
def delete_wireguard_interface(name: str):
    ensure_wg_exists(name)

    down_result = run_cmd(["ip", "link", "set", name, "down"])
    if not down_result["ok"]:
        raise HTTPException(status_code=500, detail=down_result)

    result = run_cmd(["ip", "link", "del", "dev", name])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {"status": "deleted", "interface": name}


@router.get("/wireguard/interfaces/{name}/peers")
def list_wireguard_peers(name: str):
    ensure_wg_exists(name)

    result = run_cmd(["wg", "show", name, "peers"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "interface": name,
        "peers": result["stdout"].splitlines() if result["stdout"] else []
    }


@router.post("/wireguard/interfaces/{name}/peers")
def add_wireguard_peer(name: str, req: WireGuardPeerRequest):
    ensure_wg_exists(name)

    cmd = ["wg", "set", name, "peer", req.public_key, "allowed-ips", ",".join(req.allowed_ips)]

    if req.endpoint:
        cmd.extend(["endpoint", req.endpoint])

    if req.persistent_keepalive is not None:
        cmd.extend(["persistent-keepalive", str(req.persistent_keepalive)])

    result = run_cmd(cmd)
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "applied",
        "interface": name,
        "peer": req.public_key,
        "allowed_ips": req.allowed_ips,
        "endpoint": req.endpoint,
        "persistent_keepalive": req.persistent_keepalive,
        "result": result,
    }


@router.delete("/wireguard/interfaces/{name}/peers")
def delete_wireguard_peer(name: str, req: WireGuardPeerRequest):
    ensure_wg_exists(name)

    # WireGuard no tiene "peer delete" directo clásico en todos los casos.
    # La forma simple es usar remove.
    cmd = ["wg", "set", name, "peer", req.public_key, "remove"]

    result = run_cmd(cmd)
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "deleted",
        "interface": name,
        "peer": req.public_key,
        "result": result,
    }