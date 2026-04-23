#Pydantic models Routerequest, rulerequest, interface address request
from fastapi import APIRouter, HTTPException

from app.kernel import ensure_interface_exists, run_cmd
from app.models import BridgeCreateRequest, BridgePortRequest

router = APIRouter(tags=["bridges"])


def ensure_bridge_exists(name: str) -> None:
    ensure_interface_exists(name)


@router.get("/bridges")
def list_bridges():
    result = run_cmd(["ip", "-d", "link", "show", "type", "bridge"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "bridges": result["stdout"].splitlines() if result["stdout"] else []
    }


@router.post("/bridges")
def create_bridge(req: BridgeCreateRequest):
    cmd = ["ip", "link", "add", "name", req.name, "type", "bridge"]
    result = run_cmd(cmd)
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    up_result = run_cmd(["ip", "link", "set", req.name, "up"])
    if not up_result["ok"]:
        raise HTTPException(status_code=500, detail=up_result)

    return {
        "status": "created",
        "bridge": req.name,
        "result": result,
        "up_result": up_result,
    }


@router.delete("/bridges/{name}")
def delete_bridge(name: str):
    ensure_bridge_exists(name)

    down_result = run_cmd(["ip", "link", "set", name, "down"])
    if not down_result["ok"]:
        raise HTTPException(status_code=500, detail=down_result)

    result = run_cmd(["ip", "link", "del", name, "type", "bridge"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "deleted",
        "bridge": name,
        "down_result": down_result,
        "result": result,
    }


@router.post("/bridges/{name}/ports")
def bind_interface_to_bridge(name: str, req: BridgePortRequest):
    ensure_bridge_exists(name)
    ensure_interface_exists(req.interface)

    result = run_cmd(["ip", "link", "set", req.interface, "master", name])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "bound",
        "bridge": name,
        "interface": req.interface,
        "result": result,
    }


@router.delete("/bridges/{name}/ports")
def unbind_interface_from_bridge(name: str, req: BridgePortRequest):
    ensure_bridge_exists(name)
    ensure_interface_exists(req.interface)

    result = run_cmd(["ip", "link", "set", req.interface, "nomaster"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "unbound",
        "bridge": name,
        "interface": req.interface,
        "result": result,
    }


@router.get("/bridges/{name}/ports")
def list_bridge_ports(name: str):
    ensure_bridge_exists(name)

    result = run_cmd(["bridge", "link", "show", "master", name])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "bridge": name,
        "ports": result["stdout"].splitlines() if result["stdout"] else []
    }