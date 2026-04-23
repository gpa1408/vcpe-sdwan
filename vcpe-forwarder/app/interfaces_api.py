from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.kernel import ensure_interface_exists, run_cmd
from app.models import InterfaceAddressRequest

router = APIRouter(tags=["interfaces"])


@router.get("/interfaces")
def list_interfaces():
    interfaces = sorted([p.name for p in Path("/sys/class/net").iterdir()])
    return {"interfaces": interfaces}


@router.get("/interfaces/{name}/addresses")
def get_interface_addresses(name: str):
    ensure_interface_exists(name)

    result = run_cmd(["ip", "-o", "addr", "show", "dev", name])

    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "interface": name,
        "addresses": result["stdout"].splitlines() if result["stdout"] else []
    }


@router.post("/interfaces/{name}/addresses")
def add_interface_address(name: str, req: InterfaceAddressRequest):
    ensure_interface_exists(name)

    result = run_cmd(["ip", "addr", "add", req.address, "dev", name])

    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "applied",
        "interface": name,
        "address": req.address,
        "result": result,
    }


@router.delete("/interfaces/{name}/addresses")
def delete_interface_address(name: str, req: InterfaceAddressRequest):
    ensure_interface_exists(name)

    result = run_cmd(["ip", "addr", "del", req.address, "dev", name])

    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "deleted",
        "interface": name,
        "address": req.address,
        "result": result,
    }