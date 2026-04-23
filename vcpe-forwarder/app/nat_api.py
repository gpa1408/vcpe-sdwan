from fastapi import APIRouter, HTTPException

from app.kernel import ensure_interface_exists, run_cmd
from app.models import NatMasqueradeRequest

router = APIRouter(tags=["nat"])


@router.get("/nat")
def list_nat_rules():
    result = run_cmd(["iptables", "-t", "nat", "-S"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "nat_rules": result["stdout"].splitlines() if result["stdout"] else []
    }


@router.post("/nat/masquerade")
def add_masquerade(req: NatMasqueradeRequest):
    ensure_interface_exists(req.out_interface)

    cmd = ["iptables", "-t", "nat", "-A", "POSTROUTING"]

    if req.source_subnet:
        cmd.extend(["-s", req.source_subnet])

    cmd.extend(["-o", req.out_interface, "-j", "MASQUERADE"])

    result = run_cmd(cmd)
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "applied",
        "type": "masquerade",
        "out_interface": req.out_interface,
        "source_subnet": req.source_subnet,
        "result": result,
    }


@router.delete("/nat/masquerade")
def delete_masquerade(req: NatMasqueradeRequest):
    ensure_interface_exists(req.out_interface)

    cmd = ["iptables", "-t", "nat", "-D", "POSTROUTING"]

    if req.source_subnet:
        cmd.extend(["-s", req.source_subnet])

    cmd.extend(["-o", req.out_interface, "-j", "MASQUERADE"])

    result = run_cmd(cmd)
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "deleted",
        "type": "masquerade",
        "out_interface": req.out_interface,
        "source_subnet": req.source_subnet,
        "result": result,
    }