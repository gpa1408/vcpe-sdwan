from fastapi import APIRouter, HTTPException

from app.kernel import build_rule_cmd, run_cmd
from app.models import RuleRequest

router = APIRouter(tags=["rules"])


@router.get("/rules")
def list_rules():
    result = run_cmd(["ip", "rule", "show"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "rules": result["stdout"].splitlines() if result["stdout"] else []
    }


@router.post("/rules")
def add_rule(req: RuleRequest):
    cmd = build_rule_cmd(
        action="add",
        table=req.table,
        fwmark=req.fwmark,
        priority=req.priority,
        src=req.src,
        dst=req.dst,
        iif=req.iif,
        oif=req.oif,
    )

    result = run_cmd(cmd)

    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "applied",
        "rule": {
            "table": req.table,
            "fwmark": req.fwmark,
            "priority": req.priority,
            "src": req.src,
            "dst": req.dst,
            "iif": req.iif,
            "oif": req.oif,
        },
        "result": result,
    }


@router.delete("/rules")
def delete_rule(req: RuleRequest):
    cmd = build_rule_cmd(
        action="del",
        table=req.table,
        fwmark=req.fwmark,
        priority=req.priority,
        src=req.src,
        dst=req.dst,
        iif=req.iif,
        oif=req.oif,
    )

    result = run_cmd(cmd)

    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "deleted",
        "rule": {
            "table": req.table,
            "fwmark": req.fwmark,
            "priority": req.priority,
            "src": req.src,
            "dst": req.dst,
            "iif": req.iif,
            "oif": req.oif,
        },
        "result": result,
    }