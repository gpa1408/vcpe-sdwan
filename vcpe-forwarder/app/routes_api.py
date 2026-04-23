from fastapi import APIRouter, HTTPException

from app.kernel import run_cmd
from app.models import RouteDeleteRequest, RouteRequest

router = APIRouter(tags=["routes"])


@router.get("/routes")
def list_routes():
    result = run_cmd(["ip", "route", "show"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "routes": result["stdout"].splitlines() if result["stdout"] else []
    }


@router.post("/route")
def add_route(req: RouteRequest):
    cmd = ["ip", "route", "replace", req.destination, "via", req.gateway]
    result = run_cmd(cmd)

    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "applied",
        "destination": req.destination,
        "gateway": req.gateway,
        "result": result,
    }


@router.delete("/route")
def delete_route(req: RouteDeleteRequest):
    cmd = ["ip", "route", "del", req.destination]

    if req.gateway:
        cmd.extend(["via", req.gateway])

    result = run_cmd(cmd)

    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)

    return {
        "status": "deleted",
        "destination": req.destination,
        "gateway": req.gateway,
        "result": result,
    }