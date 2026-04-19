import os
import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="vCPE Forwarder")

API_BIND = os.getenv("API_BIND", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "9090"))
STATE_DIR = os.getenv("STATE_DIR", "/state")

class RouteRequest(BaseModel):
    destination: str
    gateway: str

def run_cmd(cmd: list[str]) -> dict:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
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

@app.get("/health")
def health():
    return {"status": "ok", "service": "vcpe-forwarder"}

@app.get("/routes")
def list_routes():
    result = run_cmd(["ip", "route", "show"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)
    return {"routes": result["stdout"].splitlines()}

@app.post("/route")
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=API_BIND, port=API_PORT, reload=False)