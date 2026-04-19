import os #Read enviroment variables
import subprocess  #launch commands linux 
from fastapi import FastAPI, HTTPException #Create API HTTP
from pydantic import BaseModel  #define json expected format

app = FastAPI(title="vCPE Forwarder") #Create the web app, everything with @app.get(..) or @app.post(..) are the endpoints


#Envrioment variables
API_BIND = os.getenv("API_BIND", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "9090"))
STATE_DIR = os.getenv("STATE_DIR", "/state")

#Model to create and delete routes, define expected json for POST /route, fastapi use it to validate convert it in a python object, and json has this fields
class RouteRequest(BaseModel):
    destination: str
    gateway: str

class RouteDeleteRequest(BaseModel):
    destination: str
    gateway: str | None = None


#Helper function to launch commands, forwarder receives a list "ip, route, show", launch the command and gives it adiccionary the result
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

@app.get("/health")
def health():
    return {"status": "ok", "service": "vcpe-forwarder"}
#This endpoint request kernel with "ip route show", and gives back the namespace of the network of the container
@app.get("/routes")
def list_routes():
    result = run_cmd(["ip", "route", "show"])
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)   #Error management
    return {"routes": result["stdout"].splitlines()}

# Receives validated JSON in req and constructs the command:
# ip route replace <destination> via <gateway>

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
#Delete routes Endpoint
@app.delete("/route")
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
# Uvicorn startup
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=API_BIND, port=API_PORT, reload=False)