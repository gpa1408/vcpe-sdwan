import os

from fastapi import FastAPI
from app.bridge_api import router as bridge_router
from app.interfaces_api import router as interfaces_router
from app.nat_api import router as nat_router
from app.routes_api import router as routes_router
from app.rules_api import router as rules_router
from app.stats_api import router as stats_router
from app.wireguard_api import router as wireguard_router
from app.compat_api import router as compat_router

app = FastAPI(title="vCPE Forwarder")

API_BIND = os.getenv("API_BIND", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "9090"))
STATE_DIR = os.getenv("STATE_DIR", "/state")


@app.get("/health")
def health():
    return {"status": "ok", "service": "vcpe-forwarder"}


app.include_router(routes_router)
app.include_router(rules_router)
app.include_router(interfaces_router)
app.include_router(stats_router)
app.include_router(nat_router)
app.include_router(bridge_router)
app.include_router(wireguard_router)
app.include_router(compat_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=API_BIND, port=API_PORT, reload=False)