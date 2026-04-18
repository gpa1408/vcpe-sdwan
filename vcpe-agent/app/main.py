import os
from fastapi import FastAPI
import requests
import uvicorn

app = FastAPI(title="vCPE Agent")

API_BIND = os.getenv("API_BIND", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8080"))
SBI_URL = os.getenv("SBI_URL", "http://127.0.0.1:8383")

@app.get("/health")
def health():
    clixon_ok = False
    clixon_error = None

    try:
        r = requests.get(f"{SBI_URL}/restconf/data", timeout=2)
        clixon_ok = r.status_code < 500
    except Exception as e:
        clixon_error = str(e)

    return {
        "status": "ok",
        "service": "vcpe-agent",
        "sbi_url": SBI_URL,
        "clixon_reachable": clixon_ok,
        "clixon_error": clixon_error,
    }

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=API_BIND, port=API_PORT, reload=False)