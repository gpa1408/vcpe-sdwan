from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.getenv("FORWARDER_HOST", "127.0.0.1")
    port = int(os.getenv("FORWARDER_PORT", "8000"))
    reload = os.getenv("FORWARDER_RELOAD", "0").lower() in {"1", "true", "yes", "on"}
    uvicorn.run("forwarder.app:create_app", factory=True, host=host, port=port, reload=reload)


if __name__ == "__main__":
    main()