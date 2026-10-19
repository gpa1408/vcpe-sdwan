from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from urllib.request import urlopen

from .settings import Settings


STOP = False


def _signal_handler(signum, _frame):
    global STOP
    STOP = True
    print(f"supervisor received signal {signum}", flush=True)


def _ready(url: str) -> bool:
    try:
        with urlopen(url, timeout=1.0) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def _terminate(process: subprocess.Popen | None, name: str, timeout: float = 8.0) -> None:
    if process is None or process.poll() is not None:
        return
    print(f"stopping {name} pid={process.pid}", flush=True)
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"forcing {name} pid={process.pid}", flush=True)
        process.kill()
        process.wait(timeout=3)


def main() -> int:
    settings = Settings.from_env()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _signal_handler)

    collector = subprocess.Popen(
        [settings.otel_collector_binary, "--config", settings.otel_collector_config]
    )

    deadline = time.monotonic() + settings.otel_collector_start_timeout_sec
    while time.monotonic() < deadline:
        if collector.poll() is not None:
            print(f"OpenTelemetry Collector exited early rc={collector.returncode}", file=sys.stderr)
            return collector.returncode or 1
        if _ready(settings.otel_collector_health_url):
            break
        if STOP:
            _terminate(collector, "otelcol-contrib")
            return 0
        time.sleep(0.25)
    else:
        print("OpenTelemetry Collector readiness timeout", file=sys.stderr)
        _terminate(collector, "otelcol-contrib")
        return 1

    api = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            settings.api_bind,
            "--port",
            str(settings.api_port),
        ],
        env=os.environ.copy(),
    )

    try:
        while not STOP:
            collector_rc = collector.poll()
            api_rc = api.poll()
            if collector_rc is not None:
                print(f"OpenTelemetry Collector exited rc={collector_rc}", file=sys.stderr)
                return collector_rc or 1
            if api_rc is not None:
                print(f"Monitoring API exited rc={api_rc}", file=sys.stderr)
                return api_rc or 1
            time.sleep(0.5)
        return 0
    finally:
        # Stop API first so the SDK can flush while Collector is still available.
        _terminate(api, "monitoring API")
        _terminate(collector, "otelcol-contrib")


if __name__ == "__main__":
    raise SystemExit(main())
