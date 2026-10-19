from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from urllib.request import urlopen

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .influx import InfluxWriter
from .interface_resolver import InterfaceResolutionError, InterfaceResolver
from .jobs import JobManager
from .mef105 import Mef105Engine
from .models import (
    FlowMonitoringRequest,
    JobResponse,
    OneWaySampleBatch,
    TunnelMonitoringRequest,
)
from .settings import Settings
from .telemetry import Telemetry


settings = Settings.from_env()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOG = logging.getLogger(__name__)


def _collector_ready() -> bool:
    try:
        with urlopen(settings.otel_collector_health_url, timeout=1.5) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    writer = InfluxWriter(settings)
    resolver = InterfaceResolver(settings)
    manager = JobManager(settings, resolver, writer)
    mef105 = Mef105Engine(settings)
    telemetry = Telemetry(settings)

    app.state.settings = settings
    app.state.writer = writer
    app.state.resolver = resolver
    app.state.manager = manager
    app.state.mef105 = mef105
    app.state.telemetry = telemetry

    LOG.info(
        "vcpe-monitoring starting: WAN map=%s Influx=%s OTel=%s",
        settings.wan_link_map,
        "enabled" if writer.enabled else "disabled",
        "enabled" if telemetry.enabled else "disabled",
    )
    try:
        yield
    finally:
        await manager.stop_all()
        telemetry.shutdown()
        writer.close()


app = FastAPI(
    title="SD-WAN CPE Monitoring API",
    version="0.2.0",
    description="Legacy SD-WAN diagnostics plus a MEF 105-aligned one-way PM model.",
    lifespan=lifespan,
)


@app.exception_handler(InterfaceResolutionError)
async def interface_error_handler(_, exc: InterfaceResolutionError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.get("/health")
async def health():
    manager: JobManager = app.state.manager
    writer: InfluxWriter = app.state.writer
    collector_ready = await asyncio.to_thread(_collector_ready)
    influx_reachable = await asyncio.to_thread(writer.ping)

    healthy = collector_ready and (influx_reachable is not False)
    payload = {
        "status": "healthy" if healthy else "degraded",
        "jobs": await manager.counts(),
        "influx_configured": writer.enabled,
        "influx_reachable": influx_reachable,
        "otel_collector_ready": collector_ready,
        "mef105_alignment": "aligned-not-certified",
    }
    return JSONResponse(status_code=200 if healthy else 503, content=payload)


@app.get("/api/v1/monitoring/jobs")
async def list_jobs():
    manager: JobManager = app.state.manager
    return {"items": await manager.list_jobs()}


@app.post("/api/v1/monitoring/flows", response_model=JobResponse)
async def start_flow(request: FlowMonitoringRequest):
    manager: JobManager = app.state.manager
    handle, updated = await manager.start_flow(request)
    return JobResponse(
        status="running",
        job_type="flow",
        job_key=f"{request.flow_id}:{request.wan_link}",
        interface=handle.interface,
        updated=updated,
    )


@app.delete("/api/v1/monitoring/flows/{flow_id}/{wan_link}", response_model=JobResponse)
async def stop_flow(flow_id: str, wan_link: str):
    manager: JobManager = app.state.manager
    try:
        await manager.stop_flow(flow_id, wan_link)
    except KeyError:
        raise HTTPException(status_code=404, detail="flow monitoring job not found")
    return JobResponse(status="stopped", job_type="flow", job_key=f"{flow_id}:{wan_link}")


@app.post("/api/v1/monitoring/tunnels", response_model=JobResponse)
async def start_tunnel(request: TunnelMonitoringRequest):
    manager: JobManager = app.state.manager
    handle, updated = await manager.start_tunnel(request)
    return JobResponse(
        status="running",
        job_type="tunnel",
        job_key=request.tunnel_id,
        interface=handle.interface,
        updated=updated,
    )


@app.delete("/api/v1/monitoring/tunnels/{tunnel_id}", response_model=JobResponse)
async def stop_tunnel(tunnel_id: str):
    manager: JobManager = app.state.manager
    try:
        await manager.stop_tunnel(tunnel_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="tunnel monitoring job not found")
    return JobResponse(status="stopped", job_type="tunnel", job_key=tunnel_id)


@app.post("/api/v1/monitoring/mef105/samples")
async def ingest_one_way_samples(batch: OneWaySampleBatch):
    engine: Mef105Engine = app.state.mef105
    telemetry: Telemetry = app.state.telemetry

    windows = engine.calculate(batch)
    tcas = []
    for window in windows:
        telemetry.record_window(window)
        events = engine.evaluate_tcas(window)
        for event in events:
            telemetry.record_tca(event)
        tcas.extend(events)

    return {
        "alignment": "MEF 105-aligned; not a formal compliance claim",
        "windows": windows,
        "tca_events": tcas,
    }


@app.get("/api/v1/monitoring/mef105/tcas")
async def list_recent_tcas():
    engine: Mef105Engine = app.state.mef105
    return {
        "items": engine.recent_tcas(),
        "controller_forwarding": "not implemented in the original Agent",
    }
