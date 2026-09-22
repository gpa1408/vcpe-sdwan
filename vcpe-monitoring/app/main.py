from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .influx import InfluxWriter
from .interface_resolver import InterfaceResolutionError, InterfaceResolver
from .jobs import JobManager
from .models import FlowMonitoringRequest, JobResponse, TunnelMonitoringRequest
from .settings import Settings


settings = Settings.from_env()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOG = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    writer = InfluxWriter(settings)
    resolver = InterfaceResolver(settings)
    manager = JobManager(settings, resolver, writer)

    app.state.settings = settings
    app.state.writer = writer
    app.state.resolver = resolver
    app.state.manager = manager

    LOG.info(
        "vcpe-monitoring starting: WAN map=%s Influx=%s",
        settings.wan_link_map,
        "enabled" if writer.enabled else "disabled",
    )
    try:
        yield
    finally:
        await manager.stop_all()
        writer.close()


app = FastAPI(
    title="SD-WAN CPE Monitoring API",
    version="0.1.0",
    lifespan=lifespan,
)


@app.exception_handler(InterfaceResolutionError)
async def interface_error_handler(_, exc: InterfaceResolutionError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.get("/health")
async def health():
    manager: JobManager = app.state.manager
    writer: InfluxWriter = app.state.writer
    return {
        "status": "healthy",
        "jobs": await manager.counts(),
        "influx_configured": writer.enabled,
    }


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
