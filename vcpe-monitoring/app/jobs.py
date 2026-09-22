from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Literal

from .influx import InfluxWriter
from .interface_resolver import InterfaceResolver
from .models import FlowMonitoringRequest, JobView, MetricSample, TunnelMonitoringRequest
from .probes import run_iperf3, run_ping, run_twamp
from .settings import Settings

LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class JobHandle:
    job_type: Literal["flow", "tunnel"]
    key: str
    interface: str
    request: FlowMonitoringRequest | TunnelMonitoringRequest
    task: asyncio.Task
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    run_count: int = 0
    last_error: str | None = None
    last_sample: MetricSample | None = None


class JobManager:
    def __init__(self, settings: Settings, resolver: InterfaceResolver, writer: InfluxWriter) -> None:
        self.settings = settings
        self.resolver = resolver
        self.writer = writer
        self._jobs: dict[str, JobHandle] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def flow_key(flow_id: str, wan_link: str) -> str:
        return f"flow:{flow_id}:{wan_link}"

    @staticmethod
    def tunnel_key(tunnel_id: str) -> str:
        return f"tunnel:{tunnel_id}"

    async def start_flow(self, request: FlowMonitoringRequest) -> tuple[JobHandle, bool]:
        interface = self.resolver.resolve_wan(request.wan_link)
        key = self.flow_key(request.flow_id, request.wan_link)
        updated = await self._stop_key(key, missing_ok=True)

        task = asyncio.create_task(
            self._flow_worker(key, request, interface),
            name=f"monitor-{key}",
        )
        handle = JobHandle(
            job_type="flow",
            key=key,
            interface=interface,
            request=request,
            task=task,
        )
        async with self._lock:
            self._jobs[key] = handle
        return handle, updated

    async def start_tunnel(self, request: TunnelMonitoringRequest) -> tuple[JobHandle, bool]:
        interface = self.resolver.resolve_tunnel(request.tunnel_id)
        key = self.tunnel_key(request.tunnel_id)
        updated = await self._stop_key(key, missing_ok=True)

        task = asyncio.create_task(
            self._tunnel_worker(key, request, interface),
            name=f"monitor-{key}",
        )
        handle = JobHandle(
            job_type="tunnel",
            key=key,
            interface=interface,
            request=request,
            task=task,
        )
        async with self._lock:
            self._jobs[key] = handle
        return handle, updated

    async def stop_flow(self, flow_id: str, wan_link: str) -> bool:
        return await self._stop_key(self.flow_key(flow_id, wan_link), missing_ok=False)

    async def stop_tunnel(self, tunnel_id: str) -> bool:
        return await self._stop_key(self.tunnel_key(tunnel_id), missing_ok=False)

    async def _stop_key(self, key: str, *, missing_ok: bool) -> bool:
        async with self._lock:
            handle = self._jobs.pop(key, None)

        if handle is None:
            if missing_ok:
                return False
            raise KeyError(key)

        handle.task.cancel()
        try:
            await handle.task
        except asyncio.CancelledError:
            pass
        except Exception:
            LOG.exception("Monitoring job %s failed during cancellation", key)
        return True

    async def stop_all(self) -> None:
        async with self._lock:
            keys = list(self._jobs)
        for key in keys:
            await self._stop_key(key, missing_ok=True)

    async def list_jobs(self) -> list[JobView]:
        async with self._lock:
            handles = list(self._jobs.values())
        return [self._view(handle) for handle in handles]

    async def counts(self) -> dict[str, int]:
        async with self._lock:
            handles = list(self._jobs.values())
        return {
            "total": len(handles),
            "flows": sum(handle.job_type == "flow" for handle in handles),
            "tunnels": sum(handle.job_type == "tunnel" for handle in handles),
        }

    def _view(self, handle: JobHandle) -> JobView:
        return JobView(
            job_type=handle.job_type,
            job_key=handle.key,
            interface=handle.interface,
            destination_ip=handle.request.destination_ip,
            probe_tools=list(handle.request.probe_tools),
            interval_sec=handle.request.interval_sec,
            started_at=handle.started_at,
            run_count=handle.run_count,
            last_error=handle.last_error,
            last_sample=handle.last_sample,
        )

    async def _flow_worker(self, key: str, request: FlowMonitoringRequest, interface: str) -> None:
        if not self.settings.run_probe_immediately:
            await asyncio.sleep(request.interval_sec)
        while True:
            await self._run_flow_once(key, request, interface)
            await asyncio.sleep(request.interval_sec)

    async def _tunnel_worker(self, key: str, request: TunnelMonitoringRequest, interface: str) -> None:
        if not self.settings.run_probe_immediately:
            await asyncio.sleep(request.interval_sec)
        while True:
            await self._run_tunnel_once(key, request, interface)
            await asyncio.sleep(request.interval_sec)

    async def _run_flow_once(self, key: str, request: FlowMonitoringRequest, interface: str) -> None:
        sample = MetricSample()
        errors: list[str] = []

        if "ping" in request.probe_tools:
            ping_result = await run_ping(
                request.destination_ip,
                interface,
                count=self.settings.ping_count,
                timeout_sec=self.settings.ping_process_timeout_sec,
            )
            sample.latency_ms = ping_result.latency_ms
            sample.jitter_ms = ping_result.jitter_ms
            sample.loss_percent = ping_result.loss_percent
            if ping_result.error:
                errors.append(f"ping: {ping_result.error}")

        if "iperf3" in request.probe_tools:
            try:
                source_ip = await self.resolver.get_ipv4_address(interface)
                iperf_result = await run_iperf3(
                    request.destination_ip,
                    interface,
                    source_ip,
                    port=self.settings.iperf_port,
                    duration_sec=self.settings.iperf_duration_sec,
                    timeout_sec=self.settings.iperf_process_timeout_sec,
                    bind_device=self.settings.iperf_bind_device,
                )
                sample.available_bandwidth_kbps = iperf_result.available_bandwidth_kbps
                if iperf_result.error:
                    errors.append(f"iperf3: {iperf_result.error}")
            except Exception as exc:
                errors.append(f"iperf3: {exc}")

        await self._finalize_run(
            key,
            sample,
            errors,
            write=lambda: self.writer.write_flow(request, sample),
        )

    async def _run_tunnel_once(self, key: str, request: TunnelMonitoringRequest, interface: str) -> None:
        sample = MetricSample()
        errors: list[str] = []

        if "ping" in request.probe_tools:
            ping_result = await run_ping(
                request.destination_ip,
                interface,
                count=self.settings.ping_count,
                timeout_sec=self.settings.ping_process_timeout_sec,
            )
            sample.latency_ms = ping_result.latency_ms
            sample.jitter_ms = ping_result.jitter_ms
            sample.loss_percent = ping_result.loss_percent
            if ping_result.error:
                errors.append(f"ping: {ping_result.error}")

        if "iperf3" in request.probe_tools:
            try:
                source_ip = await self.resolver.get_ipv4_address(interface)
                iperf_result = await run_iperf3(
                    request.destination_ip,
                    interface,
                    source_ip,
                    port=self.settings.iperf_port,
                    duration_sec=self.settings.iperf_duration_sec,
                    timeout_sec=self.settings.iperf_process_timeout_sec,
                    bind_device=self.settings.iperf_bind_device,
                )
                sample.available_bandwidth_kbps = iperf_result.available_bandwidth_kbps
                if iperf_result.error:
                    errors.append(f"iperf3: {iperf_result.error}")
            except Exception as exc:
                errors.append(f"iperf3: {exc}")

        if "twamp" in request.probe_tools:
            twamp_result = await run_twamp(
                request.destination_ip,
                interface,
                command_template=self.settings.twamp_command_template,
                timeout_sec=self.settings.twamp_process_timeout_sec,
            )
            if twamp_result.latency_ms is not None:
                sample.latency_ms = twamp_result.latency_ms
            if twamp_result.jitter_ms is not None:
                sample.jitter_ms = twamp_result.jitter_ms
            if twamp_result.loss_percent is not None:
                sample.loss_percent = twamp_result.loss_percent
            if twamp_result.error:
                errors.append(f"twamp: {twamp_result.error}")

        await self._finalize_run(
            key,
            sample,
            errors,
            write=lambda: self.writer.write_tunnel(request, sample),
        )

    async def _finalize_run(
        self,
        key: str,
        sample: MetricSample,
        errors: list[str],
        *,
        write: Callable[[], bool],
    ) -> None:
        write_error: str | None = None
        if sample.has_any_metric():
            try:
                await asyncio.to_thread(write)
            except Exception as exc:
                LOG.exception("InfluxDB write failed for %s", key)
                write_error = f"influx: {exc}"
        else:
            write_error = "no metrics produced"

        if write_error:
            errors.append(write_error)

        async with self._lock:
            handle = self._jobs.get(key)
            if handle is not None:
                handle.run_count += 1
                handle.last_sample = sample
                handle.last_error = "; ".join(errors) if errors else None

        if errors:
            LOG.warning("Monitoring job %s completed with issues: %s", key, "; ".join(errors))
        else:
            LOG.info("Monitoring job %s wrote sample %s", key, sample.model_dump(mode="json"))
