from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator


UnderlayProbeTool = Literal["ping", "iperf3"]
TunnelProbeTool = Literal["ping", "iperf3", "twamp"]


class FlowMonitoringRequest(BaseModel):
    flow_id: str = Field(min_length=1, max_length=128)
    wan_link: str = Field(min_length=1, max_length=128)
    destination_ip: str
    probe_tools: list[UnderlayProbeTool] = Field(min_length=1)
    interval_sec: int = Field(ge=1, le=86400)

    @field_validator("destination_ip")
    @classmethod
    def validate_destination_ip(cls, value: str) -> str:
        ipaddress.ip_address(value)
        return value

    @field_validator("probe_tools")
    @classmethod
    def deduplicate_probe_tools(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))


class TunnelMonitoringRequest(BaseModel):
    tunnel_id: str = Field(min_length=1, max_length=128)
    destination_ip: str
    probe_tools: list[TunnelProbeTool] = Field(min_length=1)
    interval_sec: int = Field(default=600, ge=1, le=86400)

    @field_validator("destination_ip")
    @classmethod
    def validate_destination_ip(cls, value: str) -> str:
        ipaddress.ip_address(value)
        return value

    @field_validator("probe_tools")
    @classmethod
    def deduplicate_probe_tools(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))


class MetricSample(BaseModel):
    latency_ms: float | None = None
    jitter_ms: float | None = None
    loss_percent: float | None = None
    available_bandwidth_kbps: float | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def has_any_metric(self) -> bool:
        return any(
            value is not None
            for value in (
                self.latency_ms,
                self.jitter_ms,
                self.loss_percent,
                self.available_bandwidth_kbps,
            )
        )


class JobResponse(BaseModel):
    status: Literal["running", "stopped"]
    job_type: Literal["flow", "tunnel"]
    job_key: str
    interface: str | None = None
    updated: bool | None = None


class JobView(BaseModel):
    job_type: Literal["flow", "tunnel"]
    job_key: str
    interface: str
    destination_ip: str
    probe_tools: list[str]
    interval_sec: int
    started_at: datetime
    run_count: int = 0
    last_error: str | None = None
    last_sample: MetricSample | None = None
