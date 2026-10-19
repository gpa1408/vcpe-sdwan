from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


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
    # Legacy diagnostic fields consumed by the original Agent MetricReader.
    # latency_ms is RTT-derived and is NOT interpreted as MEF 105 one-way delay.
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


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include timezone information")
    return value.astimezone(timezone.utc)


class MonitoredEntity(BaseModel):
    entity_id: str = Field(min_length=1, max_length=128)
    entity_type: Literal["tvc", "application-flow", "path"] = "tvc"
    source_cpe: str | None = Field(default=None, max_length=128)
    destination_cpe: str | None = Field(default=None, max_length=128)
    source_uplink: str | None = Field(default=None, max_length=128)
    destination_uplink: str | None = Field(default=None, max_length=128)
    direction: str = Field(min_length=1, max_length=128)
    cos_name: str | None = Field(default=None, max_length=128)


class OneWaySample(BaseModel):
    sequence_number: int = Field(ge=0)
    tx_timestamp_utc: datetime
    rx_timestamp_utc: datetime | None = None
    received: bool = True

    @field_validator("tx_timestamp_utc", "rx_timestamp_utc")
    @classmethod
    def require_utc_aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value)

    @model_validator(mode="after")
    def validate_receive_timestamp(self):
        if self.received and self.rx_timestamp_utc is None:
            raise ValueError("rx_timestamp_utc is required when received=true")
        if (
            self.received
            and self.rx_timestamp_utc is not None
            and self.rx_timestamp_utc < self.tx_timestamp_utc
        ):
            raise ValueError("rx_timestamp_utc cannot be earlier than tx_timestamp_utc")
        return self

    @property
    def one_way_delay_ms(self) -> float | None:
        if not self.received or self.rx_timestamp_utc is None:
            return None
        return (self.rx_timestamp_utc - self.tx_timestamp_utc).total_seconds() * 1000.0


class OneWaySampleBatch(BaseModel):
    entity: MonitoredEntity
    samples: list[OneWaySample] = Field(min_length=1)
    calculation_interval_sec: int | None = Field(default=None, ge=1, le=3600)


class Mef105WindowMetrics(BaseModel):
    # "aligned with MEF 105" semantics; not a statement of formal compliance.
    entity: MonitoredEntity
    window_start_utc: datetime
    window_end_utc: datetime
    calculation_interval_sec: int
    sent_packets: int
    received_packets: int
    one_way_mean_packet_delay_ms: float | None = None
    one_way_mean_inter_packet_delay_variation_ms: float | None = None
    one_way_packet_loss_ratio: float


TcaMetric = Literal[
    "one_way_mean_packet_delay_ms",
    "one_way_mean_inter_packet_delay_variation_ms",
    "one_way_packet_loss_ratio",
]


class ThresholdCrossingAlert(BaseModel):
    entity: MonitoredEntity
    metric: TcaMetric
    status: Literal["SET", "CLEAR"]
    threshold: float
    value: float
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
