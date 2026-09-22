from __future__ import annotations

import logging

from .models import FlowMonitoringRequest, MetricSample, TunnelMonitoringRequest
from .settings import Settings

LOG = logging.getLogger(__name__)


class InfluxWriter:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.enabled = bool(
            settings.influx_enabled
            and settings.influx_url
            and settings.influx_org
            and settings.influx_bucket
            and settings.influx_token
        )
        self._client = None
        self._write_api = None

        if not self.enabled:
            LOG.warning("InfluxDB writer disabled or incomplete configuration")
            return

        try:
            from influxdb_client import InfluxDBClient
            from influxdb_client.client.write_api import SYNCHRONOUS
        except ImportError as exc:
            raise RuntimeError(
                "influxdb-client is required when INFLUX_ENABLED=true"
            ) from exc

        self._client = InfluxDBClient(
            url=settings.influx_url,
            token=settings.influx_token,
            org=settings.influx_org,
        )
        self._write_api = self._client.write_api(write_options=SYNCHRONOUS)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def ping(self) -> bool | None:
        if not self.enabled or self._client is None:
            return None
        try:
            return bool(self._client.ping())
        except Exception:
            LOG.exception("InfluxDB ping failed")
            return False

    def write_flow(self, request: FlowMonitoringRequest, sample: MetricSample) -> bool:
        if not self.enabled:
            LOG.info(
                "Influx disabled: flow sample flow_id=%s wan_link=%s sample=%s",
                request.flow_id,
                request.wan_link,
                sample.model_dump(mode="json"),
            )
            return False
        return self._write_point(
            measurement="sdwan_flow_metrics",
            tags={"flow_id": request.flow_id, "wan_link": request.wan_link},
            sample=sample,
        )

    def write_tunnel(self, request: TunnelMonitoringRequest, sample: MetricSample) -> bool:
        if not self.enabled:
            LOG.info(
                "Influx disabled: tunnel sample tunnel_id=%s sample=%s",
                request.tunnel_id,
                sample.model_dump(mode="json"),
            )
            return False
        return self._write_point(
            measurement="sdwan_tunnel_metrics",
            tags={"tunnel_id": request.tunnel_id},
            sample=sample,
        )

    def _write_point(self, measurement: str, tags: dict[str, str], sample: MetricSample) -> bool:
        if not sample.has_any_metric():
            LOG.warning("Skipping empty metric sample for %s", measurement)
            return False

        from influxdb_client import Point, WritePrecision

        point = Point(measurement)
        for key, value in tags.items():
            point = point.tag(key, str(value))

        for field_name in (
            "latency_ms",
            "jitter_ms",
            "loss_percent",
            "available_bandwidth_kbps",
        ):
            value = getattr(sample, field_name)
            if value is not None:
                point = point.field(field_name, float(value))

        point = point.time(sample.timestamp, WritePrecision.NS)
        self._write_api.write(
            bucket=self.settings.influx_bucket,
            org=self.settings.influx_org,
            record=point,
        )
        return True
