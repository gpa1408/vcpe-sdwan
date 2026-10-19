from __future__ import annotations

import logging
from typing import Any

from .models import Mef105WindowMetrics, ThresholdCrossingAlert
from .settings import Settings

LOG = logging.getLogger(__name__)


class Telemetry:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.enabled = False
        self._provider = None
        self._delay = None
        self._variation = None
        self._loss = None
        self._tca_counter = None

        if not settings.otel_enabled:
            LOG.warning("OpenTelemetry export disabled")
            return

        try:
            from opentelemetry import metrics
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.resources import Resource
        except ImportError as exc:
            raise RuntimeError("OpenTelemetry Python packages are required when OTEL_ENABLED=true") from exc

        exporter = OTLPMetricExporter(endpoint=settings.otel_metrics_endpoint)
        reader = PeriodicExportingMetricReader(
            exporter,
            export_interval_millis=max(1000, settings.otel_export_interval_ms),
        )
        provider = MeterProvider(
            resource=Resource.create({"service.name": settings.otel_service_name}),
            metric_readers=[reader],
        )
        metrics.set_meter_provider(provider)
        meter = metrics.get_meter("vcpe-monitoring.mef105", "1.0.0")

        self._provider = provider
        self._delay = meter.create_histogram(
            "sdwan_mef105_one_way_mean_packet_delay_ms",
            unit="ms",
            description="MEF 105-aligned one-way mean packet delay per calculation interval",
        )
        self._variation = meter.create_histogram(
            "sdwan_mef105_one_way_mean_inter_packet_delay_variation_ms",
            unit="ms",
            description="MEF 105-aligned one-way mean inter-packet delay variation",
        )
        self._loss = meter.create_histogram(
            "sdwan_mef105_one_way_packet_loss_ratio",
            unit="1",
            description="MEF 105-aligned one-way packet loss ratio",
        )
        self._tca_counter = meter.create_counter(
            "sdwan_mef105_tca_events",
            unit="1",
            description="Threshold Crossing Alert transition events",
        )
        self.enabled = True

    @staticmethod
    def _attributes(metrics: Mef105WindowMetrics) -> dict[str, Any]:
        entity = metrics.entity
        attrs: dict[str, Any] = {
            "entity.id": entity.entity_id,
            "entity.type": entity.entity_type,
            "direction": entity.direction,
            "calculation_interval_sec": metrics.calculation_interval_sec,
        }
        optional = {
            "source.cpe": entity.source_cpe,
            "destination.cpe": entity.destination_cpe,
            "source.uplink": entity.source_uplink,
            "destination.uplink": entity.destination_uplink,
            "cos.name": entity.cos_name,
        }
        for key, value in optional.items():
            if value:
                attrs[key] = value
        return attrs

    def record_window(self, metrics: Mef105WindowMetrics) -> None:
        if not self.enabled:
            return
        attrs = self._attributes(metrics)
        if metrics.one_way_mean_packet_delay_ms is not None:
            self._delay.record(metrics.one_way_mean_packet_delay_ms, attributes=attrs)
        if metrics.one_way_mean_inter_packet_delay_variation_ms is not None:
            self._variation.record(
                metrics.one_way_mean_inter_packet_delay_variation_ms,
                attributes=attrs,
            )
        self._loss.record(metrics.one_way_packet_loss_ratio, attributes=attrs)

    def record_tca(self, event: ThresholdCrossingAlert) -> None:
        if not self.enabled:
            return
        attrs: dict[str, Any] = {
            "entity.id": event.entity.entity_id,
            "entity.type": event.entity.entity_type,
            "direction": event.entity.direction,
            "metric": event.metric,
            "status": event.status,
            "threshold": event.threshold,
            "value": event.value,
        }
        self._tca_counter.add(1, attributes=attrs)
        LOG.warning(
            "MEF105 TCA %s entity=%s direction=%s metric=%s value=%s threshold=%s",
            event.status,
            event.entity.entity_id,
            event.entity.direction,
            event.metric,
            event.value,
            event.threshold,
        )

    def shutdown(self) -> None:
        if self._provider is not None:
            try:
                self._provider.shutdown()
            except Exception:
                LOG.exception("OpenTelemetry provider shutdown failed")
