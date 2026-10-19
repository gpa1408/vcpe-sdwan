from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from statistics import mean

from .models import (
    Mef105WindowMetrics,
    MonitoredEntity,
    OneWaySample,
    OneWaySampleBatch,
    ThresholdCrossingAlert,
)
from .settings import Settings


def _floor_utc(value: datetime, interval_sec: int) -> datetime:
    value = value.astimezone(timezone.utc)
    epoch = int(value.timestamp())
    floored = epoch - (epoch % interval_sec)
    return datetime.fromtimestamp(floored, tz=timezone.utc)


def _entity_key(entity: MonitoredEntity) -> str:
    return "|".join(
        [
            entity.entity_type,
            entity.entity_id,
            entity.source_cpe or "",
            entity.destination_cpe or "",
            entity.source_uplink or "",
            entity.destination_uplink or "",
            entity.direction,
            entity.cos_name or "",
        ]
    )


class Mef105Engine:
    """Small MEF 105-aligned calculation/TCA engine for thesis experiments.

    It intentionally does not claim formal MEF 105 compliance. One-way values are
    calculated only from explicitly supplied TX/RX timestamps. RTT is never divided
    by two or reinterpreted as a one-way metric.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._breached: dict[tuple[str, str], bool] = {}
        self._recent_tcas: deque[ThresholdCrossingAlert] = deque(
            maxlen=max(1, settings.mef105_recent_tca_limit)
        )

    def calculate(self, batch: OneWaySampleBatch) -> list[Mef105WindowMetrics]:
        interval_sec = batch.calculation_interval_sec or self.settings.mef105_calculation_interval_sec
        groups: dict[datetime, list[OneWaySample]] = {}
        for sample in batch.samples:
            start = _floor_utc(sample.tx_timestamp_utc, interval_sec)
            groups.setdefault(start, []).append(sample)

        results: list[Mef105WindowMetrics] = []
        for start in sorted(groups):
            samples = sorted(groups[start], key=lambda item: (item.sequence_number, item.tx_timestamp_utc))
            sent = len(samples)
            received = [sample for sample in samples if sample.received and sample.one_way_delay_ms is not None]
            delays = [float(sample.one_way_delay_ms) for sample in received if sample.one_way_delay_ms is not None]

            mean_delay = round(mean(delays), 6) if delays else None
            if len(delays) >= 2:
                variations = [abs(delays[i] - delays[i - 1]) for i in range(1, len(delays))]
                mean_variation = round(mean(variations), 6)
            else:
                mean_variation = None

            loss_ratio = round((sent - len(received)) / sent, 9) if sent else 0.0
            results.append(
                Mef105WindowMetrics(
                    entity=batch.entity,
                    window_start_utc=start,
                    window_end_utc=start + timedelta(seconds=interval_sec),
                    calculation_interval_sec=interval_sec,
                    sent_packets=sent,
                    received_packets=len(received),
                    one_way_mean_packet_delay_ms=mean_delay,
                    one_way_mean_inter_packet_delay_variation_ms=mean_variation,
                    one_way_packet_loss_ratio=loss_ratio,
                )
            )
        return results

    def evaluate_tcas(self, metrics: Mef105WindowMetrics) -> list[ThresholdCrossingAlert]:
        thresholds = {
            "one_way_mean_packet_delay_ms": self.settings.mef105_delay_threshold_ms,
            "one_way_mean_inter_packet_delay_variation_ms": self.settings.mef105_delay_variation_threshold_ms,
            "one_way_packet_loss_ratio": self.settings.mef105_loss_ratio_threshold,
        }
        events: list[ThresholdCrossingAlert] = []
        entity_key = _entity_key(metrics.entity)

        for metric_name, threshold in thresholds.items():
            if threshold < 0:
                continue
            value = getattr(metrics, metric_name)
            if value is None:
                continue
            state_key = (entity_key, metric_name)
            was_breached = self._breached.get(state_key, False)
            is_breached = float(value) > float(threshold)
            if is_breached == was_breached:
                continue

            self._breached[state_key] = is_breached
            event = ThresholdCrossingAlert(
                entity=metrics.entity,
                metric=metric_name,
                status="SET" if is_breached else "CLEAR",
                threshold=float(threshold),
                value=float(value),
            )
            self._recent_tcas.append(event)
            events.append(event)
        return events

    def recent_tcas(self) -> list[ThresholdCrossingAlert]:
        return list(self._recent_tcas)
