from datetime import datetime, timezone

from app.mef105 import Mef105Engine
from app.models import MonitoredEntity, OneWaySample, OneWaySampleBatch
from app.settings import Settings


def entity():
    return MonitoredEntity(entity_id='wg-test', direction='cpe1-to-cpe2')


def test_one_way_window_metrics_are_not_rtt_derived():
    engine = Mef105Engine(Settings(mef105_calculation_interval_sec=5))
    batch = OneWaySampleBatch(
        entity=entity(),
        calculation_interval_sec=5,
        samples=[
            OneWaySample(
                sequence_number=1,
                tx_timestamp_utc=datetime(2026, 10, 18, 0, 0, 0, tzinfo=timezone.utc),
                rx_timestamp_utc=datetime(2026, 10, 18, 0, 0, 0, 20000, tzinfo=timezone.utc),
            ),
            OneWaySample(
                sequence_number=2,
                tx_timestamp_utc=datetime(2026, 10, 18, 0, 0, 0, 100000, tzinfo=timezone.utc),
                rx_timestamp_utc=datetime(2026, 10, 18, 0, 0, 0, 126000, tzinfo=timezone.utc),
            ),
            OneWaySample(
                sequence_number=3,
                tx_timestamp_utc=datetime(2026, 10, 18, 0, 0, 0, 200000, tzinfo=timezone.utc),
                received=False,
            ),
        ],
    )
    [result] = engine.calculate(batch)
    assert result.one_way_mean_packet_delay_ms == 23.0
    assert result.one_way_mean_inter_packet_delay_variation_ms == 6.0
    assert result.one_way_packet_loss_ratio == 0.333333333
    assert result.sent_packets == 3
    assert result.received_packets == 2


def test_tca_emits_only_state_transitions():
    settings = Settings(
        mef105_calculation_interval_sec=5,
        mef105_delay_threshold_ms=10,
        mef105_delay_variation_threshold_ms=1000,
        mef105_loss_ratio_threshold=1.0,
    )
    engine = Mef105Engine(settings)

    def batch(delay_ms: int):
        tx = datetime(2026, 10, 18, 0, 0, 0, tzinfo=timezone.utc)
        return OneWaySampleBatch(
            entity=entity(),
            samples=[
                OneWaySample(
                    sequence_number=1,
                    tx_timestamp_utc=tx,
                    rx_timestamp_utc=tx.replace(microsecond=delay_ms * 1000),
                )
            ],
        )

    high = engine.calculate(batch(20))[0]
    events = engine.evaluate_tcas(high)
    assert [(e.metric, e.status) for e in events] == [('one_way_mean_packet_delay_ms', 'SET')]
    assert engine.evaluate_tcas(high) == []

    low = engine.calculate(batch(5))[0]
    events = engine.evaluate_tcas(low)
    assert [(e.metric, e.status) for e in events] == [('one_way_mean_packet_delay_ms', 'CLEAR')]
