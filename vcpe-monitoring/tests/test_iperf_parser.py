import json

from app.probes.iperf3 import parse_iperf3_json


def test_iperf_parser():
    payload = {"end": {"sum_received": {"bits_per_second": 12500000.0}}}
    result = parse_iperf3_json(json.dumps(payload))
    assert result.available_bandwidth_kbps == 12500.0
