from app.probes.ping import parse_ping_output


SAMPLE = """
64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=10.0 ms
64 bytes from 192.0.2.1: icmp_seq=2 ttl=64 time=12.0 ms
64 bytes from 192.0.2.1: icmp_seq=3 ttl=64 time=11.0 ms
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 10.000/11.000/12.000/0.816 ms
"""


def test_ping_parser():
    result = parse_ping_output(SAMPLE)
    assert result.latency_ms == 11.0
    assert result.jitter_ms == 1.5
    assert result.loss_percent == 0.0


def test_ping_parser_100_percent_loss():
    result = parse_ping_output(
        "3 packets transmitted, 0 received, 100% packet loss, time 2024ms"
    )
    assert result.loss_percent == 100.0
    assert result.latency_ms is None
