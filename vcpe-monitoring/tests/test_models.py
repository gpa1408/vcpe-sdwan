import pytest
from pydantic import ValidationError

from app.models import FlowMonitoringRequest, TunnelMonitoringRequest


def test_flow_request_accepts_pamodi_shape():
    request = FlowMonitoringRequest(
        flow_id="1001",
        wan_link="UPL1",
        destination_ip="176.16.10.1",
        probe_tools=["ping", "iperf3"],
        interval_sec=10,
    )
    assert request.flow_id == "1001"
    assert request.probe_tools == ["ping", "iperf3"]


def test_flow_request_rejects_invalid_ip():
    with pytest.raises(ValidationError):
        FlowMonitoringRequest(
            flow_id="1001",
            wan_link="UPL1",
            destination_ip="not-an-ip",
            probe_tools=["ping"],
            interval_sec=10,
        )


def test_tunnel_request_accepts_pamodi_shape():
    request = TunnelMonitoringRequest(
        tunnel_id="wg01",
        destination_ip="203.0.113.10",
        probe_tools=["ping", "iperf3", "twamp"],
        interval_sec=600,
    )
    assert request.tunnel_id == "wg01"
