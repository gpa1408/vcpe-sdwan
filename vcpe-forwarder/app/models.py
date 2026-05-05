from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ForwarderModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RevisionInfo(ForwarderModel):
    revision: str
    status: Literal["active", "validating", "rolled_back"] = "active"
    applied_at: str = Field(default_factory=utc_now)


class TransactionOperation(ForwarderModel):
    method: Literal["GET", "PUT", "POST", "DELETE"]
    path: str
    payload: dict[str, Any] | None = None


class TransactionRequest(ForwarderModel):
    expected_revision: str | None = None
    validate_only: bool = False
    operations: list[TransactionOperation]


class TransactionOperationResult(ForwarderModel):
    path: str
    status: int
    message: str


class TransactionResponse(ForwarderModel):
    status: Literal["validated", "applied", "rejected"]
    revision: str | None = None
    results: list[TransactionOperationResult] = Field(default_factory=list)


class Interface(ForwarderModel):
    name: str
    kind: Literal["physical", "bridge", "wireguard", "vlan", "dummy", "wifi"] = "physical"
    role: Literal["wan", "lan", "tunnel", "service", "unknown"] = "unknown"
    admin_state: Literal["up", "down"] = "down"
    oper_state: Literal["up", "down", "dormant", "unknown"] = "unknown"
    mtu: int | None = None
    master_bridge: str | None = None
    addresses: list[str] = Field(default_factory=list)


class InterfaceStateUpdate(ForwarderModel):
    state: Literal["up", "down"]


class InterfaceAddressesUpdate(ForwarderModel):
    addresses: list[str]


class InterfaceCounters(ForwarderModel):
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0


class Bridge(ForwarderModel):
    bridge_id: str
    members: list[str] = Field(default_factory=list)
    admin_state: Literal["up", "down"] = "up"


class BridgeMembersUpdate(ForwarderModel):
    interfaces: list[str]


class WireGuardTunnel(ForwarderModel):
    private_key_ref: str | None = None
    listen_port: int
    local_addresses: list[str]
    mtu: int | None = None
    description: str | None = None


class WireGuardPeer(ForwarderModel):
    public_key: str
    endpoint: str | None = None
    allowed_ips: list[str]
    persistent_keepalive: int | None = None
    preshared_key_ref: str | None = None
    description: str | None = None


class Path(ForwarderModel):
    type: Literal["wireguard_peer", "local_breakout"]
    tunnel_id: str | None = None
    peer_id: str | None = None
    wan_interface: str
    nat_policy_id: str | None = None
    failure_behavior: Literal["strict", "fallback_to_group", "drop"]
    description: str | None = None

    @model_validator(mode="after")
    def validate_path_shape(self) -> "Path":
        if self.type == "wireguard_peer" and (not self.tunnel_id or not self.peer_id):
            raise ValueError("wireguard_peer paths require tunnel_id and peer_id")
        return self


class PathGroupMember(ForwarderModel):
    path_id: str
    priority: int | None = None
    weight: int | None = None


class PathGroup(ForwarderModel):
    strategy: Literal["ordered_failover", "weighted_ecmp"]
    active_path_id: str | None = None
    members: list[PathGroupMember]

    @model_validator(mode="after")
    def validate_group_shape(self) -> "PathGroup":
        member_ids = [member.path_id for member in self.members]
        if len(member_ids) != len(set(member_ids)):
            raise ValueError("path group members must be unique")
        if self.strategy == "ordered_failover":
            if not self.active_path_id:
                raise ValueError("ordered_failover requires active_path_id")
            if self.active_path_id not in member_ids:
                raise ValueError("active_path_id must refer to a member path")
        return self


class PortRange(ForwarderModel):
    start: int
    end: int


PortSelector = str | PortRange


class FlowMatch(ForwarderModel):
    src_prefix: str | None = None
    dst_prefix: str | None = None
    protocol: Literal["tcp", "udp", "icmp", "any"] | None = None
    src_ports: PortSelector | None = None
    dst_ports: PortSelector | None = None
    ingress_interface: str | None = None
    ingress_bridge: str | None = None
    dscp: int | None = Field(default=None, ge=0, le=63)


class FlowAction(ForwarderModel):
    type: Literal["use_path", "use_path_group", "drop", "reject"]
    path_id: str | None = None
    path_group_id: str | None = None

    @model_validator(mode="after")
    def validate_flow_action(self) -> "FlowAction":
        if self.type == "use_path" and not self.path_id:
            raise ValueError("use_path actions require path_id")
        if self.type == "use_path_group" and not self.path_group_id:
            raise ValueError("use_path_group actions require path_group_id")
        return self


class FlowPolicy(ForwarderModel):
    priority: int | None = None
    match: FlowMatch
    action: FlowAction
    description: str | None = None


class StaticRoute(ForwarderModel):
    destination_cidr: str
    next_hop_ip: str | None = None
    out_interface: str | None = None
    metric: int | None = None


class StaticRouteSet(ForwarderModel):
    routes: list[StaticRoute]


class NatRule(ForwarderModel):
    action: Literal["masquerade", "snat", "dnat", "port_forward"]
    out_interface: str | None = None
    src_prefix: str | None = None
    dst_prefix: str | None = None
    translated_source: str | None = None
    translated_destination: str | None = None
    protocol: Literal["tcp", "udp", "any"] | None = None


class NatPolicy(ForwarderModel):
    rules: list[NatRule]


class DhcpReservation(ForwarderModel):
    mac_address: str
    ip_address: str


class DhcpServer(ForwarderModel):
    enabled: bool
    served_interface: str
    range_start: str | None = None
    range_end: str | None = None
    gateway: str | None = None
    dns_servers: list[str] = Field(default_factory=list)
    lease_time: str | None = None
    reservations: list[DhcpReservation] = Field(default_factory=list)


class AccessPoint(ForwarderModel):
    enabled: bool
    radio_interface: str
    bridge_id: str | None = None
    ssid: str
    credential_ref: str | None = None
    security: Literal["WPA2", "WPA3"]
    channel: int | None = None
    hw_mode: Literal["g", "a", "ac", "ax"] | None = None


class NatDiscoveryRequest(ForwarderModel):
    stun_servers: list[str] = Field(default_factory=list)


class NatDiscoveryTask(ForwarderModel):
    task_id: str
    status: Literal["running"] = "running"


class NatDiscoveryObserved(ForwarderModel):
    public_ip: str | None = None
    public_port: int | None = None
    nat_type: str | None = None


class NatDiscoveryResult(ForwarderModel):
    status: Literal["running", "completed", "failed"]
    results: NatDiscoveryObserved | None = None


class ManagedInterfaceOverride(ForwarderModel):
    admin_state: Literal["up", "down"] | None = None
    addresses: list[str] = Field(default_factory=list)


class DesiredConfig(ForwarderModel):
    interfaces: dict[str, ManagedInterfaceOverride] = Field(default_factory=dict)
    bridges: dict[str, Bridge] = Field(default_factory=dict)
    wireguard_tunnels: dict[str, WireGuardTunnel] = Field(default_factory=dict)
    wireguard_peers: dict[str, dict[str, WireGuardPeer]] = Field(default_factory=dict)
    paths: dict[str, Path] = Field(default_factory=dict)
    path_groups: dict[str, PathGroup] = Field(default_factory=dict)
    flow_policies: dict[str, FlowPolicy] = Field(default_factory=dict)
    static_route_sets: dict[str, StaticRouteSet] = Field(default_factory=dict)
    nat_policies: dict[str, NatPolicy] = Field(default_factory=dict)
    dhcp_servers: dict[str, DhcpServer] = Field(default_factory=dict)
    access_points: dict[str, AccessPoint] = Field(default_factory=dict)


class RevisionRecord(ForwarderModel):
    revision: str
    status: Literal["active", "validating", "rolled_back"] = "active"
    applied_at: str = Field(default_factory=utc_now)
    note: str | None = None
    snapshot: DesiredConfig = Field(default_factory=DesiredConfig)


class NatTaskRecord(ForwarderModel):
    task_id: str
    interface_name: str
    stun_servers: list[str] = Field(default_factory=list)
    status: Literal["running", "completed", "failed"] = "running"
    results: NatDiscoveryObserved | None = None
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)


class RenderPhase(ForwarderModel):
    name: str
    commands: list[str] = Field(default_factory=list)


class RenderPlan(ForwarderModel):
    generated_at: str = Field(default_factory=utc_now)
    phases: list[RenderPhase] = Field(default_factory=list)
    files: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class StateEnvelope(ForwarderModel):
    version: str = "1.2.0"
    active_revision: str = "rev-0000"
    revision_counter: int = 0
    started_at: str = Field(default_factory=utc_now)
    config: DesiredConfig = Field(default_factory=DesiredConfig)
    revisions: dict[str, RevisionRecord] = Field(default_factory=dict)
    nat_tasks: dict[str, NatTaskRecord] = Field(default_factory=dict)
    last_render: RenderPlan | None = None


TransactionResult = TransactionOperationResult
InterfaceStateRequest = InterfaceStateUpdate
InterfaceAddressesRequest = InterfaceAddressesUpdate
BridgeMembershipRequest = BridgeMembersUpdate
NatDiscoveryResultPayload = NatDiscoveryObserved


class Allocation(ForwarderModel):
    ct_mark: int
    packet_mark: int
    route_table: int
    priority: int
    label: str


class NatDiscoveryTaskRecord(ForwarderModel):
    task_id: str
    interface_name: str
    stun_servers: list[str] = Field(default_factory=list)
    status: Literal["running", "completed", "failed"] = "running"
    results: NatDiscoveryObserved | None = None
    requested_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)
    error: str | None = None


class ForwarderState(ForwarderModel):
    revision_counter: int = 0
    allocation_counter: int = 0
    current_revision: str = "rev-0000"
    current_status: Literal["active", "validating", "rolled_back"] = "active"
    started_at: str = Field(default_factory=utc_now)
    applied_at: str = Field(default_factory=utc_now)
    interfaces: dict[str, Interface] = Field(default_factory=dict)
    bridges: dict[str, Bridge] = Field(default_factory=dict)
    tunnels: dict[str, WireGuardTunnel] = Field(default_factory=dict)
    peers: dict[str, dict[str, WireGuardPeer]] = Field(default_factory=dict)
    paths: dict[str, Path] = Field(default_factory=dict)
    path_groups: dict[str, PathGroup] = Field(default_factory=dict)
    flow_policies: dict[str, FlowPolicy] = Field(default_factory=dict)
    static_route_sets: dict[str, StaticRouteSet] = Field(default_factory=dict)
    nat_policies: dict[str, NatPolicy] = Field(default_factory=dict)
    dhcp_servers: dict[str, DhcpServer] = Field(default_factory=dict)
    access_points: dict[str, AccessPoint] = Field(default_factory=dict)
    nat_discovery_tasks: dict[str, NatDiscoveryTaskRecord] = Field(default_factory=dict)
    allocations: dict[str, Allocation] = Field(default_factory=dict)