from __future__ import annotations

import time
import uuid
from threading import RLock
from typing import Any, TypeVar

from pydantic import BaseModel

from .models import (
    AccessPoint,
    Bridge,
    BridgeMembershipRequest,
    DesiredConfig,
    DhcpServer,
    FlowPolicy,
    ForwarderModel,
    Interface,
    InterfaceAddressesRequest,
    InterfaceCounters,
    InterfaceStateRequest,
    ManagedInterfaceOverride,
    NatDiscoveryRequest,
    NatDiscoveryResult,
    NatDiscoveryResultPayload,
    NatDiscoveryTask,
    NatPolicy,
    NatTaskRecord,
    Path,
    PathGroup,
    RenderPhase,
    RenderPlan,
    RevisionInfo,
    RevisionRecord,
    StaticRouteSet,
    StateEnvelope,
    TransactionOperation,
    TransactionRequest,
    TransactionResponse,
    TransactionResult,
    WireGuardPeer,
    WireGuardTunnel,
    utc_now,
)


ModelT = TypeVar("ModelT", bound=ForwarderModel)


class ForwarderError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ForwarderStateStore:
    def __init__(self, initial_state: StateEnvelope | None = None) -> None:
        self._lock = RLock()
        self._started_monotonic = time.monotonic()
        self._state = initial_state.model_copy(deep=True) if initial_state else StateEnvelope()
        self._ensure_initial_revision()

    @property
    def state(self) -> StateEnvelope:
        with self._lock:
            return self._state.model_copy(deep=True)

    def health(self) -> dict[str, Any]:
        with self._lock:
            return {
                "status": "healthy",
                "uptime_seconds": int(time.monotonic() - self._started_monotonic),
                "version": self._state.version,
            }

    def current_revision(self) -> RevisionInfo:
        with self._lock:
            record = self._state.revisions[self._state.active_revision]
            return RevisionInfo(
                revision=record.revision,
                status=record.status,
                applied_at=record.applied_at,
            )

    def rollback(self, revision: str) -> RevisionInfo:
        with self._lock:
            if revision not in self._state.revisions:
                raise ForwarderError(f"revision '{revision}' was not found", 404)
            candidate = self._state.model_copy(deep=True)
            candidate.config = candidate.revisions[revision].snapshot.model_copy(deep=True)
            self._validate_config(candidate.config)
            record = self._append_revision(candidate, status="rolled_back", note=f"rollback to {revision}")
            self._state = candidate
            return RevisionInfo(
                revision=record.revision,
                status=record.status,
                applied_at=record.applied_at,
            )

    def apply_transaction(self, request: TransactionRequest) -> TransactionResponse:
        with self._lock:
            if not request.operations:
                return TransactionResponse(
                    status="rejected",
                    revision=self._state.active_revision,
                    results=[
                        TransactionResult(
                            path="/api/v1/transactions",
                            status=400,
                            message="transaction must contain at least one operation",
                        )
                    ],
                )

            if request.expected_revision and request.expected_revision != self._state.active_revision:
                return TransactionResponse(
                    status="rejected",
                    revision=self._state.active_revision,
                    results=[
                        TransactionResult(
                            path="/api/v1/transactions",
                            status=409,
                            message=(
                                "expected_revision does not match the active revision "
                                f"({self._state.active_revision})"
                            ),
                        )
                    ],
                )

            candidate = self._state.model_copy(deep=True)
            results: list[TransactionResult] = []
            for operation in request.operations:
                try:
                    self._apply_operation(candidate, operation)
                    self._validate_config(candidate.config)
                except ForwarderError as exc:
                    results.append(
                        TransactionResult(
                            path=operation.path,
                            status=exc.status_code,
                            message=exc.message,
                        )
                    )
                    return TransactionResponse(
                        status="rejected",
                        revision=self._state.active_revision,
                        results=results,
                    )
                results.append(
                    TransactionResult(
                        path=operation.path,
                        status=200,
                        message="validated" if request.validate_only else "applied",
                    )
                )

            if request.validate_only:
                return TransactionResponse(
                    status="validated",
                    revision=self._state.active_revision,
                    results=results,
                )

            record = self._append_revision(
                candidate,
                status="active",
                note=f"transaction with {len(request.operations)} operations",
            )
            self._state = candidate
            return TransactionResponse(
                status="applied",
                revision=record.revision,
                results=results,
            )

    def list_interfaces(self) -> list[Interface]:
        with self._lock:
            names = self._known_interface_names(self._state.config)
            return [self._build_interface(self._state.config, name) for name in sorted(names)]

    def get_interface(self, interface_name: str) -> Interface:
        with self._lock:
            if interface_name not in self._known_interface_names(self._state.config):
                raise ForwarderError(f"interface '{interface_name}' was not found", 404)
            return self._build_interface(self._state.config, interface_name)

    def set_interface_state(self, interface_name: str, request: InterfaceStateRequest) -> Interface:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/interfaces/{interface_name}/state",
            payload=request.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"set interface state for {interface_name}")
        return self.get_interface(interface_name)

    def set_interface_addresses(
        self,
        interface_name: str,
        request: InterfaceAddressesRequest,
    ) -> Interface:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/interfaces/{interface_name}/addresses",
            payload=request.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"set interface addresses for {interface_name}")
        return self.get_interface(interface_name)

    def get_interface_counters(self, interface_name: str) -> InterfaceCounters:
        self.get_interface(interface_name)
        return InterfaceCounters()

    def list_bridges(self) -> list[Bridge]:
        return self._list_named_resources("bridges")

    def get_bridge(self, bridge_id: str) -> Bridge:
        return self._get_named_resource("bridges", bridge_id, "bridge")

    def create_bridge(self, bridge: Bridge) -> Bridge:
        operation = TransactionOperation(
            method="POST",
            path="/api/v1/bridges",
            payload=bridge.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"create bridge {bridge.bridge_id}")
        return self.get_bridge(bridge.bridge_id)

    def put_bridge(self, bridge_id: str, bridge: Bridge) -> Bridge:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/bridges/{bridge_id}",
            payload=bridge.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"upsert bridge {bridge_id}")
        return self.get_bridge(bridge_id)

    def delete_bridge(self, bridge_id: str) -> None:
        operation = TransactionOperation(method="DELETE", path=f"/api/v1/bridges/{bridge_id}")
        self._commit_operation(operation, note=f"delete bridge {bridge_id}")

    def set_bridge_members(self, bridge_id: str, request: BridgeMembershipRequest) -> Bridge:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/bridges/{bridge_id}/members",
            payload=request.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"set bridge members for {bridge_id}")
        return self.get_bridge(bridge_id)

    def list_wireguard_tunnels(self) -> list[WireGuardTunnel]:
        return self._list_named_resources("wireguard_tunnels")

    def get_wireguard_tunnel(self, tunnel_id: str) -> WireGuardTunnel:
        return self._get_named_resource("wireguard_tunnels", tunnel_id, "WireGuard tunnel")

    def put_wireguard_tunnel(self, tunnel_id: str, tunnel: WireGuardTunnel) -> WireGuardTunnel:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/tunnels/wireguard/{tunnel_id}",
            payload=tunnel.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"upsert WireGuard tunnel {tunnel_id}")
        return self.get_wireguard_tunnel(tunnel_id)

    def delete_wireguard_tunnel(self, tunnel_id: str) -> None:
        operation = TransactionOperation(
            method="DELETE",
            path=f"/api/v1/tunnels/wireguard/{tunnel_id}",
        )
        self._commit_operation(operation, note=f"delete WireGuard tunnel {tunnel_id}")

    def list_wireguard_peers(self, tunnel_id: str) -> list[WireGuardPeer]:
        with self._lock:
            self._ensure_tunnel_exists(self._state, tunnel_id)
            peers = self._state.config.wireguard_peers.get(tunnel_id, {})
            return [peer.model_copy(deep=True) for _, peer in sorted(peers.items())]

    def get_wireguard_peer(self, tunnel_id: str, peer_id: str) -> WireGuardPeer:
        with self._lock:
            self._ensure_tunnel_exists(self._state, tunnel_id)
            peers = self._state.config.wireguard_peers.get(tunnel_id, {})
            if peer_id not in peers:
                raise ForwarderError(f"WireGuard peer '{peer_id}' was not found", 404)
            return peers[peer_id].model_copy(deep=True)

    def put_wireguard_peer(self, tunnel_id: str, peer_id: str, peer: WireGuardPeer) -> WireGuardPeer:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}",
            payload=peer.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"upsert WireGuard peer {peer_id} on {tunnel_id}")
        return self.get_wireguard_peer(tunnel_id, peer_id)

    def delete_wireguard_peer(self, tunnel_id: str, peer_id: str) -> None:
        operation = TransactionOperation(
            method="DELETE",
            path=f"/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}",
        )
        self._commit_operation(operation, note=f"delete WireGuard peer {peer_id} on {tunnel_id}")

    def list_paths(self) -> list[Path]:
        return self._list_named_resources("paths")

    def get_path(self, path_id: str) -> Path:
        return self._get_named_resource("paths", path_id, "path")

    def put_path(self, path_id: str, path: Path) -> Path:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/paths/{path_id}",
            payload=path.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"upsert path {path_id}")
        return self.get_path(path_id)

    def delete_path(self, path_id: str) -> None:
        operation = TransactionOperation(method="DELETE", path=f"/api/v1/paths/{path_id}")
        self._commit_operation(operation, note=f"delete path {path_id}")

    def get_path_group(self, path_group_id: str) -> PathGroup:
        return self._get_named_resource("path_groups", path_group_id, "path group")

    def put_path_group(self, path_group_id: str, group: PathGroup) -> PathGroup:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/path-groups/{path_group_id}",
            payload=group.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"upsert path group {path_group_id}")
        return self.get_path_group(path_group_id)

    def delete_path_group(self, path_group_id: str) -> None:
        operation = TransactionOperation(
            method="DELETE",
            path=f"/api/v1/path-groups/{path_group_id}",
        )
        self._commit_operation(operation, note=f"delete path group {path_group_id}")

    def list_flow_policies(self) -> list[FlowPolicy]:
        return self._list_named_resources("flow_policies")

    def get_flow_policy(self, policy_id: str) -> FlowPolicy:
        return self._get_named_resource("flow_policies", policy_id, "flow policy")

    def put_flow_policy(self, policy_id: str, policy: FlowPolicy) -> FlowPolicy:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/flow-policies/{policy_id}",
            payload=policy.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"upsert flow policy {policy_id}")
        return self.get_flow_policy(policy_id)

    def delete_flow_policy(self, policy_id: str) -> None:
        operation = TransactionOperation(method="DELETE", path=f"/api/v1/flow-policies/{policy_id}")
        self._commit_operation(operation, note=f"delete flow policy {policy_id}")

    def get_static_route_set(self, route_set_id: str) -> StaticRouteSet:
        return self._get_named_resource("static_route_sets", route_set_id, "static route set")

    def put_static_route_set(self, route_set_id: str, route_set: StaticRouteSet) -> StaticRouteSet:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/routes/static/{route_set_id}",
            payload=route_set.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"upsert static route set {route_set_id}")
        return self.get_static_route_set(route_set_id)

    def delete_static_route_set(self, route_set_id: str) -> None:
        operation = TransactionOperation(
            method="DELETE",
            path=f"/api/v1/routes/static/{route_set_id}",
        )
        self._commit_operation(operation, note=f"delete static route set {route_set_id}")

    def get_nat_policy(self, nat_policy_id: str) -> NatPolicy:
        return self._get_named_resource("nat_policies", nat_policy_id, "NAT policy")

    def put_nat_policy(self, nat_policy_id: str, policy: NatPolicy) -> NatPolicy:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/services/nat/policies/{nat_policy_id}",
            payload=policy.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"upsert NAT policy {nat_policy_id}")
        return self.get_nat_policy(nat_policy_id)

    def delete_nat_policy(self, nat_policy_id: str) -> None:
        operation = TransactionOperation(
            method="DELETE",
            path=f"/api/v1/services/nat/policies/{nat_policy_id}",
        )
        self._commit_operation(operation, note=f"delete NAT policy {nat_policy_id}")

    def get_dhcp_server(self, server_id: str) -> DhcpServer:
        return self._get_named_resource("dhcp_servers", server_id, "DHCP server")

    def put_dhcp_server(self, server_id: str, server: DhcpServer) -> DhcpServer:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/services/dhcp/{server_id}",
            payload=server.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"upsert DHCP server {server_id}")
        return self.get_dhcp_server(server_id)

    def delete_dhcp_server(self, server_id: str) -> None:
        operation = TransactionOperation(method="DELETE", path=f"/api/v1/services/dhcp/{server_id}")
        self._commit_operation(operation, note=f"delete DHCP server {server_id}")

    def get_access_point(self, ap_id: str) -> AccessPoint:
        return self._get_named_resource("access_points", ap_id, "access point")

    def put_access_point(self, ap_id: str, access_point: AccessPoint) -> AccessPoint:
        operation = TransactionOperation(
            method="PUT",
            path=f"/api/v1/services/ap/{ap_id}",
            payload=access_point.model_dump(mode="json"),
        )
        self._commit_operation(operation, note=f"upsert access point {ap_id}")
        return self.get_access_point(ap_id)

    def delete_access_point(self, ap_id: str) -> None:
        operation = TransactionOperation(method="DELETE", path=f"/api/v1/services/ap/{ap_id}")
        self._commit_operation(operation, note=f"delete access point {ap_id}")

    def start_nat_discovery(
        self,
        interface_name: str,
        request: NatDiscoveryRequest,
    ) -> NatDiscoveryTask:
        self.get_interface(interface_name)
        task_id = f"nat-{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._state.nat_tasks[task_id] = NatTaskRecord(
                task_id=task_id,
                interface_name=interface_name,
                stun_servers=list(request.stun_servers),
            )
        return NatDiscoveryTask(task_id=task_id, status="running")

    def get_nat_discovery(self, interface_name: str, task_id: str) -> NatDiscoveryResult:
        with self._lock:
            if task_id not in self._state.nat_tasks:
                raise ForwarderError(f"NAT discovery task '{task_id}' was not found", 404)
            task = self._state.nat_tasks[task_id]
            if task.interface_name != interface_name:
                raise ForwarderError(
                    f"NAT discovery task '{task_id}' does not belong to interface '{interface_name}'",
                    404,
                )
            if task.status == "running":
                task.status = "completed"
                task.results = NatDiscoveryResultPayload(
                    public_ip=f"198.51.100.{(sum(ord(ch) for ch in interface_name) % 200) + 1}",
                    public_port=51820,
                    nat_type="cone",
                )
                task.updated_at = utc_now()
            return NatDiscoveryResult(status=task.status, results=self._copy_value(task.results))

    def _commit_operation(self, operation: TransactionOperation, note: str) -> RevisionRecord:
        with self._lock:
            candidate = self._state.model_copy(deep=True)
            self._apply_operation(candidate, operation)
            self._validate_config(candidate.config)
            record = self._append_revision(candidate, status="active", note=note)
            self._state = candidate
            return record

    def _apply_operation(self, state: StateEnvelope, operation: TransactionOperation) -> None:
        method = operation.method.upper()
        path = operation.path.rstrip("/") or "/"
        payload = operation.payload

        if method == "POST" and path == "/api/v1/bridges":
            bridge = Bridge.model_validate(payload)
            if bridge.bridge_id in state.config.bridges:
                raise ForwarderError(f"bridge '{bridge.bridge_id}' already exists", 409)
            state.config.bridges[bridge.bridge_id] = bridge
            return

        parts = [segment for segment in path.split("/") if segment]
        if len(parts) < 4 or parts[0:2] != ["api", "v1"]:
            raise ForwarderError(f"unsupported operation path '{operation.path}'", 400)

        resource = parts[2:]
        if resource[0] == "interfaces" and len(resource) == 3 and resource[2] == "state" and method == "PUT":
            request = InterfaceStateRequest.model_validate(payload)
            override = state.config.interfaces.setdefault(resource[1], ManagedInterfaceOverride())
            override.admin_state = request.state
            return

        if resource[0] == "interfaces" and len(resource) == 3 and resource[2] == "addresses" and method == "PUT":
            request = InterfaceAddressesRequest.model_validate(payload)
            override = state.config.interfaces.setdefault(resource[1], ManagedInterfaceOverride())
            override.addresses = list(request.addresses)
            return

        if resource[0] == "bridges" and len(resource) == 2:
            bridge_id = resource[1]
            if method == "PUT":
                bridge = Bridge.model_validate(payload)
                if bridge.bridge_id != bridge_id:
                    raise ForwarderError(
                        f"bridge body id '{bridge.bridge_id}' does not match path id '{bridge_id}'",
                        400,
                    )
                state.config.bridges[bridge_id] = bridge
                return
            if method == "DELETE":
                self._delete_named_from_state(state.config.bridges, bridge_id, "bridge")
                return

        if resource[0] == "bridges" and len(resource) == 3 and resource[2] == "members" and method == "PUT":
            bridge_id = resource[1]
            self._ensure_named_exists(state.config.bridges, bridge_id, "bridge")
            request = BridgeMembershipRequest.model_validate(payload)
            state.config.bridges[bridge_id].members = list(request.interfaces)
            return

        if resource[0:2] == ["tunnels", "wireguard"] and len(resource) == 3:
            tunnel_id = resource[2]
            if method == "PUT":
                state.config.wireguard_tunnels[tunnel_id] = WireGuardTunnel.model_validate(payload)
                state.config.wireguard_peers.setdefault(tunnel_id, {})
                return
            if method == "DELETE":
                self._delete_named_from_state(state.config.wireguard_tunnels, tunnel_id, "WireGuard tunnel")
                state.config.wireguard_peers.pop(tunnel_id, None)
                return

        if resource[0:2] == ["tunnels", "wireguard"] and len(resource) == 5 and resource[3] == "peers":
            tunnel_id = resource[2]
            peer_id = resource[4]
            self._ensure_tunnel_exists(state, tunnel_id)
            peers = state.config.wireguard_peers.setdefault(tunnel_id, {})
            if method == "PUT":
                peers[peer_id] = WireGuardPeer.model_validate(payload)
                return
            if method == "DELETE":
                self._delete_named_from_state(peers, peer_id, "WireGuard peer")
                return

        if resource[0] == "paths" and len(resource) == 2:
            path_id = resource[1]
            if method == "PUT":
                state.config.paths[path_id] = Path.model_validate(payload)
                return
            if method == "DELETE":
                self._delete_named_from_state(state.config.paths, path_id, "path")
                return

        if resource[0] == "path-groups" and len(resource) == 2:
            path_group_id = resource[1]
            if method == "PUT":
                state.config.path_groups[path_group_id] = PathGroup.model_validate(payload)
                return
            if method == "DELETE":
                self._delete_named_from_state(state.config.path_groups, path_group_id, "path group")
                return

        if resource[0] == "flow-policies" and len(resource) == 2:
            policy_id = resource[1]
            if method == "PUT":
                state.config.flow_policies[policy_id] = FlowPolicy.model_validate(payload)
                return
            if method == "DELETE":
                self._delete_named_from_state(state.config.flow_policies, policy_id, "flow policy")
                return

        if resource[0:2] == ["routes", "static"] and len(resource) == 3:
            route_set_id = resource[2]
            if method == "PUT":
                state.config.static_route_sets[route_set_id] = StaticRouteSet.model_validate(payload)
                return
            if method == "DELETE":
                self._delete_named_from_state(state.config.static_route_sets, route_set_id, "static route set")
                return

        if resource[0:3] == ["services", "nat", "policies"] and len(resource) == 4:
            nat_policy_id = resource[3]
            if method == "PUT":
                state.config.nat_policies[nat_policy_id] = NatPolicy.model_validate(payload)
                return
            if method == "DELETE":
                self._delete_named_from_state(state.config.nat_policies, nat_policy_id, "NAT policy")
                return

        if resource[0:2] == ["services", "dhcp"] and len(resource) == 3:
            server_id = resource[2]
            if method == "PUT":
                state.config.dhcp_servers[server_id] = DhcpServer.model_validate(payload)
                return
            if method == "DELETE":
                self._delete_named_from_state(state.config.dhcp_servers, server_id, "DHCP server")
                return

        if resource[0:2] == ["services", "ap"] and len(resource) == 3:
            ap_id = resource[2]
            if method == "PUT":
                state.config.access_points[ap_id] = AccessPoint.model_validate(payload)
                return
            if method == "DELETE":
                self._delete_named_from_state(state.config.access_points, ap_id, "access point")
                return

        raise ForwarderError(
            f"unsupported operation '{method} {operation.path}'",
            400,
        )

    def _validate_config(self, config: DesiredConfig) -> None:
        for path_id, path in config.paths.items():
            if path.type == "wireguard_peer":
                if path.tunnel_id not in config.wireguard_tunnels:
                    raise ForwarderError(
                        f"path '{path_id}' references unknown tunnel '{path.tunnel_id}'",
                        400,
                    )
                peers = config.wireguard_peers.get(path.tunnel_id, {})
                if path.peer_id not in peers:
                    raise ForwarderError(
                        f"path '{path_id}' references unknown peer '{path.peer_id}' on tunnel '{path.tunnel_id}'",
                        400,
                    )

        for path_group_id, group in config.path_groups.items():
            for member in group.members:
                if member.path_id not in config.paths:
                    raise ForwarderError(
                        f"path group '{path_group_id}' references unknown path '{member.path_id}'",
                        400,
                    )

        for policy_id, policy in config.flow_policies.items():
            if policy.action.type == "use_path" and policy.action.path_id not in config.paths:
                raise ForwarderError(
                    f"flow policy '{policy_id}' references unknown path '{policy.action.path_id}'",
                    400,
                )
            if (
                policy.action.type == "use_path_group"
                and policy.action.path_group_id not in config.path_groups
            ):
                raise ForwarderError(
                    f"flow policy '{policy_id}' references unknown path group '{policy.action.path_group_id}'",
                    400,
                )

        for server_id, server in config.dhcp_servers.items():
            if server.served_interface not in self._known_interface_names(config):
                raise ForwarderError(
                    f"DHCP server '{server_id}' references unknown interface '{server.served_interface}'",
                    400,
                )

        for ap_id, access_point in config.access_points.items():
            if access_point.radio_interface not in self._known_interface_names(config):
                raise ForwarderError(
                    f"access point '{ap_id}' references unknown interface '{access_point.radio_interface}'",
                    400,
                )
            if access_point.bridge_id and access_point.bridge_id not in config.bridges:
                raise ForwarderError(
                    f"access point '{ap_id}' references unknown bridge '{access_point.bridge_id}'",
                    400,
                )

    def _append_revision(self, state: StateEnvelope, status: str, note: str | None) -> RevisionRecord:
        state.revision_counter += 1
        revision = f"rev-{state.revision_counter:04d}"
        state.active_revision = revision
        state.last_render = self._build_render_plan(state.config, note)
        record = RevisionRecord(
            revision=revision,
            status=status,
            note=note,
            snapshot=state.config.model_copy(deep=True),
        )
        state.revisions[revision] = record
        return record

    def _build_render_plan(self, config: DesiredConfig, note: str | None) -> RenderPlan:
        phases: list[RenderPhase] = []

        if config.bridges:
            phases.append(
                RenderPhase(
                    name="bridges",
                    commands=[f"ip link add name {bridge_id} type bridge" for bridge_id in sorted(config.bridges)],
                )
            )
        if config.wireguard_tunnels:
            phases.append(
                RenderPhase(
                    name="wireguard",
                    commands=[f"ip link add {tunnel_id} type wireguard" for tunnel_id in sorted(config.wireguard_tunnels)],
                )
            )
        if config.paths or config.path_groups or config.flow_policies:
            phases.append(
                RenderPhase(
                    name="policy-routing",
                    commands=["nft -f /run/forwarder/policy-routing.nft"],
                )
            )
        if config.nat_policies:
            phases.append(
                RenderPhase(
                    name="nat",
                    commands=["nft -f /run/forwarder/nat.nft"],
                )
            )
        if config.dhcp_servers:
            phases.append(
                RenderPhase(
                    name="dhcp",
                    commands=[
                        f"dnsmasq --conf-file=/etc/forwarder/dnsmasq/{server_id}.conf"
                        for server_id in sorted(config.dhcp_servers)
                    ],
                )
            )
        if config.access_points:
            phases.append(
                RenderPhase(
                    name="wifi",
                    commands=[
                        f"hostapd /etc/forwarder/hostapd/{ap_id}.conf"
                        for ap_id in sorted(config.access_points)
                    ],
                )
            )
        if not phases:
            phases.append(RenderPhase(name="noop"))

        metadata = {
            "bridges": len(config.bridges),
            "wireguard_tunnels": len(config.wireguard_tunnels),
            "paths": len(config.paths),
            "path_groups": len(config.path_groups),
            "flow_policies": len(config.flow_policies),
            "nat_policies": len(config.nat_policies),
            "dhcp_servers": len(config.dhcp_servers),
            "access_points": len(config.access_points),
        }
        if note:
            metadata["note"] = note

        return RenderPlan(phases=phases, metadata=metadata)

    def _known_interface_names(self, config: DesiredConfig) -> set[str]:
        names = set(config.interfaces)
        names.update(config.bridges)
        names.update(config.wireguard_tunnels)
        for bridge in config.bridges.values():
            names.update(bridge.members)
        for path in config.paths.values():
            names.add(path.wan_interface)
        for server in config.dhcp_servers.values():
            names.add(server.served_interface)
        for access_point in config.access_points.values():
            names.add(access_point.radio_interface)
        return names

    def _build_interface(self, config: DesiredConfig, interface_name: str) -> Interface:
        override = config.interfaces.get(interface_name, ManagedInterfaceOverride())
        bridge = config.bridges.get(interface_name)
        tunnel = config.wireguard_tunnels.get(interface_name)

        bridge_of_member = None
        for bridge_id, candidate in config.bridges.items():
            if interface_name in candidate.members:
                bridge_of_member = bridge_id
                break

        role = "unknown"
        if tunnel:
            role = "tunnel"
        elif any(path.wan_interface == interface_name for path in config.paths.values()):
            role = "wan"
        elif bridge or bridge_of_member or any(server.served_interface == interface_name for server in config.dhcp_servers.values()):
            role = "lan"

        kind = "physical"
        admin_state = override.admin_state or "down"
        mtu = 1500
        addresses = list(override.addresses)

        if bridge:
            kind = "bridge"
            admin_state = bridge.admin_state
        elif tunnel:
            kind = "wireguard"
            admin_state = override.admin_state or "up"
            mtu = tunnel.mtu or mtu
            addresses = list(tunnel.local_addresses)
        elif any(access_point.radio_interface == interface_name for access_point in config.access_points.values()):
            kind = "wifi"

        return Interface(
            name=interface_name,
            kind=kind,
            role=role,
            admin_state=admin_state,
            oper_state="unknown",
            mtu=mtu,
            master_bridge=bridge_of_member,
            addresses=addresses,
        )

    def _ensure_initial_revision(self) -> None:
        if self._state.active_revision not in self._state.revisions:
            self._state.revisions[self._state.active_revision] = RevisionRecord(
                revision=self._state.active_revision,
                status="active",
                applied_at=self._state.started_at,
                note="initial empty configuration",
                snapshot=self._state.config.model_copy(deep=True),
            )

    def _get_named_resource(self, attribute: str, key: str, label: str) -> ModelT:
        with self._lock:
            mapping = getattr(self._state.config, attribute)
            if key not in mapping:
                raise ForwarderError(f"{label} '{key}' was not found", 404)
            return mapping[key].model_copy(deep=True)

    def _list_named_resources(self, attribute: str) -> list[ModelT]:
        with self._lock:
            mapping = getattr(self._state.config, attribute)
            return [item.model_copy(deep=True) for _, item in sorted(mapping.items())]

    @staticmethod
    def _copy_value(value: Any) -> Any:
        if isinstance(value, BaseModel):
            return value.model_copy(deep=True)
        if isinstance(value, list):
            return [ForwarderStateStore._copy_value(item) for item in value]
        if isinstance(value, dict):
            return {key: ForwarderStateStore._copy_value(item) for key, item in value.items()}
        return value

    @staticmethod
    def _delete_named_from_state(mapping: dict[str, Any], key: str, label: str) -> None:
        if key not in mapping:
            raise ForwarderError(f"{label} '{key}' was not found", 404)
        del mapping[key]

    @staticmethod
    def _ensure_named_exists(mapping: dict[str, Any], key: str, label: str) -> None:
        if key not in mapping:
            raise ForwarderError(f"{label} '{key}' was not found", 404)

    def _ensure_tunnel_exists(self, state: StateEnvelope, tunnel_id: str) -> None:
        self._ensure_named_exists(state.config.wireguard_tunnels, tunnel_id, "WireGuard tunnel")