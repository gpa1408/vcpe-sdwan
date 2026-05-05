from __future__ import annotations

import re
import subprocess
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path as FilesystemPath
from typing import Any

from .linux import CommandRunner, SystemInspector
from .models import (
    AccessPoint,
    Bridge,
    BridgeMembersUpdate,
    DhcpServer,
    FlowPolicy,
    ForwarderState,
    Interface,
    NatDiscoveryObserved,
    NatDiscoveryRequest,
    NatDiscoveryResult,
    NatDiscoveryTask,
    NatDiscoveryTaskRecord,
    NatPolicy,
    Path as ForwardPath,
    PathGroup,
    RevisionInfo,
    StaticRouteSet,
    TransactionOperation,
    TransactionOperationResult,
    TransactionRequest,
    TransactionResponse,
    WireGuardPeer,
    WireGuardTunnel,
    InterfaceStateUpdate,
    InterfaceAddressesUpdate,
    utc_now,
)
from .renderer import Renderer
from .storage import ForwarderStore


@dataclass(slots=True)
class OperationOutcome:
    status_code: int
    message: str
    body: Any = None
    revision: str | None = None


class ForwarderError(Exception):
    def __init__(self, status_code: int, detail: str, *, extra: dict[str, Any] | None = None) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.extra = extra or {}


class ForwarderService:
    def __init__(
        self,
        root: FilesystemPath,
        *,
        version: str = "1.2.0",
        execute: bool = False,
        use_system_state: bool = True,
    ) -> None:
        self.root = root
        self.version = version
        self.store = ForwarderStore(root)
        self.renderer = Renderer(root)
        self.runner = CommandRunner(root, execute=execute)
        self.inspector = SystemInspector(use_system_state=use_system_state)
        self._nat_threads: dict[str, threading.Thread] = {}

    def health(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "uptime_seconds": self.inspector.get_uptime_seconds(),
            "version": self.version,
        }

    def current_revision(self) -> RevisionInfo:
        return self.store.current_revision()

    def apply_operation(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected_revision: str | None = None,
    ) -> OperationOutcome:
        method = method.upper()
        if method == "GET":
            return self._dispatch_read(self.store.state_copy(), path)

        previous = self.store.state_copy()
        if expected_revision and previous.current_revision != expected_revision:
            raise ForwarderError(409, f"expected revision {expected_revision}, found {previous.current_revision}")

        candidate = previous.model_copy(deep=True)
        outcome = self._dispatch_mutation(candidate, method, path, payload)
        self._validate_state(candidate)
        revision = self._apply_candidate(previous, candidate)
        outcome.revision = revision.revision
        return outcome

    def process_transaction(self, request: TransactionRequest) -> TransactionResponse:
        previous = self.store.state_copy()
        if request.expected_revision and previous.current_revision != request.expected_revision:
            return TransactionResponse(
                status="rejected",
                results=[
                    TransactionOperationResult(
                        path="/api/v1/transactions",
                        status=409,
                        message=f"expected revision {request.expected_revision}, found {previous.current_revision}",
                    )
                ],
            )

        candidate = previous.model_copy(deep=True)
        results: list[TransactionOperationResult] = []
        last_path = "/api/v1/transactions"
        mutated = False

        try:
            for operation in request.operations:
                last_path = operation.path
                outcome = self._dispatch_operation(candidate, operation)
                mutated = mutated or operation.method != "GET"
                results.append(
                    TransactionOperationResult(
                        path=operation.path,
                        status=outcome.status_code,
                        message=outcome.message,
                    )
                )

            if mutated:
                self._validate_state(candidate)

            if request.validate_only:
                return TransactionResponse(status="validated", results=results)

            if not mutated:
                return TransactionResponse(status="applied", revision=previous.current_revision, results=results)

            revision = self._apply_candidate(previous, candidate)
            return TransactionResponse(status="applied", revision=revision.revision, results=results)
        except ForwarderError as exc:
            results.append(TransactionOperationResult(path=last_path, status=exc.status_code, message=exc.detail))
            return TransactionResponse(status="rejected", results=results)

    def rollback(self, revision: str) -> RevisionInfo:
        previous = self.store.state_copy()
        snapshot_path = self.store.revisions_dir / f"{revision}.json"
        if not snapshot_path.exists():
            raise ForwarderError(404, f"revision {revision} not found")

        snapshot = ForwarderState.model_validate_json(snapshot_path.read_text(encoding="utf-8"))
        snapshot.revision_counter = previous.revision_counter
        snapshot.allocation_counter = max(snapshot.allocation_counter, previous.allocation_counter)
        snapshot.current_revision = revision
        snapshot.current_status = "rolled_back"
        snapshot.applied_at = utc_now()

        self._validate_state(snapshot)
        plan = self.renderer.render_transition(previous, snapshot, revision)
        journal = self.runner.run_plan(plan.phases)
        self.store.save_render_plan(plan, journal)
        self._raise_for_failures(revision, journal)
        self.store.rollback(revision)
        return self.store.current_revision()

    def start_nat_discovery(self, interface_name: str, request: NatDiscoveryRequest) -> NatDiscoveryTask:
        state = self.store.state_copy()
        if self._get_interface_view(state, interface_name) is None:
            raise ForwarderError(404, f"interface {interface_name} not found")

        task_id = uuid.uuid4().hex[:12]
        record = NatDiscoveryTaskRecord(
            task_id=task_id,
            interface_name=interface_name,
            stun_servers=request.stun_servers,
        )

        def mutator(candidate: ForwarderState) -> None:
            candidate.nat_discovery_tasks[task_id] = record

        self.store.mutate_state(mutator)
        self.store.write_task_record(record)

        thread = threading.Thread(target=self._run_nat_discovery_task, args=(task_id,), daemon=True)
        thread.start()
        self._nat_threads[task_id] = thread
        return NatDiscoveryTask(task_id=task_id)

    def _run_nat_discovery_task(self, task_id: str) -> None:
        state = self.store.state_copy()
        record = state.nat_discovery_tasks.get(task_id)
        if record is None:
            return

        try:
            results = self._discover_nat(record.interface_name, record.stun_servers)
            updated = record.model_copy(
                update={
                    "status": "completed",
                    "results": results,
                    "updated_at": utc_now(),
                    "error": None,
                }
            )
        except Exception as exc:
            updated = record.model_copy(
                update={
                    "status": "failed",
                    "results": None,
                    "updated_at": utc_now(),
                    "error": str(exc),
                }
            )

        def mutator(candidate: ForwarderState) -> None:
            candidate.nat_discovery_tasks[task_id] = updated

        self.store.mutate_state(mutator)
        self.store.write_task_record(updated)

    def _discover_nat(self, interface_name: str, stun_servers: list[str]) -> NatDiscoveryObserved:
        servers = stun_servers or ["stun.l.google.com:19302"]
        server = servers[0]
        host, port = self._split_host_port(server)

        if self.inspector.command_exists("turnutils_stunclient"):
            completed = subprocess.run(
                ["turnutils_stunclient", "-p", str(port), host],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
        elif self.inspector.command_exists("stunclient"):
            completed = subprocess.run(
                ["stunclient", host, str(port)],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
        else:
            raise RuntimeError("no STUN client available")

        output = "\n".join(part for part in [completed.stdout, completed.stderr] if part)
        if completed.returncode != 0:
            raise RuntimeError(output.strip() or f"STUN command failed for {interface_name}")

        public_ip, public_port = self._parse_mapped_address(output)
        nat_type = self._parse_nat_type(output)
        return NatDiscoveryObserved(public_ip=public_ip, public_port=public_port, nat_type=nat_type)

    def _split_host_port(self, server: str) -> tuple[str, int]:
        if server.startswith("["):
            match = re.fullmatch(r"\[(.+)]:(\d+)", server)
            if match:
                return match.group(1), int(match.group(2))
        if server.count(":") == 1:
            host, port_text = server.rsplit(":", 1)
            if port_text.isdigit():
                return host, int(port_text)
        return server, 3478

    def _parse_mapped_address(self, output: str) -> tuple[str | None, int | None]:
        patterns = [
            r"MappedAddress[^\n]*?(\d+\.\d+\.\d+\.\d+):(\d+)",
            r"Mapped address[^\n]*?(\d+\.\d+\.\d+\.\d+):(\d+)",
            r"External address[^\n]*?(\d+\.\d+\.\d+\.\d+):(\d+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1), int(match.group(2))
        return None, None

    def _parse_nat_type(self, output: str) -> str | None:
        match = re.search(r"NAT Type[^\n:]*[:=]\s*([^\n]+)", output, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        lowered = output.lower()
        for token in [
            "endpoint-independent",
            "address-dependent",
            "port-dependent",
            "full cone",
            "restricted cone",
            "symmetric",
        ]:
            if token in lowered:
                return token
        return None

    def _apply_candidate(self, previous: ForwarderState, candidate: ForwarderState) -> RevisionInfo:
        revision = self._predict_revision(previous, candidate)
        plan = self.renderer.render_transition(previous, candidate, revision)
        journal = self.runner.run_plan(plan.phases)
        self.store.save_render_plan(plan, journal)
        self._raise_for_failures(revision, journal)
        return self.store.commit(candidate)

    def _predict_revision(self, previous: ForwarderState, candidate: ForwarderState) -> str:
        next_counter = max(previous.revision_counter, candidate.revision_counter) + 1
        return f"rev-{next_counter:04d}"

    def _raise_for_failures(self, revision: str, journal: dict[str, list[dict[str, Any]]]) -> None:
        failures: list[dict[str, Any]] = []
        for phase, entries in journal.items():
            for entry in entries:
                if entry.get("returncode", 0) != 0:
                    failures.append({"phase": phase, **entry})

        if not failures:
            return

        first = failures[0]
        raise ForwarderError(
            500,
            f"failed to apply {revision} during {first['phase']}: {first['command']}",
            extra={"failures": failures},
        )

    def _dispatch_operation(self, state: ForwarderState, operation: TransactionOperation) -> OperationOutcome:
        method = operation.method.upper()
        if method == "GET":
            return self._dispatch_read(state, operation.path)
        return self._dispatch_mutation(state, method, operation.path, operation.payload)

    def _dispatch_read(self, state: ForwarderState, path: str) -> OperationOutcome:
        if path == "/api/v1/health":
            return OperationOutcome(200, "ok", self.health())
        if path == "/api/v1/revisions/current":
            return OperationOutcome(200, "ok", RevisionInfo(revision=state.current_revision, status=state.current_status, applied_at=state.applied_at))
        if path == "/api/v1/interfaces":
            return OperationOutcome(200, "ok", {"items": self._collect_interfaces(state)})
        if path == "/api/v1/bridges":
            return OperationOutcome(200, "ok", {"items": self._sorted_values(state.bridges)})
        if path == "/api/v1/tunnels/wireguard":
            return OperationOutcome(200, "ok", {"items": self._sorted_values(state.tunnels)})
        if path == "/api/v1/paths":
            return OperationOutcome(200, "ok", {"items": self._sorted_values(state.paths)})
        if path == "/api/v1/flow-policies":
            return OperationOutcome(200, "ok", {"items": self._sorted_values(state.flow_policies)})

        match = re.fullmatch(r"/api/v1/interfaces/([^/]+)", path)
        if match:
            interface_name = match.group(1)
            interface = self._get_interface_view(state, interface_name)
            if interface is None:
                raise ForwarderError(404, f"interface {interface_name} not found")
            return OperationOutcome(200, "ok", interface)

        match = re.fullmatch(r"/api/v1/interfaces/([^/]+)/counters", path)
        if match:
            interface_name = match.group(1)
            interface = self._get_interface_view(state, interface_name)
            if interface is None:
                raise ForwarderError(404, f"interface {interface_name} not found")
            return OperationOutcome(200, "ok", self.inspector.get_interface_counters(interface_name))

        match = re.fullmatch(r"/api/v1/bridges/([^/]+)", path)
        if match:
            bridge_id = match.group(1)
            return OperationOutcome(200, "ok", self._require_mapping_item(state.bridges, bridge_id, "bridge"))

        match = re.fullmatch(r"/api/v1/tunnels/wireguard/([^/]+)", path)
        if match:
            tunnel_id = match.group(1)
            return OperationOutcome(200, "ok", self._require_mapping_item(state.tunnels, tunnel_id, "tunnel"))

        match = re.fullmatch(r"/api/v1/tunnels/wireguard/([^/]+)/peers", path)
        if match:
            tunnel_id = match.group(1)
            self._require_mapping_item(state.tunnels, tunnel_id, "tunnel")
            peers = state.peers.get(tunnel_id, {})
            return OperationOutcome(200, "ok", {"items": self._sorted_values(peers)})

        match = re.fullmatch(r"/api/v1/tunnels/wireguard/([^/]+)/peers/([^/]+)", path)
        if match:
            tunnel_id, peer_id = match.groups()
            self._require_mapping_item(state.tunnels, tunnel_id, "tunnel")
            peers = state.peers.get(tunnel_id, {})
            return OperationOutcome(200, "ok", self._require_mapping_item(peers, peer_id, "peer"))

        match = re.fullmatch(r"/api/v1/paths/([^/]+)", path)
        if match:
            path_id = match.group(1)
            return OperationOutcome(200, "ok", self._require_mapping_item(state.paths, path_id, "path"))

        match = re.fullmatch(r"/api/v1/path-groups/([^/]+)", path)
        if match:
            group_id = match.group(1)
            return OperationOutcome(200, "ok", self._require_mapping_item(state.path_groups, group_id, "path group"))

        match = re.fullmatch(r"/api/v1/flow-policies/([^/]+)", path)
        if match:
            policy_id = match.group(1)
            return OperationOutcome(200, "ok", self._require_mapping_item(state.flow_policies, policy_id, "flow policy"))

        match = re.fullmatch(r"/api/v1/routes/static/([^/]+)", path)
        if match:
            route_set_id = match.group(1)
            return OperationOutcome(200, "ok", self._require_mapping_item(state.static_route_sets, route_set_id, "static route set"))

        match = re.fullmatch(r"/api/v1/services/nat/policies/([^/]+)", path)
        if match:
            nat_policy_id = match.group(1)
            return OperationOutcome(200, "ok", self._require_mapping_item(state.nat_policies, nat_policy_id, "NAT policy"))

        match = re.fullmatch(r"/api/v1/services/dhcp/([^/]+)", path)
        if match:
            server_id = match.group(1)
            return OperationOutcome(200, "ok", self._require_mapping_item(state.dhcp_servers, server_id, "DHCP server"))

        match = re.fullmatch(r"/api/v1/services/ap/([^/]+)", path)
        if match:
            ap_id = match.group(1)
            return OperationOutcome(200, "ok", self._require_mapping_item(state.access_points, ap_id, "access point"))

        match = re.fullmatch(r"/api/v1/interfaces/([^/]+)/nat-discovery/([^/]+)", path)
        if match:
            interface_name, task_id = match.groups()
            record = self._require_mapping_item(state.nat_discovery_tasks, task_id, "NAT discovery task")
            if record.interface_name != interface_name:
                raise ForwarderError(404, f"NAT discovery task {task_id} not found for interface {interface_name}")
            body = NatDiscoveryResult(status=record.status, results=record.results)
            if record.error:
                return OperationOutcome(200, "ok", {**body.model_dump(mode="json"), "error": record.error})
            return OperationOutcome(200, "ok", body)

        raise ForwarderError(404, f"unsupported path {path}")

    def _dispatch_mutation(
        self,
        state: ForwarderState,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> OperationOutcome:
        if method == "POST" and path == "/api/v1/bridges":
            bridge = Bridge.model_validate(payload or {})
            if bridge.bridge_id in state.bridges:
                raise ForwarderError(409, f"bridge {bridge.bridge_id} already exists")
            self._set_bridge(state, bridge.bridge_id, bridge)
            return OperationOutcome(201, "created", state.bridges[bridge.bridge_id])

        if method == "POST" and re.fullmatch(r"/api/v1/revisions/[^/]+/rollback", path):
            raise ForwarderError(400, "rollback operations are not supported inside transactions")

        if method == "POST" and re.fullmatch(r"/api/v1/interfaces/[^/]+/nat-discovery", path):
            raise ForwarderError(400, "NAT discovery operations are not supported inside transactions")

        match = re.fullmatch(r"/api/v1/interfaces/([^/]+)/state", path)
        if method == "PUT" and match:
            interface_name = match.group(1)
            update = InterfaceStateUpdate.model_validate(payload or {})
            interface = self._get_or_create_interface(state, interface_name)
            state.interfaces[interface_name] = interface.model_copy(update={"name": interface_name, "admin_state": update.state})
            if interface_name in state.bridges:
                state.bridges[interface_name] = state.bridges[interface_name].model_copy(update={"admin_state": update.state})
            return OperationOutcome(200, "configured", state.interfaces[interface_name])

        match = re.fullmatch(r"/api/v1/interfaces/([^/]+)/addresses", path)
        if method == "PUT" and match:
            interface_name = match.group(1)
            update = InterfaceAddressesUpdate.model_validate(payload or {})
            interface = self._get_or_create_interface(state, interface_name)
            state.interfaces[interface_name] = interface.model_copy(update={"name": interface_name, "addresses": update.addresses})
            if interface_name in state.tunnels:
                state.tunnels[interface_name] = state.tunnels[interface_name].model_copy(update={"local_addresses": update.addresses})
            return OperationOutcome(200, "configured", state.interfaces[interface_name])

        match = re.fullmatch(r"/api/v1/bridges/([^/]+)/members", path)
        if method == "PUT" and match:
            bridge_id = match.group(1)
            update = BridgeMembersUpdate.model_validate(payload or {})
            bridge = self._require_mapping_item(state.bridges, bridge_id, "bridge")
            self._set_bridge(state, bridge_id, bridge.model_copy(update={"members": update.interfaces}))
            return OperationOutcome(200, "configured", state.bridges[bridge_id])

        match = re.fullmatch(r"/api/v1/bridges/([^/]+)", path)
        if match:
            bridge_id = match.group(1)
            if method == "PUT":
                bridge = Bridge.model_validate(payload or {})
                if bridge.bridge_id != bridge_id:
                    raise ForwarderError(409, f"bridge body id {bridge.bridge_id} does not match {bridge_id}")
                self._set_bridge(state, bridge_id, bridge)
                return OperationOutcome(200, "configured", state.bridges[bridge_id])
            if method == "DELETE":
                bridge = self._require_mapping_item(state.bridges, bridge_id, "bridge")
                for member in bridge.members:
                    self._clear_interface_master(state, member, bridge_id)
                state.bridges.pop(bridge_id, None)
                if state.interfaces.get(bridge_id) and state.interfaces[bridge_id].kind == "bridge":
                    state.interfaces.pop(bridge_id, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/tunnels/wireguard/([^/]+)/peers/([^/]+)", path)
        if match:
            tunnel_id, peer_id = match.groups()
            if method == "PUT":
                peer = WireGuardPeer.model_validate(payload or {})
                state.peers.setdefault(tunnel_id, {})[peer_id] = peer
                return OperationOutcome(200, "configured", peer)
            if method == "DELETE":
                if tunnel_id not in state.peers or peer_id not in state.peers[tunnel_id]:
                    raise ForwarderError(404, f"peer {peer_id} not found on tunnel {tunnel_id}")
                state.peers[tunnel_id].pop(peer_id)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/tunnels/wireguard/([^/]+)", path)
        if match:
            tunnel_id = match.group(1)
            if method == "PUT":
                tunnel = WireGuardTunnel.model_validate(payload or {})
                state.tunnels[tunnel_id] = tunnel
                state.peers.setdefault(tunnel_id, {})
                interface = self._get_or_create_interface(state, tunnel_id, kind="wireguard", role="tunnel")
                state.interfaces[tunnel_id] = interface.model_copy(
                    update={
                        "name": tunnel_id,
                        "kind": "wireguard",
                        "role": "tunnel",
                        "addresses": tunnel.local_addresses,
                        "mtu": tunnel.mtu,
                    }
                )
                return OperationOutcome(200, "configured", tunnel)
            if method == "DELETE":
                self._require_mapping_item(state.tunnels, tunnel_id, "tunnel")
                state.tunnels.pop(tunnel_id, None)
                state.peers.pop(tunnel_id, None)
                if state.interfaces.get(tunnel_id) and state.interfaces[tunnel_id].kind == "wireguard":
                    state.interfaces.pop(tunnel_id, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/paths/([^/]+)", path)
        if match:
            path_id = match.group(1)
            if method == "PUT":
                path_model = ForwardPath.model_validate(payload or {})
                state.paths[path_id] = path_model
                return OperationOutcome(200, "configured", path_model)
            if method == "DELETE":
                self._require_mapping_item(state.paths, path_id, "path")
                state.paths.pop(path_id, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/path-groups/([^/]+)", path)
        if match:
            group_id = match.group(1)
            if method == "PUT":
                group = PathGroup.model_validate(payload or {})
                state.path_groups[group_id] = group
                return OperationOutcome(200, "configured", group)
            if method == "DELETE":
                self._require_mapping_item(state.path_groups, group_id, "path group")
                state.path_groups.pop(group_id, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/flow-policies/([^/]+)", path)
        if match:
            policy_id = match.group(1)
            if method == "PUT":
                policy = FlowPolicy.model_validate(payload or {})
                state.flow_policies[policy_id] = policy
                return OperationOutcome(200, "configured", policy)
            if method == "DELETE":
                self._require_mapping_item(state.flow_policies, policy_id, "flow policy")
                state.flow_policies.pop(policy_id, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/routes/static/([^/]+)", path)
        if match:
            route_set_id = match.group(1)
            if method == "PUT":
                route_set = StaticRouteSet.model_validate(payload or {})
                state.static_route_sets[route_set_id] = route_set
                return OperationOutcome(200, "configured", route_set)
            if method == "DELETE":
                self._require_mapping_item(state.static_route_sets, route_set_id, "static route set")
                state.static_route_sets.pop(route_set_id, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/services/nat/policies/([^/]+)", path)
        if match:
            nat_policy_id = match.group(1)
            if method == "PUT":
                nat_policy = NatPolicy.model_validate(payload or {})
                state.nat_policies[nat_policy_id] = nat_policy
                return OperationOutcome(200, "configured", nat_policy)
            if method == "DELETE":
                self._require_mapping_item(state.nat_policies, nat_policy_id, "NAT policy")
                state.nat_policies.pop(nat_policy_id, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/services/dhcp/([^/]+)", path)
        if match:
            server_id = match.group(1)
            if method == "PUT":
                server = DhcpServer.model_validate(payload or {})
                state.dhcp_servers[server_id] = server
                return OperationOutcome(200, "configured", server)
            if method == "DELETE":
                self._require_mapping_item(state.dhcp_servers, server_id, "DHCP server")
                state.dhcp_servers.pop(server_id, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/services/ap/([^/]+)", path)
        if match:
            ap_id = match.group(1)
            if method == "PUT":
                access_point = AccessPoint.model_validate(payload or {})
                state.access_points[ap_id] = access_point
                return OperationOutcome(200, "configured", access_point)
            if method == "DELETE":
                self._require_mapping_item(state.access_points, ap_id, "access point")
                state.access_points.pop(ap_id, None)
                return OperationOutcome(204, "deleted")

        raise ForwarderError(405, f"unsupported operation {method} {path}")

    def _set_bridge(self, state: ForwarderState, bridge_id: str, bridge: Bridge) -> None:
        previous = state.bridges.get(bridge_id)
        old_members = set(previous.members if previous else [])
        new_members = set(bridge.members)
        state.bridges[bridge_id] = bridge.model_copy(update={"bridge_id": bridge_id})

        interface = self._get_or_create_interface(state, bridge_id, kind="bridge", role="lan")
        state.interfaces[bridge_id] = interface.model_copy(
            update={
                "name": bridge_id,
                "kind": "bridge",
                "role": "lan",
                "admin_state": bridge.admin_state,
                "master_bridge": None,
            }
        )

        for member in sorted(old_members - new_members):
            self._clear_interface_master(state, member, bridge_id)
        for member in sorted(new_members):
            member_interface = self._get_or_create_interface(state, member)
            state.interfaces[member] = member_interface.model_copy(
                update={
                    "name": member,
                    "master_bridge": bridge_id,
                    "role": "lan",
                }
            )

    def _clear_interface_master(self, state: ForwarderState, interface_name: str, bridge_id: str) -> None:
        interface = state.interfaces.get(interface_name)
        if interface and interface.master_bridge == bridge_id:
            state.interfaces[interface_name] = interface.model_copy(update={"master_bridge": None})

    def _collect_interfaces(self, state: ForwarderState) -> list[Interface]:
        interfaces = {name: interface.model_copy(deep=True) for name, interface in state.interfaces.items()}
        for interface in self.inspector.list_interfaces():
            interfaces.setdefault(interface.name, interface)
        return [interfaces[name] for name in sorted(interfaces)]

    def _get_interface_view(self, state: ForwarderState, interface_name: str) -> Interface | None:
        interface = state.interfaces.get(interface_name)
        if interface is not None:
            return interface
        if interface_name in state.bridges:
            bridge = state.bridges[interface_name]
            return Interface(name=interface_name, kind="bridge", role="lan", admin_state=bridge.admin_state)
        if interface_name in state.tunnels:
            tunnel = state.tunnels[interface_name]
            return Interface(
                name=interface_name,
                kind="wireguard",
                role="tunnel",
                admin_state="up",
                addresses=tunnel.local_addresses,
                mtu=tunnel.mtu,
            )
        return self.inspector.get_interface(interface_name)

    def _get_or_create_interface(
        self,
        state: ForwarderState,
        interface_name: str,
        *,
        kind: str | None = None,
        role: str | None = None,
    ) -> Interface:
        interface = self._get_interface_view(state, interface_name)
        if interface is None:
            interface = Interface(
                name=interface_name,
                kind=self._default_interface_kind(interface_name),
                role=role or "unknown",
            )
        updates: dict[str, Any] = {"name": interface_name}
        if kind is not None:
            updates["kind"] = kind
        if role is not None:
            updates["role"] = role
        return interface.model_copy(update=updates)

    def _default_interface_kind(self, interface_name: str) -> str:
        return "wifi" if interface_name.startswith(("wlan", "wl")) else "physical"

    def _require_mapping_item(self, mapping: dict[str, Any], key: str, label: str) -> Any:
        if key not in mapping:
            raise ForwarderError(404, f"{label} {key} not found")
        return mapping[key]

    def _sorted_values(self, mapping: dict[str, Any]) -> list[Any]:
        return [mapping[key] for key in sorted(mapping)]

    def _validate_state(self, state: ForwarderState) -> None:
        for bridge_id, bridge in state.bridges.items():
            interface = self._get_or_create_interface(state, bridge_id, kind="bridge", role="lan")
            state.interfaces[bridge_id] = interface.model_copy(update={"admin_state": bridge.admin_state})

        for tunnel_id, tunnel in state.tunnels.items():
            interface = self._get_or_create_interface(state, tunnel_id, kind="wireguard", role="tunnel")
            state.interfaces[tunnel_id] = interface.model_copy(
                update={
                    "addresses": tunnel.local_addresses,
                    "mtu": tunnel.mtu,
                }
            )

        for tunnel_id in state.peers:
            if tunnel_id not in state.tunnels:
                raise ForwarderError(400, f"peers reference missing tunnel {tunnel_id}")

        for path_id, path in state.paths.items():
            if path.type == "wireguard_peer":
                if path.tunnel_id not in state.tunnels:
                    raise ForwarderError(400, f"path {path_id} references missing tunnel {path.tunnel_id}")
                if path.peer_id not in state.peers.get(path.tunnel_id or "", {}):
                    raise ForwarderError(
                        400,
                        f"path {path_id} references missing peer {path.peer_id} on tunnel {path.tunnel_id}",
                    )
            if path.nat_policy_id and path.nat_policy_id not in state.nat_policies:
                raise ForwarderError(400, f"path {path_id} references missing NAT policy {path.nat_policy_id}")

        for group_id, group in state.path_groups.items():
            for member in group.members:
                if member.path_id not in state.paths:
                    raise ForwarderError(400, f"path group {group_id} references missing path {member.path_id}")
            if group.active_path_id and group.active_path_id not in state.paths:
                raise ForwarderError(400, f"path group {group_id} references missing active path {group.active_path_id}")

        for policy_id, policy in state.flow_policies.items():
            action = policy.action
            if action.type == "use_path" and action.path_id not in state.paths:
                raise ForwarderError(400, f"flow policy {policy_id} references missing path {action.path_id}")
            if action.type == "use_path_group" and action.path_group_id not in state.path_groups:
                raise ForwarderError(
                    400,
                    f"flow policy {policy_id} references missing path group {action.path_group_id}",
                )
            if policy.match.ingress_bridge and policy.match.ingress_bridge not in state.bridges:
                raise ForwarderError(400, f"flow policy {policy_id} references missing bridge {policy.match.ingress_bridge}")

        for ap_id, access_point in state.access_points.items():
            if access_point.bridge_id and access_point.bridge_id not in state.bridges:
                raise ForwarderError(400, f"access point {ap_id} references missing bridge {access_point.bridge_id}")
