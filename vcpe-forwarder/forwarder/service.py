


from __future__ import annotations

import json
import os
import re
import socket
import struct
import subprocess
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path as FilesystemPath
from typing import Any

from .linux import CommandRunner, SystemInspector
from .models import (
    AccessPoint,
    Allocation,
    Bridge,
    BridgeMembersUpdate,
    DhcpServer,
    FlowPolicy,
    FirewallRule,
    SteeringActivePathRequest,
    SteeringLoadBalanceRequest,
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

        # Pamodi's Agent steers using logical YANG WAN names (UPL1, UPL2, ...).
        # The mapping is deployment-specific, so load it from the same style of env used by Monitoring.
        self._configured_wan_link_map = self._load_wan_link_map()
        if self._configured_wan_link_map:
            def merge_wan_map(state: ForwarderState) -> None:
                state.wan_link_map.update(self._configured_wan_link_map)
                for interface_name in self._configured_wan_link_map.values():
                    interface = self._get_or_create_interface(state, interface_name, role="wan")
                    state.interfaces[interface_name] = interface.model_copy(update={"role": "wan"})
            self.store.mutate_state(merge_wan_map)

    def _load_wan_link_map(self) -> dict[str, str]:
        raw = os.getenv("WAN_LINK_MAP_JSON", "").strip()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid WAN_LINK_MAP_JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("WAN_LINK_MAP_JSON must be a JSON object")
        result: dict[str, str] = {}
        for logical, interface in data.items():
            if logical and interface:
                result[str(logical)] = str(interface)
        return result

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
                result_payload: dict[str, Any] = {
                    "path": operation.path,
                    "status": outcome.status_code,
                    "message": outcome.message,
                }

                fwmark = self._extract_fwmark(outcome.body)
                if fwmark is not None:
                    result_payload["fwmark"] = fwmark

                results.append(TransactionOperationResult(**result_payload))

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
        self.store.save_render_plan(plan)                            #NEW LINE PAMODI
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
        """Run an RFC5389 Binding Request explicitly bound to the requested WAN.

        A single binding request reliably discovers the mapped address, but it is not
        sufficient to distinguish full-cone/restricted/symmetric NAT. We therefore
        report `none` only when public and local IPv4 are equal; otherwise `unknown`.
        This matches the YANG enum without inventing a NAT classification.
        """
        interface = self.inspector.get_interface(interface_name)
        if interface is None:
            raise RuntimeError(f"interface {interface_name} is not available in kernel")

        local_ip = None
        for address in interface.addresses:
            if ":" not in address:
                local_ip = address.split("/", 1)[0]
                break
        if not local_ip:
            raise RuntimeError(f"interface {interface_name} has no IPv4 address")

        servers = stun_servers or ["stun.l.google.com:19302"]
        host, port = self._split_host_port(servers[0])
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        if not infos:
            raise RuntimeError(f"cannot resolve STUN server {host}")
        server_addr = infos[0][4]

        magic_cookie = 0x2112A442
        transaction_id = os.urandom(12)
        request = struct.pack("!HHI12s", 0x0001, 0, magic_cookie, transaction_id)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(8.0)
            # Force packets to the requested WAN, not the management/default route.
            if hasattr(socket, "SO_BINDTODEVICE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface_name.encode() + b"\0")
            sock.bind((local_ip, 0))
            sock.sendto(request, server_addr)
            response, _ = sock.recvfrom(2048)

        public_ip, public_port = self._parse_stun_binding_response(
            response, transaction_id, magic_cookie
        )
        nat_type = "none" if public_ip == local_ip else "unknown"
        return NatDiscoveryObserved(public_ip=public_ip, public_port=public_port, nat_type=nat_type)

    def _parse_stun_binding_response(
        self, data: bytes, transaction_id: bytes, magic_cookie: int
    ) -> tuple[str, int]:
        if len(data) < 20:
            raise RuntimeError("short STUN response")
        msg_type, msg_len, cookie, rx_id = struct.unpack("!HHI12s", data[:20])
        if msg_type != 0x0101 or cookie != magic_cookie or rx_id != transaction_id:
            raise RuntimeError("invalid STUN binding response")

        end = min(len(data), 20 + msg_len)
        offset = 20
        mapped = None
        while offset + 4 <= end:
            attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
            value = data[offset + 4:offset + 4 + attr_len]
            if len(value) != attr_len:
                break

            if attr_type in (0x0020, 0x0001) and attr_len >= 8 and value[1] == 0x01:
                port = struct.unpack("!H", value[2:4])[0]
                addr_int = struct.unpack("!I", value[4:8])[0]
                if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                    port ^= (magic_cookie >> 16)
                    addr_int ^= magic_cookie
                ip = socket.inet_ntoa(struct.pack("!I", addr_int))
                mapped = (ip, port)
                if attr_type == 0x0020:
                    break

            offset += 4 + ((attr_len + 3) & ~3)

        if mapped is None:
            raise RuntimeError("STUN response has no mapped address")
        return mapped

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
        try:
            plan = self.renderer.render_transition(previous, candidate, revision)
        except (ValueError, OSError) as exc:
            raise ForwarderError(400, f"cannot render dataplane: {exc}") from exc
        self.store.save_render_plan(plan)
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

    def _extract_fwmark(self, body: Any) -> int | None:
        if isinstance(body, dict):
            fwmark = body.get("fwmark")
            if isinstance(fwmark, int):
                return fwmark
        return None

    def _ensure_flow_policy_fwmark(self, state: ForwarderState, policy_id: str) -> int:
        allocation_key = f"flow-policy:{policy_id}"
        allocation = state.allocations.get(allocation_key)

        if allocation is None:
            state.allocation_counter += 1
            index = state.allocation_counter
            mark = 0x100 + index

            allocation = Allocation(
                ct_mark=mark,
                packet_mark=mark,
                route_table=10100 + index,
                priority=1000 + index,
                label=allocation_key,
            )
            state.allocations[allocation_key] = allocation

        return allocation.packet_mark

    def _get_flow_policy_fwmark(self, state: ForwarderState, policy_id: str) -> int | None:
        allocation = state.allocations.get(f"flow-policy:{policy_id}")
        if allocation is None:
            return None
        return allocation.packet_mark

    def _flow_policy_view(
        self,
        state: ForwarderState,
        policy_id: str,
        *,
        fwmark: int | None = None,
    ) -> dict[str, Any]:
        policy = self._require_mapping_item(state.flow_policies, policy_id, "flow policy")
        body = policy.model_dump(mode="json")
        body["policy_id"] = policy_id

        if fwmark is None:
            fwmark = self._get_flow_policy_fwmark(state, policy_id)

        if fwmark is not None:
            body["fwmark"] = fwmark

        return body

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
        if path == "/api/v1/firewall/rules":
            return OperationOutcome(200, "ok", {"items": self._sorted_values(state.firewall_rules)})
        if path == "/api/v1/steering/active-paths":
            return OperationOutcome(200, "ok", {"items": self._sorted_values(state.steering_active_paths)})
        if path == "/api/v1/steering/load-balances":
            return OperationOutcome(200, "ok", {"items": self._sorted_values(state.steering_load_balances)})
        if path == "/api/v1/flow-policies":
            items = [
                self._flow_policy_view(state, policy_id)
                for policy_id in sorted(state.flow_policies)
            ]
            return OperationOutcome(200, "ok", {"items": items, "flow_policies": items})

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

        match = re.fullmatch(r"/api/v1/firewall/rules/([^/]+)", path)
        if match:
            rule_id = match.group(1)
            return OperationOutcome(200, "ok", self._require_mapping_item(state.firewall_rules, rule_id, "firewall rule"))

        match = re.fullmatch(r"/api/v1/steering/([^/]+)/active-path", path)
        if match:
            traffic_class = match.group(1)
            return OperationOutcome(
                200,
                "ok",
                self._require_mapping_item(state.steering_active_paths, traffic_class, "steering active-path decision"),
            )

        match = re.fullmatch(r"/api/v1/steering/([^/]+)/load-balance", path)
        if match:
            traffic_class = match.group(1)
            return OperationOutcome(
                200,
                "ok",
                self._require_mapping_item(state.steering_load_balances, traffic_class, "steering load-balance decision"),
            )

        match = re.fullmatch(r"/api/v1/flow-policies/([^/]+)", path)
        if match:
            policy_id = match.group(1)
            self._require_mapping_item(state.flow_policies, policy_id, "flow policy")
            return OperationOutcome(200, "ok", self._flow_policy_view(state, policy_id))

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
            is_wan = interface_name in state.wan_link_map.values()
            interface = self._get_or_create_interface(
                state, interface_name, role="wan" if is_wan else None
            )
            if interface_name in state.tunnels:
                address_mode = "static"
            elif update.addresses:
                address_mode = "static"
            elif is_wan:
                # Pamodi Agent encodes address-mode=dhcp as addresses: [].
                address_mode = "dhcp"
            else:
                address_mode = "none"
            state.interfaces[interface_name] = interface.model_copy(
                update={"name": interface_name, "addresses": update.addresses, "address_mode": address_mode}
            )
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
                        "address_mode": "static",
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

        match = re.fullmatch(r"/api/v1/firewall/rules/([^/]+)", path)
        if match:
            rule_id = match.group(1)
            if method == "PUT":
                rule = FirewallRule.model_validate(payload or {})
                if rule.rule_id and rule.rule_id != rule_id:
                    raise ForwarderError(409, f"firewall rule body id {rule.rule_id} does not match {rule_id}")
                state.firewall_rules[rule_id] = rule.model_copy(update={"rule_id": rule_id})
                return OperationOutcome(200, "configured", state.firewall_rules[rule_id])

            if method == "DELETE":
                self._require_mapping_item(state.firewall_rules, rule_id, "firewall rule")
                state.firewall_rules.pop(rule_id, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/steering/([^/]+)/active-path", path)
        if match:
            traffic_class = match.group(1)
            if method == "PUT":
                decision = SteeringActivePathRequest.model_validate(payload or {})
                if decision.traffic_class and decision.traffic_class != traffic_class:
                    raise ForwarderError(
                        409,
                        f"steering active-path body traffic_class {decision.traffic_class} does not match {traffic_class}",
                    )
                state.steering_active_paths[traffic_class] = decision.model_copy(update={"traffic_class": traffic_class})
                return OperationOutcome(200, "configured", state.steering_active_paths[traffic_class])

            if method == "DELETE":
                self._require_mapping_item(state.steering_active_paths, traffic_class, "steering active-path decision")
                state.steering_active_paths.pop(traffic_class, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/steering/([^/]+)/load-balance", path)
        if match:
            traffic_class = match.group(1)
            if method == "PUT":
                decision = SteeringLoadBalanceRequest.model_validate(payload or {})
                if decision.traffic_class and decision.traffic_class != traffic_class:
                    raise ForwarderError(
                        409,
                        f"steering load-balance body traffic_class {decision.traffic_class} does not match {traffic_class}",
                    )
                state.steering_load_balances[traffic_class] = decision.model_copy(update={"traffic_class": traffic_class})
                return OperationOutcome(200, "configured", state.steering_load_balances[traffic_class])

            if method == "DELETE":
                self._require_mapping_item(state.steering_load_balances, traffic_class, "steering load-balance decision")
                state.steering_load_balances.pop(traffic_class, None)
                return OperationOutcome(204, "deleted")

        match = re.fullmatch(r"/api/v1/flow-policies/([^/]+)", path)
        if match:
            policy_id = match.group(1)
            if method == "PUT":
                policy = FlowPolicy.model_validate(payload or {})
                state.flow_policies[policy_id] = policy

                fwmark = None
                if policy_id.startswith("traffic-class-"):
                    fwmark = self._ensure_flow_policy_fwmark(state, policy_id)

                return OperationOutcome(
                200,
                "configured",
                self._flow_policy_view(state, policy_id, fwmark=fwmark),
                )

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
                if route_set_id.endswith("-default"):
                    logical_name = route_set_id.removesuffix("-default")
                    for route in route_set.routes:
                        if route.out_interface:
                            state.wan_link_map[logical_name] = route.out_interface
                            interface = self._get_or_create_interface(state, route.out_interface, role="wan")
                            state.interfaces[route.out_interface] = interface.model_copy(update={"role": "wan"})
                            break
                return OperationOutcome(200, "configured", route_set)
            if method == "DELETE":
                # Keep DELETE idempotent. Startup reconciliation may ask to remove a
                # stale static default even when no such object exists yet.
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
                    "address_mode": "static",
                    "mtu": tunnel.mtu,
                }
            )

            if not tunnel.private_key_ref:
                raise ForwarderError(400, f"WireGuard tunnel {tunnel_id} requires private_key_ref")
            try:
                self.renderer.secrets.resolve(tunnel.private_key_ref)
            except (ValueError, OSError) as exc:
                raise ForwarderError(400, f"WireGuard tunnel {tunnel_id} key cannot be resolved: {exc}") from exc

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

        for rule_id, rule in state.firewall_rules.items():
            if rule.match.ingress_bridge and rule.match.ingress_bridge not in state.bridges:
                raise ForwarderError(400, f"firewall rule {rule_id} references missing bridge {rule.match.ingress_bridge}")

        for policy_id, policy in state.flow_policies.items():
            action = policy.action

            if action is not None:
                if action.type == "use_path" and action.path_id not in state.paths:
                    raise ForwarderError(400, f"flow policy {policy_id} references missing path {action.path_id}")

                if action.type == "use_path_group" and action.path_group_id not in state.path_groups:
                    raise ForwarderError(
                        400,
                        f"flow policy {policy_id} references missing path group {action.path_group_id}",
                    )

            if policy.match.ingress_bridge and policy.match.ingress_bridge not in state.bridges:
                raise ForwarderError(400, f"flow policy {policy_id} references missing bridge {policy.match.ingress_bridge}")

        def validate_selected_path(name: str | None, selected_type: str | None, label: str) -> None:
            if not name:
                return
            if selected_type == "wan-link":
                mapped = state.wan_link_map.get(name)
                if not mapped:
                    route_set = state.static_route_sets.get(f"{name}-default")
                    if route_set:
                        mapped = next((r.out_interface for r in route_set.routes if r.out_interface), None)
                if not mapped:
                    raise ForwarderError(400, f"{label} references logical WAN {name} but no WAN->interface mapping exists")
            elif selected_type == "tunnel" and name not in state.tunnels:
                raise ForwarderError(400, f"{label} references missing tunnel {name}")
            elif selected_type == "path" and name not in state.paths:
                raise ForwarderError(400, f"{label} references missing path {name}")
            elif selected_type == "path-group" and name not in state.path_groups:
                raise ForwarderError(400, f"{label} references missing path-group {name}")

        for traffic_class, decision in state.steering_active_paths.items():
            if decision.decision_status == "selected":
                validate_selected_path(
                    decision.selected_path, decision.selected_path_type, f"steering decision {traffic_class}"
                )

        for traffic_class, decision in state.steering_load_balances.items():
            if decision.decision_status == "selected":
                for selected in decision.eligible_paths:
                    validate_selected_path(
                        selected, decision.selected_path_type, f"load-balance decision {traffic_class}"
                    )

        for ap_id, access_point in state.access_points.items():
            if access_point.bridge_id and access_point.bridge_id not in state.bridges:
                raise ForwarderError(400, f"access point {ap_id} references missing bridge {access_point.bridge_id}")
