from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path

from .models import (
    AccessPoint,
    Allocation,
    DhcpServer,
    FlowPolicy,
    FirewallRule,
    ForwarderState,
    NatPolicy,
    Path as ForwardPath,
    PortRange,
    RenderPlan,
)


class SecretResolver:
    """Resolve secret references without inventing placeholder credentials.

    Pamodi's Agent sends WireGuard private keys as file:///var/lib/sdwan-cpe/keys/<tunnel>.private.
    The Forwarder container must see that same path (shared read-only volume is recommended).
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.secrets_file = root / "var/lib/forwarder/secrets.json"
        self.secrets = {}
        if self.secrets_file.exists():
            import json
            try:
                self.secrets = json.loads(self.secrets_file.read_text(encoding="utf-8"))
            except Exception:
                self.secrets = {}

    def resolve(self, reference: str | None) -> str:
        if not reference:
            raise ValueError("secret reference is empty")

        if reference in self.secrets:
            value = str(self.secrets[reference]).strip()
            if not value:
                raise ValueError(f"secret {reference!r} is empty")
            return value

        if reference.startswith("file://"):
            path = Path(reference.removeprefix("file://"))
            if not path.is_absolute():
                path = self.root / path
            if not path.exists():
                raise ValueError(
                    f"secret file {path} does not exist; share /var/lib/sdwan-cpe/keys "
                    "between Agent and Forwarder containers"
                )
            value = path.read_text(encoding="utf-8").strip()
            if not value:
                raise ValueError(f"secret file {path} is empty")
            return value

        if reference.startswith("env://"):
            import os
            name = reference.removeprefix("env://")
            value = os.getenv(name, "").strip()
            if not value:
                raise ValueError(f"environment secret {name!r} is not set")
            return value

        raise ValueError(f"unresolved secret reference: {reference}")


class Renderer:
    # Forwarder-owned return-path marks live in the high half of the 32-bit mark
    # space so they cannot collide with the existing steering/path marks (0x1xx...).
    # These marks are local dataplane state only; the Agent does not need to know them.
    RETURN_MARK_FLAG = 0x80000000
    RETURN_TABLE_BASE = 30000
    RETURN_RULE_PRIORITY_BASE = 500

    def __init__(self, root: Path) -> None:
        self.root = root
        self.secrets = SecretResolver(root)

    def render_transition(self, previous: ForwarderState, current: ForwarderState, revision: str) -> RenderPlan:
        self._ensure_allocations(current)
        plan = RenderPlan(revision=revision)
        plan.phases = {
            "cleanup": self._render_cleanup(previous, current),
            "bridges": self._render_bridges(previous, current),
            "interfaces": self._render_interfaces(current),
            "tunnels": self._render_tunnels(previous, current, revision, plan),
            "routing": self._render_routing(previous, current),
            "nftables": self._render_nftables(current, revision, plan),
            "services": self._render_services(previous, current, revision, plan),
        }
        return plan

    def render_runtime_services(self, current: ForwarderState, revision: str) -> RenderPlan:
        """Reconcile ephemeral service runtime without replaying the dataplane.

        state.json is persistent, while dnsmasq processes, pid files and the active
        /app/etc/forwarder/dnsmasq configs are runtime artifacts.  Re-render only
        the services phase so a Forwarder/container restart can restore DHCP without
        touching interfaces, WireGuard, routing or nftables.
        """
        plan = RenderPlan(revision=revision)
        plan.phases = {
            "services": self._render_services(current, current, revision, plan),
        }
        return plan

    def _ensure_allocations(self, state: ForwarderState) -> None:
        flow_policy_labels = set(state.flow_policies)
        flow_policy_labels.update(f"traffic-class-{tc}" for tc in state.steering_active_paths)
        flow_policy_labels.update(f"traffic-class-{tc}" for tc in state.steering_load_balances)

        for prefix, labels in (
            ("path", sorted(state.paths)),
            ("group", sorted(state.path_groups)),
            ("flow-policy", sorted(flow_policy_labels)),
        ):
            for label in labels:
                alloc_label = f"{prefix}:{label}"
                if alloc_label in state.allocations:
                    continue
                state.allocation_counter += 1
                index = state.allocation_counter
                mark = 0x100 + index
                state.allocations[alloc_label] = Allocation(
                    ct_mark=mark,
                    packet_mark=mark,
                    route_table=10100 + index,
                    priority=1000 + index,
                    label=alloc_label,
                )

        # Keep one internal return-path allocation per configured WireGuard tunnel.
        # The remote CPE learns the ingress tunnel for each conntrack entry and uses
        # this high-bit mark only in the reply direction.  This makes the return path
        # symmetric without requiring any Agent/Controller coordination.
        desired_return_keys = {f"return-tunnel:{tunnel_id}" for tunnel_id in state.tunnels}
        for key in list(state.allocations):
            if key.startswith("return-tunnel:") and key not in desired_return_keys:
                state.allocations.pop(key, None)

        used_return_indexes: set[int] = set()
        for key, allocation in state.allocations.items():
            if not key.startswith("return-tunnel:"):
                continue
            if allocation.packet_mark & self.RETURN_MARK_FLAG:
                used_return_indexes.add(allocation.packet_mark & ~self.RETURN_MARK_FLAG)

        next_return_index = max(used_return_indexes, default=0) + 1
        for tunnel_id in sorted(state.tunnels):
            key = f"return-tunnel:{tunnel_id}"
            existing = state.allocations.get(key)
            if existing is not None and (existing.packet_mark & self.RETURN_MARK_FLAG):
                continue

            # Replace any malformed/legacy allocation for the same internal key.
            state.allocations.pop(key, None)
            while next_return_index in used_return_indexes:
                next_return_index += 1
            if next_return_index >= self.RETURN_MARK_FLAG:
                raise ValueError("return-path allocation space exhausted")

            return_mark = self.RETURN_MARK_FLAG | next_return_index
            state.allocations[key] = Allocation(
                ct_mark=return_mark,
                packet_mark=return_mark,
                route_table=self.RETURN_TABLE_BASE + next_return_index,
                priority=self.RETURN_RULE_PRIORITY_BASE + next_return_index,
                label=key,
            )
            used_return_indexes.add(next_return_index)
            next_return_index += 1

    def _render_cleanup(self, previous: ForwarderState, current: ForwarderState) -> list[str]:
        commands: list[str] = []

        # A physical interface removed from Forwarder desired state must lose only
        # Forwarder-owned configuration.  Keep the physical NIC itself, but stop its
        # DHCP client, run the DHCP deconfig hook (address/source-rule/table/default
        # cleanup), flush non-DHCP managed addresses when applicable, and leave it
        # administratively down.
        removed_interfaces = set(previous.interfaces) - set(current.interfaces)
        for name in sorted(removed_interfaces):
            old = previous.interfaces[name]
            if old.kind in {"bridge", "wireguard"}:
                continue

            pid_path = f"/run/forwarder/udhcpc-{name}.pid"
            commands.append(
                f"if [ -f {pid_path} ]; then "
                f"kill $(cat {pid_path}) >/dev/null 2>&1 || true; "
                f"rm -f {pid_path}; fi"
            )

            if old.role == "wan" or old.address_mode == "dhcp":
                commands.append(
                    f"interface={name} /usr/local/sbin/forwarder-udhcpc-script "
                    f"deconfig >/dev/null 2>&1 || true"
                )

            # DHCP deconfig removes the IPv4 lease. Static/manual interfaces also
            # need their configured addresses removed explicitly (including IPv6).
            if old.address_mode != "dhcp":
                commands.append(f"ip address flush dev {name} || true")

            commands.append(f"ip link set dev {name} down || true")

        for bridge_id in sorted(set(previous.bridges) - set(current.bridges)):
            for member in previous.bridges[bridge_id].members:
                commands.append(f"ip link set dev {member} nomaster || true")
            commands.append(f"ip link delete dev {bridge_id} type bridge || true")

        for tunnel_id in sorted(set(previous.tunnels) - set(current.tunnels)):
            commands.append(f"ip link delete dev {tunnel_id} || true")

        for tunnel_id, peers in previous.peers.items():
            current_peers = current.peers.get(tunnel_id, {})
            for peer_id, peer in peers.items():
                if peer_id not in current_peers:
                    commands.append(f"wg set {tunnel_id} peer {peer.public_key} remove || true")
                    host = self._endpoint_host(peer.endpoint)
                    if host:
                        commands.append(f"ip route del {host}/32 || true")

        for server_id in sorted(set(previous.dhcp_servers) - set(current.dhcp_servers)):
            # Stop only the dnsmasq instance owned by this DHCP service and remove
            # its active configuration. Tini (PID 1 in the container) reaps the
            # daemon after it exits, preventing zombie accumulation.
            commands.append(self._dnsmasq_stop_command(server_id))
            commands.append(f"rm -f /app/etc/forwarder/dnsmasq/{server_id}.conf")


        for ap_id in sorted(set(previous.access_points) - set(current.access_points)):
            old_ap = previous.access_points[ap_id]
            commands.extend(
                [
                    f"systemctl stop hostapd@{ap_id} || true",
                    f"systemctl disable hostapd@{ap_id} || true",
                    f"rm -f etc/forwarder/hostapd/{ap_id}.conf",
                    f"ip link set dev {old_ap.radio_interface} down || true",
                ]
            )

        for key in sorted(set(previous.allocations) - set(current.allocations)):
            alloc = previous.allocations[key]
            commands.append(f"ip rule del fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority} || true")
            commands.append(f"ip route flush table {alloc.route_table} || true")

        return commands

    def _render_bridges(self, previous: ForwarderState, current: ForwarderState) -> list[str]:
        commands: list[str] = []
        for bridge_id, bridge in sorted(current.bridges.items()):
            commands.append(f"ip link show dev {bridge_id} >/dev/null 2>&1 || ip link add name {bridge_id} type bridge")
            commands.append(f"ip link set dev {bridge_id} {bridge.admin_state}")

            old_members = set(previous.bridges.get(bridge_id, type(bridge)(bridge_id=bridge_id)).members)
            new_members = set(bridge.members)
            for removed in sorted(old_members - new_members):
                commands.append(f"ip link set dev {removed} nomaster || true")
            for member in sorted(new_members):
                commands.append(f"ip link set dev {member} master {bridge_id}")
        return commands

    def _render_interfaces(self, current: ForwarderState) -> list[str]:
        commands: list[str] = []

        for name, interface in sorted(current.interfaces.items()):
            if interface.kind in {"bridge", "wireguard"}:
                continue

            # Administrative state is authoritative. A disabled WAN must not keep a DHCP client alive.
            commands.append(f"ip link set dev {name} {interface.admin_state}")
            pid_path = f"/run/forwarder/udhcpc-{name}.pid"

            if interface.admin_state == "down":
                commands.append(
                    f"if [ -f {pid_path} ]; then kill $(cat {pid_path}) >/dev/null 2>&1 || true; rm -f {pid_path}; fi"
                )
                # Killing udhcpc does not reliably emit a deconfig event. Run the
                # hook explicitly so the DHCP address, source rule, dedicated table
                # and management default owned by this WAN are removed as well.
                commands.append(
                    f"interface={name} /usr/local/sbin/forwarder-udhcpc-script deconfig >/dev/null 2>&1 || true"
                )
                continue

            if interface.mtu:
                commands.append(f"ip link set mtu {interface.mtu} dev {name}")

            if interface.address_mode == "dhcp" and interface.role == "wan":
                commands.append("mkdir -p /run/forwarder/dhcp")
                commands.append(
                    f"if [ ! -s {pid_path} ] || ! kill -0 $(cat {pid_path}) >/dev/null 2>&1; then "
                    f"rm -f {pid_path}; "
                    f"udhcpc -i {name} -p {pid_path} -s /usr/local/sbin/forwarder-udhcpc-script -b -R; "
                    f"fi"
                )
                continue

            # Static/manual addressing: stop a previous DHCP client and make kernel addresses match desired state.
            commands.append(
                f"if [ -f {pid_path} ]; then kill $(cat {pid_path}) >/dev/null 2>&1 || true; rm -f {pid_path}; fi"
            )
            commands.append(f"ip address flush dev {name}")
            for address in interface.addresses:
                family_flag = "-6 " if ":" in address else ""
                commands.append(f"ip {family_flag}address add {address} dev {name}")

        return commands

    def _render_tunnels(self, previous: ForwarderState, current: ForwarderState, revision: str, plan: RenderPlan) -> list[str]:
        commands: list[str] = []
        for tunnel_id, tunnel in sorted(current.tunnels.items()):
            conf_path = f"var/lib/forwarder/rendered/{revision}/wireguard/{tunnel_id}.conf"
            plan.files[conf_path] = self._wireguard_config(tunnel_id, tunnel, current.peers.get(tunnel_id, {}))
            commands.append(f"ip link show dev {tunnel_id} >/dev/null 2>&1 || ip link add dev {tunnel_id} type wireguard")
            for address in tunnel.local_addresses:
                commands.append(f"ip address replace {address} dev {tunnel_id}")
            if tunnel.mtu:
                commands.append(f"ip link set mtu {tunnel.mtu} dev {tunnel_id}")
            commands.append(f"wg syncconf {tunnel_id} {self.root / conf_path}")
            interface = current.interfaces.get(tunnel_id)
            admin_state = interface.admin_state if interface else "up"
            commands.append(f"ip link set dev {tunnel_id} {admin_state}")

            old_peers = previous.peers.get(tunnel_id, {})
            for peer_id, peer in old_peers.items():
                if peer_id not in current.peers.get(tunnel_id, {}):
                    commands.append(f"wg set {tunnel_id} peer {peer.public_key} remove || true")
        return commands

    def _local_lan_route_commands(self, state: ForwarderState, route_table: int) -> list[str]:
        """Install local LAN prefixes in a policy-routing table.

        Conntrack restores the traffic-class/path fwmark on return packets.  Those
        packets therefore consult the marked table too.  Without connected LAN
        routes in that table, a return packet for a local client can match the
        table's default route and be sent back into WireGuard/WAN instead of LAN.
        """
        lan_interfaces: set[str] = {
            name for name, interface in state.interfaces.items() if interface.role == "lan"
        }
        lan_interfaces.update(state.bridges.keys())
        lan_interfaces.update(
            server.served_interface for server in state.dhcp_servers.values() if server.served_interface
        )

        wan_interfaces = set(state.wan_link_map.values())
        commands: list[str] = []
        seen: set[tuple[str, str]] = set()

        for interface_name in sorted(lan_interfaces):
            if interface_name in wan_interfaces or interface_name in state.tunnels:
                continue

            interface = state.interfaces.get(interface_name)
            if interface is None or interface.admin_state == "down":
                continue

            for address in interface.addresses:
                if ":" in address:
                    continue
                try:
                    ip_interface = ipaddress.ip_interface(address)
                except ValueError:
                    continue

                network = str(ip_interface.network)
                identity = (network, interface_name)
                if identity in seen:
                    continue
                seen.add(identity)

                commands.append(
                    f"ip route replace {network} dev {interface_name} "
                    f"src {ip_interface.ip} table {route_table}"
                )

        return commands

    def _render_routing(self, previous: ForwarderState, current: ForwarderState) -> list[str]:
        commands: list[str] = []

        # Stateful symmetric return path.  Each WireGuard tunnel gets a private
        # fwmark/table pair.  nftables assigns this mark to the conntrack entry on
        # the receiving CPE; only reply-direction packets restore it to meta mark.
        for tunnel_id in sorted(current.tunnels):
            alloc = current.allocations.get(f"return-tunnel:{tunnel_id}")
            if alloc is None:
                continue
            commands.extend(
                [
                    f"ip route flush table {alloc.route_table} || true",
                    f"ip rule del fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority} || true",
                    f"ip rule add fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority}",
                    f"ip route replace default dev {tunnel_id} table {alloc.route_table}",
                ]
            )

        for path_id, path in sorted(current.paths.items()):
            alloc = current.allocations[f"path:{path_id}"]
            commands.extend(
                [
                    f"ip route flush table {alloc.route_table} || true",
                    f"ip rule del fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority} || true",
                    f"ip rule add fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority}",
                ]
            )
            commands.extend(self._local_lan_route_commands(current, alloc.route_table))
            commands.extend(self._route_for_path(path, current, alloc.route_table))

        for group_id, group in sorted(current.path_groups.items()):
            alloc = current.allocations[f"group:{group_id}"]
            commands.extend(
                [
                    f"ip route flush table {alloc.route_table} || true",
                    f"ip rule del fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority} || true",
                    f"ip rule add fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority}",
                ]
            )
            commands.extend(self._local_lan_route_commands(current, alloc.route_table))
            commands.extend(self._route_for_group(group_id, current, alloc.route_table))

        for traffic_class, decision in sorted(current.steering_active_paths.items()):
            policy_id = f"traffic-class-{traffic_class}"
            alloc = current.allocations.get(f"flow-policy:{policy_id}")
            selected_path = decision.selected_path

            if not alloc:
                continue

            commands.append(f"ip route flush table {alloc.route_table} || true")
            commands.append(f"ip rule del fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority} || true")
            commands.append(f"ip rule add fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority}")
            commands.extend(self._local_lan_route_commands(current, alloc.route_table))

            if decision.decision_status == "selected" and selected_path:
                commands.extend(self._route_for_selected_path(selected_path, current, alloc.route_table, decision.selected_path_type))

        for traffic_class, decision in sorted(current.steering_load_balances.items()):
            policy_id = f"traffic-class-{traffic_class}"
            alloc = current.allocations.get(f"flow-policy:{policy_id}")
            if not alloc:
                continue

            # Always clear the previous route before applying the current decision.
            # This is required when a previously selected load-balance decision
            # transitions to no-path: the old ECMP route must not remain installed.
            commands.append(f"ip route flush table {alloc.route_table} || true")
            commands.append(f"ip rule del fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority} || true")
            commands.append(f"ip rule add fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority}")
            commands.extend(self._local_lan_route_commands(current, alloc.route_table))

            if decision.decision_status == "selected" and decision.eligible_paths:
                commands.extend(
                    self._route_for_dynamic_load_balance(
                        decision.eligible_paths, current, alloc.route_table, decision.selected_path_type
                    )
                )

        # Reconcile Forwarder-managed static routes against the previous state.
        # This removes prefixes that disappeared from desired state and renders
        # WireGuard peer routes sharing the same destination as one multipath route
        # instead of letting repeated `ip route replace` calls overwrite each other.
        commands.extend(self._render_static_routes(previous, current))
        return commands

    @staticmethod
    def _route_identity(route) -> tuple[str, str | None, str | None, int | None]:
        return (
            route.destination_cidr,
            route.next_hop_ip,
            route.out_interface,
            route.metric,
        )

    def _collect_peer_route_groups(self, state: ForwarderState) -> dict[tuple[str, int | None], list]:
        groups: dict[tuple[str, int | None], dict[tuple[str | None, str | None], object]] = {}

        for route_set_id, route_set in state.static_route_sets.items():
            if not route_set_id.endswith("-peer-routes"):
                continue

            for route in route_set.routes:
                key = (route.destination_cidr, route.metric)
                identity = (route.next_hop_ip, route.out_interface)
                groups.setdefault(key, {})[identity] = route

        return {key: list(routes.values()) for key, routes in groups.items()}

    def _render_static_routes(self, previous: ForwarderState, current: ForwarderState) -> list[str]:
        commands: list[str] = []

        # --- Ordinary static routes -------------------------------------------------
        # Peer route sets are handled separately below because several WireGuard
        # tunnels may legitimately advertise the same remote LAN prefix.
        previous_normal: dict[tuple[str, str | None, str | None, int | None], object] = {}
        current_normal: dict[tuple[str, str | None, str | None, int | None], object] = {}

        for route_set_id, route_set in previous.static_route_sets.items():
            if route_set_id.endswith("-peer-routes"):
                continue
            for route in route_set.routes:
                previous_normal[self._route_identity(route)] = route

        for route_set_id, route_set in current.static_route_sets.items():
            if route_set_id.endswith("-peer-routes"):
                continue
            for route in route_set.routes:
                current_normal[self._route_identity(route)] = route

        # Remove routes that existed before but no longer exist in desired state.
        for key in sorted(previous_normal.keys() - current_normal.keys(), key=str):
            route = previous_normal[key]
            route_cmd = ["ip route del", route.destination_cidr]
            if route.next_hop_ip:
                route_cmd.append(f"via {route.next_hop_ip}")
            if route.out_interface:
                route_cmd.append(f"dev {route.out_interface}")
            if route.metric is not None:
                route_cmd.append(f"metric {route.metric}")
            commands.append(" ".join(route_cmd) + " >/dev/null 2>&1 || true")

        # Apply the current ordinary static routes.
        for key in sorted(current_normal, key=str):
            route = current_normal[key]
            if route.out_interface and not self._interface_is_usable_for_routing(route.out_interface, current):
                continue

            route_cmd = ["ip route replace", route.destination_cidr]
            if route.next_hop_ip:
                route_cmd.append(f"via {route.next_hop_ip}")
            if route.out_interface:
                route_cmd.append(f"dev {route.out_interface}")
            if route.metric is not None:
                route_cmd.append(f"metric {route.metric}")
            commands.append(" ".join(route_cmd))

        # --- WireGuard peer routes --------------------------------------------------
        previous_peer_groups = self._collect_peer_route_groups(previous)
        current_peer_groups = self._collect_peer_route_groups(current)

        # If a prefix disappeared completely (for example after deleting an
        # allowed-prefix), remove the old kernel route.
        for destination, metric in sorted(
            previous_peer_groups.keys() - current_peer_groups.keys(),
            key=lambda item: (item[0], -1 if item[1] is None else item[1]),
        ):
            route_cmd = ["ip route del", destination]
            if metric is not None:
                route_cmd.append(f"metric {metric}")
            commands.append(" ".join(route_cmd) + " >/dev/null 2>&1 || true")

        # Rebuild every current peer prefix from the complete desired state.
        # One tunnel -> normal route. Several tunnels -> one Linux multipath route.
        for destination, metric in sorted(
            current_peer_groups,
            key=lambda item: (item[0], -1 if item[1] is None else item[1]),
        ):
            usable_routes = [
                route
                for route in current_peer_groups[(destination, metric)]
                if not route.out_interface
                or self._interface_is_usable_for_routing(route.out_interface, current)
            ]

            if not usable_routes:
                route_cmd = ["ip route del", destination]
                if metric is not None:
                    route_cmd.append(f"metric {metric}")
                commands.append(" ".join(route_cmd) + " >/dev/null 2>&1 || true")
                continue

            route_cmd = ["ip route replace", destination]
            if metric is not None:
                route_cmd.append(f"metric {metric}")

            if len(usable_routes) == 1:
                route = usable_routes[0]
                if route.next_hop_ip:
                    route_cmd.append(f"via {route.next_hop_ip}")
                if route.out_interface:
                    route_cmd.append(f"dev {route.out_interface}")
            else:
                for route in sorted(
                    usable_routes,
                    key=lambda item: (item.out_interface or "", item.next_hop_ip or ""),
                ):
                    nexthop = ["nexthop"]
                    if route.next_hop_ip:
                        nexthop.append(f"via {route.next_hop_ip}")
                    if route.out_interface:
                        nexthop.append(f"dev {route.out_interface}")
                    nexthop.append("weight 1")
                    route_cmd.append(" ".join(nexthop))

            commands.append(" ".join(route_cmd))

        return commands

    def _render_nftables(self, current: ForwarderState, revision: str, plan: RenderPlan) -> list[str]:
        nft_path = f"var/lib/forwarder/rendered/{revision}/nftables/forwarder.nft"
        nft_abs_path = self.root / nft_path
        nft_abs_dir = nft_abs_path.parent
        ruleset = self._nftables_ruleset(current)

        # Keep the rendered file in the render plan for audit/debug.
        plan.files[nft_path] = ruleset

        return [
            f"mkdir -p {nft_abs_dir}",
            f"cat > {nft_abs_path} <<'NFT_EOF'\n{ruleset}\nNFT_EOF",
            "nft delete table inet forwarder >/dev/null 2>&1 || true",
            f"nft -f {nft_abs_path}",
        ]

    def _dnsmasq_stop_command(self, server_id: str) -> str:
        pid_path = f"/run/dnsmasq-{server_id}.pid"
        active_conf_path = f"/app/etc/forwarder/dnsmasq/{server_id}.conf"

        # Stop the process referenced by the pidfile, wait briefly for it to exit,
        # then fall back to matching the service-specific command line. With tini as
        # PID 1, exited/re-parented dnsmasq processes are reaped instead of becoming
        # permanent zombies.
        return (
            f"PID=''; "
            f"if [ -s {pid_path} ]; then PID=$(cat {pid_path}); fi; "
            f'if [ -n "$PID" ] && kill -0 "$PID" >/dev/null 2>&1; then '
            f'kill "$PID" >/dev/null 2>&1 || true; '
            f"for i in $(seq 1 30); do "
            f'kill -0 "$PID" >/dev/null 2>&1 || break; '
            f"sleep 0.1; "
            f"done; "
            f'if kill -0 "$PID" >/dev/null 2>&1; then '
            f'kill -9 "$PID" >/dev/null 2>&1 || true; '
            f"fi; "
            f"fi; "
            f"rm -f {pid_path}; "
            f"pkill -f '^dnsmasq .*--conf-file={active_conf_path}([[:space:]]|$)' "
            f">/dev/null 2>&1 || true"
        )

    def _dnsmasq_start_command(self, server_id: str, active_conf_path: str, pid_path: str) -> str:
        return (
            f"dnsmasq --conf-file={active_conf_path} --pid-file={pid_path}; "
            f"for i in $(seq 1 30); do "
            f"if [ -s {pid_path} ] && kill -0 $(cat {pid_path}) >/dev/null 2>&1; then "
            f"exit 0; "
            f"fi; "
            f"sleep 0.1; "
            f"done; "
            f"echo 'dnsmasq failed to stay running for {server_id}' >&2; "
            f"exit 1"
        )

    def _dnsmasq_runtime_reconcile_command(
        self, server_id: str, rendered_conf_path: str, active_conf_path: str, pid_path: str
    ) -> str:
        """Repair dnsmasq only when the persisted desired service is not healthy."""
        stop_command = self._dnsmasq_stop_command(server_id)
        start_command = self._dnsmasq_start_command(server_id, active_conf_path, pid_path)
        return (
            f"HEALTHY=0; PID=''; "
            f"if [ -s {pid_path} ]; then PID=$(cat {pid_path}); fi; "
            f'if [ -n "$PID" ] && kill -0 "$PID" >/dev/null 2>&1 '
            f"&& [ -r /proc/$PID/cmdline ] "
            f"&& tr '\\000' ' ' < /proc/$PID/cmdline | grep -F -- '--conf-file={active_conf_path}' >/dev/null 2>&1 "
            f"&& [ -f {active_conf_path} ] "
            f"&& cmp -s {rendered_conf_path} {active_conf_path}; then HEALTHY=1; fi; "
            f'if [ "$HEALTHY" -eq 0 ]; then '
            f"mkdir -p /app/etc/forwarder/dnsmasq; "
            f"install -m 0644 {rendered_conf_path} {active_conf_path}; "
            f"dnsmasq --test --conf-file={active_conf_path} || exit $?; "
            f"{stop_command}; "
            f"{start_command}; "
            f"fi"
        )

    def _render_services(self, previous: ForwarderState, current: ForwarderState, revision: str, plan: RenderPlan) -> list[str]:
        commands: list[str] = []

        for server_id, server in sorted(current.dhcp_servers.items()):
            conf_path = f"var/lib/forwarder/rendered/{revision}/dnsmasq/{server_id}.conf"
            active_conf_path = f"/app/etc/forwarder/dnsmasq/{server_id}.conf"
            pid_path = f"/run/dnsmasq-{server_id}.pid"

            # Keep a rendered copy for this revision even when no restart is needed.
            plan.files[conf_path] = self._dnsmasq_config(server)

            previous_server = previous.dhcp_servers.get(server_id)
            if (
                previous_server is not None
                and previous_server.model_dump(mode="json") == server.model_dump(mode="json")
            ):
                # Preserve the previous no-bounce behaviour, but verify ephemeral
                # runtime.  If dnsmasq/config disappeared after a restart, restore
                # them without touching a healthy service.
                if server.enabled:
                    commands.append(
                        self._dnsmasq_runtime_reconcile_command(
                            server_id, f"/app/{conf_path}", active_conf_path, pid_path
                        )
                    )
                else:
                    commands.append(self._dnsmasq_stop_command(server_id))
                continue

            commands.append("mkdir -p /app/etc/forwarder/dnsmasq")
            commands.append(f"install -m 0644 /app/{conf_path} {active_conf_path}")

            # Validate the new configuration before touching the currently running
            # dnsmasq instance. If validation fails, the old service stays alive.
            commands.append(f"dnsmasq --test --conf-file={active_conf_path}")
            commands.append(self._dnsmasq_stop_command(server_id))

            if server.enabled:
                commands.append(self._dnsmasq_start_command(server_id, active_conf_path, pid_path))

        for ap_id, ap in sorted(current.access_points.items()):
            conf_path = f"var/lib/forwarder/rendered/{revision}/hostapd/{ap_id}.conf"
            plan.files[conf_path] = self._hostapd_config(ap)

            previous_ap = previous.access_points.get(ap_id)
            if (
                previous_ap is not None
                and previous_ap.model_dump(mode="json") == ap.model_dump(mode="json")
            ):
                continue

            if ap.enabled:
                commands.append(f"ip link set dev {ap.radio_interface} up")
                commands.append(f"install -m 0600 {conf_path} etc/forwarder/hostapd/{ap_id}.conf")
                commands.append(f"systemctl restart hostapd@{ap_id}")
                commands.append(f"systemctl enable hostapd@{ap_id}")
                if ap.channel is not None:
                    commands.append(f"iw dev {ap.radio_interface} set channel {ap.channel}")
            else:
                commands.append(f"systemctl stop hostapd@{ap_id} || true")
                commands.append(f"systemctl disable hostapd@{ap_id} || true")
                commands.append(f"ip link set dev {ap.radio_interface} down || true")

        return commands

    def _resolve_wan_interface(self, logical_name: str, state: ForwarderState) -> str | None:
        if logical_name in state.wan_link_map:
            mapped = state.wan_link_map[logical_name]
            configured = state.interfaces.get(mapped)
            # WAN_LINK_MAP_JSON is passive metadata, not proof that this WAN is
            # configured.  A deleted/stale WAN must therefore not become routable
            # merely because its UPLx -> NIC mapping still exists.
            if configured is not None and configured.role == "wan":
                return mapped
            return None
        # Static WAN routes created by the Agent use <WAN>-default and expose out_interface.
        route_set = state.static_route_sets.get(f"{logical_name}-default")
        if route_set:
            for route in route_set.routes:
                if route.out_interface:
                    return route.out_interface
        # If the value already is a real/known interface, keep it.
        if logical_name in state.interfaces:
            return logical_name
        return None

    def _interface_is_usable_for_routing(self, dev: str, state: ForwarderState) -> bool:
        """
        Return False when Forwarder desired state explicitly marks an interface DOWN.

        The renderer reapplies the complete desired state on every transaction. Without
        this guard, the interfaces phase can correctly bring a WAN down and the routing
        phase can immediately try to recreate a route through that same disabled WAN,
        causing the whole transaction to fail.
        """
        interface = state.interfaces.get(dev)
        if interface is None:
            # A physical NIC that appears in WAN_LINK_MAP_JSON but is absent from
            # state.interfaces is only passive deployment metadata: it is not an
            # active/configured WAN and must not be used by stale routing objects.
            if dev in state.wan_link_map.values():
                return False
            # Other external/unmanaged devices may still be used by explicit path
            # objects; preserve the previous behavior for those devices.
            return True
        return interface.admin_state != "down"

    def _unreachable_default_command(self, route_table: int) -> str:
        """
        Keep policy-routing traffic from falling through to later rules (including main)
        when its selected WAN/tunnel is administratively unavailable.
        """
        return f"ip route replace unreachable default table {route_table}"

    def _device_for_selected_path(
        self, selected_path: str, state: ForwarderState, selected_path_type: str | None = None
    ) -> str | None:
        if selected_path_type == "wan-link":
            return self._resolve_wan_interface(selected_path, state)
        if selected_path_type == "tunnel":
            return selected_path if selected_path in state.tunnels else None
        if selected_path in state.paths:
            path = state.paths[selected_path]
            return path.tunnel_id if path.type == "wireguard_peer" and path.tunnel_id else path.wan_interface
        if selected_path in state.tunnels:
            return selected_path
        if selected_path in state.interfaces:
            return selected_path
        return self._resolve_wan_interface(selected_path, state)

    def _default_route_command(self, dev: str, route_table: int) -> str:
        # Use the gateway learned by DHCP/static configuration when present.
        # Falling back to a device-only route is useful for point-to-point links.
        return (
            f"GW=$(ip -4 route show table all default dev {dev} 2>/dev/null "
            f"| awk '/^default/ {{for(i=1;i<=NF;i++) if($i==\"via\"){{print $(i+1); exit}}}}'); "
            f"if [ -n \"$GW\" ]; then "
            f"ip route replace default via \"$GW\" dev {dev} onlink table {route_table}; "
            f"else ip route replace default dev {dev} table {route_table}; fi"
        )

    def _route_for_selected_path(
        self, selected_path: str, state: ForwarderState, route_table: int, selected_path_type: str | None = None
    ) -> list[str]:
        if selected_path in state.paths:
            return self._route_for_path(state.paths[selected_path], state, route_table)
        if selected_path in state.path_groups:
            return self._route_for_group(selected_path, state, route_table)

        dev = self._device_for_selected_path(selected_path, state, selected_path_type)
        if not dev:
            if selected_path_type == "wan-link" and selected_path in state.wan_link_map:
                # The logical mapping still exists as deployment metadata, but the
                # mapped WAN is not currently configured.  Keep marked traffic from
                # falling through to main while allowing the WAN deletion to apply.
                return [self._unreachable_default_command(route_table)]
            return [f"echo 'unresolved selected path: {selected_path}' >&2; exit 42"]

        if not self._interface_is_usable_for_routing(dev, state):
            return [self._unreachable_default_command(route_table)]

        return [self._default_route_command(dev, route_table)]

    def _endpoint_route_command(self, host: str, dev: str) -> str:
        return (
            f"GW=$(ip -4 route show table all default dev {dev} 2>/dev/null "
            f"| awk '/^default/ {{for(i=1;i<=NF;i++) if($i==\"via\"){{print $(i+1); exit}}}}'); "
            f"if [ -n \"$GW\" ]; then ip route replace {host}/32 via \"$GW\" dev {dev}; "
            f"else ip route replace {host}/32 dev {dev}; fi"
        )

    def _route_for_path(self, path: ForwardPath, state: ForwarderState, route_table: int) -> list[str]:
        commands: list[str] = []

        if path.type == "wireguard_peer" and path.tunnel_id and path.peer_id:
            if not self._interface_is_usable_for_routing(path.wan_interface, state):
                return [self._unreachable_default_command(route_table)]
            if not self._interface_is_usable_for_routing(path.tunnel_id, state):
                return [self._unreachable_default_command(route_table)]

            peer = state.peers.get(path.tunnel_id, {}).get(path.peer_id)
            host = self._endpoint_host(peer.endpoint if peer else None)
            if host:
                commands.append(self._endpoint_route_command(host, path.wan_interface))
            commands.append(self._default_route_command(path.tunnel_id, route_table))
        else:
            if not self._interface_is_usable_for_routing(path.wan_interface, state):
                return [self._unreachable_default_command(route_table)]
            commands.append(self._default_route_command(path.wan_interface, route_table))

        return commands

    def _route_for_group(self, group_id: str, state: ForwarderState, route_table: int) -> list[str]:
        group = state.path_groups[group_id]
        commands: list[str] = []

        if group.strategy == "ordered_failover" and group.active_path_id:
            active = state.paths[group.active_path_id]
            commands.extend(self._route_for_path(active, state, route_table))
            return commands

        nexthops: list[str] = []
        for member in group.members:
            path = state.paths[member.path_id]
            weight = member.weight or 1

            if path.type == "wireguard_peer" and path.tunnel_id:
                if not self._interface_is_usable_for_routing(path.wan_interface, state):
                    continue
                dev = path.tunnel_id
            else:
                dev = path.wan_interface

            if not self._interface_is_usable_for_routing(dev, state):
                continue

            nexthops.append(f"nexthop dev {dev} weight {weight}")

        if nexthops:
            commands.append(f"ip route replace default table {route_table} {' '.join(nexthops)}")
        else:
            commands.append(self._unreachable_default_command(route_table))

        return commands

    def _route_for_dynamic_load_balance(
        self, selected_paths: list[str], state: ForwarderState, route_table: int, selected_path_type: str | None = None
    ) -> list[str]:
        devices: list[str] = []
        for selected in selected_paths:
            dev = self._device_for_selected_path(selected, state, selected_path_type)
            if dev and self._interface_is_usable_for_routing(dev, state):
                devices.append(dev)

        if not devices:
            return [self._unreachable_default_command(route_table)]

        commands: list[str] = []

        # Linux defaults to Layer-3 ECMP hashing (fib_multipath_hash_policy=0).
        # With SD-WAN traffic tests the source/destination IP pair can stay the same
        # while only TCP/UDP ports change, so several independent flows may hash to
        # the same next-hop.  Policy 1 makes IPv4 ECMP Layer-4 aware.
        #
        # BusyBox provides the sysctl applet in the Forwarder image, so no procps
        # dependency is required.  Apply this only when real multipath ECMP exists.
        if len(devices) > 1:
            commands.append(
                "CURRENT=$(cat /proc/sys/net/ipv4/fib_multipath_hash_policy 2>/dev/null || echo unknown); "
                "if [ \"$CURRENT\" = \"1\" ]; then "
                "echo 'fib_multipath_hash_policy already set to 1'; "
                "else "
                "sysctl -w net.ipv4.fib_multipath_hash_policy=1 >/dev/null; "
                "fi"
            )

        # Build a gateway-aware multipath route at apply time.
        # IMPORTANT: the routing table belongs to the route itself and must be
        # placed before the multipath nexthop blocks.
        parts = [f"ROUTE='ip route replace default table {route_table}'"]
        for dev in devices:
            parts.append(
                f"GW=$(ip -4 route show table all default dev {dev} 2>/dev/null "
                f"| awk '/^default/ {{for(i=1;i<=NF;i++) if($i==\"via\"){{print $(i+1); exit}}}}')"
            )
            parts.append(
                f"if [ -n \"$GW\" ]; then ROUTE=\"$ROUTE nexthop via $GW dev {dev} weight 1\"; "
                f"else ROUTE=\"$ROUTE nexthop dev {dev} weight 1\"; fi"
            )
        parts.append('eval "$ROUTE"')
        commands.append("; ".join(parts))
        return commands

    def _can_route_direct(self, selected_path: str | None, state: ForwarderState) -> bool:
        if not selected_path:
            return False
        return selected_path in state.interfaces or selected_path in state.tunnels or selected_path in state.wan_link_map

    def _wireguard_config(self, tunnel_id: str, tunnel, peers: dict) -> str:
        # wg syncconf accepts wg(8) configuration, not wg-quick directives.
        # Address and MTU are therefore applied with `ip` in _render_tunnels, not written here.
        lines = ["[Interface]"]
        if not tunnel.private_key_ref:
            raise ValueError(f"WireGuard tunnel {tunnel_id} has no private_key_ref")
        lines.append(f"PrivateKey = {self.secrets.resolve(tunnel.private_key_ref)}")
        lines.append(f"ListenPort = {tunnel.listen_port}")

        for peer_id, peer in sorted(peers.items()):
            lines.extend(["", "[Peer]"])
            lines.append(f"# peer_id = {peer_id}")
            lines.append(f"PublicKey = {peer.public_key}")
            if peer.endpoint:
                lines.append(f"Endpoint = {peer.endpoint}")
            if peer.allowed_ips:
                lines.append(f"AllowedIPs = {', '.join(peer.allowed_ips)}")
            if peer.persistent_keepalive is not None:
                lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")
            if peer.preshared_key_ref:
                lines.append(f"PresharedKey = {self.secrets.resolve(peer.preshared_key_ref)}")
        return "\n".join(lines) + "\n"

    def _nftables_ruleset(self, current: ForwarderState) -> str:
        lines = [
            "table inet forwarder {",
            "  chain prerouting {",
            "    type filter hook prerouting priority mangle; policy accept;",
        ]

        # Learn the actual ingress WireGuard tunnel on the receiving CPE.  The rule
        # runs for every original-direction packet, not only ct state new, so an
        # established flow that fails over to another tunnel updates its return path.
        for tunnel_id in sorted(current.tunnels):
            alloc = current.allocations.get(f"return-tunnel:{tunnel_id}")
            if alloc is None:
                continue
            escaped_tunnel = tunnel_id.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(
                f'    iifname "{escaped_tunnel}" ct direction original '
                f'ct mark set 0x{alloc.ct_mark:x}'
            )

        # Existing steering marks are restored only in the original direction.
        # Learned return-path marks (high bit set) are restored only in reply
        # direction.  This prevents the remote CPE from independently re-steering
        # the reply through another ECMP tunnel.
        lines.extend(
            [
                f"    ct direction original ct mark != 0 ct mark and 0x{self.RETURN_MARK_FLAG:x} == 0 meta mark set ct mark",
                f"    ct direction reply ct mark and 0x{self.RETURN_MARK_FLAG:x} != 0 meta mark set ct mark",
            ]
        )

        for policy_id, policy in sorted(current.flow_policies.items(), key=lambda item: ((item[1].priority or 10**9), item[0])):
            rule = self._flow_policy_rule(policy_id, policy, current)
            if rule:
                lines.append(f"    {rule}")

        lines.extend(
            [
                "  }",
                "  chain output {",
                "    type route hook output priority mangle; policy accept;",
                f"    ct direction original ct mark != 0 ct mark and 0x{self.RETURN_MARK_FLAG:x} == 0 meta mark set ct mark",
                f"    ct direction reply ct mark and 0x{self.RETURN_MARK_FLAG:x} != 0 meta mark set ct mark",
                "  }",
                "  chain forward {",
                "    type filter hook forward priority filter; policy accept;",
            ]
        )

        for rule_id, rule in sorted(current.firewall_rules.items(), key=lambda item: ((item[1].priority or 10**9), item[0])):
            rendered_rule = self._firewall_rule(rule_id, rule)
            if rendered_rule:
                lines.append(f"    {rendered_rule}")

        lines.extend(
            [
                "  }",
                "  chain prerouting_nat {",
                "    type nat hook prerouting priority dstnat; policy accept;",
            ]
        )

        for path_id, path in sorted(current.paths.items()):
            if not path.nat_policy_id:
                continue
            alloc = current.allocations.get(f"path:{path_id}")
            policy = current.nat_policies.get(path.nat_policy_id)
            if alloc and policy and policy.scope == "path":
                for rule in self._nat_rules_for_policy(policy, alloc.ct_mark, "prerouting"):
                    lines.append(f"    {rule}")

        lines.extend(
            [
                "  }",
                "  chain postrouting_nat {",
                "    type nat hook postrouting priority srcnat; policy accept;",
            ]
        )

        for path_id, path in sorted(current.paths.items()):
            if not path.nat_policy_id:
                continue
            alloc = current.allocations.get(f"path:{path_id}")
            policy = current.nat_policies.get(path.nat_policy_id)
            if alloc and policy and policy.scope == "path":
                for rule in self._nat_rules_for_policy(policy, alloc.ct_mark, "postrouting"):
                    lines.append(f"    {rule}")

        # WAN egress NAT is intentionally independent from traffic-class fwmarks.
        # This covers both:
        #   1) marked traffic-class traffic using policy-routing tables, and
        #   2) unmarked best-effort traffic using the main routing table.
        # The Agent decides which WAN roles require Internet NAT and sends these
        # policies with scope="egress" and an out_interface (for example ens5).
        for _policy_id, policy in sorted(current.nat_policies.items()):
            if policy.scope != "egress":
                continue
            for rule in self._nat_rules_for_policy(policy, None, "postrouting"):
                lines.append(f"    {rule}")

        lines.extend(["  }", "}"])
        return "\n".join(lines) + "\n"

    def _match_tokens(self, match) -> list[str]:
        tokens: list[str] = []

        if match.ingress_interface:
            tokens.append(f'iifname "{match.ingress_interface}"')
        if match.ingress_bridge:
            tokens.append(f'iifname "{match.ingress_bridge}"')
        if match.src_prefix:
            tokens.append(f"ip saddr {match.src_prefix}")
        if match.dst_prefix:
            tokens.append(f"ip daddr {match.dst_prefix}")

        if match.protocol and match.protocol != "any":
            if match.protocol in {"tcp", "udp"}:
                tokens.append(match.protocol)
            elif match.protocol == "icmp":
                tokens.append("ip protocol icmp")

        if match.protocol in {"tcp", "udp"}:
            if match.src_ports is not None:
                selector = self._port_selector(match.src_ports)
                if selector:
                    tokens.append(f"sport {selector}")
            if match.dst_ports is not None:
                selector = self._port_selector(match.dst_ports)
                if selector:
                    tokens.append(f"dport {selector}")

        if match.dscp is not None:
            tokens.append(f"ip dscp {match.dscp}")

        return tokens

    def _flow_policy_rule(self, policy_id: str, policy: FlowPolicy, current: ForwarderState) -> str:
        # Traffic-class steering applies only to the original direction and only to
        # connections that are not carrying a learned return-path mark.  This keeps
        # remote replies pinned to the tunnel learned from the real ingress path.
        tokens: list[str] = [
            "ct direction original",
            f"ct mark and 0x{self.RETURN_MARK_FLAG:x} == 0",
        ]
        tokens.extend(self._match_tokens(policy.match))

        action = policy.action
        if action is None:
            steering_action = self._steering_action_for_policy(policy_id, current)
            if steering_action == "drop":
                tokens.append("drop")
                return " ".join(tokens)
            if isinstance(steering_action, Allocation):
                tokens.append(f"ct mark set 0x{steering_action.ct_mark:x} meta mark set ct mark")
                return " ".join(tokens)
            return ""

        if action.type == "use_path" and action.path_id:
            alloc = current.allocations[f"path:{action.path_id}"]
            tokens.append(f"ct mark set 0x{alloc.ct_mark:x} meta mark set ct mark")
        elif action.type == "use_path_group" and action.path_group_id:
            alloc = current.allocations[f"group:{action.path_group_id}"]
            tokens.append(f"ct mark set 0x{alloc.ct_mark:x} meta mark set ct mark")
        elif action.type == "drop":
            tokens.append("drop")
        elif action.type == "reject":
            tokens.append("reject")

        return " ".join(tokens)

    def _steering_action_for_policy(self, policy_id: str, current: ForwarderState) -> Allocation | str | None:
        if not policy_id.startswith("traffic-class-"):
            return current.allocations.get(f"flow-policy:{policy_id}")

        traffic_class = policy_id.removeprefix("traffic-class-")

        active = current.steering_active_paths.get(traffic_class)
        if active and active.decision_status == "no-path":
            return "drop"

        load_balance = current.steering_load_balances.get(traffic_class)
        if load_balance and load_balance.decision_status == "no-path":
            return "drop"

        # Important: the flow-policy fwmark is the traffic-class identity returned to the agent.
        # Steering changes the route table behind this mark; it should not change the packet mark.
        return current.allocations.get(f"flow-policy:{policy_id}")

    def _firewall_rule(self, rule_id: str, rule: FirewallRule) -> str:
        tokens: list[str] = self._match_tokens(rule.match)

        if rule.log:
            tokens.append(f'log prefix "fw-{rule_id} "')

        if rule.action == "allow":
            tokens.append("accept")
        elif rule.action == "deny":
            tokens.append("drop")

        return " ".join(tokens)

    def _nat_rules_for_policy(self, policy: NatPolicy, ct_mark: int | None, phase: str) -> list[str]:
        rules: list[str] = []
        for rule in policy.rules:
            if phase == "prerouting" and rule.action not in {"dnat", "port_forward"}:
                continue
            if phase == "postrouting" and rule.action not in {"masquerade", "snat"}:
                continue

            tokens: list[str] = []
            if ct_mark is not None:
                tokens.append(f"ct mark 0x{ct_mark:x}")
            if rule.out_interface:
                tokens.append(f'oifname "{rule.out_interface}"')
            if rule.src_prefix:
                tokens.append(f"ip saddr {rule.src_prefix}")
            if rule.dst_prefix and rule.dst_prefix != "any":
                tokens.append(f"ip daddr {rule.dst_prefix}")
            if rule.protocol and rule.protocol != "any":
                tokens.append(rule.protocol)

            if rule.action == "masquerade":
                tokens.append("masquerade")
            elif rule.action == "snat" and rule.translated_source:
                tokens.append(f"snat to {rule.translated_source}")
            elif rule.action in {"dnat", "port_forward"} and rule.translated_destination:
                tokens.append(f"dnat to {rule.translated_destination}")
            rules.append(" ".join(tokens))
        return rules

    def _dnsmasq_config(self, server: DhcpServer) -> str:
        lines = [f"interface={server.served_interface}", "bind-interfaces"]
        if server.range_start and server.range_end:
            lease_time = server.lease_time or "24h"
            lines.append(f"dhcp-range={server.range_start},{server.range_end},{lease_time}")
        if server.gateway:
            lines.append(f"dhcp-option=option:router,{server.gateway}")
        if server.dns_servers:
            lines.append(f"dhcp-option=option:dns-server,{','.join(server.dns_servers)}")
        for reservation in server.reservations:
            lines.append(f"dhcp-host={reservation.mac_address},{reservation.ip_address}")
        return "\n".join(lines) + "\n"

    def _hostapd_config(self, ap: AccessPoint) -> str:
        lines = [f"interface={ap.radio_interface}"]
        if ap.bridge_id:
            lines.append(f"bridge={ap.bridge_id}")
        lines.append(f"ssid={ap.ssid}")
        if ap.hw_mode:
            lines.append(f"hw_mode={ap.hw_mode[0]}")
        if ap.channel is not None:
            lines.append(f"channel={ap.channel}")
        if ap.security == "WPA3":
            lines.extend(
                [
                    "wpa=2",
                    "wpa_key_mgmt=SAE",
                    "rsn_pairwise=CCMP",
                    f"sae_password={self.secrets.resolve(ap.credential_ref)}",
                    "ieee80211w=2",
                ]
            )
        else:
            lines.extend(
                [
                    "wpa=2",
                    "wpa_key_mgmt=WPA-PSK",
                    "rsn_pairwise=CCMP",
                    f"wpa_passphrase={self.secrets.resolve(ap.credential_ref)}",
                ]
            )
        return "\n".join(lines) + "\n"

    def _port_selector(self, selector) -> str | None:
        if selector is None:
            return None
        if isinstance(selector, str):
            return None if selector == "any" else selector
        if isinstance(selector, PortRange):
            if selector.start == selector.end:
                return str(selector.start)
            return f"{selector.start}-{selector.end}"
        return None

    def _endpoint_host(self, endpoint: str | None) -> str | None:
        if not endpoint:
            return None
        if endpoint.startswith("["):
            match = re.match(r"\[(.+)]:(\d+)$", endpoint)
            return match.group(1) if match else None
        if ":" not in endpoint:
            return None
        return endpoint.rsplit(":", 1)[0]
