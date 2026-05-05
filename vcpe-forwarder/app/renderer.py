from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .models import (
    AccessPoint,
    Allocation,
    DhcpServer,
    FlowPolicy,
    ForwarderState,
    NatPolicy,
    Path as ForwardPath,
    PortRange,
    RenderPlan,
)


class SecretResolver:
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
            return ""
        if reference in self.secrets:
            return str(self.secrets[reference])
        digest = hashlib.sha1(reference.encode("utf-8")).hexdigest()[:12]
        return f"resolved-{digest}"


class Renderer:
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

    def _ensure_allocations(self, state: ForwarderState) -> None:
        for prefix, labels in (("path", sorted(state.paths)), ("group", sorted(state.path_groups))):
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

    def _render_cleanup(self, previous: ForwarderState, current: ForwarderState) -> list[str]:
        commands: list[str] = []

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
            commands.extend(
                [
                    f"systemctl stop dnsmasq@{server_id} || true",
                    f"systemctl disable dnsmasq@{server_id} || true",
                    f"rm -f etc/forwarder/dnsmasq/{server_id}.conf",
                ]
            )

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
            if interface.kind not in {"bridge", "wireguard"}:
                commands.append(f"ip link set dev {name} {interface.admin_state}")
            if interface.kind != "wireguard" and interface.mtu:
                commands.append(f"ip link set mtu {interface.mtu} dev {name}")
            if interface.kind == "wireguard":
                continue
            for address in interface.addresses:
                family_flag = "-6 " if ":" in address else ""
                commands.append(f"ip {family_flag}address replace {address} dev {name}")
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
            commands.append(f"wg syncconf {tunnel_id} {conf_path}")
            interface = current.interfaces.get(tunnel_id)
            admin_state = interface.admin_state if interface else "up"
            commands.append(f"ip link set dev {tunnel_id} {admin_state}")

            old_peers = previous.peers.get(tunnel_id, {})
            for peer_id, peer in old_peers.items():
                if peer_id not in current.peers.get(tunnel_id, {}):
                    commands.append(f"wg set {tunnel_id} peer {peer.public_key} remove || true")
        return commands

    def _render_routing(self, previous: ForwarderState, current: ForwarderState) -> list[str]:
        commands: list[str] = []

        for path_id, path in sorted(current.paths.items()):
            alloc = current.allocations[f"path:{path_id}"]
            commands.extend(
                [
                    f"ip route flush table {alloc.route_table} || true",
                    f"ip rule replace fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority}",
                ]
            )
            commands.extend(self._route_for_path(path, current, alloc.route_table))

        for group_id, group in sorted(current.path_groups.items()):
            alloc = current.allocations[f"group:{group_id}"]
            commands.extend(
                [
                    f"ip route flush table {alloc.route_table} || true",
                    f"ip rule replace fwmark 0x{alloc.packet_mark:x}/0xffffffff lookup {alloc.route_table} priority {alloc.priority}",
                ]
            )
            commands.extend(self._route_for_group(group_id, current, alloc.route_table))

        for route_set_id, route_set in sorted(current.static_route_sets.items()):
            for route in route_set.routes:
                route_cmd = ["ip route replace", route.destination_cidr]
                if route.next_hop_ip:
                    route_cmd.append(f"via {route.next_hop_ip}")
                if route.out_interface:
                    route_cmd.append(f"dev {route.out_interface}")
                if route.metric is not None:
                    route_cmd.append(f"metric {route.metric}")
                commands.append(" ".join(route_cmd))
        return commands

    def _render_nftables(self, current: ForwarderState, revision: str, plan: RenderPlan) -> list[str]:
        nft_path = f"var/lib/forwarder/rendered/{revision}/nftables/forwarder.nft"
        plan.files[nft_path] = self._nftables_ruleset(current)
        return [f"nft -f {nft_path}"]

    def _render_services(self, previous: ForwarderState, current: ForwarderState, revision: str, plan: RenderPlan) -> list[str]:
        commands: list[str] = []

        for server_id, server in sorted(current.dhcp_servers.items()):
            conf_path = f"var/lib/forwarder/rendered/{revision}/dnsmasq/{server_id}.conf"
            plan.files[conf_path] = self._dnsmasq_config(server)
            commands.append(f"install -m 0644 {conf_path} etc/forwarder/dnsmasq/{server_id}.conf")
            if server.enabled:
                commands.append(f"systemctl restart dnsmasq@{server_id}")
                commands.append(f"systemctl enable dnsmasq@{server_id}")
            else:
                commands.append(f"systemctl stop dnsmasq@{server_id} || true")
                commands.append(f"systemctl disable dnsmasq@{server_id} || true")

        for ap_id, ap in sorted(current.access_points.items()):
            conf_path = f"var/lib/forwarder/rendered/{revision}/hostapd/{ap_id}.conf"
            plan.files[conf_path] = self._hostapd_config(ap)
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

    def _route_for_path(self, path: ForwardPath, state: ForwarderState, route_table: int) -> list[str]:
        commands: list[str] = []
        if path.type == "wireguard_peer" and path.tunnel_id and path.peer_id:
            peer = state.peers.get(path.tunnel_id, {}).get(path.peer_id)
            host = self._endpoint_host(peer.endpoint if peer else None)
            if host:
                commands.append(f"ip route replace {host}/32 dev {path.wan_interface}")
            commands.append(f"ip route replace default dev {path.tunnel_id} table {route_table}")
        else:
            commands.append(f"ip route replace default dev {path.wan_interface} table {route_table}")
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
            dev = path.tunnel_id if path.type == "wireguard_peer" and path.tunnel_id else path.wan_interface
            nexthops.append(f"nexthop dev {dev} weight {weight}")
        if nexthops:
            commands.append(f"ip route replace default {' '.join(nexthops)} table {route_table}")
        return commands

    def _wireguard_config(self, tunnel_id: str, tunnel, peers: dict) -> str:
        lines = ["[Interface]"]
        if tunnel.private_key_ref:
            lines.append(f"PrivateKey = {self.secrets.resolve(tunnel.private_key_ref)}")
        lines.append(f"ListenPort = {tunnel.listen_port}")
        for address in tunnel.local_addresses:
            lines.append(f"Address = {address}")
        if tunnel.mtu:
            lines.append(f"MTU = {tunnel.mtu}")

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
            "flush table inet forwarder",
            "table inet forwarder {",
            "  chain prerouting {",
            "    type filter hook prerouting priority mangle; policy accept;",
            "    ct mark != 0 meta mark set ct mark",
        ]

        for policy_id, policy in sorted(current.flow_policies.items(), key=lambda item: ((item[1].priority or 10**9), item[0])):
            rule = self._flow_policy_rule(policy_id, policy, current)
            if rule:
                lines.append(f"    {rule}")

        lines.extend(
            [
                "  }",
                "  chain output {",
                "    type route hook output priority mangle; policy accept;",
                "    ct mark != 0 meta mark set ct mark",
                "  }",
                "  chain forward {",
                "    type filter hook forward priority filter; policy accept;",
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
            if alloc and policy:
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
            if alloc and policy:
                for rule in self._nat_rules_for_policy(policy, alloc.ct_mark, "postrouting"):
                    lines.append(f"    {rule}")

        lines.extend(["  }", "}"])
        return "\n".join(lines) + "\n"

    def _flow_policy_rule(self, policy_id: str, policy: FlowPolicy, current: ForwarderState) -> str:
        tokens: list[str] = [f"# policy_id = {policy_id}"]
        match = policy.match
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

        action = policy.action
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

    def _nat_rules_for_policy(self, policy: NatPolicy, ct_mark: int, phase: str) -> list[str]:
        rules: list[str] = []
        for rule in policy.rules:
            if phase == "prerouting" and rule.action not in {"dnat", "port_forward"}:
                continue
            if phase == "postrouting" and rule.action not in {"masquerade", "snat"}:
                continue

            tokens = [f"ct mark 0x{ct_mark:x}"]
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