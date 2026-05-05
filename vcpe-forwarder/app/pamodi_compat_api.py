from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from .models import (
    DhcpServer,
    FlowPolicy,
    InterfaceAddressesRequest,
    InterfaceStateRequest,
    NatPolicy,
    Path as ForwardPath,
    PathGroup,
    WireGuardPeer,
    WireGuardTunnel,
)

router = APIRouter(tags=["pamodi-compat"])


# ======================================================================================
# Small compatibility memory
# ======================================================================================

def _compat_state(request: Request) -> dict[str, Any]:
    """
    Keeps logical mappings received from Pamodi's SteeringManager.

    Example:
      UPL1 -> eth0
      traffic class test -> five tuple match
      wg0 -> tunnel/peer metadata
    """
    if not hasattr(request.app.state, "pamodi_compat"):
        request.app.state.pamodi_compat = {
            "wan_links": {},
            "lan_links": {},
            "tunnels": {},
            "traffic_classes": {},
            "steering": {},
        }

    return request.app.state.pamodi_compat


def _store(request: Request):
    return request.app.state.store


def _slug(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    text = re.sub(r"[^a-z0-9_.-]+", "-", text)
    return text.strip("-") or "unknown"


def _drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(v) for v in value if v is not None]
    return value


def _ensure_prefix(address: str | None) -> list[str]:
    if not address:
        return []
    if "/" in address:
        return [address]
    if ":" in address:
        return [f"{address}/128"]
    return [f"{address}/32"]


def _gateway_from_prefix(prefix: str | None) -> str | None:
    if not prefix or "/" not in prefix:
        return None
    return prefix.split("/", 1)[0]


def _normalize_protocol(value: Any) -> str | None:
    if not value:
        return "any"
    value = str(value).lower()
    if value in {"tcp", "udp", "icmp", "any"}:
        return value
    return "any"


def _normalize_port(value: Any) -> Any:
    if value in {None, "", "any"}:
        return None
    return value


def _match_from_five_tuple(five_tuple: dict[str, Any]) -> dict[str, Any]:
    return _drop_none(
        {
            "src_prefix": five_tuple.get("src-prefix"),
            "dst_prefix": five_tuple.get("dst-prefix"),
            "protocol": _normalize_protocol(five_tuple.get("l4-protocol")),
            "src_ports": _normalize_port(five_tuple.get("src-port")),
            "dst_ports": _normalize_port(five_tuple.get("dst-port")),
        }
    )


def _ok(resource: str, name: str, result: Any | None = None, extra: dict[str, Any] | None = None):
    body = {
        "status": "success",
        "compat": "pamodi-restconf-to-api-v1",
        "resource": resource,
        "name": name,
    }

    if result is not None:
        try:
            body["result"] = result.model_dump(mode="json")
        except Exception:
            body["result"] = result

    if extra:
        body.update(extra)

    return body


# ======================================================================================
# NAT state expected by Pamodi get_nat_state()
# GET /restconf/data/forwarder:nat-state
# ======================================================================================

@router.get("/restconf/data/forwarder:nat-state")
def get_nat_state(request: Request):
    state = _compat_state(request)

    return {
        "forwarder:nat-state": {
            "status": "available",
            "wan-links": state["wan_links"],
        }
    }


# ======================================================================================
# WAN link
# Pamodi calls:
# PATCH /restconf/data/forwarder:wan-links/wan-link={name}
# ======================================================================================

@router.patch("/restconf/data/forwarder:wan-links/wan-link={name}")
async def apply_wan_link_config(name: str, request: Request):
    payload = await request.json()
    wan = payload.get("wan-link", {})

    interface_name = wan.get("interface-name")
    if not interface_name:
        raise HTTPException(status_code=400, detail="wan-link.interface-name is required")

    admin_enabled = wan.get("admin-enabled", True)
    address_mode = wan.get("address-mode", "dhcp")

    # Pamodi's current payload may not include nat-enabled, so default to True.
    nat_enabled = wan.get("nat-enabled", True)

    store = _store(request)
    state = _compat_state(request)

    results = {}

    # 1. Interface state
    results["interface_state"] = store.set_interface_state(
        interface_name,
        InterfaceStateRequest(state="up" if admin_enabled else "down"),
    )

    # 2. Static address if configured
    if admin_enabled and address_mode == "static" and wan.get("static-address"):
        results["interface_addresses"] = store.set_interface_addresses(
            interface_name,
            InterfaceAddressesRequest(addresses=[wan["static-address"]]),
        )

    # 3. NAT policy if enabled
    nat_policy_id = None
    if admin_enabled and nat_enabled:
        nat_policy_id = f"{_slug(name)}-nat"
        results["nat_policy"] = store.put_nat_policy(
            nat_policy_id,
            NatPolicy(
                rules=[
                    {
                        "action": "masquerade",
                        "out_interface": interface_name,
                    }
                ]
            ),
        )

    saved = dict(wan)
    saved["interface-name"] = interface_name
    saved["nat_policy_id"] = nat_policy_id
    state["wan_links"][name] = saved

    return _ok(
        "wan-link",
        name,
        extra={
            "mapped_interface": interface_name,
            "nat_policy_id": nat_policy_id,
            "results": _safe_results(results),
        },
    )


# ======================================================================================
# LAN link
# Pamodi calls:
# PATCH /restconf/data/forwarder:lan-links/lan-link={name}
# ======================================================================================

@router.patch("/restconf/data/forwarder:lan-links/lan-link={name}")
async def apply_lan_link_config(name: str, request: Request):
    payload = await request.json()
    lan = payload.get("lan-link", {})

    interface_name = lan.get("name") or name
    admin_enabled = lan.get("admin-enabled", True)
    ipv4_prefix = lan.get("ipv4-prefix")
    dhcp = lan.get("dhcp-server", {}) or {}

    store = _store(request)
    state = _compat_state(request)

    results = {}

    results["interface_state"] = store.set_interface_state(
        interface_name,
        InterfaceStateRequest(state="up" if admin_enabled else "down"),
    )

    if admin_enabled and ipv4_prefix:
        results["interface_addresses"] = store.set_interface_addresses(
            interface_name,
            InterfaceAddressesRequest(addresses=[ipv4_prefix]),
        )

    dhcp_id = None
    if dhcp.get("enabled"):
        dhcp_id = f"{_slug(interface_name)}-dhcp"
        results["dhcp_server"] = store.put_dhcp_server(
            dhcp_id,
            DhcpServer(
                enabled=True,
                served_interface=interface_name,
                range_start=dhcp.get("pool-start"),
                range_end=dhcp.get("pool-end"),
                gateway=_gateway_from_prefix(ipv4_prefix),
                dns_servers=[dhcp["dns-server"]] if dhcp.get("dns-server") else [],
                lease_time=f"{dhcp.get('lease-time-seconds', 86400)}s",
                reservations=[],
            ),
        )

    state["lan_links"][name] = dict(lan)

    return _ok(
        "lan-link",
        name,
        extra={
            "mapped_interface": interface_name,
            "dhcp_id": dhcp_id,
            "results": _safe_results(results),
        },
    )


# ======================================================================================
# WireGuard tunnel
# Pamodi calls:
# PATCH /restconf/data/forwarder:tunnels/tunnel={name}
# ======================================================================================

@router.patch("/restconf/data/forwarder:tunnels/tunnel={name}")
async def apply_tunnel_config(name: str, request: Request):
    payload = await request.json()
    tunnel = payload.get("tunnel", {})

    store = _store(request)
    state = _compat_state(request)

    tunnel_id = tunnel.get("name") or name
    peer_id = tunnel.get("peer-id") or f"{tunnel_id}-peer"

    listen_port = tunnel.get("local-port", 51820)
    local_addresses = _ensure_prefix(tunnel.get("local-address"))

    # The elegant API uses secret references, not raw private keys.
    # Pamodi's current steering sends public-key fields, not private-key-ref.
    private_key_ref = (
        tunnel.get("private-key-ref")
        or tunnel.get("local-private-key-ref")
        or f"{tunnel_id}-private-key"
    )

    results = {}

    results["tunnel"] = store.put_wireguard_tunnel(
        tunnel_id,
        WireGuardTunnel(
            private_key_ref=private_key_ref,
            listen_port=listen_port,
            local_addresses=local_addresses,
            mtu=tunnel.get("mtu"),
            description=f"Created from Pamodi tunnel {tunnel_id}",
        ),
    )

    if tunnel.get("peer-public-key"):
        endpoint = None
        if tunnel.get("peer-address"):
            endpoint = f"{tunnel.get('peer-address')}:{tunnel.get('peer-port', 51820)}"

        results["peer"] = store.put_wireguard_peer(
            tunnel_id,
            peer_id,
            WireGuardPeer(
                public_key=tunnel["peer-public-key"],
                endpoint=endpoint,
                allowed_ips=tunnel.get("allowed-prefix", []),
                persistent_keepalive=tunnel.get("keepalive-seconds"),
                description=f"Peer for {tunnel_id}",
            ),
        )

    state["tunnels"][tunnel_id] = {
        "tunnel_id": tunnel_id,
        "peer_id": peer_id,
        "bind_wan_link": tunnel.get("bind-wan-link"),
        "payload": tunnel,
    }

    return _ok(
        "tunnel",
        tunnel_id,
        extra={
            "peer_id": peer_id,
            "results": _safe_results(results),
        },
    )


# ======================================================================================
# Firewall rule
# Pamodi calls:
# PATCH /restconf/data/forwarder:firewall/rule={rule_id}
# ======================================================================================

@router.patch("/restconf/data/forwarder:firewall/rule={rule_id}")
async def apply_firewall_rule(rule_id: str, request: Request):
    payload = await request.json()
    rule = payload.get("rule", {})

    action = rule.get("action")

    if action == "allow":
        return _ok(
            "firewall-rule",
            rule_id,
            extra={
                "note": "allow treated as no-op; forwarding behavior is controlled by flow-policies",
            },
        )

    if action != "deny":
        raise HTTPException(status_code=400, detail=f"Unsupported firewall action: {action}")

    policy_id = f"fw-{_slug(rule_id)}"

    flow_policy = FlowPolicy(
        priority=10,
        match=_match_from_five_tuple(rule),
        action={"type": "drop"},
        description=f"Firewall deny rule {rule_id}",
    )

    result = _store(request).put_flow_policy(policy_id, flow_policy)

    return _ok(
        "firewall-rule",
        rule_id,
        result,
        extra={"flow_policy_id": policy_id},
    )


# ======================================================================================
# Traffic class
# Pamodi calls:
# PATCH /restconf/data/forwarder:traffic-classes/classifier={traffic_class}
# ======================================================================================

@router.patch("/restconf/data/forwarder:traffic-classes/classifier={traffic_class}")
async def install_traffic_class(traffic_class: str, request: Request):
    payload = await request.json()
    cls = payload.get("class", {})

    state = _compat_state(request)

    state["traffic_classes"][traffic_class] = {
        "fwmark": cls.get("fwmark"),
        "five_tuple": cls.get("five-tuple", {}),
        "payload": cls,
    }

    return _ok(
        "traffic-class",
        traffic_class,
        extra={
            "note": "stored traffic class; flow-policy will be created when steering is received",
            "stored": state["traffic_classes"][traffic_class],
        },
    )


# ======================================================================================
# Ordered failover / active path
# Pamodi calls:
# PATCH /restconf/data/forwarder:steering/active-path={traffic_class}
# ======================================================================================

@router.patch("/restconf/data/forwarder:steering/active-path={traffic_class}")
async def set_active_path(traffic_class: str, request: Request):
    payload = await request.json()
    steering = payload.get("steering", {})

    selected_path = steering.get("selected-path")
    if not selected_path:
        return _install_drop_policy(request, traffic_class, "no selected path received")

    state = _compat_state(request)
    state["steering"][traffic_class] = steering

    selected_type = steering.get("selected-path-type") or _infer_selected_type(state, selected_path)

    path_result = _ensure_path(request, selected_path, selected_type)

    path_id = path_result["path_id"]
    group_id = f"{_slug(traffic_class)}-failover"
    policy_id = f"{_slug(traffic_class)}-policy"

    group = PathGroup(
        strategy="ordered_failover",
        active_path_id=path_id,
        members=[
            {
                "path_id": path_id,
                "priority": 10,
                "weight": 100,
            }
        ],
    )

    group_result = _store(request).put_path_group(group_id, group)

    flow_policy = FlowPolicy(
        priority=100,
        match=_match_for_class(state, traffic_class),
        action={
            "type": "use_path_group",
            "path_group_id": group_id,
        },
        description=f"Policy for traffic class {traffic_class}",
    )

    policy_result = _store(request).put_flow_policy(policy_id, flow_policy)

    return _ok(
        "active-path",
        traffic_class,
        extra={
            "selected_path": selected_path,
            "selected_type": selected_type,
            "path_id": path_id,
            "path_group_id": group_id,
            "flow_policy_id": policy_id,
            "path": path_result,
            "path_group": _safe_model(group_result),
            "flow_policy": _safe_model(policy_result),
        },
    )


# ======================================================================================
# Weighted ECMP
#
# Pamodi's current _weighted_ecmp has a variable bug: it builds payload with
# eligible_names, but defines eligible_paths. If that method raises before sending,
# the forwarder cannot fix it. This endpoint is still here for when the request arrives.
# ======================================================================================

@router.patch("/restconf/data/forwarder:steering/weighted_ecmp={traffic_class}")
@router.patch("/restconf/data/forwarder:steering/load-balance={traffic_class}")
async def set_weighted_ecmp(traffic_class: str, request: Request):
    payload = await request.json()
    steering = payload.get("steering", {})

    selected_paths = (
        steering.get("eligible-paths")
        or steering.get("selected-path")
        or steering.get("selected-paths")
        or []
    )

    if not isinstance(selected_paths, list):
        raise HTTPException(status_code=400, detail="eligible paths must be a list")

    if not selected_paths:
        return _install_drop_policy(request, traffic_class, "no eligible paths received")

    state = _compat_state(request)
    state["steering"][traffic_class] = steering

    group_id = f"{_slug(traffic_class)}-ecmp"
    policy_id = f"{_slug(traffic_class)}-policy"

    members = []
    path_results = []

    for index, item in enumerate(selected_paths, start=1):
        selected_type = steering.get("selected-path-type") or _infer_selected_type(state, item)
        path_result = _ensure_path(request, item, selected_type)

        members.append(
            {
                "path_id": path_result["path_id"],
                "priority": index * 10,
                "weight": 100,
            }
        )
        path_results.append(path_result)

    group = PathGroup(
        strategy="weighted_ecmp",
        members=members,
    )

    group_result = _store(request).put_path_group(group_id, group)

    flow_policy = FlowPolicy(
        priority=100,
        match=_match_for_class(state, traffic_class),
        action={
            "type": "use_path_group",
            "path_group_id": group_id,
        },
        description=f"Weighted ECMP policy for traffic class {traffic_class}",
    )

    policy_result = _store(request).put_flow_policy(policy_id, flow_policy)

    return _ok(
        "weighted-ecmp",
        traffic_class,
        extra={
            "path_group_id": group_id,
            "flow_policy_id": policy_id,
            "paths": path_results,
            "path_group": _safe_model(group_result),
            "flow_policy": _safe_model(policy_result),
        },
    )


# ======================================================================================
# Internal path helpers
# ======================================================================================

def _ensure_path(request: Request, selected_name: str, selected_type: str) -> dict[str, Any]:
    if selected_type == "tunnel":
        return _ensure_wireguard_path(request, selected_name)

    return _ensure_local_breakout_path(request, selected_name)


def _ensure_local_breakout_path(request: Request, wan_link_name: str) -> dict[str, Any]:
    state = _compat_state(request)
    wan = state["wan_links"].get(wan_link_name, {})

    interface_name = wan.get("interface-name") or wan_link_name
    nat_policy_id = wan.get("nat_policy_id")

    if wan.get("nat-enabled", True) and not nat_policy_id:
        nat_policy_id = f"{_slug(wan_link_name)}-nat"
        _store(request).put_nat_policy(
            nat_policy_id,
            NatPolicy(
                rules=[
                    {
                        "action": "masquerade",
                        "out_interface": interface_name,
                    }
                ]
            ),
        )

    path_id = f"{_slug(wan_link_name)}-local-breakout"

    path = ForwardPath(
        type="local_breakout",
        wan_interface=interface_name,
        nat_policy_id=nat_policy_id,
        failure_behavior="drop",
        description=f"Local breakout through {wan_link_name}/{interface_name}",
    )

    result = _store(request).put_path(path_id, path)

    return {
        "status": "success",
        "path_id": path_id,
        "path": _safe_model(result),
    }


def _ensure_wireguard_path(request: Request, tunnel_name: str) -> dict[str, Any]:
    state = _compat_state(request)
    tunnel = state["tunnels"].get(tunnel_name, {})

    tunnel_id = tunnel.get("tunnel_id") or tunnel_name
    peer_id = tunnel.get("peer_id") or f"{tunnel_id}-peer"
    bind_wan_link = tunnel.get("bind_wan_link")

    wan = state["wan_links"].get(bind_wan_link, {}) if bind_wan_link else {}
    wan_interface = wan.get("interface-name") or bind_wan_link or "eth0"

    path_id = f"{_slug(tunnel_id)}-{_slug(peer_id)}-overlay"

    path = ForwardPath(
        type="wireguard_peer",
        tunnel_id=tunnel_id,
        peer_id=peer_id,
        wan_interface=wan_interface,
        failure_behavior="drop",
        description=f"Overlay path through tunnel {tunnel_id}, peer {peer_id}",
    )

    result = _store(request).put_path(path_id, path)

    return {
        "status": "success",
        "path_id": path_id,
        "path": _safe_model(result),
    }


def _install_drop_policy(request: Request, traffic_class: str, reason: str):
    state = _compat_state(request)

    policy_id = f"{_slug(traffic_class)}-policy"

    flow_policy = FlowPolicy(
        priority=100,
        match=_match_for_class(state, traffic_class),
        action={"type": "drop"},
        description=reason,
    )

    result = _store(request).put_flow_policy(policy_id, flow_policy)

    return _ok(
        "drop-policy",
        traffic_class,
        result,
        extra={
            "flow_policy_id": policy_id,
            "reason": reason,
        },
    )


def _match_for_class(state: dict[str, Any], traffic_class: str) -> dict[str, Any]:
    stored = state["traffic_classes"].get(traffic_class, {})
    five_tuple = stored.get("five_tuple", {})
    return _match_from_five_tuple(five_tuple)


def _infer_selected_type(state: dict[str, Any], selected_name: str) -> str:
    if selected_name in state["tunnels"]:
        return "tunnel"

    if selected_name in state["wan_links"]:
        return "wan-link"

    if str(selected_name).startswith("wg"):
        return "tunnel"

    return "wan-link"


def _safe_model(value: Any) -> Any:
    try:
        return value.model_dump(mode="json")
    except Exception:
        return value


def _safe_results(results: dict[str, Any]) -> dict[str, Any]:
    return {key: _safe_model(value) for key, value in results.items()}