import json
import os
import subprocess
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from app.kernel import run_cmd, ensure_interface_exists

router = APIRouter(tags=["compat"])

STATE_DIR = Path(os.getenv("STATE_DIR", "/state"))
STATE_FILE = STATE_DIR / "compat_state.json"


# ============================================================
# Small local state
# ============================================================

def load_state() -> dict:
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass

    return {
        "wan_links": {},
        "lan_links": {},
        "tunnels": {},
        "classes": {},
        "steering": {},
    }


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True))


def iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


def cmd_or_500(cmd: list[str], ignore_exists: bool = False, ignore_missing: bool = False) -> dict:
    result = run_cmd(cmd)

    if result["ok"]:
        return result

    stderr = result.get("stderr", "")

    if ignore_exists and ("File exists" in stderr or "exists" in stderr):
        result["ok"] = True
        result["ignored"] = "already exists"
        return result

    if ignore_missing and (
        "No such process" in stderr
        or "Cannot find" in stderr
        or "No such file" in stderr
        or "does not exist" in stderr
    ):
        result["ok"] = True
        result["ignored"] = "missing"
        return result

    raise HTTPException(status_code=500, detail=result)


def run_wg_private_key(interface: str, private_key: str, listen_port: int | None = None) -> dict:
    cmd = ["wg", "set", interface, "private-key", "/dev/stdin"]

    if listen_port is not None:
        cmd.extend(["listen-port", str(listen_port)])

    try:
        result = subprocess.run(
            cmd,
            input=private_key + "\n",
            text=True,
            capture_output=True,
            timeout=5,
        )

        data = {
            "ok": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "cmd": cmd,
            "returncode": result.returncode,
        }

        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=data)

        return data

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=500,
            detail={"ok": False, "cmd": cmd, "stderr": "command timed out"},
        )


def add_iptables_once(cmd: list[str]) -> dict:
    check_cmd = cmd.copy()

    if "-A" in check_cmd:
        check_cmd[check_cmd.index("-A")] = "-C"

    check = run_cmd(check_cmd)

    if check["ok"]:
        return {
            "ok": True,
            "cmd": cmd,
            "already_exists": True,
            "stdout": "",
            "stderr": "",
        }

    return cmd_or_500(cmd)


def fwmark_to_int(fwmark) -> int:
    if isinstance(fwmark, int):
        return fwmark

    return int(str(fwmark), 0)


# ============================================================
# WAN link compatibility
# Agent calls:
# PATCH /restconf/data/forwarder:wan-links/wan-link={name}
# ============================================================

@router.patch("/restconf/data/forwarder:wan-links/wan-link={name}")
async def compat_wan_link(name: str, request: Request):
    payload = await request.json()
    wan = payload.get("wan-link", {})

    interface = wan.get("interface-name")
    admin_enabled = wan.get("admin-enabled", True)
    address_mode = wan.get("address-mode")
    static_address = wan.get("static-address")
    static_gateway = wan.get("static-gateway")
    nat_enabled = wan.get("nat-enabled", True)

    if not interface:
        raise HTTPException(status_code=400, detail="wan-link.interface-name is required")

    ensure_interface_exists(interface)

    results = []

    if admin_enabled is False:
        results.append(cmd_or_500(["ip", "link", "set", interface, "down"]))
    else:
        results.append(cmd_or_500(["ip", "link", "set", interface, "up"]))

    if admin_enabled is not False and address_mode == "static" and static_address:
        results.append(cmd_or_500(["ip", "addr", "replace", static_address, "dev", interface]))

    if admin_enabled is not False and address_mode == "static" and static_gateway:
        results.append(
            cmd_or_500(["ip", "route", "replace", "default", "via", static_gateway, "dev", interface])
        )

    if admin_enabled is not False and nat_enabled:
        results.append(
            add_iptables_once(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", interface, "-j", "MASQUERADE"])
        )

    state = load_state()
    state["wan_links"][name] = wan
    save_state(state)

    return {
        "status": "success",
        "compat": True,
        "resource": "wan-link",
        "name": name,
        "results": results,
    }


# ============================================================
# LAN link compatibility
# Agent calls:
# PATCH /restconf/data/forwarder:lan-links/lan-link={name}
# ============================================================

@router.patch("/restconf/data/forwarder:lan-links/lan-link={name}")
async def compat_lan_link(name: str, request: Request):
    payload = await request.json()
    lan = payload.get("lan-link", {})

    interface = lan.get("name") or name
    admin_enabled = lan.get("admin-enabled", True)
    ipv4_prefix = lan.get("ipv4-prefix")
    dhcp = lan.get("dhcp-server", {})

    ensure_interface_exists(interface)

    results = []

    if admin_enabled is False:
        results.append(cmd_or_500(["ip", "link", "set", interface, "down"]))
    else:
        results.append(cmd_or_500(["ip", "link", "set", interface, "up"]))

    if admin_enabled is not False and ipv4_prefix:
        results.append(cmd_or_500(["ip", "addr", "replace", ipv4_prefix, "dev", interface]))

    state = load_state()
    state["lan_links"][name] = lan
    save_state(state)

    return {
        "status": "success",
        "compat": True,
        "resource": "lan-link",
        "name": name,
        "dhcp_note": "DHCP server API is not implemented yet" if dhcp.get("enabled") else None,
        "results": results,
    }


# ============================================================
# WireGuard tunnel compatibility
# Agent calls:
# PATCH /restconf/data/forwarder:tunnels/tunnel={name}
# ============================================================

@router.patch("/restconf/data/forwarder:tunnels/tunnel={name}")
async def compat_tunnel(name: str, request: Request):
    payload = await request.json()
    tunnel = payload.get("tunnel", {})

    tunnel_name = tunnel.get("name") or name
    admin_enabled = tunnel.get("admin-enabled", True)

    private_key = tunnel.get("local-private-key")
    listen_port = tunnel.get("local-port")
    peer_public_key = tunnel.get("peer-public-key")
    peer_address = tunnel.get("peer-address")
    peer_port = tunnel.get("peer-port", 51820)
    allowed_prefixes = tunnel.get("allowed-prefix", [])
    keepalive = tunnel.get("keepalive-seconds", 25)

    results = []

    if admin_enabled is False:
        if iface_exists(tunnel_name):
            results.append(cmd_or_500(["ip", "link", "set", tunnel_name, "down"]))
        status = "disabled"
    else:
        if not iface_exists(tunnel_name):
            results.append(cmd_or_500(["ip", "link", "add", "dev", tunnel_name, "type", "wireguard"]))

        if private_key:
            results.append(run_wg_private_key(tunnel_name, private_key, listen_port))

        if peer_public_key:
            cmd = [
                "wg",
                "set",
                tunnel_name,
                "peer",
                peer_public_key,
                "allowed-ips",
                ",".join(allowed_prefixes),
            ]

            if peer_address:
                cmd.extend(["endpoint", f"{peer_address}:{peer_port}"])

            if keepalive is not None:
                cmd.extend(["persistent-keepalive", str(keepalive)])

            results.append(cmd_or_500(cmd))

        results.append(cmd_or_500(["ip", "link", "set", tunnel_name, "up"]))

        for prefix in allowed_prefixes:
            results.append(cmd_or_500(["ip", "route", "replace", prefix, "dev", tunnel_name]))

        status = "configured"

    state = load_state()
    state["tunnels"][tunnel_name] = tunnel
    save_state(state)

    return {
        "status": "success",
        "compat": True,
        "resource": "tunnel",
        "name": tunnel_name,
        "tunnel_status": status,
        "results": results,
    }


# ============================================================
# Firewall compatibility
# Agent calls:
# PATCH /restconf/data/forwarder:firewall/rule={rule_id}
# ============================================================

@router.patch("/restconf/data/forwarder:firewall/rule={rule_id}")
async def compat_firewall_rule(rule_id: str, request: Request):
    payload = await request.json()
    rule = payload.get("rule", {})

    action = rule.get("action")
    target = "ACCEPT" if action == "allow" else "DROP"

    cmd = ["iptables", "-A", "FORWARD"]

    if rule.get("src-prefix"):
        cmd.extend(["-s", rule["src-prefix"]])

    if rule.get("dst-prefix"):
        cmd.extend(["-d", rule["dst-prefix"]])

    proto = rule.get("l4-protocol")
    if proto and proto != "any":
        cmd.extend(["-p", proto])

        src_port = rule.get("src-port")
        dst_port = rule.get("dst-port")

        if src_port and src_port != "any":
            cmd.extend(["--sport", str(src_port)])

        if dst_port and dst_port != "any":
            cmd.extend(["--dport", str(dst_port)])

    cmd.extend(["-j", target])

    result = add_iptables_once(cmd)

    return {
        "status": "success",
        "compat": True,
        "resource": "firewall-rule",
        "id": rule_id,
        "result": result,
    }


# ============================================================
# Traffic classifier compatibility
# Agent calls:
# PATCH /restconf/data/forwarder:traffic-classes/classifier={traffic_class}
# ============================================================

@router.patch("/restconf/data/forwarder:traffic-classes/classifier={traffic_class}")
async def compat_traffic_class(traffic_class: str, request: Request):
    payload = await request.json()
    class_cfg = payload.get("class", {})

    class_name = class_cfg.get("name") or traffic_class
    fwmark = class_cfg.get("fwmark")
    five_tuple = class_cfg.get("five-tuple", {})

    if fwmark is None:
        raise HTTPException(status_code=400, detail="class.fwmark is required")

    cmd = ["iptables", "-t", "mangle", "-A", "PREROUTING"]

    if five_tuple.get("src-prefix"):
        cmd.extend(["-s", five_tuple["src-prefix"]])

    if five_tuple.get("dst-prefix"):
        cmd.extend(["-d", five_tuple["dst-prefix"]])

    proto = five_tuple.get("l4-protocol")
    if proto and proto != "any":
        cmd.extend(["-p", proto])

        src_port = five_tuple.get("src-port")
        dst_port = five_tuple.get("dst-port")

        if src_port and src_port != "any":
            cmd.extend(["--sport", str(src_port)])

        if dst_port and dst_port != "any":
            cmd.extend(["--dport", str(dst_port)])

    cmd.extend(["-j", "MARK", "--set-mark", str(fwmark)])

    result = add_iptables_once(cmd)

    state = load_state()
    state["classes"][class_name] = {
        "fwmark": fwmark,
        "table": fwmark_to_int(fwmark),
        "payload": class_cfg,
    }
    save_state(state)

    return {
        "status": "success",
        "compat": True,
        "resource": "traffic-class",
        "class": class_name,
        "fwmark": fwmark,
        "result": result,
    }


# ============================================================
# Steering helper
# ============================================================

def apply_selected_path_to_table(selected_path: str, selected_type: str, table: int) -> list[dict]:
    state = load_state()
    results = []

    if selected_type == "wan-link":
        wan = state["wan_links"].get(selected_path)
        if not wan:
            raise HTTPException(status_code=404, detail=f"WAN link '{selected_path}' not found in compat state")

        interface = wan.get("interface-name")
        gateway = wan.get("static-gateway")

        if not interface:
            raise HTTPException(status_code=400, detail=f"WAN link '{selected_path}' has no interface-name")

        ensure_interface_exists(interface)

        if gateway:
            results.append(
                cmd_or_500([
                    "ip", "route", "replace",
                    "default",
                    "via", gateway,
                    "dev", interface,
                    "table", str(table),
                ])
            )
        else:
            results.append(
                cmd_or_500([
                    "ip", "route", "replace",
                    "default",
                    "dev", interface,
                    "table", str(table),
                ])
            )

    elif selected_type == "tunnel":
        if not iface_exists(selected_path):
            raise HTTPException(status_code=404, detail=f"Tunnel interface '{selected_path}' not found")

        results.append(
            cmd_or_500([
                "ip", "route", "replace",
                "default",
                "dev", selected_path,
                "table", str(table),
            ])
        )

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported selected-path-type: {selected_type}")

    return results


# ============================================================
# Active path compatibility
# Agent calls:
# PATCH /restconf/data/forwarder:steering/active-path={traffic_class}
# ============================================================

@router.patch("/restconf/data/forwarder:steering/active-path={traffic_class}")
async def compat_active_path(traffic_class: str, request: Request):
    payload = await request.json()
    steering = payload.get("steering", {})

    class_name = steering.get("class") or traffic_class
    selected_path = steering.get("selected-path")
    selected_type = steering.get("selected-path-type")
    decision_status = steering.get("decision-status")

    state = load_state()
    state["steering"][class_name] = steering
    save_state(state)

    class_state = state["classes"].get(class_name)
    if not class_state:
        return {
            "status": "stored",
            "compat": True,
            "resource": "active-path",
            "class": class_name,
            "note": "Traffic class has no fwmark yet. Run install-traffic-class first.",
        }

    fwmark = fwmark_to_int(class_state["fwmark"])
    table = int(class_state["table"])
    priority = 1000 + fwmark

    results = []

    results.append(
        cmd_or_500(
            ["ip", "rule", "add", "priority", str(priority), "fwmark", str(fwmark), "table", str(table)],
            ignore_exists=True,
        )
    )

    if decision_status == "no-path" or selected_path is None:
        return {
            "status": "success",
            "compat": True,
            "resource": "active-path",
            "class": class_name,
            "decision_status": decision_status,
            "note": "No path selected. Rule installed but route not changed.",
            "results": results,
        }

    results.extend(apply_selected_path_to_table(selected_path, selected_type, table))

    return {
        "status": "success",
        "compat": True,
        "resource": "active-path",
        "class": class_name,
        "selected_path": selected_path,
        "selected_type": selected_type,
        "fwmark": fwmark,
        "table": table,
        "results": results,
    }


# ============================================================
# Load-balance compatibility
# Agent calls:
# PATCH /restconf/data/forwarder:steering/load-balance={traffic_class}
# ============================================================

@router.patch("/restconf/data/forwarder:steering/load-balance={traffic_class}")
async def compat_load_balance(traffic_class: str, request: Request):
    payload = await request.json()
    steering = payload.get("steering", {})

    class_name = steering.get("class") or traffic_class
    selected_paths = steering.get("selected-path", [])
    selected_type = steering.get("selected-path-type")

    if not isinstance(selected_paths, list):
        raise HTTPException(status_code=400, detail="steering.selected-path must be a list")

    state = load_state()
    state["steering"][class_name] = steering
    save_state(state)

    class_state = state["classes"].get(class_name)
    if not class_state:
        return {
            "status": "stored",
            "compat": True,
            "resource": "load-balance",
            "class": class_name,
            "note": "Traffic class has no fwmark yet. Run install-traffic-class first.",
        }

    if not selected_paths:
        return {
            "status": "success",
            "compat": True,
            "resource": "load-balance",
            "class": class_name,
            "note": "No selected paths received.",
        }

    # MVP behavior:
    # Apply the first selected path. Full ECMP can be added later.
    fwmark = fwmark_to_int(class_state["fwmark"])
    table = int(class_state["table"])
    priority = 1000 + fwmark

    results = []

    results.append(
        cmd_or_500(
            ["ip", "rule", "add", "priority", str(priority), "fwmark", str(fwmark), "table", str(table)],
            ignore_exists=True,
        )
    )

    results.extend(apply_selected_path_to_table(selected_paths[0], selected_type, table))

    return {
        "status": "success",
        "compat": True,
        "resource": "load-balance",
        "class": class_name,
        "selected_paths": selected_paths,
        "applied_path": selected_paths[0],
        "note": "MVP applies first selected path. ECMP/multipath can be implemented later.",
        "fwmark": fwmark,
        "table": table,
        "results": results,
    }