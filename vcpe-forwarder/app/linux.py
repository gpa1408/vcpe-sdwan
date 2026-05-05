from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .models import Interface, InterfaceCounters


class CommandRunner:
    def __init__(self, root: Path, execute: bool = False) -> None:
        self.root = root
        self.execute = execute

    def run_plan(self, phases: dict[str, list[str]]) -> dict[str, list[dict[str, Any]]]:
        journal: dict[str, list[dict[str, Any]]] = {}
        for phase, commands in phases.items():
            entries: list[dict[str, Any]] = []
            for command in commands:
                entries.append(self.run(command))
            journal[phase] = entries
        return journal

    def run(self, command: str) -> dict[str, Any]:
        if not self.execute:
            return {
                "command": command,
                "mode": "dry-run",
                "returncode": 0,
                "stdout": "",
                "stderr": "",
            }

        completed = subprocess.run(
            ["bash", "-lc", command],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )
        return {
            "command": command,
            "mode": "execute",
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }


class SystemInspector:
    def __init__(self, use_system_state: bool = True) -> None:
        self.use_system_state = use_system_state

    def command_exists(self, name: str) -> bool:
        return shutil.which(name) is not None

    def get_uptime_seconds(self) -> int:
        try:
            uptime_text = Path("/proc/uptime").read_text(encoding="utf-8").strip().split()[0]
            return int(float(uptime_text))
        except Exception:
            return 0

    def list_interfaces(self) -> list[Interface]:
        if not self.use_system_state or not self.command_exists("ip"):
            return []

        link_data = self._run_json(["ip", "-j", "-d", "link", "show"]) or []
        addr_data = self._run_json(["ip", "-j", "addr", "show"]) or []
        bridge_data = self._run_json(["bridge", "-j", "link", "show"]) if self.command_exists("bridge") else []

        addr_map = {entry.get("ifname"): self._addresses_from_entry(entry) for entry in addr_data}
        master_map = self._bridge_master_map(bridge_data or [])

        interfaces: list[Interface] = []
        for entry in link_data:
            name = entry.get("ifname")
            if not name:
                continue
            interfaces.append(
                Interface(
                    name=name,
                    kind=self._kind_from_link(entry),
                    role=self._role_from_link(entry, master_map.get(name)),
                    admin_state="up" if "UP" in entry.get("flags", []) else "down",
                    oper_state=self._oper_state(entry.get("operstate")),
                    mtu=entry.get("mtu"),
                    master_bridge=master_map.get(name),
                    addresses=addr_map.get(name, []),
                )
            )
        return interfaces

    def get_interface(self, interface_name: str) -> Interface | None:
        for interface in self.list_interfaces():
            if interface.name == interface_name:
                return interface
        return None

    def get_interface_counters(self, interface_name: str) -> InterfaceCounters:
        def read_stat(name: str) -> int:
            try:
                stat_path = Path("/sys/class/net") / interface_name / "statistics" / name
                return int(stat_path.read_text(encoding="utf-8").strip())
            except Exception:
                return 0

        return InterfaceCounters(
            rx_bytes=read_stat("rx_bytes"),
            tx_bytes=read_stat("tx_bytes"),
            rx_packets=read_stat("rx_packets"),
            tx_packets=read_stat("tx_packets"),
        )

    def service_active(self, service_name: str) -> bool | None:
        if not self.use_system_state or not self.command_exists("systemctl"):
            return None
        completed = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.returncode == 0

    def _run_json(self, command: list[str]) -> Any | None:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            return None
        if completed.returncode != 0 or not completed.stdout.strip():
            return None
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError:
            return None

    def _addresses_from_entry(self, entry: dict[str, Any]) -> list[str]:
        addresses: list[str] = []
        for addr in entry.get("addr_info", []):
            local = addr.get("local")
            prefix = addr.get("prefixlen")
            if local is not None and prefix is not None:
                addresses.append(f"{local}/{prefix}")
        return addresses

    def _bridge_master_map(self, bridge_data: list[dict[str, Any]]) -> dict[str, str]:
        master_map: dict[str, str] = {}
        for entry in bridge_data:
            name = entry.get("ifname")
            master = entry.get("master")
            if name and master:
                master_map[name] = master
        return master_map

    def _kind_from_link(self, entry: dict[str, Any]) -> str:
        kind = (entry.get("linkinfo") or {}).get("info_kind")
        if kind in {"bridge", "wireguard", "vlan", "dummy"}:
            return kind
        name = entry.get("ifname", "")
        if name.startswith(("wlan", "wl")):
            return "wifi"
        return "physical"

    def _role_from_link(self, entry: dict[str, Any], master_bridge: str | None) -> str:
        kind = self._kind_from_link(entry)
        if kind == "wireguard":
            return "tunnel"
        if kind == "bridge" or master_bridge:
            return "lan"
        if kind == "wifi":
            return "service"
        return "unknown"

    def _oper_state(self, value: str | None) -> str:
        value = (value or "unknown").lower()
        if value in {"up", "down", "dormant", "unknown"}:
            return value
        return "unknown"
