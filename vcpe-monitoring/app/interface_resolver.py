from __future__ import annotations

import asyncio
import json
from pathlib import Path

from .settings import Settings


class InterfaceResolutionError(ValueError):
    pass


class InterfaceResolver:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def resolve_wan(self, wan_link: str) -> str:
        interface = self.settings.wan_link_map.get(wan_link, wan_link)
        self.ensure_exists(interface)
        return interface

    def resolve_tunnel(self, tunnel_id: str) -> str:
        self.ensure_exists(tunnel_id)
        return tunnel_id

    def ensure_exists(self, interface: str) -> None:
        if not (Path("/sys/class/net") / interface).exists():
            raise InterfaceResolutionError(
                f"Linux interface {interface!r} is not visible. "
                "Check WAN_LINK_MAP_JSON and use host networking for vcpe-monitoring."
            )

    async def get_ipv4_address(self, interface: str) -> str:
        self.ensure_exists(interface)
        process = await asyncio.create_subprocess_exec(
            "ip", "-4", "-j", "address", "show", "dev", interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise InterfaceResolutionError(
                stderr.decode(errors="replace").strip()
                or f"failed to inspect IPv4 address for {interface}"
            )

        records = json.loads(stdout.decode() or "[]")
        for record in records:
            for address in record.get("addr_info", []):
                if address.get("family") == "inet" and address.get("scope") in {"global", "site"}:
                    local = address.get("local")
                    if local:
                        return str(local)

        for record in records:
            for address in record.get("addr_info", []):
                if address.get("family") == "inet" and address.get("local"):
                    return str(address["local"])

        raise InterfaceResolutionError(f"interface {interface} has no IPv4 address")
