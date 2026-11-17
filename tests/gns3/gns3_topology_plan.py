#!/usr/bin/env python3
r"""Read-only GNS3 CI topology planner: never contacts or changes GNS3.

Usage (Windows PowerShell):
    py "$HOME\vcpe-sdwan\tests\gns3\gns3_topology_plan.py"

Reads C:\Users\<user>\sdwan-ci\current-topology.json, created earlier from
GET /v2/projects/<project>/nodes and /links. Performs strict safety checks,
then prints the intended recreation order. No POST/PATCH/DELETE calls.
"""

import argparse
import json
import sys
from pathlib import Path
import os

EXPECTED_PROJECT_ID = os.environ.get("GNS3_PROJECT_ID")

if not EXPECTED_PROJECT_ID:
    raise SystemExit("ERROR: GNS3_PROJECT_ID environment variable is required.")
EXPECTED_PROJECT_NAME = "sdwan-ci"
EXPECTED_TYPES = {
    "CPE-1": "qemu",
    "CPE-2": "qemu",
    "NAT1": "nat",
    "NAT2": "nat",
    "Switch1": "ethernet_switch",
    "Switch2": "ethernet_switch",
    "PC1": "vpcs",
    "PC2": "vpcs",
}


def port(name, adapter, port_num):
    return (name, adapter, port_num)


def edge(a, b):
    return frozenset((a, b))


EXPECTED_LINKS = {
    edge(port("CPE-1", 0, 0), port("NAT1", 0, 0)),
    edge(port("CPE-1", 1, 0), port("CPE-2", 1, 0)),
    edge(port("CPE-1", 2, 0), port("Switch1", 0, 0)),
    edge(port("PC1", 0, 0), port("Switch1", 0, 1)),
    edge(port("CPE-2", 0, 0), port("NAT2", 0, 0)),
    edge(port("CPE-2", 2, 0), port("Switch2", 0, 0)),
    edge(port("PC2", 0, 0), port("Switch2", 0, 1)),
}


def label(item):
    name, adapter, port_num = item
    return f"{name} [adapter {adapter}, port {port_num}]"


def plan(snapshot_path):
    if not snapshot_path.is_file():
        raise ValueError(f"Snapshot not found: {snapshot_path}")
    data = json.loads(snapshot_path.read_text(encoding="utf-8-sig"))
    project = data.get("project", {})
    if project.get("project_id") != EXPECTED_PROJECT_ID or project.get("name") != EXPECTED_PROJECT_NAME:
        raise ValueError("Wrong GNS3 project in snapshot; refusing to plan")

    nodes = data.get("nodes")
    links = data.get("links")
    if not isinstance(nodes, list) or not isinstance(links, list):
        raise ValueError("Snapshot must contain node and link arrays")

    by_name = {n.get("name"): n for n in nodes}
    if len(nodes) != len(EXPECTED_TYPES) or set(by_name) != set(EXPECTED_TYPES):
        raise ValueError("Unexpected node count, node names, or duplicate names")
    if len(links) != len(EXPECTED_LINKS):
        raise ValueError(f"Expected exactly 7 links, found {len(links)}")

    by_id = {}
    for name, expected_type in EXPECTED_TYPES.items():
        node = by_name[name]
        if node.get("node_type") != expected_type:
            raise ValueError(f"{name}: unexpected node type {node.get('node_type')!r}")
        identifier = node.get("node_id")
        if not identifier or identifier in by_id:
            raise ValueError(f"{name}: missing or duplicated node_id")
        by_id[identifier] = name
        if name.startswith("CPE-"):
            props = node.get("properties") or {}
            if props.get("adapters") != 3:
                raise ValueError(f"{name}: expected 3 network adapters")
            if props.get("hda_disk_image") != "alpine-virt-3.18.4.qcow2":
                raise ValueError(f"{name}: unexpected system disk")
            if props.get("hdb_disk_image") != "empty20G.qcow2":
                raise ValueError(f"{name}: unexpected data disk")

    actual_edges = set()
    used_ports = set()
    for link in links:
        if link.get("link_type") != "ethernet":
            raise ValueError("Unexpected non-Ethernet link")
        endpoints = link.get("nodes", [])
        if len(endpoints) != 2:
            raise ValueError("Link does not have exactly two endpoints")
        parsed = []
        for endpoint in endpoints:
            identifier = endpoint.get("node_id")
            if identifier not in by_id:
                raise ValueError("Link refers to unknown node_id")
            connection = port(by_id[identifier], endpoint.get("adapter_number"), endpoint.get("port_number"))
            if connection in used_ports:
                raise ValueError(f"Port connected more than once: {label(connection)}")
            used_ports.add(connection)
            parsed.append(connection)
        actual_edges.add(edge(*parsed))
    if actual_edges != EXPECTED_LINKS:
        missing = EXPECTED_LINKS - actual_edges
        extra = actual_edges - EXPECTED_LINKS
        raise ValueError(f"Unexpected connections: missing={len(missing)}, extra={len(extra)}")

    print("=== SAFE GNS3 TOPOLOGY REBUILD PLAN (DRY RUN) ===")
    print(f"Validated snapshot: {snapshot_path}")
    print(f"Project: {EXPECTED_PROJECT_NAME} ({EXPECTED_PROJECT_ID})")
    print("PASS: Exactly 8 expected nodes and 7 expected links")
    print("\nPHASE 1 — Future node creation (NOT EXECUTED)")
    for name in ("NAT1", "NAT2", "Switch1", "Switch2", "PC1", "PC2", "CPE-1", "CPE-2"):
        node = by_name[name]
        print(f"  PLAN: Create {name} ({node['node_type']})")
    print("\nPHASE 2 — Future link creation (NOT EXECUTED)")
    for link in sorted(actual_edges, key=lambda e: sorted(e)):
        a, b = sorted(link)
        print(f"  PLAN: {label(a)} <--> {label(b)}")
    print("\nPHASE 3 — Provisioning required (NOT EXECUTED)")
    print("  - Reproduce Alpine + /data disk, Docker/Compose and Forwarder from source")
    print("  - Generate CI-only keys; do not copy live private keys")
    print("  - Configure CPE WAN/LAN, bridges, DHCP, IPv4 forwarding, and underlay routes")
    print("  - Run setup_namespace.sh and then gns3_console.py --test-cross")
    print("\nSAFETY: NO GNS3 API REQUESTS. NO RESETS. NO VM DISK BACKUP CREATED.")
    print("RESULT: DRY-RUN PLAN PASSED; AUTOMATIC REBUILD NOT YET IMPLEMENTED")


def main():
    parser = argparse.ArgumentParser(description="Plan an isolated GNS3 CI rebuild without making any changes")
    parser.add_argument("--snapshot", type=Path, default=Path.home() / "sdwan-ci" / "current-topology.json")
    args = parser.parse_args()
    try:
        plan(args.snapshot)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
