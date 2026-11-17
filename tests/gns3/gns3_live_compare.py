#!/usr/bin/env python3
"""Read-only comparison of a GNS3 CI project's live topology with a saved snapshot.

Required environment variables:
    GNS3_URL         GNS3 server base URL, e.g. http://gns3.example:3080
    GNS3_PROJECT_ID  Exact ID of the dedicated CI project

Optional:
    GNS3_TOPOLOGY_SNAPSHOT  Path to snapshot JSON
                             (default ~/sdwan-ci/current-topology.json)

This program makes HTTP GET requests only. It never starts/stops VMs or modifies
projects, nodes, links, files, or guest configurations.
"""

import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

EXPECTED_PROJECT_NAME = "sdwan-ci"
EXPECTED_NODE_NAMES = {
    "NAT1", "NAT2", "Switch1", "Switch2", "PC1", "PC2", "CPE-1", "CPE-2"
}
EXPECTED_LINK_COUNT = 7
CPE_PROPERTIES = (
    "hda_disk_image", "hdb_disk_image", "linked_clone", "ram", "cpus", "adapters"
)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def fetch_json(base_url, path):
    url = base_url.rstrip("/") + path
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    with urlopen(request, timeout=12) as response:
        return json.load(response)


def node_index(nodes, label):
    if not isinstance(nodes, list):
        raise ValueError(f"{label}: nodes must be a list")
    by_name = {}
    for node in nodes:
        name = node.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{label}: node with missing name")
        if name in by_name:
            raise ValueError(f"{label}: duplicate node name {name!r}")
        by_name[name] = node
    return by_name


def link_keys(nodes, links, label):
    if not isinstance(links, list):
        raise ValueError(f"{label}: links must be a list")
    names = {}
    for node in nodes:
        node_id = node.get("node_id")
        if not node_id or node_id in names:
            raise ValueError(f"{label}: missing or duplicate node ID")
        names[node_id] = node["name"]
    keys = []
    for link in links:
        ends = link.get("nodes", [])
        if len(ends) != 2:
            raise ValueError(f"{label}: link does not have exactly two endpoints")
        endpoint_labels = []
        for end in ends:
            node_id = end.get("node_id")
            if node_id not in names:
                raise ValueError(f"{label}: link references unknown node {node_id}")
            adapter = end.get("adapter_number")
            port = end.get("port_number")
            if not isinstance(adapter, int) or not isinstance(port, int):
                raise ValueError(f"{label}: link adapter/port missing")
            endpoint_labels.append(f"{names[node_id]} [adapter {adapter}, port {port}]")
        keys.append(" <--> ".join(sorted(endpoint_labels)))
    if len(keys) != len(set(keys)):
        raise ValueError(f"{label}: duplicate links detected")
    return set(keys)


def main():
    print("=== GNS3 LIVE TOPOLOGY COMPARISON (READ ONLY) ===")
    base_url = os.environ.get("GNS3_URL", "").strip()
    project_id = os.environ.get("GNS3_PROJECT_ID", "").strip()
    if not base_url or not project_id:
        return fail("Set both GNS3_URL and GNS3_PROJECT_ID environment variables")
    parsed = urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.query or parsed.fragment:
        return fail("GNS3_URL must be a valid HTTP(S) server base URL")
    snapshot = Path(os.environ.get("GNS3_TOPOLOGY_SNAPSHOT", str(Path.home() / "sdwan-ci" / "current-topology.json"))).expanduser()
    try:
        data = json.loads(snapshot.read_text(encoding="utf-8-sig"))
        saved_project = data["project"]
        if saved_project.get("project_id") != project_id or saved_project.get("name") != EXPECTED_PROJECT_NAME:
            return fail("Snapshot does not match the explicitly selected sdwan-ci project")
        saved_nodes = data["nodes"]
        saved_links = data["links"]
        saved_by_name = node_index(saved_nodes, "snapshot")
        if set(saved_by_name) != EXPECTED_NODE_NAMES or len(saved_links) != EXPECTED_LINK_COUNT:
            return fail("Snapshot must have exactly the 8 expected nodes and 7 links")
        saved_link_set = link_keys(saved_nodes, saved_links, "snapshot")

        api_root = "/v2/projects/" + quote(project_id, safe="")
        live_project = fetch_json(base_url, api_root)
        if live_project.get("project_id") != project_id or live_project.get("name") != EXPECTED_PROJECT_NAME:
            return fail("GNS3 server returned a different project; comparison aborted")
        live_nodes = fetch_json(base_url, api_root + "/nodes")
        live_links = fetch_json(base_url, api_root + "/links")
        live_by_name = node_index(live_nodes, "live")
        live_link_set = link_keys(live_nodes, live_links, "live")

        print(f"Snapshot: {snapshot}")
        print(f"Project : {EXPECTED_PROJECT_NAME} (project ID verified)")
        print(f"Nodes   : saved {len(saved_nodes)}, live {len(live_nodes)}")
        print(f"Links   : saved {len(saved_links)}, live {len(live_links)}")
        problems = []

        missing = sorted(set(saved_by_name) - set(live_by_name))
        extra = sorted(set(live_by_name) - set(saved_by_name))
        if missing:
            problems.append("Missing nodes: " + ", ".join(missing))
        if extra:
            problems.append("Extra nodes: " + ", ".join(extra))
        for name in sorted(set(saved_by_name) & set(live_by_name)):
            saved = saved_by_name[name]
            live = live_by_name[name]
            if saved.get("node_type") != live.get("node_type"):
                problems.append(f"Node type differs: {name}")
            if name in ("CPE-1", "CPE-2"):
                a, b = saved.get("properties", {}), live.get("properties", {})
                for key in CPE_PROPERTIES:
                    if a.get(key) != b.get(key):
                        problems.append(f"{name} hardware setting differs: {key}")

        missing_links = sorted(saved_link_set - live_link_set)
        extra_links = sorted(live_link_set - saved_link_set)
        for link in missing_links:
            problems.append("Missing link: " + link)
        for link in extra_links:
            problems.append("Extra link: " + link)

        if problems:
            for problem in problems:
                print("MISMATCH: " + problem)
            print("RESULT: FAIL — LIVE TOPOLOGY DIFFERS FROM SAVED SNAPSHOT")
            print("SAFETY: GET requests only; nothing changed on GNS3")
            return 1

        print("PASS: Node names, types, CPE virtual hardware, and link endpoints match")
        print("RESULT: PASS — LIVE TOPOLOGY MATCHES SAVED SNAPSHOT")
        print("NOTE: Guest OS configuration, Docker contents and VM disk data were NOT compared")
        print("SAFETY: GET requests only; no GNS3 changes made")
        return 0
    except (OSError, ValueError, KeyError, TypeError, HTTPError, URLError) as exc:
        return fail(f"Cannot complete comparison: {exc}")


if __name__ == "__main__":
    sys.exit(main())
