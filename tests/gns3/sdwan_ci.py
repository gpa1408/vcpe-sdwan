
import os
import json
from pathlib import Path

import requests


# ============================================================
# SD-WAN CI AUTOMATION
# GNS3 topology inspection and inter-CPE link dry run
#
# Project: vcpe-sdwan
# GNS3 project: sdwan-ci
#
# IMPORTANT: This script is READ-ONLY.
# It does not create, delete, or modify GNS3 devices.
# ============================================================


# ------------------------------------------------------------
# 1. GNS3 CONFIGURATION
# ------------------------------------------------------------

GNS3_URL = os.environ.get("GNS3_URL", "").rstrip("/")
PROJECT_ID = os.environ.get("GNS3_PROJECT_ID", "")
PROJECT_NAME = "sdwan-ci"

if not GNS3_URL or not PROJECT_ID:
    raise SystemExit(
        "Missing configuration.\n"
        "Please set GNS3_URL and GNS3_PROJECT_ID "
        "in PowerShell before running."
    )

BASE_URL = f"{GNS3_URL}/v2/projects/{PROJECT_ID}"


# ------------------------------------------------------------
# 2. OPTIONAL BASELINE TOPOLOGY
# ------------------------------------------------------------

default_baseline = (
    Path.home() / "sdwan-ci" / "baseline-topology.json"
)

snapshot_path = Path(
    os.environ.get(
        "GNS3_BASELINE_PATH",
        str(default_baseline)
    )
)

baseline = None

if snapshot_path.is_file():
    with open(snapshot_path, "r", encoding="utf-8-sig") as f:
        baseline = json.load(f)

    print("Baseline topology loaded successfully.")
else:
    print("Baseline file not found.")
    print("Baseline comparison will be skipped.")


# ------------------------------------------------------------
# 3. CONNECT TO GNS3 API
# ------------------------------------------------------------

def get_api(path):
    response = requests.get(
        BASE_URL + path,
        timeout=15
    )

    response.raise_for_status()

    return response.json()


# ------------------------------------------------------------
# 4. MAIN CI INSPECTION
# ------------------------------------------------------------

def main():

    print("\n=== SD-WAN CI TEST PLAN ===")

    # Retrieve project information
    project = get_api("")

    # Confirm correct project
    if project["name"] != PROJECT_NAME:
        raise RuntimeError(
            "Wrong GNS3 project detected. Stopping!"
        )

    # Check saved baseline project ID, if available
    if baseline is not None:
        saved_project_id = baseline["project"]["project_id"]

        if saved_project_id != PROJECT_ID:
            raise RuntimeError(
                "Baseline project mismatch. Stopping!"
            )

    # Retrieve nodes and links
    nodes = get_api("/nodes")
    links = get_api("/links")

    print(f"Project: {project['name']}")
    print(f"Nodes: {len(nodes)}")
    print(f"Links: {len(links)}")


    # --------------------------------------------------------
    # 5. DISPLAY NETWORK DEVICES
    # --------------------------------------------------------

    print("\n--- DEVICES ---")

    names = {}

    for node in nodes:

        names[node["node_id"]] = node["name"]

        print(
            f"{node['name']} "
            f"({node['node_type']})"
        )


    # --------------------------------------------------------
    # 6. DISPLAY NETWORK CONNECTIONS
    # --------------------------------------------------------

    print("\n--- CONNECTIONS ---")

    for link in links:

        endpoints = []

        for port in link["nodes"]:

            node_name = names.get(
                port["node_id"],
                "Unknown"
            )

            endpoints.append(
                f"{node_name} "
                f"[adapter {port['adapter_number']}, "
                f"port {port['port_number']}]"
            )

        print(" <--> ".join(endpoints))


    # --------------------------------------------------------
    # 7. VALIDATE REQUIRED CPE DEVICES
    # --------------------------------------------------------

    print("\n--- VALIDATION ---")

    node_names = [node["name"] for node in nodes]

    required_cpes = ["CPE-1", "CPE-2"]

    for cpe_name in required_cpes:

        if node_names.count(cpe_name) != 1:
            raise RuntimeError(
                f"{cpe_name} is missing or duplicated."
            )

        print(f"{cpe_name}: FOUND")


    # --------------------------------------------------------
    # 8. COMPARE SAVED BASELINE
    # --------------------------------------------------------

    if baseline is not None:

        old_nodes = {
            node["node_id"]
            for node in baseline["nodes"]
        }

        new_nodes = {
            node["node_id"]
            for node in nodes
        }

        same_nodes = old_nodes == new_nodes

        print("Same baseline nodes:", same_nodes)

        if not same_nodes:
            print(
                "WARNING: Current nodes differ "
                "from the saved baseline."
            )

    else:
        print(
            "Baseline unavailable: "
            "comparison skipped."
        )


    # --------------------------------------------------------
    # 9. INTER-CPE LINK PREPARATION
    # --------------------------------------------------------

    print("\n--- INTER-CPE LINK DRY RUN ---")

    cpe1 = next(
        node for node in nodes
        if node["name"] == "CPE-1"
    )

    cpe2 = next(
        node for node in nodes
        if node["name"] == "CPE-2"
    )

    # Identify ports already used by existing links
    used_ports = {
        (
            port["node_id"],
            port["adapter_number"],
            port["port_number"]
        )
        for link in links
        for port in link["nodes"]
    }

    # Confirm adapter 1 is available on both CPEs
    for cpe in (cpe1, cpe2):

        interface = (
            cpe["node_id"],
            1,
            0
        )

        if interface in used_ports:
            raise RuntimeError(
                f"{cpe['name']} adapter 1 "
                "is already occupied."
            )

    # Prepare GNS3 link configuration
    link_plan = {
        "nodes": [
            {
                "node_id": cpe1["node_id"],
                "adapter_number": 1,
                "port_number": 0
            },
            {
                "node_id": cpe2["node_id"],
                "adapter_number": 1,
                "port_number": 0
            }
        ]
    }

    print(
        "CPE-1 adapter 1 <--> "
        "CPE-2 adapter 1"
    )

    print(json.dumps(link_plan, indent=2))

    print(
        "\nDRY RUN PASSED - No changes made"
    )


    # --------------------------------------------------------
    # 10. NEXT AUTOMATION TARGETS
    # --------------------------------------------------------

    print("\n--- NEXT AUTOMATION TARGETS ---")

    print("1. Recreate the dedicated test topology")
    print("2. Configure SD-WAN on both CPEs")
    print("3. Create one namespace per CPE")
    print("4. Test LAN connectivity")
    print("5. Test inter-CPE connectivity")
    print("6. Generate PASS/FAIL test results")

    print("\nREAD-ONLY CI INSPECTION COMPLETED")


# ------------------------------------------------------------
# 11. RUN MAIN
# ------------------------------------------------------------

if __name__ == "__main__":

    try:
        main()

    except requests.RequestException as error:
        print("\nGNS3 API ERROR:", error)
        raise SystemExit(1)

    except (RuntimeError, ValueError, KeyError) as error:
        print("\nVALIDATION ERROR:", error)
        raise SystemExit(1)
