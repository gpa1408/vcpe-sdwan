#!/usr/bin/env python3
# coding: utf-8
import json
import logging
import time
import requests
import os
import base64
import xml.etree.ElementTree as ET                                                    # to parse XML transaction messages sent by Clixon callback plugin
import threading

from http.server import BaseHTTPRequestHandler, HTTPServer                            # internal HTTP server for receiving Clixon callback messages
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from config_reader import ConfigReader
#from metric_reader import MetricReader                  #REMOVE COMMENT
#from state_writer import StateWriter                    #REMOVE COMMENT
#from monitoring_manager import MonitoringManager        #REMOVE COMMENT

logging.basicConfig(level=logging.INFO)                                               # to show info messages and errors

class Agent:
    def __init__(self):
        self.config_reader = ConfigReader()
        #self.metric_reader = MetricReader()              #REMOVE COMMENT
        #self.state_writer = StateWriter()                #REMOVE COMMENT
        #self.monitoring_manager = MonitoringManager()    #REMOVE COMMENT

        self.generated_tunnel_keys = {}                                               # stores generated WireGuard keys during the current agent runtime
        self.forwarder_base_url = "http://vcpe-forwarder:9090"                       # fixed forwarder API URL used by the agent
        self.forwarder_dry_run = False                                                # Since forwarder is not ready yet,a dry-run will be enabled by default (false send real API calls)

    # =====================================================================================
    # Basic helpers
    # =====================================================================================
    def _allocate_fwmark(self, class_name, index):                                    # called by "_make_steering_decisions()". CPE agent assigned fwmark for a traffic class.
        return 1000 + index

    def _index_states_by_name(self, states):                                          # called by "_make_steering_decisions()"
        indexed = {}
        for item in states:                                                           # Loops through each state item in the list
            name = item.get("name")                                                   # Reads the name field from the state dictionary
            if name:
                indexed[name] = item                                                  # If the state has a name, store that item in the dictionary using the name as key
        return indexed

    def _local_name(self, tag):
        if tag is None:
            return ""
        if "}" in tag:
            return tag.split("}", 1)[1]                                               # splits the string variable tag at the first } and returns everything that comes after it
        return tag

    def _first_child(self, element):
        if element is None:
            return None
        children = list(element)                                                      # gets all direct child XML nodes inside this element
        return children[0] if children else None                                      # returns the real object inside wrappers like parent data

    def _bool_value(self, value):                                                     # converts YANG/Clixon boolean text into real Python boolean without adding Python defaults
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        return str(value).lower() in ["true", "1", "yes"]

    def _xml_to_dict(self, element):                                                  # Convert XML parent object from Clixon into a Python dictionary to avoids hardcoding every YANG leaf one by one
        if element is None:
            return {}

        result = {}
        for child in list(element):
            name = self._local_name(child.tag)
            if len(list(child)) == 0:                                                 #if this XML node has no child nodes, it is a simple leaf
                value = child.text
            else:
                value = self._xml_to_dict(child)                                     #if this XML node has child nodes, convert that nested object also

            if name in result:                                                       #if the same leaf/list name appears again, store values as a list
                if not isinstance(result[name], list):
                    result[name] = [result[name]]
                result[name].append(value)
            else:
                result[name] = value

        return result

    def _as_list(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]                                                               # single value is wrapped as a list to make later processing easier

    def _has_change(self, changed_leafs, *names):                                    # agent decides whether to send a field to the forwarder.
        if "*" in changed_leafs:
            return True                                                              # used for added objects where the full object must be configured
        return any(name in changed_leafs for name in names)                          # returns True if at least one requested leaf is in the changed leaf list

    def _add_if_not_none(self, payload, api_field, value):
        if value is not None:
            payload[api_field] = value                                               # avoids sending Python defaults when the datastore did not provide a value

    def _port_range(self, value):                                                    # Even when YANG has only one port, forwarder may expect port ranges. This converts a single port into forwarder format.
        if isinstance(value, list):
            value = value[0] if value else None
        if value is None or value == "any":
            return None                                                              # no port filter is needed when the YANG value is any
        port = int(value)                                                            # forwarder expects port numbers as integers
        return {"start": port, "end": port}                                        # single port is represented as a range with same start and end

    def _ip_from_prefix(self, prefix):
        if not prefix:
            return None
        return str(prefix).split("/", 1)[0]                                          # converts 10.0.1.1/24 into 10.0.1.1 for DHCP gateway field

    def _lease_time(self, seconds):
        if seconds is None:
            return None                                                              # YANG default is trusted, so Python does not create its own default here
        return f"{seconds}s"                                                         # forwarder OpenAPI expects lease_time as a string such as 86400s or 24h

    def _generate_wireguard_tunnel_keys(self, tunnel_name):                          # generate and save WireGuard tunnel keys uding curve25519
        private_dir = "/var/lib/sdwan-cpe/keys"
        public_dir = "/var/lib/clixon/local-public-keys"

        private_path = f"{private_dir}/{tunnel_name}.private"                       # local private key file path for this tunnel
        public_path = f"{public_dir}/{tunnel_name}.pub"                             # local public key file path exposed later as config false state

        try:
            if os.path.exists(private_path) and os.path.exists(public_path):          # reuse existing keys instead of generating new keys every restart
                with open(private_path, "r") as f:
                    private_key = f.read().strip()

                with open(public_path, "r") as f:
                    public_key = f.read().strip()

                return private_key, public_key, private_path

            private_key_obj = X25519PrivateKey.generate()                            # creates a new WireGuard-compatible private key
            public_key_obj = private_key_obj.public_key()                            # derives the matching public key from the private key

            private_key_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption())

            public_key_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw)

            private_key = base64.b64encode(private_key_bytes).decode("ascii")       # WireGuard keys are stored and passed as base64 text
            public_key = base64.b64encode(public_key_bytes).decode("ascii")         # public key is also stored as base64 text

            os.makedirs(private_dir, exist_ok=True)
            os.makedirs(public_dir, exist_ok=True)

            with open(private_path, "w") as f:
                f.write(private_key)
            os.chmod(private_path, 0o600)                                            # private key file is readable only by the owner

            with open(public_path, "w") as f:
                f.write(public_key)
            os.chmod(public_path, 0o644)                                             # public key can be read by Clixon state plugin

            logging.info("Created WireGuard keys for tunnel %s", tunnel_name)
            return private_key, public_key, private_path

        except Exception as e:
            logging.exception("Failed to get or create WireGuard keys for tunnel %s: %s", tunnel_name, e)
            return None, None, None

    # =====================================================================================
    # Config lookup helpers for nested callback parents
    # =====================================================================================
    def _get_current_config(self):
        try:
            return self.config_reader.get_intended_config()
        except Exception as e:
            logging.exception("Failed to read current config for nested callback resolution: %s", e)
            return {}

    def _find_lan_link_for_dhcp(self, dhcp_server):
        current_config = self._get_current_config()
        lan_links = current_config.get("interfaces", {}).get("lan", {}).get("lan-link", [])
        for lan in self._as_list(lan_links):
            if lan.get("dhcp-server") == dhcp_server:
                return lan
        return None

    def _find_tunnel_for_resolved_peer(self, resolved_peer):
        current_config = self._get_current_config()
        tunnels = current_config.get("overlay", {}).get("tunnel", [])
        for tunnel in self._as_list(tunnels):
            if tunnel.get("resolved-peer") == resolved_peer:
                return tunnel
        return None

    def _find_class_for_five_tuple(self, five_tuple):
        current_config = self._get_current_config()
        classes = current_config.get("traffic", {}).get("class", [])
        for traffic_class in self._as_list(classes):
            if traffic_class.get("five-tuple") == five_tuple:
                return traffic_class
        return None

    # =====================================================================================
    # Publish operations data in Datastore
    # =====================================================================================
    def detect_and_store_nat_type(self, wan_name, interface_name, role):
        if role != "ipvpn" and wan_name and interface_name:
            if self.forwarder_dry_run:                                                   # in dry-run mode, only print the transaction without calling forwarder
                logging.info("Dry-run: NAT detection skipped for WAN link %s", wan_name)
                return None

            try:
                url = f"{self.forwarder_base_url}/api/v1/interfaces/{interface_name}/nat-discovery" # OpenAPI NAT discovery endpoint is interface based
                response = requests.post(url, json={}, timeout=10)
                response.raise_for_status()                                              # raises an error if the forwarder returns a failed HTTP status

                task_id = response.json().get("task_id")
                if not task_id:
                    return None

                result_url = f"{self.forwarder_base_url}/api/v1/interfaces/{interface_name}/nat-discovery/{task_id}"
                nat_type = None

                for _ in range(5):                                                       # small polling loop for the asynchronous NAT discovery task
                    result = requests.get(result_url, headers={"Accept": "application/json"}, timeout=10)
                    result.raise_for_status()
                    data = result.json()
                    if data.get("status") == "completed":
                        nat_type = data.get("results", {}).get("nat_type")              # reads nat_type value returned by the forwarder
                        break
                    if data.get("status") == "failed":
                        return None
                    time.sleep(1)

                if not nat_type:
                    return None

                state_dir = "/var/lib/clixon/wan-link-nat-types"                         # state plugin can read this directory to publish config false nat-type
                os.makedirs(state_dir, exist_ok=True)

                with open(f"{state_dir}/{wan_name}.nat", "w") as f:                      # one runtime state file is stored per WAN link
                    f.write(nat_type)

                logging.info("Stored nat-type=%s for wan-link=%s", nat_type, wan_name)
                return nat_type

            except Exception as e:
                logging.exception("NAT detection failed for WAN link %s: %s", wan_name, e)
                return None

        return None
    # =====================================================================================
    # Check RESTCONF Server status before running Steering Loop
    # =====================================================================================
    def wait_for_restconf(self, timeout_sec=60):
        start_time = time.time()

        while time.time() - start_time < timeout_sec:
            try:
                self.config_reader.get_intended_config()
                logging.info("RESTCONF is ready for steering loop")
                return True
            except Exception:
                logging.info("Waiting for RESTCONF before starting steering loop")
                time.sleep(2)

        logging.warning("RESTCONF was not ready within timeout")
        return False

    def run_steering_loop_after_restconf_ready(self, interval_sec=10):
        if not self.wait_for_restconf():
            return

        self.run_forever(interval_sec=interval_sec)
    # =====================================================================================
    # Forwarder API helpers
    # =====================================================================================
    def _operation(self, method, path, payload=None):
        operation = {"method": method, "path": path}                                   # basic forwarder operation structure
        if payload is not None:
            operation["payload"] = payload                                               # payload is added only when the operation needs data
        return operation

    def _send_forwarder_transaction(self, operations, validate_only):
        payload = {
            "validate_only": validate_only,                                              # "True" during Clixon validate phase, "False" during commit phase. Detection happens in happens in handle_clixon_transaction()
            "operations": operations}                                                    # all forwarder operations are sent as one transaction

        print("\n===== FORWARDER TRANSACTION GENERATED =====")
        print(json.dumps(payload, indent=2))

        if self.forwarder_dry_run:                                                        #in dry-run mode, only print the transaction without calling forwarder
            return {
                "status": "dry-run",
                "message": "Forwarder is not called because it's not available",
                "payload": payload}

        url = f"{self.forwarder_base_url}/api/v1/transactions"
        response = requests.post(url, json=payload, timeout=10)                           #send the transaction to the forwarder API
        response.raise_for_status()

        if response.text:
            return response.json()

        return {"status": "ok"}

    # =====================================================================================
    # Build forwarder operations (for Clixon YANG Datastore config-diff triggered operations)
    # =====================================================================================
    def _build_wan_link_operations(self, parent_dict, changed_leafs, delete=False):
        name = parent_dict.get("name")
        route_set_id = f"{name}-default"
        interface_name = parent_dict.get("interface-name")
        role = parent_dict.get("role")
        admin_enabled = self._bool_value(parent_dict.get("admin-enabled"))
        address_mode = parent_dict.get("address-mode")
        static_address = parent_dict.get("static-address")
        static_gateway = parent_dict.get("static-gateway")

        if isinstance(changed_leafs, str):
            changed_leafs = [changed_leafs]                                               #allows the function to accept either one leaf or a list of leaves

        if not interface_name:
            logging.warning("WAN link %s has no interface-name", name)
            return []

        operations = []                                                                   #stores the forwarder operations generated for this object

        if delete:
            operations.append(self._operation("PUT", f"/api/v1/interfaces/{interface_name}/state", {"state": "down"}))
            operations.append(self._operation("DELETE", f"/api/v1/routes/static/{route_set_id}"))
            return operations

        if self._has_change(changed_leafs, "admin-enabled") and admin_enabled is not None:
            operations.append(
                self._operation("PUT", f"/api/v1/interfaces/{interface_name}/state",
                                {"state": "up" if admin_enabled else "down"}))

        if self._has_change(changed_leafs, "static-address", "address-mode", "interface-name"):
            addresses = []
            if address_mode == "static" and static_address:
                addresses.append(static_address)
            operations.append(self._operation("PUT", f"/api/v1/interfaces/{interface_name}/addresses", {"addresses": addresses}))

        if self._has_change(changed_leafs, "static-gateway", "address-mode", "interface-name"):
            if address_mode == "static" and static_gateway:
                operations.append(self._operation("PUT", f"/api/v1/routes/static/{route_set_id}", {
                    "routes": [{
                        "destination_cidr": "0.0.0.0/0",
                        "next_hop_ip": static_gateway,
                        "out_interface": interface_name
                    }]
                }))
            elif address_mode == "dhcp":
                operations.append(self._operation("DELETE", f"/api/v1/routes/static/{route_set_id}"))

        return operations

    def _build_lan_link_operations(self, parent_dict, changed_leafs, delete=False):
        name = parent_dict.get("name")
        bridge_name = parent_dict.get("bridge-name")
        target_interface = bridge_name if bridge_name else name
        member_interfaces = self._as_list(parent_dict.get("member-interface"))
        ipv4_prefix = parent_dict.get("ipv4-prefix")
        admin_enabled = self._bool_value(parent_dict.get("admin-enabled"))
        dhcp_server = parent_dict.get("dhcp-server", {})

        if isinstance(changed_leafs, str):
            changed_leafs = [changed_leafs]                                               #allows the function to accept either one leaf or a list of leaves

        if not target_interface:
            logging.warning("LAN link has no interface name")
            return []

        operations = []                                                                   #stores the forwarder operations generated for this object

        if delete:
            if bridge_name:
                operations.append(self._operation("DELETE", f"/api/v1/bridges/{bridge_name}"))
            else:
                operations.append(self._operation("PUT", f"/api/v1/interfaces/{name}/state", {"state": "down"}))
            operations.append(self._operation("DELETE", f"/api/v1/services/dhcp/{target_interface}"))
            return operations

        if bridge_name and self._has_change(changed_leafs, "name", "bridge-name", "member-interface", "admin-enabled"):
            bridge_payload = {"bridge_id": bridge_name}                                  # OpenAPI bridge payload requires bridge_id
            if self._has_change(changed_leafs, "member-interface"):
                bridge_payload["members"] = member_interfaces
            if self._has_change(changed_leafs, "admin-enabled") and admin_enabled is not None:
                bridge_payload["admin_state"] = "up" if admin_enabled else "down"

            operations.append(self._operation("PUT", f"/api/v1/bridges/{bridge_name}", bridge_payload))

            if self._has_change(changed_leafs, "member-interface"):
                for member in member_interfaces:
                    operations.append(self._operation("PUT", f"/api/v1/interfaces/{member}/state", {"state": "up"}))

        if not bridge_name and self._has_change(changed_leafs, "admin-enabled") and admin_enabled is not None:
            operations.append(
                self._operation("PUT", f"/api/v1/interfaces/{name}/state",
                                {"state": "up" if admin_enabled else "down"}))

        if self._has_change(changed_leafs, "ipv4-prefix", "bridge-name"):
            operations.append(
                self._operation("PUT", f"/api/v1/interfaces/{target_interface}/addresses",
                                {"addresses": [ipv4_prefix] if ipv4_prefix else []}))

        if self._has_change(changed_leafs, "enabled", "pool-start", "pool-end", "dns-server", "lease-time-seconds", "ipv4-prefix", "bridge-name"):
            dhcp_enabled = self._bool_value(dhcp_server.get("enabled"))
            dhcp_payload = {
                "enabled": dhcp_enabled,
                "served_interface": target_interface
            }
            self._add_if_not_none(dhcp_payload, "range_start", dhcp_server.get("pool-start"))
            self._add_if_not_none(dhcp_payload, "range_end", dhcp_server.get("pool-end"))
            self._add_if_not_none(dhcp_payload, "gateway", self._ip_from_prefix(ipv4_prefix))
            dns_servers = self._as_list(dhcp_server.get("dns-server"))
            if dns_servers:
                dhcp_payload["dns_servers"] = dns_servers
            self._add_if_not_none(dhcp_payload, "lease_time", self._lease_time(dhcp_server.get("lease-time-seconds")))

            if dhcp_enabled is False:
                operations.append(self._operation("DELETE", f"/api/v1/services/dhcp/{target_interface}"))
            elif dhcp_enabled is True:
                operations.append(self._operation("PUT", f"/api/v1/services/dhcp/{target_interface}", dhcp_payload))

        return operations

    def _build_dhcp_server_operations(self, parent_dict, changed_leafs, delete=False):
        lan_link = self._find_lan_link_for_dhcp(parent_dict)
        if not lan_link:
            logging.warning("Cannot map dhcp-server callback to lan-link; update C plugin to send keyed parent lan-link")
            return []
        return self._build_lan_link_operations(lan_link, changed_leafs, delete)

    def _build_tunnel_operations(self, parent_dict, changed_leafs, delete=False):
        name = parent_dict.get("name")

        if isinstance(changed_leafs, str):
            changed_leafs = [changed_leafs]                                               #allows the function to accept either one leaf or a list of leaves

        if not name:
            logging.warning("Tunnel has no name")
            return []

        if delete:
            return [self._operation("DELETE", f"/api/v1/tunnels/wireguard/{name}")]

        if name not in self.generated_tunnel_keys:
            private_key, public_key, private_path = self._generate_wireguard_tunnel_keys(name)
            if private_key and public_key:
                self.generated_tunnel_keys[name] = {
                    "private-key": private_key,
                    "public-key": public_key,
                    "private-path": private_path}

        operations = []                                                                   #stores the forwarder operations generated for this object

        admin_enabled = self._bool_value(parent_dict.get("admin-enabled"))
        if self._has_change(changed_leafs, "admin-enabled") and admin_enabled is False:
            operations.append(self._operation("DELETE", f"/api/v1/tunnels/wireguard/{name}"))
            return operations

        tunnel_change_leafs = ["name", "local-port", "local-address", "mtu", "admin-enabled"]
        if self._has_change(changed_leafs, *tunnel_change_leafs):
            local_port = parent_dict.get("local-port")
            local_address = parent_dict.get("local-address")
            mtu = parent_dict.get("mtu")
            private_path = self.generated_tunnel_keys.get(name, {}).get("private-path")

            tunnel_payload = {}
            if private_path:
                tunnel_payload["private_key_ref"] = f"file://{private_path}"
            self._add_if_not_none(tunnel_payload, "listen_port", int(local_port) if local_port else None)
            tunnel_payload["local_addresses"] = [local_address] if local_address else []
            self._add_if_not_none(tunnel_payload, "mtu", int(mtu) if mtu else None)
            tunnel_payload["description"] = f"WireGuard tunnel {name}"

            if "listen_port" in tunnel_payload and "local_addresses" in tunnel_payload:
                operations.append(self._operation("PUT", f"/api/v1/tunnels/wireguard/{name}", tunnel_payload))

        peer_change_leafs = ["peer-address", "peer-port", "peer-public-key", "allowed-prefix", "keepalive-seconds", "resolved-peer"]
        if self._has_change(changed_leafs, *peer_change_leafs):
            peer_operation = self._build_wireguard_peer_operation(parent_dict)
            if peer_operation:
                operations.append(peer_operation)

        return operations

    def _build_resolved_peer_operations(self, parent_dict, changed_leafs, delete=False):
        tunnel = self._find_tunnel_for_resolved_peer(parent_dict)
        if not tunnel:
            logging.warning("Cannot map resolved-peer callback to tunnel; update C plugin to send keyed parent tunnel")
            return []
        return self._build_tunnel_operations(tunnel, changed_leafs, delete)

    def _build_wireguard_peer_operation(self, tunnel):
        name = tunnel.get("name")
        resolved_peer = tunnel.get("resolved-peer", {})                                #peer details are nested under resolved-peer in the YANG model
        if not name or not resolved_peer:
            return None

        peer_id = tunnel.get("remote-cpe-id") or f"{name}-peer"
        peer_address = resolved_peer.get("peer-address")
        peer_port = resolved_peer.get("peer-port")
        peer_public_key = resolved_peer.get("peer-public-key")
        allowed_prefixes = self._as_list(resolved_peer.get("allowed-prefix"))
        keepalive = tunnel.get("keepalive-seconds")

        peer_payload = {}
        self._add_if_not_none(peer_payload, "public_key", peer_public_key)
        peer_payload["allowed_ips"] = allowed_prefixes
        if peer_address and peer_port:
            peer_payload["endpoint"] = f"{peer_address}:{peer_port}"
        self._add_if_not_none(peer_payload, "persistent_keepalive", int(keepalive) if keepalive else None)
        peer_payload["description"] = f"Peer {peer_id} for tunnel {name}"

        if "public_key" not in peer_payload or "allowed_ips" not in peer_payload:
            return None

        return self._operation("PUT", f"/api/v1/tunnels/wireguard/{name}/peers/{peer_id}", peer_payload)

    def _build_firewall_rule_operations(self, parent_dict, changed_leafs, delete=False):
        rule_id = parent_dict.get("id")

        if isinstance(changed_leafs, str):
            changed_leafs = [changed_leafs]                                               #allows the function to accept either one leaf or a list of leaves

        if not rule_id:
            logging.warning("Firewall rule has no id")
            return []

        policy_id = f"firewall-rule-{rule_id}"

        if delete:
            return [self._operation("DELETE", f"/api/v1/flow-policies/{policy_id}")]

        match = self._build_match_from_dict(parent_dict)
        action = parent_dict.get("action")

        if action == "allow":
            logging.info("No OpenAPI firewall allow action exists; skipping allow rule %s", rule_id)
            return []

        payload = {
            "match": match,
            "action": {"type": "drop"},
            "description": f"Firewall deny rule {rule_id}"
        }
        self._add_if_not_none(payload, "priority", int(parent_dict.get("priority")) if parent_dict.get("priority") else None)

        return [self._operation("PUT", f"/api/v1/flow-policies/{policy_id}", payload)]

    def _build_traffic_class_operations(self, parent_dict, changed_leafs, delete=False):
        class_name = parent_dict.get("name")
        if not class_name:
            logging.warning("Traffic class has no name")
            return []

        logging.info("Traffic class %s changed; no direct forwarder operation because YANG class has match only and no OpenAPI action", class_name)
        return []

    def _build_five_tuple_operations(self, parent_dict, changed_leafs, delete=False):
        traffic_class = self._find_class_for_five_tuple(parent_dict)
        if not traffic_class:
            logging.warning("Cannot map five-tuple callback to traffic class; update C plugin to send keyed parent class")
            return []
        return self._build_traffic_class_operations(traffic_class, changed_leafs, delete)

    def _build_match_from_dict(self, parent_dict):
        match = {}                                                                         #traffic match fields such as prefixes, ports and protocol
        self._add_if_not_none(match, "src_prefix", parent_dict.get("src-prefix"))
        self._add_if_not_none(match, "dst_prefix", parent_dict.get("dst-prefix"))

        protocol = parent_dict.get("l4-protocol")
        if protocol:
            match["protocol"] = protocol

        src_ports = self._port_range(parent_dict.get("src-port"))
        if src_ports:
            match["src_ports"] = src_ports

        dst_ports = self._port_range(parent_dict.get("dst-port"))
        if dst_ports:
            match["dst_ports"] = dst_ports

        return match

    def _build_operations_from_object(self, object_type, parent_dict, changed_leafs, delete=False):
        if object_type == "wan-link":
            return self._build_wan_link_operations(parent_dict, changed_leafs, delete)

        if object_type == "lan-link":
            return self._build_lan_link_operations(parent_dict, changed_leafs, delete)

        if object_type == "dhcp-server":
            return self._build_dhcp_server_operations(parent_dict, changed_leafs, delete)

        if object_type == "tunnel":
            return self._build_tunnel_operations(parent_dict, changed_leafs, delete)

        if object_type == "resolved-peer":
            return self._build_resolved_peer_operations(parent_dict, changed_leafs, delete)

        if object_type == "rule":
            return self._build_firewall_rule_operations(parent_dict, changed_leafs, delete)

        if object_type == "class":
            return self._build_traffic_class_operations(parent_dict, changed_leafs, delete)

        if object_type == "five-tuple":
            return self._build_five_tuple_operations(parent_dict, changed_leafs, delete)

        logging.info("No forwarder mapping yet for object type=%s, changed_leafs=%s",
                     object_type, changed_leafs)
        return []

    def _build_operations_from_parent_xml(self, parent_xml, changed_leafs, delete=False):
        if parent_xml is None:
            return []

        object_type = self._local_name(parent_xml.tag)
        parent_dict = self._xml_to_dict(parent_xml)

        return self._build_operations_from_object(object_type, parent_dict, changed_leafs, delete)

    # =====================================================================================
    # Clixon callback handling
    # =====================================================================================
    def handle_clixon_transaction(self, xml_body):
        root = ET.fromstring(xml_body)                                                    #parses the XML transaction body received from Clixon

        phase = root.findtext("phase")
        transaction_id = root.findtext("transaction-id")
        validate_only = phase == "validate"                                               #Clixon sends validate first and commit after successful validation. If Clixon sends phase = "validate"→ validate_only = True

        if transaction_id == "0":                                                         #transaction 0 is startup data, not a real user config change
            logging.info("Ignoring Clixon startup transaction 0")
            return {
                "status": "ok",
                "phase": phase,
                "ignored": True,
                "reason": "startup transaction"}

        if phase not in ["validate", "commit"]:
            raise ValueError(f"Unsupported Clixon phase: {phase}")

        operations = []                                                                    #stores the forwarder operations generated for this object
        changed_objects = {}
        nat_detection_candidates = []

        changed = root.find("changed")                                                    #contains leaf changes sent by the Clixon diff callback
        if changed is not None:
            for change in changed.findall("change"):
                new_node = change.find("new")
                if new_node is None:
                    continue

                changed_leaf = new_node.findtext("node-name")                              #name of the YANG leaf that changed
                parent_data = new_node.find("parent-data")                                 #contains the full parent object of the changed leaf
                parent_xml = self._first_child(parent_data)                                 #extracts the real changed object from parent-data

                if parent_xml is None:
                    continue

                object_type = self._local_name(parent_xml.tag)                              #example: wan-link, tunnel, rule, class
                parent_dict = self._xml_to_dict(parent_xml)                                 #converted parent object used by the operation builders

                object_name = (
                    parent_dict.get("name")
                    or parent_dict.get("id")
                    or parent_dict.get("class")
                    or object_type)

                object_key = f"{object_type}:{object_name}"                                #unique key used to group multiple changed leafs under same object

                if object_key not in changed_objects:
                    changed_objects[object_key] = {
                        "object_type": object_type,
                        "parent_dict": parent_dict,
                        "changed_leafs": []}

                changed_objects[object_key]["changed_leafs"].append(changed_leaf)           #stores all changed leafs for this object

        for item in changed_objects.values():                                               #after grouping, build operations once per changed object
            object_type = item["object_type"]
            parent_dict = item["parent_dict"]
            changed_leafs = item["changed_leafs"]

            operations.extend(
                self._build_operations_from_object(
                    object_type,
                    parent_dict,
                    changed_leafs,
                    delete=False))

            if object_type == "wan-link":                                                  #WAN changes may require NAT detection after commit
                if self._has_change(
                    changed_leafs,
                    "interface-name",
                    "role",
                    "address-mode",
                    "static-address",
                    "static-gateway",
                    "admin-enabled"):
                    nat_detection_candidates.append(parent_dict)                            #store this WAN object for NAT detection after commit

        added = root.find("added")                                                          #contains newly added datastore objects
        if added is not None:
            for node in added.findall("node"):
                parent_data = node.find("parent-data")
                parent_xml = self._first_child(parent_data)                                 #extracts the real changed object from parent-data

                operations.extend(
                    self._build_operations_from_parent_xml(
                        parent_xml,
                        ["*"],
                        delete=False))

        deleted = root.find("deleted")                                                      # contains deleted datastore objects (normally delete=False, but when clixon reports delete->delete=True)
        if deleted is not None:
            for node in deleted.findall("node"):
                data = node.find("data")
                deleted_xml = self._first_child(data)

                operations.extend(
                    self._build_operations_from_parent_xml(
                        deleted_xml,
                        ["*"],
                        delete=True))

        if not operations:                                                                  #if this config change has no forwarder mapping, return OK without sending anything
            return {
                "status": "ok",
                "phase": phase,
                "message": "No forwarder operation generated",
                "operations": []}

        forwarder_result = self._send_forwarder_transaction(
            operations=operations,
            validate_only=validate_only)

        if phase == "commit":                                                              #NAT detection is triggered only after the config is committed
            for wan in nat_detection_candidates:
                self.detect_and_store_nat_type(
                    wan.get("name"),
                    wan.get("interface-name"),
                    wan.get("role"))

        return {
            "status": "ok",
            "phase": phase,
            "validate_only": validate_only,
            "operations": operations,
            "forwarder_result": forwarder_result}

    # ===========================================================================================================
    # Runtime steering decisions (Decisions made according to Metric values recived from Monitoring module)
    # ===========================================================================================================
    def _candidate_satisfies_slo(self, candidate_state, policy):
        if not candidate_state:                                                            #If there is no state object, candidate is invalid.
            return False

        oper_status = candidate_state.get("oper-status")                                   #Reads the operational status.
        if oper_status not in ["up", "degraded"]:                                         #Only candidates with up or degraded are accepted. Anything else is rejected
            return False

        max_latency = policy.get("max-latency-ms")                                         #Reads max allowed latency from policy.
        if max_latency is not None:
            latency = candidate_state.get("latency-ms")                                    #Reads measured latency from state
            if latency is None or latency > max_latency:                                   #Reject if latency is missing or exceeds the threshold.
                return False

        max_jitter = policy.get("max-jitter-ms")                                           #Reads max allowed jitter from policy.
        if max_jitter is not None:
            jitter = candidate_state.get("jitter-ms")                                      #Reads measured jitter from state
            if jitter is None or jitter > max_jitter:                                      #Reject if jitter is missing or exceeds the threshold
                return False

        max_loss = policy.get("max-loss-percent")                                          #Reads max allowed packet loss from policy.
        if max_loss is not None:
            loss = candidate_state.get("loss-percent")                                     #Reads measured packet loss from state
            if loss is None or loss > float(max_loss):                                     #Reject if packet loss is missing or exceeds the threshold
                return False

        min_bw = policy.get("min-bandwidth-kbps")                                          #Reads min allowed BW from policy.
        if min_bw is not None:
            bw = candidate_state.get("available-bandwidth-kbps")                           #Reads available BW from state
            if bw is None or bw < min_bw:                                                  #Reject if BW is missing or less than the threshold
                return False

        return True                                                                        #If all checks pass, candidate satisfies the SLO

    def _extract_candidate_states(self, policy, wan_state_map, tunnel_state_map):           #Return candidate type and candidate state objects according to policy.
        steering_mode = policy.get("steering-mode")                                        #Reads steering mode from policy. Default is "failover"
        candidates = []

        if steering_mode == "failover":
            failover_link_type = policy.get("failover-link-type")                          #If mode is failover, read whether policy uses tunnels or WAN links.

            if failover_link_type == "tunnel":
                ordered_names = []
                primary = policy.get("primary-tunnel")
                if primary:
                    ordered_names.append(primary)                                          #If a primary tunnel exists, add it first
                ordered_names.extend(policy.get("secondary-tunnel", []))                   #Then append all secondary tunnels.

                for name in ordered_names:
                    state = tunnel_state_map.get(name)
                    if state:
                        candidates.append(("tunnel", name, state))                         #For each configured tunnel name, look up its state and add it as candidate.

            elif failover_link_type == "wan-link":
                ordered_names = []
                primary = policy.get("primary-wan-link")
                if primary:
                    ordered_names.append(primary)                                          #If a primary wan link exists, add it first
                ordered_names.extend(policy.get("secondary-wan-link", []))                 #Then append all secondary wan links

                for name in ordered_names:
                    state = wan_state_map.get(name)
                    if state:
                        candidates.append(("wan-link", name, state))                       #For each configured wan link, look up its state and add it as candidate

        elif steering_mode == "load-balance":
            lb_type = policy.get("load-balance-link-type")                                 #If mode is load-balance, read whether balancing uses tunnels or WAN links.

            if lb_type == "tunnel":
                for name in policy.get("load-balance-tunnel", []):
                    state = tunnel_state_map.get(name)
                    if state:
                        candidates.append(("tunnel", name, state))                         #adds configured tunnels as load-balance candidates.

            elif lb_type == "wan-link":
                for name in policy.get("load-balance-wan-link", []):
                    state = wan_state_map.get(name)
                    if state:
                        candidates.append(("wan-link", name, state))                       #adds configured WAN links as load-balance candidates

        return candidates                                                                  #returns the final candidate list.

    def _make_steering_decisions(self, current_config, wan_link_states, tunnel_states):
        decisions = []                                                                      #Creates an empty list for steering decisions.

        steering_policies = current_config.get("policy", {}).get("steering", [])            #Reads steering policies from config.

        wan_state_map = self._index_states_by_name(wan_link_states)                         #Converts state lists into dictionaries for fast lookup by name
        tunnel_state_map = self._index_states_by_name(tunnel_states)                        #Converts state lists into dictionaries for fast lookup by name

        for policy in steering_policies:                                                    #Loops through each steering policy.
            traffic_class = policy.get("class")                                             #Reads traffic class associated with this policy.
            if not traffic_class:
                continue                                                                    #Skip if missing

            steering_mode = policy.get("steering-mode")                                     #Reads steering mode
            candidates = self._extract_candidate_states(policy, wan_state_map, tunnel_state_map) #Builds the list of candidate paths according to this policy.

            eligible = []                                                                   #Creates lists for accepted and rejected candidates
            rejected = []

            for link_type, name, state in candidates:                                       #Loops through each candidate.
                if self._candidate_satisfies_slo(state, policy):
                    eligible.append((link_type, name, state))                               #If candidate passes SLO checks, put it in eligible
                else:
                    rejected.append({                                                       #If candidate fails, add summary info into rejected
                        "name": name,
                        "link-type": link_type,
                        "oper-status": state.get("oper-status"),
                        "latency-ms": state.get("latency-ms"),
                        "jitter-ms": state.get("jitter-ms"),
                        "loss-percent": state.get("loss-percent"),
                        "available-bandwidth-kbps": state.get("available-bandwidth-kbps")})

            now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())                     #Creates current UTC timestamp in ISO-like format.

            if steering_mode == "failover":                                                 #Enter failover logic.
                if eligible:                                                                #If at least one candidate satisfies the SLO
                    selected_link_type, selected_name, selected_state = eligible[0]          #Choose the first eligible candidate.

                    if candidates and selected_name == candidates[0][1]:
                        reason = "primary path satisfies SLO"
                    else:
                        reason = "primary path failed SLO; failed over to next eligible path"

                    decision = {
                        "action": "set-active-path",
                        "traffic-class": traffic_class,
                        "selected-path": selected_name,
                        "selected-path-type": selected_link_type,
                        "decision-status": "selected",
                        "reason": reason,
                        "last-change": now_ts,
                        "candidate-summary": {
                            "eligible": [item[1] for item in eligible],
                            "rejected": rejected}}
                else:                                                                       #If no candidate is eligible, creates a no-path decision.
                    decision = {
                        "action": "set-active-path",
                        "traffic-class": traffic_class,
                        "selected-path": None,
                        "selected-path-type": policy.get("failover-link-type"),
                        "decision-status": "no-path",
                        "reason": "no candidate satisfies SLO or candidates are down",
                        "last-change": now_ts,
                        "candidate-summary": {
                            "eligible": [],
                            "rejected": rejected}}

                decisions.append(decision)

            elif steering_mode == "load-balance":                                          #Enter load-balance logic
                if eligible:                                                                #If some candidates satisfy SLO:
                    eligible_names = [item[1] for item in eligible]

                    decision = {                                                            #Creates load-balance decision listing all selected paths
                        "action": "set-load-balance-policy",
                        "traffic-class": traffic_class,
                        "eligible-paths": eligible_names,
                        "selected-path-type": policy.get("load-balance-link-type"),
                        "decision-status": "selected",
                        "reason": "Candidates satisfying SLO for Load-Balance",
                        "last-change": now_ts,
                        "candidate-summary": {
                            "eligible": eligible_names,
                            "rejected": rejected}}
                else:                                                                       #If none are eligible, create a no-path load-balance decision.
                    decision = {
                        "action": "set-load-balance-policy",
                        "traffic-class": traffic_class,
                        "eligible-paths": [],
                        "selected-path-type": policy.get("load-balance-link-type"),
                        "decision-status": "no-path",
                        "reason": "no load-balance candidate satisfies SLO or candidates are down",
                        "last-change": now_ts,
                        "candidate-summary": {
                            "eligible": [],
                            "rejected": rejected}}

                decisions.append(decision)

        return decisions                                                                     #returns all steering decisions.

    def _build_steering_operations(self, steering_decisions):
        operations = []

        for decision in steering_decisions:
            traffic_class = decision.get("traffic-class")
            action = decision.get("action")

            if not traffic_class:
                continue

            if action == "set-active-path":
                payload = {
                    "traffic_class": traffic_class,
                    "selected_path": decision.get("selected-path"),
                    "selected_path_type": decision.get("selected-path-type"),
                    "decision_status": decision.get("decision-status"),
                    "reason": decision.get("reason"),
                    "candidate_summary": decision.get("candidate-summary", {})
                }

                operations.append(
                    self._operation(
                        "PUT",
                        f"/api/v1/steering/{traffic_class}/active-path",
                        payload
                    )
                )

            elif action == "set-load-balance-policy":
                payload = {
                    "traffic_class": traffic_class,
                    "eligible_paths": decision.get("eligible-paths", []),
                    "selected_path_type": decision.get("selected-path-type"),
                    "decision_status": decision.get("decision-status"),
                    "reason": decision.get("reason"),
                    "candidate_summary": decision.get("candidate-summary", {})
                }

                operations.append(
                    self._operation(
                        "PUT",
                        f"/api/v1/steering/{traffic_class}/load-balance",
                        payload
                    )
                )

        return operations
    # =====================================================================================
    # Main cycle
    # =====================================================================================
    def run_once(self):
        current_config = self.config_reader.get_intended_config()

        if not hasattr(self, "metric_reader"):
            logging.warning("metric_reader not configured")
            return {"status": "skipped", "reason": "metric_reader not configured"}

        wan_links = current_config.get("interfaces", {}).get("underlay", {}).get("wan-link", [])
        tunnels = current_config.get("overlay", {}).get("tunnel", [])

        wan_link_states = []                                                                #Builds WAN operational states.
        for wan_link in self._as_list(wan_links):
            name = wan_link.get("name")
            metric = self.metric_reader.get_wan_link_metric(name)

            wan_link_states.append({
                "name": name,
                "oper-status": "down" if metric.get("stale") else "up",
                "latency-ms": metric.get("latency_ms"),
                "jitter-ms": metric.get("jitter_ms"),
                "loss-percent": metric.get("loss_percent"),
                "available-bandwidth-kbps": metric.get("available_bandwidth_kbps")})

        tunnel_states = []                                                                  #Builds tunnel operational states.
        for tunnel in self._as_list(tunnels):
            name = tunnel.get("name")
            metric = self.metric_reader.get_tunnel_metric(name)

            tunnel_states.append({
                "name": name,
                "oper-status": "down" if metric.get("stale") else "up",
                "active-wan-link": tunnel.get("bind-wan-link"),
                "latency-ms": metric.get("latency_ms"),
                "jitter-ms": metric.get("jitter_ms"),
                "loss-percent": metric.get("loss_percent"),
                "available-bandwidth-kbps": metric.get("available_bandwidth_kbps")})

        steering_decisions = self._make_steering_decisions(current_config, wan_link_states, tunnel_states) #Makes steering decisions using current states and policies

        steering_operations = self._build_steering_operations(steering_decisions)

        if steering_operations:
            self._send_forwarder_transaction(
                operations=steering_operations,
                validate_only=False)
            
        result = {                                                                                         #Build final result object
            #"wan_link_states": wan_link_states,        #REMOVE COMMENT IF NEED TO TEST
            #"tunnel_states": tunnel_states,            #REMOVE COMMENT IF NEED TO TEST
            "decisions": steering_decisions}

        logging.info("Agent runtime steering cycle completed")                                            #Builds a summary dictionary of everything done in a cycle.
        print("\n===== STEERING DECISIONS =====")
        print(json.dumps(result, indent=2))                                                               #Logs success message.

        return result

    def run_forever(self, interval_sec=5):                                                                # Repeat the full execution cycle continuously.
        while True:
            try:
                self.run_once()
            except Exception as e:
                logging.exception("Agent loop failed: %s", e)

            time.sleep(interval_sec)

    def run_clixon_callback_server(self, host="0.0.0.0", port=8080):
        ClixonCallbackHandler.agent = self

        server = HTTPServer((host, port), ClixonCallbackHandler)                            #creates the small HTTP server used by Clixon callback plugin

        logging.info("Starting Clixon callback server on %s:%s", host, port)
        server.serve_forever()

class ClixonCallbackHandler(BaseHTTPRequestHandler):
    agent = None

    def do_POST(self):
        try:
            if self.path not in [
                "/internal/clixon/validate-config-change",
                "/internal/clixon/commit-config-change"]:

                self.send_response(404)
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", 0))                           #number of bytes in the Clixon callback request body
            body = self.rfile.read(length).decode("utf-8")                                #reads the XML callback body as text

            print("\n===== RAW CLIXON CALLBACK XML =====")                                #JUST TO VERIFY. CAN REMOVE THIS LINE LATER
            print(body)

            result = self.agent.handle_clixon_transaction(body)                            #passes the XML transaction to the main agent logic

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))

        except Exception as e:
            logging.exception("Clixon callback handling failed: %s", e)

            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "reason": str(e)}).encode("utf-8"))

    def log_message(self, format, *args):
        return

# =====================================================================================
# Temporary fake metric reader for testing agent.py before real metric_reader.py is ready
# =====================================================================================
class FakeMetricReader:
    def get_wan_link_metric(self, name):
        if name == "UPL1":
            return {
                "latency_ms": 10,
                "jitter_ms": 1,
                "loss_percent": 0,
                "available_bandwidth_kbps": 100000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for UPL1"}

        if name == "UPL2":
            return {
                "latency_ms": 40,
                "jitter_ms": 5,
                "loss_percent": 1,
                "available_bandwidth_kbps": 50000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for UPL2"}

        if name == "UPL3":
            return {
                "latency_ms": 40,
                "jitter_ms": 5,
                "loss_percent": 1,
                "available_bandwidth_kbps": 50000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for UPL3"}

        return {
            "latency_ms": None,
            "jitter_ms": None,
            "loss_percent": None,
            "available_bandwidth_kbps": None,
            "timestamp": "test",
            "stale": True,
            "source": "fake",
            "reason": "unknown WAN link"}

    def get_tunnel_metric(self, name):
        if name == "wg01":
            return {
                "latency_ms": 105,
                "jitter_ms": 2,
                "loss_percent": 0,
                "available_bandwidth_kbps": 50000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for wg01"}

        if name == "wg02":
            return {
                "latency_ms": 30,
                "jitter_ms": 3,
                "loss_percent": 0,
                "available_bandwidth_kbps": 70000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for wg02"}

        if name == "wg03":
            return {
                "latency_ms": 30,
                "jitter_ms": 3,
                "loss_percent": 0,
                "available_bandwidth_kbps": 70000,
                "timestamp": "test",
                "stale": False,
                "source": "fake",
                "reason": "fake metric for wg03"}

        return {
            "latency_ms": None,
            "jitter_ms": None,
            "loss_percent": None,
            "available_bandwidth_kbps": None,
            "timestamp": "test",
            "stale": True,
            "source": "fake",
            "reason": "unknown tunnel"}

if __name__ == "__main__":
    agent = Agent()
    agent.metric_reader = FakeMetricReader()                  # Temporary fake metric reader for testing agent.py before real metric_reader.py is ready

    steering_thread = threading.Thread(
        target=agent.run_steering_loop_after_restconf_ready,
        kwargs={"interval_sec": 10},
        daemon=True
    )
    steering_thread.start()                                   # Run steering loop in background after RESTCONF is ready
    
    agent.run_clixon_callback_server()                        # Start internal API used by Clixon callback plugin.
