#!/usr/bin/env python3
# coding: utf-8

import copy
import json
import logging
import requests    #HTTP library used to send RESTCONF requests to the forwarder container.

logging.basicConfig(level=logging.INFO)

class SteeringManager:

    def __init__(self):
        self.base_url = "http://forwarder:9090"
        self.timeout = 5                                  #if the forwarder does not respond within 5 seconds, the request will fail.
        self.headers = {
            "Content-Type": "application/yang-data+json", #tells forwarder that the requests are sending in YANG JSON format. 
            "Accept": "application/yang-data+json",       #tells the forwarder to reply in YANG JSON format.
        }
        
    # ============================================================
    # Public entry point
    # ============================================================

    def execute_decision(self, action):                  #main method that agent.py calls.

        action_type = action.get("action")               #reads the "action" field from the incoming action dictionary from "agent.py"

        try:                                             #check the action type and call the correct internal handler.
            if action_type == "apply-wan-link-config":   
                return self._apply_wan_link_config(action)

            if action_type == "apply-lan-link-config":
                return self._apply_lan_link_config(action)

            if action_type == "apply-tunnel-config":
                return self._apply_tunnel_config(action)

            if action_type == "apply-firewall-rule":
                return self._apply_firewall_rule(action)

            if action_type == "install-traffic-class":
                return self._install_traffic_class(action)

            if action_type == "set-active-path":
                return self._set_active_path(action)

            if action_type == "set-load-balance-policy":
                return self._set_load_balance_policy(action)

            return self._result_error(                  # If none of the known action types match, return an error dictionary.
                action=action,
                reason=f"Unsupported action: {action_type}",
            )

        except Exception as e:                          # If any unexpected Python error happens in the try block, execution jumps here.
            logging.exception("Action execution failed for %s: %s", action_type, e)
            return self._result_error(
                action=action,
                reason=str(e),
            )

    # ============================================================
    # Action handlers
    # ============================================================

    def _apply_wan_link_config(self, action):
        name = action.get("name")                                                    # reads the WAN link name from the action dictionary.
        params = copy.deepcopy(action.get("parameters", {}))                         # reads the "parameters" dictionary from the action and makes a deep copy of it.

        if not name:
            return self._result_error(action, "WAN link name is missing")            # If name is empty or missing, return an error immediately.

        url = f"{self.base_url}/restconf/data/forwarder:wan-links/wan-link={name}"   # Builds the RESTCONF URL for this WAN link.

        address_mode = params.get("address-mode")
        
        payload = {                                                                  # Builds the JSON payload to send.
            "action": "configure-wan-link",
            "name": name,
            "target-type": "wan-link",
            "wan-link": {
                "name": name,
                "interface-name": params.get("interface-name"),
                "role": params.get("role"),
                "admin-enabled": params.get("admin-enabled"),
                "address-mode": address_mode,
                "nat-enabled": params.get("nat-enabled"),
            },
        }                                
        if address_mode == "static":
            payload["wan-link"]["static-address"] = params.get("static-address")
            payload["wan-link"]["static-gateway"] = params.get("static-gateway")
    
        elif address_mode == "dhcp":
            payload["wan-link"]["dhcp-enabled"] = True
    
        return self._patch(url, payload, action)
        

    def _apply_lan_link_config(self, action):                                        # Handles LAN link configuration.
        name = action.get("name")
        params = copy.deepcopy(action.get("parameters", {}))
        dhcp = copy.deepcopy(params.get("dhcp-server", {}))

        if not name:
            return self._result_error(action, "LAN link name is missing")           # checks that LAN name exists.

        url = f"{self.base_url}/restconf/data/forwarder:lan-links/lan-link={name}"  # Builds the LAN RESTCONF URL.
        
        payload = {                                                                 # Builds the JSON payload to send.
            "action": "configure-lan-link",
            "name": name,
            "target-type": "lan-link",
            "lan-link": {
                "name": name,
                "admin-enabled": params.get("admin-enabled"),
                "ipv4-prefix": params.get("ipv4-prefix"),
                "dhcp-server": {
                    "enabled": dhcp.get("enabled"),
                    "pool-start": dhcp.get("pool-start"),
                    "pool-end": dhcp.get("pool-end"),
                    "dns-server": dhcp.get("dns-server"),
                    "lease-time-seconds": dhcp.get("lease-time-seconds"),
                },
            },        
        }

        return self._patch(url, payload, action)

    def _apply_tunnel_config(self, action):                                        # handles LAN link configuration
        name = action.get("name")
        params = copy.deepcopy(action.get("parameters", {}))

        if not name:
            return self._result_error(action, "Tunnel name is missing")            # checks that LAN name exists.

        url = f"{self.base_url}/restconf/data/forwarder:tunnels/tunnel={name}"     # Builds the Tunnel RESTCONF URL.
        payload = {
            "action": "configure-wireguard-tunnel",
            "name": name,
            "target-type": "tunnel",
            "tunnel": {
                "name": name,
                "bind-wan-link": params.get("bind-wan-link"),
                "admin-enabled": params.get("admin-enabled"),
                "local-address": params.get("local-address"),
                "local-port": params.get("local-port"),
                "local-private-key": params.get("local-private-key"),
                "local-public-key": params.get("local-public-key"),
                "peer-address": params.get("peer-address"),
                "peer-port": params.get("peer-port"),
                "peer-public-key": params.get("peer-public-key"),
                "allowed-prefix": params.get("allowed-prefix", []),
                "keepalive-seconds": params.get("keepalive-seconds"),
            },  
            
        }

        return self._patch(url, payload, action)

    def _apply_firewall_rule(self, action):                                        # Handles firewall configuration.
        rule_id = action.get("name")
        params = copy.deepcopy(action.get("parameters", {}))

        if rule_id is None:
            return self._result_error(action, "Firewall rule id is missing")

        url = f"{self.base_url}/restconf/data/forwarder:firewall/rule={rule_id}"
        payload = {
            "action": "apply-firewall-rule",
            "target-type": "firewall-rule",
            "rule": {
                "id": rule_id,
                "action": params.get("action"),
                "src-prefix": params.get("src-prefix"),
                "dst-prefix": params.get("dst-prefix"),
                "l4-protocol": params.get("l4-protocol"),
                "src-port": params.get("src-port"),
                "dst-port": params.get("dst-port"),
                "log": params.get("log"),
            },
        }

        return self._patch(url, payload, action)

    def _install_traffic_class(self, action):
        traffic_class = action.get("traffic-class")
        fwmark = action.get("fwmark")
        match = copy.deepcopy(action.get("match", {}))

        if not traffic_class:
            return self._result_error(action, "Traffic class is missing")
        if fwmark is None:
            return self._result_error(action, "fwmark is missing")

        url = f"{self.base_url}/restconf/data/forwarder:traffic-classes/classifier={traffic_class}"
        payload = {
            "action": "install-traffic-classifier",
            "target-type": "traffic-class",
            "class": {
                "name": traffic_class,
                "fwmark": fwmark,
                "five-tuple": {
                    "src-prefix": match.get("src-prefix"),
                    "dst-prefix": match.get("dst-prefix"),
                    "l4-protocol": match.get("l4-protocol"),
                    "src-port": match.get("src-port"),
                    "dst-port": match.get("dst-port"),
                },
            },
            "marking-mode": action.get("marking-mode"),
            "default-unmatched-fwmark": action.get("default-unmatched-fwmark"),
        }

        return self._patch(url, payload, action)

    def _set_active_path(self, action):

        traffic_class = action.get("traffic-class")

        if not traffic_class:
            return self._result_error(action, "Traffic class is missing")

        url = f"{self.base_url}/restconf/data/forwarder:steering/active-path={traffic_class}"

        payload = {
            "action": "set-active-path",
            "target-type": "steering",
            "steering": {
                "class": traffic_class,
                "selected-path": action.get("selected-path"),
                "selected-path-type": action.get("selected-path-type"),
                "decision-status": action.get("decision-status"),
                "reason": action.get("reason"),
                "last-change": action.get("last-change"),
                "slo-policy": action.get("slo-policy"),
                "candidate-summary": action.get("candidate-summary"),
                "selected-state": action.get("selected-state"),
            },
        }

        return self._patch(url, payload, action)

    def _set_load_balance_policy(self, action):
        
        traffic_class = action.get("traffic-class")
        selected_paths = action.get("selected-path", [])

        if not traffic_class:
            return self._result_error(action, "Traffic class is missing")

        if not isinstance(selected_paths, list):
            return self._result_error(action, "selected-path must be a list")

        url = f"{self.base_url}/restconf/data/forwarder:steering/load-balance={traffic_class}"

        payload = {
            "action": "set-load-balance-policy",
            "target-type": "steering",
            "steering": {
                "class": traffic_class,
                "selected-path": selected_paths,
                "selected-path-type": action.get("selected-path-type"),
                "decision-status": action.get("decision-status"),
                "reason": action.get("reason"),
                "last-change": action.get("last-change"),
                "slo-policy": action.get("slo-policy"),
                "candidate-summary": action.get("candidate-summary"),
            },
        }

        return self._patch(url, payload, action)

    # ============================================================
    # REST helper
    # ============================================================

    def _patch(self, url: str, payload, action):

        logging.info("PATCH %s", url)
        logging.info("Payload: %s", json.dumps(payload, indent=2))

        response = requests.patch(
            url,
            headers=self.headers,
            data=json.dumps(payload),
            timeout=self.timeout,
        )

        try:
            response_body = response.json() if response.text else None
        except Exception:
            response_body = response.text if response.text else None

        if 200 <= response.status_code < 300:
            return {
                "status": "success",
                "action": action.get("action"),
                "target": action.get("name") or action.get("traffic-class"),
                "http-status": response.status_code,
                "response": response_body,
            }

        return {
            "status": "error",
            "action": action.get("action"),
            "target": action.get("name") or action.get("traffic-class"),
            "http-status": response.status_code,
            "response": response_body,
        }

    # ============================================================
    # Result helpers
    # ============================================================

    def _result_error(self, action, reason: str):
        return {
            "status": "error",
            "action": action.get("action"),
            "target": action.get("name") or action.get("traffic-class"),
            "reason": reason,
        }
