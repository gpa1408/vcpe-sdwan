#!/usr/bin/env python3
# coding: utf-8

import copy                                                                        #to make copied versions of dictionaries/lists so the original config objects are not modified by mistake
import json                                                                        #converting Python objects into JSON strings
import logging                                                                     #to print info and error logs.
import time
import requests
import os
import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from config_reader import ConfigReader
#from metric_reader import MetricReader                  #REMOVE COMMENT 
#from state_writer import StateWriter                    #REMOVE COMMENT 
from steering_manager import SteeringManager            
#from monitoring_manager import MonitoringManager        #REMOVE COMMENT 

logging.basicConfig(level=logging.INFO)                                            # to show info messages and errors 

class Agent:
    def __init__(self):                                                            #Creates object for each python module and stores it inside the agent       
        self.config_reader = ConfigReader()
        #self.metric_reader = MetricReader()              #REMOVE COMMENT                                
        #self.state_writer = StateWriter()                #REMOVE COMMENT 
        self.steering_manager = SteeringManager()        
        #self.monitoring_manager = MonitoringManager()    #REMOVE COMMENT 
        self.generated_tunnel_keys = {}

    # =====================================================================================
    # Basic helpers
    # =====================================================================================
    def _allocate_fwmark(self, class_name, index):  #called by "_make_steering_decisions()"
        # Agent-assigned fwmark for a traffic class.
        return 1000 + index

    def _index_states_by_name(self, states):                                                 #called by "_make_steering_decisions()"
        indexed = {}
        for item in states:                                                                  #Loops through each state item in the list
            name = item.get("name")                                                          #Reads the name field from the state dictionary
            if name:
                indexed[name] = item                                                         #If the state has a name, store that item in the dictionary using the name as key
        return indexed

    def _generate_wireguard_tunnel_keys(self, tunnel_name):                                 # generate and save WireGuard tunnel keys uding curve25519
        private_dir = "/var/lib/sdwan-cpe/keys"
        public_dir = "/var/lib/clixon/local-public-keys"
    
        private_path = f"{private_dir}/{tunnel_name}.private"
        public_path = f"{public_dir}/{tunnel_name}.pub"
    
        try:
            if os.path.exists(private_path) and os.path.exists(public_path):
                with open(private_path, "r") as f:
                    private_key = f.read().strip()
    
                with open(public_path, "r") as f:
                    public_key = f.read().strip()
    
                return private_key, public_key
    
            private_key_obj = X25519PrivateKey.generate()
            public_key_obj = private_key_obj.public_key()
    
            private_key_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
    
            public_key_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
    
            private_key = base64.b64encode(private_key_bytes).decode("ascii")
            public_key = base64.b64encode(public_key_bytes).decode("ascii")
    
            os.makedirs(private_dir, exist_ok=True)
            os.makedirs(public_dir, exist_ok=True)
    
            with open(private_path, "w") as f:
                f.write(private_key)
            os.chmod(private_path, 0o600)
    
            with open(public_path, "w") as f:
                f.write(public_key)
            os.chmod(public_path, 0o644)
    
            logging.info("Created WireGuard keys for tunnel %s", tunnel_name)
    
            return private_key, public_key
    
        except Exception as e:
            logging.exception("Failed to get or create WireGuard keys for tunnel %s: %s", tunnel_name, e)
            return None, None
            
    def _candidate_satisfies_slo(self, candidate_state, policy):
        if not candidate_state:                                                                     #If there is no state object, candidate is invalid.
            return False

        oper_status = candidate_state.get("oper-status")                                            #Reads the operational status.
        if oper_status not in ["up", "degraded"]:                                                   #Only candidates with up or degraded are accepted. Anything else is rejected
            return False

        max_latency = policy.get("max-latency-ms")                                                  #Reads max allowed latency from policy.
        if max_latency is not None:
            latency = candidate_state.get("latency-ms")                                             #Reads measured latency from state
            if latency is None or latency > max_latency:                                            #Reject if latency is missing or exceeds the threshold.
                return False

        max_jitter = policy.get("max-jitter-ms")                                                   #Reads max allowed jitter from policy.
        if max_jitter is not None:
            jitter = candidate_state.get("jitter-ms")                                              #Reads measured jitter from state
            if jitter is None or jitter > max_jitter:                                              #Reject if jitter is missing or exceeds the threshold
                return False

        max_loss = policy.get("max-loss-percent")                                                  #Reads max allowed packet loss from policy.
        max_loss = float(max_loss)
        if max_loss is not None:
            loss = candidate_state.get("loss-percent")                                             #Reads measured packet loss from state
            if loss is None or loss > max_loss:                                                    #Reject if packet loss is missing or exceeds the threshold
                return False

        min_bw = policy.get("min-bandwidth-kbps")                                                  #Reads min allowed BW from policy.
        if min_bw is not None:
            bw = candidate_state.get("available-bandwidth-kbps")                                   #Reads available BW from state
            if bw is None or bw < min_bw:                                                          #Reject if BW is missing or less than the threshold
                return False
        return True                                                                                #If all checks pass, candidate satisfies the SLO

    def _extract_candidate_states(self, policy, wan_state_map, tunnel_state_map):                  #Return candidate type and candidate state objects according to policy.
        steering_mode = policy.get("steering-mode")                                                #Reads steering mode from policy. Default is "failover"
        candidates = []

        if steering_mode == "failover": 
            failover_link_type = policy.get("failover-link-type")                                  #If mode is failover, read whether policy uses tunnels or WAN links.

            if failover_link_type == "tunnel":
                ordered_names = []
                primary = policy.get("primary-tunnel")
                if primary:
                    ordered_names.append(primary)                                                 #If a primary tunnel exists, add it first
                ordered_names.extend(policy.get("secondary-tunnel", []))                          #Then append all secondary tunnels.

                for name in ordered_names:
                    state = tunnel_state_map.get(name)
                    if state:
                        candidates.append(("tunnel", name, state))                               #For each configured tunnel name, look up its state and add it as candidate.

            elif failover_link_type == "wan-link":                       
                ordered_names = []
                primary = policy.get("primary-wan-link")
                if primary:
                    ordered_names.append(primary)                                         #If a primary wan link exists, add it first
                ordered_names.extend(policy.get("secondary-wan-link", []))                #Then append all secondary wan links

                for name in ordered_names:
                    state = wan_state_map.get(name)
                    if state:
                        candidates.append(("wan-link", name, state))                      #For each configured wan link, look up its state and add it as candidate

        elif steering_mode == "load-balance":
            lb_type = policy.get("load-balance-link-type")                                #If mode is load-balance, read whether balancing uses tunnels or WAN links.

            if lb_type == "tunnel":
                for name in policy.get("load-balance-tunnel", []):
                    state = tunnel_state_map.get(name)
                    if state:
                        candidates.append(("tunnel", name, state))                       #adds configured tunnels as load-balance candidates.

            elif lb_type == "wan-link":
                for name in policy.get("load-balance-wan-link", []):
                    state = wan_state_map.get(name)
                    if state:
                        candidates.append(("wan-link", name, state))                     #adds configured WAN links as load-balance candidates
        return candidates                                                                #returns the final candidate list.

    # =====================================================================================
    # State building
    # =====================================================================================
    def _build_wan_link_states(self, wan_links):
        wan_link_states = []

        for wan_link in wan_links:                                             #Loops over each WAN link from configuration.
            name = wan_link.get("name")
            if not name:
                continue                                                       #Reads WAN-link name.If missing, skip that entry.

            metric = self.metric_reader.get_wan_link_metric(name)              #Gets current metrics for this WAN link using metric_reader.

            if wan_link.get("admin-enabled") == False: 
                oper_status = "down"
                reason = "wan link admin-disabled"                 #If config says WAN link is administratively disabled, state is down
            elif metric["stale"]:
                oper_status = "down"                               #If metric data is stale, state is down.
                reason = metric["reason"]
            else:
                oper_status = "up"
                reason = metric["reason"]
            state = {                                             #Builds one state dictionary for each WAN link
                "name": name,
                "oper-status": oper_status,
                "latency-ms": metric["latency_ms"] if metric["latency_ms"] is not None else None,
                "jitter-ms": metric["jitter_ms"] if metric["jitter_ms"] is not None else None,
                "loss-percent": metric["loss_percent"] if metric["loss_percent"] is not None else None,
                "available-bandwidth-kbps": metric["available_bandwidth_kbps"] if metric["available_bandwidth_kbps"] is not None else None,
                "last-updated": metric["timestamp"] if metric["timestamp"] is not None else None,
                "metrics-stale": metric["stale"] if metric["stale"] is not None else None,
                "metric-source": metric["source"] if metric["source"] is not None else None,
                "state-reason": reason,
            }
            wan_link_states.append(state)                         #Adds the state to the result list.
        return wan_link_states

    def _build_tunnel_states(self, tunnels):
        tunnel_states = []

        for tunnel in tunnels:
            name = tunnel.get("name")                             #Loops over each tunnel from configuration.
            if not name:
                continue                                          #Reads tunnel name.If missing, skip that entry.

            metric = self.metric_reader.get_tunnel_metric(name)   #Gets current metrics for this WAN link using metric_reader.

            if tunnel.get("admin-enabled") == False:
                oper_status = "down"                              #If config says tunnel is administratively disabled, state is down
                reason = "tunnel admin-disabled"
            elif metric["stale"]:                                 #If metric data is stale, state is down.
                oper_status = "down"
                reason = metric["reason"]
            else:
                oper_status = "up"
                reason = metric["reason"]
            state = {                                             #Builds one state dictionary for each tunnel
                "name": name,
                "oper-status": oper_status,
                "active-wan-link": tunnel.get("bind-wan-link"),
                "latency-ms": metric["latency_ms"] if metric["latency_ms"] is not None else None,
                "jitter-ms": metric["jitter_ms"] if metric["jitter_ms"] is not None else None,
                "loss-percent": metric["loss_percent"] if metric["loss_percent"] is not None else None,
                "available-bandwidth-kbps": metric["available_bandwidth_kbps"] if metric["available_bandwidth_kbps"] is not None else None,
                "last-updated": metric["timestamp"] if metric["timestamp"] is not None else None,
                "metrics-stale": metric["stale"] if metric["stale"] is not None else None,
                "metric-source": metric["source"] if metric["source"] is not None else None,
                "state-reason": reason,
            }
            tunnel_states.append(state)
        return tunnel_states

    # =====================================================================================
    # Config apply actions
    # =====================================================================================
    
    def _build_interface_apply_actions(self, sdwan_root, changed):                               #Build execution actions for WAN, LAN and tunnels,when config changes. 
        if not changed:                                                                          #If config did not change, do nothing and return empty list.
            return []

        interface_actions = []                                                                   #Creates empty action list.

        wan_links = sdwan_root.get("interfaces", {}).get("underlay", {}).get("wan-link", [])     #Reads WAN-link list from config.
        for wan_link in wan_links:                                                               #Loops through WAN links.
            nat_check_required = wan_link.get("role") != "ipvpn"
            
            interface_actions.append({
                "action": "apply-wan-link-config",                                               #Adds one action per WAN link telling the executor to apply its config.
                "name": wan_link.get("name"),
                "parameters": copy.deepcopy(wan_link),
                "nat-check-required": nat_check_required,   })

        lan_links = sdwan_root.get("interfaces", {}).get("lan", {}).get("lan-link", [])          #Reads LAN links from config.
        for lan_link in lan_links:
            lan_params = copy.deepcopy(lan_link)
            dhcp_cfg = lan_params.get("dhcp-server", {})
            effective_dhcp_enabled = bool(lan_params.get("admin-enabled")) and bool(dhcp_cfg.get("enabled"))

            if "dhcp-server" not in lan_params:
                lan_params["dhcp-server"] = {}
        
            lan_params["dhcp-server"]["enabled"] = effective_dhcp_enabled

            interface_actions.append({                                                           #Adds one action per LAN link telling the executor to apply its config.
                "action": "apply-lan-link-config",
                "name": lan_link.get("name"),
                "parameters": lan_params,    })

        tunnels = sdwan_root.get("overlay", {}).get("tunnel", [])                               #Reads tunnel list.
        
        for tunnel in tunnels:
            tunnel_params = copy.deepcopy(tunnel)
            tunnel_name = tunnel.get("name")

            if tunnel_name not in self.generated_tunnel_keys:
                private_key, public_key = self._generate_wireguard_tunnel_keys(tunnel_name)

                if private_key and public_key:
                    self.generated_tunnel_keys[tunnel_name] = {
                        "private-key": private_key,
                        "public-key": public_key,
                    }
            tunnel_params.update(self.generated_tunnel_keys.get(tunnel_name, {}))

            interface_actions.append({                                                        #Adds one action per tunne, telling the executor to apply its config.
                "action": "apply-tunnel-config",
                "name": tunnel_name,
                "parameters": tunnel_params,
            })
        return interface_actions                                                           #Returns all config-apply actions.

    def _build_firewall_apply_actions(self, sdwan_root, changed):
        if not changed:                                                                     #If config did not change, do nothing and return empty list.
            return []

        firewall_actions = []                                                               #Creates empty action list.
        firewall_rules = sdwan_root.get("firewall", {}).get("rule", [])                     #Reads firewall rules from config
        for rule in firewall_rules:
            firewall_actions.append({                                                       #Adds one action per firewall rule.
                "action": "apply-firewall-rule",               
                "name": rule.get("id"),
                "parameters": copy.deepcopy(rule),
            })
        return firewall_actions
            
    # =====================================================================================
    # Traffic classification actions
    # =====================================================================================

    def _build_classifier_actions(self, sdwan_root, changed):
        if not changed:                                                                    #If config did not change, no need to rebuild classifier actions.
            return [] 

        classifier_actions = []                                                            #Creates empty action list.
        traffic_classes = sdwan_root.get("traffic", {}).get("class", [])                   #Reads configured traffic classes.

        for idx, traffic_class in enumerate(traffic_classes, start=1):                     #Loops through traffic classes and also gives each one an index starting from 1.
            class_name = traffic_class.get("name")
            five_tuple = traffic_class.get("five-tuple", {})                               #Reads class name and its five-tuple match fields.

            if not class_name:         
                continue                                                                   #Skip if class has no name

            fwmark = self._allocate_fwmark(class_name, idx)                                #Alocates an fwmark for this traffic class.

            classifier_actions.append({
                "action": "install-traffic-class",                                         #tells executor to install the classifier
                "target-type": "traffic-class",
                "traffic-class": class_name,
                "fwmark": fwmark,                                                          #the mark to apply
                "marking-mode": "mark-on-match-only",
                "default-unmatched-fwmark": 0,
                "match": {                                                                 #contains matching criteria
                    "src-prefix": five_tuple.get("src-prefix"),
                    "dst-prefix": five_tuple.get("dst-prefix"),
                    "l4-protocol": five_tuple.get("l4-protocol"),
                    "src-port": five_tuple.get("src-port"),
                    "dst-port": five_tuple.get("dst-port"),
                },
                "parameters": copy.deepcopy(traffic_class),                                #full copied config
            })
        return classifier_actions

    # =====================================================================================
    # Steering decisions
    # =====================================================================================

    def _make_steering_decisions(self, current_config, wan_link_states, tunnel_states):
        decisions = []                                                                                    #Creates an empty list for steering decisions.

        sdwan_root = current_config                                                                       #Stores config in a shorter variable name
        steering_policies = sdwan_root.get("policy", {}).get("steering", [])                              #Reads steering policies from config.

        wan_state_map = self._index_states_by_name(wan_link_states)                                       #Converts state lists into dictionaries for fast lookup by name
        tunnel_state_map = self._index_states_by_name(tunnel_states)                                      #Converts state lists into dictionaries for fast lookup by name

        for policy in steering_policies:                                                                  #Loops through each steering policy.
            traffic_class = policy.get("class")                                                           #Reads traffic class associated with this policy. 
            if not traffic_class:
                continue                                                                                 #Skip if missing

            steering_mode = policy.get("steering-mode",)                                                 #Reads steering mode
            candidates = self._extract_candidate_states(policy, wan_state_map, tunnel_state_map)         #Builds the list of candidate paths according to this policy.

            eligible = []                                                                                #Creates lists for accepted and rejected candidates                                 
            rejected = []

            for link_type, name, state in candidates:                                                    #Loops through each candidate.
                if self._candidate_satisfies_slo(state, policy):
                    eligible.append((link_type, name, state))                                            #If candidate passes SLO checks, put it in eligible
                else:
                    rejected.append({                                                                    #If candidate fails, add summary info into rejected
                        "name": name,
                        "link-type": link_type,
                        "oper-status": state.get("oper-status"),
                        "latency-ms": state.get("latency-ms"),
                        "jitter-ms": state.get("jitter-ms"),
                        "loss-percent": state.get("loss-percent"),
                        "available-bandwidth-kbps": state.get("available-bandwidth-kbps"),
                    })
            now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())                                   #Creates current UTC timestamp in ISO-like format.

            if steering_mode == "failover":                                                               #Enter failover logic.
                if eligible:                                                                              #If at least one candidate satisfies the SLO
                    selected_link_type, selected_name, selected_state = eligible[0]                       #Choose the first eligible candidate.

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
                        "slo-policy": {
                            "max-latency-ms": policy.get("max-latency-ms"),
                            "max-jitter-ms": policy.get("max-jitter-ms"),
                            "max-loss-percent": policy.get("max-loss-percent"),
                            "min-bandwidth-kbps": policy.get("min-bandwidth-kbps"),
                        },
                        "candidate-summary": {
                            "eligible": [item[1] for item in eligible],
                            "rejected": rejected,
                        },
                        "selected-state": {
                            "oper-status": selected_state.get("oper-status"),
                            "latency-ms": selected_state.get("latency-ms"),
                            "jitter-ms": selected_state.get("jitter-ms"),
                            "loss-percent": selected_state.get("loss-percent"),
                            "available-bandwidth-kbps": selected_state.get("available-bandwidth-kbps"), }  }
                else:                                                                                      #If no candidate is eligible, creates a no-path decision.
                    decision = {
                        "action": "set-active-path",
                        "traffic-class": traffic_class,
                        "selected-path": None,
                        "selected-path-type": policy.get("failover-link-type"),
                        "decision-status": "no-path",
                        "reason": "no candidate satisfies SLO or candidates are down",
                        "last-change": now_ts,
                        "slo-policy": {
                            "max-latency-ms": policy.get("max-latency-ms"),
                            "max-jitter-ms": policy.get("max-jitter-ms"),
                            "max-loss-percent": policy.get("max-loss-percent"),
                            "min-bandwidth-kbps": policy.get("min-bandwidth-kbps"),
                        },
                        "candidate-summary": {
                            "eligible": [],
                            "rejected": rejected, }, }

                decisions.append(decision)

            elif steering_mode == "load-balance":                                                           #Enter load-balance logic
                if eligible:                                                                                #If some candidates satisfy SLO:                       
                    eligible_names = [item[1] for item in eligible]

                    decision = {                                                                            #Creates load-balance decision listing all selected paths
                        "action": "set-load-balance-policy",
                        "traffic-class": traffic_class,
                        "eligible-paths": eligible_names,
                        "selected-path-type": policy.get("load-balance-link-type"),
                        "decision-status": "selected",
                        "reason": "Candidates satisfying SLO for Load-Balance",
                        "last-change": now_ts,
                        "slo-policy": {
                            "max-latency-ms": policy.get("max-latency-ms"),
                            "max-jitter-ms": policy.get("max-jitter-ms"),
                            "max-loss-percent": policy.get("max-loss-percent"),
                            "min-bandwidth-kbps": policy.get("min-bandwidth-kbps"),
                        },
                        "candidate-summary": {
                            "eligible": eligible_names,
                            "rejected": rejected,   }, }
                else:                                                                            #If none are eligible, create a no-path load-balance decision.
                    decision = {
                        "action": "set-load-balance-policy",
                        "traffic-class": traffic_class,
                        "eligible-paths": [],
                        "selected-path-type": policy.get("load-balance-link-type"),
                        "decision-status": "no-path",
                        "reason": "no load-balance candidate satisfies SLO or candidates are down",
                        "last-change": now_ts,
                        "slo-policy": {
                            "max-latency-ms": policy.get("max-latency-ms"),
                            "max-jitter-ms": policy.get("max-jitter-ms"),
                            "max-loss-percent": policy.get("max-loss-percent"),
                            "min-bandwidth-kbps": policy.get("min-bandwidth-kbps"),
                        },
                        "candidate-summary": {
                            "eligible": [],
                            "rejected": rejected,  },  }
                decisions.append(decision)
        return decisions                                                                                #returns all steering decisions.

    # =====================================================================================
    # Execution
    # =====================================================================================

    def _execute_decisions(self, decisions):                                                           #function to pass decisions/actions to the executor module (steering_manager.py)
        results = []

        for decision in decisions:                                                                    #Loops through every action/decision
            result = self.steering_manager.execute_decision(decision)                                 #Calls the executor module for that action.
            results.append(result)                                                                    #Stores returned result

        return results

    def _apply_monitoring_updates_if_needed(self, current_config, changed):                          #function to notify the monitoring manager when config changes.
        if not changed:                                                                              #If config did not change, no monitoring update is needed.
            return []

        sdwan_root = current_config                                                                  #Stores config in shorter variable.

        wan_links = sdwan_root.get("interfaces", {}).get("underlay", {}).get("wan-link", [])         #Reads configured WAN links and tunnels.
        tunnels = sdwan_root.get("overlay", {}).get("tunnel", [])

        instructions = {                                                                             #Creates one instruction dictionary for monitoring manager
            "action": "apply-monitoring-config",
            "wan-links": [],
            "tunnels": [], }

        for wan_link in wan_links:
            instructions["wan-links"].append({                                                      #Adds WAN-link info that monitoring manager may need.
                "name": wan_link.get("name"),
                "interface-name": wan_link.get("interface-name"),
                "admin-enabled": wan_link.get("admin-enabled"),
                "role": wan_link.get("role"),
                "address-mode": wan_link.get("address-mode"),
                "static-address": wan_link.get("static-address"),
                "static-gateway": wan_link.get("static-gateway"), })

        for tunnel in tunnels:
            instructions["tunnels"].append({                                                        #Adds tunnel info that monitoring manager may need.
                "name": tunnel.get("name"),
                "bind-wan-link": tunnel.get("bind-wan-link"),
                "admin-enabled": tunnel.get("admin-enabled"),
                "local-address": tunnel.get("local-address"),
                "local-port": tunnel.get("local-port"),
                "peer-address": tunnel.get("peer-address"),
                "peer-port": tunnel.get("peer-port"),  })

        return self.monitoring_manager.apply_configuration(instructions)

    # =====================================================================================
    # Main cycle
    # =====================================================================================

    def run_once(self):                                                                                     #One full execution cycle.
        current_config, changed = self.config_reader.get_config_with_change_flag()
        sdwan_root = current_config

        wan_links = sdwan_root.get("interfaces", {}).get("underlay", {}).get("wan-link", [])
        tunnels = sdwan_root.get("overlay", {}).get("tunnel", [])

        wan_link_states = self._build_wan_link_states(wan_links)                                                                  #Builds WAN operational states.
        tunnel_states = self._build_tunnel_states(tunnels)                                                                        #Builds tunnel operational states.

        interface_config_apply_actions = self._build_interface_apply_actions(sdwan_root, changed)                                 #Builds config-apply actions if interface config changed
        firewall_config_apply_actions = self._build_firewall_apply_actions(sdwan_root,changed)                                    #Builds config-apply actions if firewall config changed
        classifier_actions = self._build_classifier_actions(sdwan_root, changed)                                                  #Builds traffic classification actions if config changed.
        steering_decisions = self._make_steering_decisions(current_config, wan_link_states, tunnel_states)                        #Makes steering decisions using current states and policies

        all_actions = interface_config_apply_actions + firewall_config_apply_actions + classifier_actions + steering_decisions    #Combines all actions and decisions into one list.
        execution_results = self._execute_decisions(all_actions)                                                                  #Sends all of them to the executor module

        #nat_state = self.steering_manager.get_nat_state_from_forwarder()   #REMOVE COMMENT                                       #call steering manager to get NAT state
        #nat_store_results = []
        #nat_entries = nat_state.get("forwarder:nat-state", {}).get("wan-link", [])                                                #take one (wan_name, nat_type) pair from that returned data
        #for entry in nat_entries:
            #wan_name = entry.get("name")
            #nat_type = entry.get("nat-type")
            
            #written = self.steering_manager.store_nat_status_in_datastore(wan_name, nat_type)     #REMOVE COMMENT               #call steering manager again to store (wan_name, nat_type) pair
            #nat_store_results.append({
                #"wan-link": wan_name,
                #"nat-type": nat_type,
                #"written": written,  })

        monitoring_results = self._apply_monitoring_updates_if_needed(current_config, changed)                                    #Updates monitoring if config changed

        steering_state = []                                                                                                       #Build steering state summary         
        for decision in steering_decisions:
            steering_state.append({
                "class": decision.get("traffic-class"),
                "selected-path": decision.get("selected-path"),
                "decision-status": decision.get("decision-status"),
                "reason": decision.get("reason"),
                "last-change": decision.get("last-change")    })

        output_file = self.state_writer.write_state(                                                                             #Write state
            wan_link_states=wan_link_states,
            tunnel_states=tunnel_states,
            steering_state=steering_state
        )
        result = {                                                                                        #Build final result object
            "config_changed": changed,
            "wan_link_states": wan_link_states,
            #"nat_store_results": nat_store_results,                                                     #REMOVE COMMENT
            "tunnel_states": tunnel_states,
            "interface_config_apply_actions": interface_config_apply_actions,
            "firewall_config_apply_actions": firewall_config_apply_actions,
            "classifier_actions": classifier_actions,
            "decisions": steering_decisions,
            "execution_results": execution_results,
            "monitoring_results": monitoring_results,
            "state_file": output_file
        }

        logging.info("Agent cycle completed")                                                             #Builds a summary dictionary of everything done in this cycle.
        print(json.dumps(result, indent=2))                                                               #Logs success message.                                                               
                    
        return result

    def run_forever(self, interval_sec=5):                                                                # Repeat the full execution cycle continuously.
        while True:
            try:
                self.run_once()
            except Exception as e:
                logging.exception("Agent loop failed: %s", e)

            time.sleep(interval_sec)


#if __name__ == "__main__":
    #agent = Agent()
   # agent.run_once()

if __name__ == "__main__":
    agent = Agent()

    # Temporary fake metric reader for testing agent.py before real metric_reader.py is ready
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
                    "reason": "fake metric for UPL1"
                }
            if name == "UPL2":
                return {
                    "latency_ms": 40,
                    "jitter_ms": 5,
                    "loss_percent": 1,
                    "available_bandwidth_kbps": 50000,
                    "timestamp": "test",
                    "stale": False,
                    "source": "fake",
                    "reason": "fake metric for UPL2"
                }
            if name == "UPL3":
                return {
                    "latency_ms": 40,
                    "jitter_ms": 5,
                    "loss_percent": 1,
                    "available_bandwidth_kbps": 50000,
                    "timestamp": "test",
                    "stale": False,
                    "source": "fake",
                    "reason": "fake metric for UPL3"
                }
            return {
                "latency_ms": None,
                "jitter_ms": None,
                "loss_percent": None,
                "available_bandwidth_kbps": None,
                "timestamp": "test",
                "stale": True,
                "source": "fake",
                "reason": "unknown WAN link"
            }

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
                    "reason": "fake metric for wg01"
                }

            if name == "wg02":
                return {
                    "latency_ms": 30,
                    "jitter_ms": 3,
                    "loss_percent": 0,
                    "available_bandwidth_kbps": 70000,
                    "timestamp": "test",
                    "stale": False,
                    "source": "fake",
                    "reason": "fake metric for wg02"
                }
            if name == "wg03":
                return {
                    "latency_ms": 30,
                    "jitter_ms": 3,
                    "loss_percent": 0,
                    "available_bandwidth_kbps": 70000,
                    "timestamp": "test",
                    "stale": False,
                    "source": "fake",
                    "reason": "fake metric for wg03"
                }
            return {
                "latency_ms": None,
                "jitter_ms": None,
                "loss_percent": None,
                "available_bandwidth_kbps": None,
                "timestamp": "test",
                "stale": True,
                "source": "fake",
                "reason": "unknown tunnel"
            }

    # Temporary fake steering manager for checking all actions received from agent.py
    class FakeSteeringManager:
        def execute_decision(self, decision):
            print("\n===== DRY-RUN steering_manager received =====")
            print(json.dumps(decision, indent=2))
            return {
                "status": "dry-run",
                "received-action": decision.get("action"),
                "target-type": decision.get("target-type"),
                "name": decision.get("name"),
            }

    # Temporary fake state writer for testing before real state_writer.py is ready
    class FakeStateWriter:
        def write_state(self, wan_link_states, tunnel_states, steering_state):
            state = {
                "wan_link_states": wan_link_states,
                "tunnel_states": tunnel_states,
                "steering_state": steering_state
            }
            print("\n===== DRY-RUN state_writer written into JSON file =====")
            with open("/tmp/fake_state.json", "w") as f:
                json.dump(state, f, indent=2)
            return "/tmp/fake_state.json"

    # Temporary fake monitoring manager for testing before real monitoring_manager.py is ready
    class FakeMonitoringManager:
        def apply_configuration(self, instructions):
            print("\n===== DRY-RUN monitoring_manager received =====")
            print(json.dumps(instructions, indent=2))
            return {"status": "dry-run"}

    agent.metric_reader = FakeMetricReader()
    #agent.steering_manager = FakeSteeringManager()
    agent.state_writer = FakeStateWriter()
    agent.monitoring_manager = FakeMonitoringManager()

    agent.run_once()
