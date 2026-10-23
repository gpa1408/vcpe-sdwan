#!/usr/bin/env python3                                                                
# coding: utf-8                                                                        
import logging                                                                         
import requests                                                                        

class MonitoringManager:                                                               
    def __init__(self):      
        self.monitoring_base_url = "http://host.docker.internal:9100/api/v1"                                                       
        
    def _as_list(self, value):                                                            # helper to normalize a value into a list
        if value is None:                                                              
            return []                                                                  
        if isinstance(value, list):                                                    
            return value                                                                  # if the value is already a list return it as it is
        return [value]                                                                    # otherwise wrap a single value as a list

    def _ip_from_prefix(self, prefix):                                                     # helper to extract IP from prefix
        if not prefix:                                                                     # if prefix is missing, no destination IP can be extracted
            return None                                                                  
        return str(prefix).split("/", 1)[0]                                                # convert 192.168.10.2/24 into 192.168.10.2

    def _calculate_interval_from_slo(self, slo):
        if not isinstance(slo, dict) or not slo:
            return 600                                                                      # best-effort traffic: probe every 10 minutes
    
        candidate_intervals = []
    
        # Latency
        if slo.get("max-latency-ms") is not None:
            candidate_intervals.append(5)                                                    # latency -> every 5 seconds
    
        # Jitter
        if slo.get("max-jitter-ms") is not None:
            candidate_intervals.append(2)                                                     # jitter -> every 2 seconds 
    
        # Packet loss
        if slo.get("max-loss-percent") is not None:
            loss = float(slo["max-loss-percent"])
    
            if loss == 0:
                interval_sec = 200                                                            # practical maximum sample for zero-loss requirement
            else:
                packet_count = max(1, round(100 / loss))                                      # Ex: 0.5% -> 200 packets, 1% -> 100 packets
                probe_rate_pps = 10                                                           # assumes the monitoring module can send 10 probe packets per second.
                interval_sec = max(1, round(packet_count / probe_rate_pps))
    
            candidate_intervals.append(interval_sec)
    
        if slo.get("min-bandwidth-kbps") is not None:                                     # Bandwidth
            candidate_intervals.append(60)
    
        if not candidate_intervals:                                                        # No SLO configured
            return 600
    
        return min(candidate_intervals)                                                    # Use the most frequent interval required
    
    def _select_probe_tools(self, slo):                                                   
        if not isinstance(slo, dict):                                                      # if no SLO is provided use ping as default reachability/RTT probe
            return ["ping"]                                                                

        tools = set()                                                                      # use a set to avoid duplicate tools

        if slo.get("max-latency-ms") is not None:                                          # if RTT/latency is part of the SLO -> ping 
            tools.add("ping")                                                              

        if slo.get("max-loss-percent") is not None:                                        # if packet loss is part of the SLO ->ping 
            tools.add("ping")                                                        

        if slo.get("max-jitter-ms") is not None:                                           # if jitter is part of the SLO -> iperf3 and Twamp
            tools.update(["iperf3", "twamp"])                                                         

        if slo.get("min-bandwidth-kbps") is not None:                                      # if bandwidth is part of the SLO -> iperf3
            tools.add("iperf3")                                                        

        return sorted(list(tools))                                                         # return stable list such as ["iperf3", "ping"]

    def start_underlay_flow_monitoring(self, traffic_class, steering_policy, flow_id, wan_link_name):                  
        five_tuple = traffic_class.get("five-tuple", {})                               
        dst_prefix = five_tuple.get("dst-prefix")                                      
        destination_ip = self._ip_from_prefix(dst_prefix)                              

        if not destination_ip or destination_ip == "any":                                  # active probe needs a specific destination
            raise ValueError("Cannot start flow monitoring without a specific dst-prefix") # fail clearly when destination is not usable

        slo = steering_policy                                                                       # SLO thresholds are under policy > steering

        if slo is None:
            slo = {}

        payload = {                                                                       # payload sent to vcpe-monitoring
            "flow_id": str(flow_id),                                                      # underlay flow ID; this is fwmark received from forwarder via agent.py
            "wan_link": str(wan_link_name),                                               # candidate WAN link used for this flow probe
            "destination_ip": destination_ip,                                             # target IP where probe packets are sent
            "probe_tools": self._select_probe_tools(slo),                                 # selected tools based on SLO metrics
            "interval_sec": self._calculate_interval_from_slo(slo)                        # selected probe frequency based on SLO strictness
        }

        url = f"{self.monitoring_base_url}/monitoring/flows"                              # vcpe-monitoring endpoint for flow monitoring                                                         

        logging.info("Sending flow monitoring request: %s", payload)                     

        response = requests.post(url, json=payload, timeout=5)                            # send POST request to vcpe-monitoring
        response.raise_for_status()                                                      

        return payload                                                                        # return sent payload for agent logging/debugging

    def stop_underlay_flow_monitoring(self, flow_id, wan_link_name):        
        url = f"{self.monitoring_base_url}/monitoring/flows/{flow_id}/{wan_link_name}"        # vcpe-monitoring endpoint for deleting flow monitor 
                    
        logging.info("Stopping flow monitoring for flow_id=%s wan_link=%s", flow_id, wan_link_name)
                
        response = requests.delete(url, timeout=5)                                        # send DELETE request to vcpe-monitoring
        response.raise_for_status()                                                   

    def start_overlay_tunnel_monitoring(self, tunnel):                                   
        tunnel_id = tunnel.get("name")                                                 
        resolved_peer = tunnel.get("resolved-peer", {})                                
        destination_ip = resolved_peer.get("peer-address")                                # use peer-address as tunnel monitoring destination

        if not tunnel_id:                                                              
            raise ValueError("Cannot start tunnel monitoring without tunnel name")       

        if not destination_ip:                                                           
            raise ValueError("Cannot start tunnel monitoring without peer-address")       

        payload = {                                                                      # payload sent to vcpe-monitoring
            "tunnel_id": str(tunnel_id),                                                 # overlay tunnel ID; not a flow_id
            "destination_ip": destination_ip,                                            # tunnel peer/endpoint IP used as probe target
            "probe_tools": ["ping","iperf3","twamp"],                                                      
            "interval_sec": 600                                                          # fixed interval for tunnel monitoring
        }

        url = f"{self.monitoring_base_url}/monitoring/tunnels"                           # vcpe-monitoring endpoint for tunnel monitoring  
            
        logging.info("Sending tunnel monitoring request: %s", payload)                   

        response = requests.post(url, json=payload, timeout=5)                           # send POST request to vcpe-monitoring
        response.raise_for_status()                                                      

        return payload                                                                  

    def stop_overlay_tunnel_monitoring(self, tunnel_id):                                  
        url = f"{self.monitoring_base_url}/monitoring/tunnels/{tunnel_id}"               # vcpe-monitoring endpoint for deleting tunnel monitor  
                    
        logging.info("Stopping tunnel monitoring for tunnel_id=%s", tunnel_id)           

        response = requests.delete(url, timeout=5)                                       # send DELETE request to vcpe-monitoring
        response.raise_for_status()                                                     
