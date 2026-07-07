#!/usr/bin/env python3                                                                
# coding: utf-8                                                                        
import logging                                                                         
import requests                                                                        

class MonitoringManager:                                                               
    def __init__(self,dry_run=True):      
        self.monitoring_base_url = "http://vcpe-monitoring:8090/api/v1"
        self.dry_run = dry_run                                                          
        
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
        if not isinstance(slo, dict):                                                      # if SLO object is missing or invalid use default interval for best-effort traffic
            return 600                                                         

        max_latency = slo.get("max-latency-ms")                                          
        max_jitter = slo.get("max-jitter-ms")                                            
        max_loss = slo.get("max-loss-percent")                                             
        min_bandwidth = slo.get("min-bandwidth-kbps")                                      

        candidate_intervals = []                                                          # stores suggested intervals from each configured SLO metric

        if max_latency is not None:                                                      
            if max_latency <= 30:                                                       
                candidate_intervals.append(2)                                             # strict latency requirement suggest 2 seconds
            elif max_latency <= 100:                                                     
                candidate_intervals.append(5)                                             # moderate latency requirement suggest 5 seconds
            else:                                                                         
                candidate_intervals.append(10)                                            # relaxed latency requirement suggest 10 seconds

        if max_jitter is not None:                                                   
            if max_jitter <= 10:                                                         
                candidate_intervals.append(2)                                          
            elif max_jitter <= 30:                                                       
                candidate_intervals.append(5)                                           
            else:                                                                      
                candidate_intervals.append(10)                                           

        if max_loss is not None:                                                       
            if max_loss <= 1:                                                            
                candidate_intervals.append(5)                                           
            else:                                                                        
                candidate_intervals.append(10)                                         

        if min_bandwidth is not None:                                                 
            candidate_intervals.append(10)                                               

        if not candidate_intervals:                                                    
            return 600                                                                    # if no SLO metric is configured, use default best-effort interval

        return min(candidate_intervals)                                                   # choose the smallest interval as common interval

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

        if self.dry_run:                                                                 # dry_run if monitoring module is not available
            print("\n===== DRY-RUN MONITORING FLOW START =====")                         
            print("POST", url)                                                          
            print(payload)                                                               # payload that would be sent
            return payload                                                               

        logging.info("Sending flow monitoring request: %s", payload)                     

        response = requests.post(url, json=payload, timeout=5)                            # send POST request to vcpe-monitoring
        response.raise_for_status()                                                      

        return payload                                                                        # return sent payload for agent logging/debugging

    def stop_underlay_flow_monitoring(self, flow_id):        
        url = f"{self.monitoring_base_url}/monitoring/flows/{flow_id}/{wan_link_name}"        # vcpe-monitoring endpoint for deleting flow monitor

        if self.dry_run:                                                                      # dry_run if monitoring module is not available
            print("\n===== DRY-RUN MONITORING FLOW STOP =====")                          
            print("DELETE", url)                                                         
            return     
                    
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
        
        if self.dry_run:                                                                 # dry_run if monitoring module is not available
            print("\n===== DRY-RUN MONITORING TUNNEL START =====")                         
            print("POST", url)                                                          
            print(payload)                                                               # payload that would be sent
            return payload       
            
        logging.info("Sending tunnel monitoring request: %s", payload)                   

        response = requests.post(url, json=payload, timeout=5)                           # send POST request to vcpe-monitoring
        response.raise_for_status()                                                      

        return payload                                                                  

    def stop_overlay_tunnel_monitoring(self, tunnel_id):                                  
        url = f"{self.monitoring_base_url}/monitoring/tunnels/{tunnel_id}"               # vcpe-monitoring endpoint for deleting tunnel monitor

        if self.dry_run:                                                                 # dry_run if monitoring module is not available
            print("\n===== DRY-RUN MONITORING TUNNEL STOP =====")                        
            print("DELETE", url)                                                         
            return     
                    
        logging.info("Stopping tunnel monitoring for tunnel_id=%s", tunnel_id)           

        response = requests.delete(url, timeout=5)                                       # send DELETE request to vcpe-monitoring
        response.raise_for_status()                                                     
