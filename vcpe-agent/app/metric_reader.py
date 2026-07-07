#!/usr/bin/env python3                                     
# coding: utf-8                                             

import os                                                   
import logging                                             
from datetime import datetime, timezone                                                         # compare metric timestamp with current UTC time
from influxdb_client import InfluxDBClient                                                      # InfluxDB 2.x Python client


class MetricReader:
    def __init__(self):
        self.influx_url = os.environ["INFLUX_URL"]             
        self.influx_token = os.environ["INFLUX_TOKEN"]         
        self.influx_org = os.environ["INFLUX_ORG"]              
        self.influx_bucket = os.environ["INFLUX_BUCKET"]     

        self.reader_mode = os.getenv("METRIC_READER_MODE", "influxdb")                         # use "fake" for dry run, "influxdb" for real InfluxDB

        self.stale_after_sec = int(os.getenv("METRIC_STALE_AFTER_SEC", "15"))                  # metric older than this becomes stale (15 sec)

        self.client = InfluxDBClient(                                                          # create InfluxDB client
            url=self.influx_url,                                                      
            token=self.influx_token,                                                   
            org=self.influx_org)

        self.query_api = self.client.query_api()                                               # object used to run Flux queries

    # =====================================================================================
    # Return empty/stale metric when there is no valid metric
    # =====================================================================================
    def _empty_metric(self, reason):
        return {
            "latency_ms": None,                                                      
            "jitter_ms": None,                                                        
            "loss_percent": None,                                                    
            "available_bandwidth_kbps": None,                                         
            "timestamp": None,                                                      
            "stale": True,                                                             
            "source": self.reader_mode,                                                     
            "reason": reason}

    # =====================================================================================
    # Metric object expected by agent.py
    # =====================================================================================
    def _build_metric(self, values, timestamp, reason="metric read from influxdb"):
        if timestamp is None:                                                            
            return self._empty_metric("metric timestamp missing")                                   # if InfluxDB returned no timestamp, return stale metric

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)                                                            # get current time in UTC

        age_sec = (now - timestamp).total_seconds()                                     
        stale = age_sec > self.stale_after_sec                                                      # decide whether metric is stale

        return {                                                                                    # return latest values from InfluxDB
            "latency_ms": values.get("latency_ms"),                                     
            "jitter_ms": values.get("jitter_ms"),                                       
            "loss_percent": values.get("loss_percent"),                             
            "available_bandwidth_kbps": values.get("available_bandwidth_kbps"),        
            "timestamp": timestamp.isoformat(),                                        
            "stale": stale,                                                                         # True if metric is too old
            "source": self.reader_mode,
        }
    # =====================================================================================
    # Return fake metric for dry-run testing without InfluxDB (TO BE REMOVED ONCE INFLUXDB IS READY)
    # =====================================================================================
    def _get_fake_metric(self, metric_id, wan_link_name=None):
        now = datetime.now(timezone.utc)
    
        fake_flow_metrics = {
            ("1001", "UPL1"): {
                "latency_ms": 20,
                "jitter_ms": 3,
                "loss_percent": 0.1,
                "available_bandwidth_kbps": 50000
            },
            ("1001", "UPL2"): {
                "latency_ms": 45,
                "jitter_ms": 8,
                "loss_percent": 0.5,
                "available_bandwidth_kbps": 30000
            },
            ("1001", "UPL3"): {
                "latency_ms": 90,
                "jitter_ms": 25,
                "loss_percent": 3.0,
                "available_bandwidth_kbps": 5000
            },
    
            ("1002", "UPL1"): {
                "latency_ms": 15,
                "jitter_ms": 2,
                "loss_percent": 0.1,
                "available_bandwidth_kbps": 40000
            },
            ("1002", "UPL2"): {
                "latency_ms": 60,
                "jitter_ms": 10,
                "loss_percent": 0.8,
                "available_bandwidth_kbps": 20000
            },
            ("1002", "UPL3"): {
                "latency_ms": 110,
                "jitter_ms": 30,
                "loss_percent": 4.0,
                "available_bandwidth_kbps": 6000
            }
        }
    
        fake_tunnel_metrics = {
            "wg01": {
                "latency_ms": 25,
                "jitter_ms": 4,
                "loss_percent": 0.2,
                "available_bandwidth_kbps": 60000
            },
            "wg02": {
                "latency_ms": 120,
                "jitter_ms": 25,
                "loss_percent": 3.0,
                "available_bandwidth_kbps": 8000
            },
            "wg03": {
                "latency_ms": 40,
                "jitter_ms": 8,
                "loss_percent": 0.5,
                "available_bandwidth_kbps": 25000
            }
        }
    
        if wan_link_name is not None:
            values = fake_flow_metrics.get((str(metric_id), str(wan_link_name)))
    
            if values is None:
                return self._empty_metric(
                    f"no fake flow metric found for flow_id={metric_id}, wan_link={wan_link_name}"
                )
    
            return self._build_metric(values, now, reason="fake flow metric for dry run")
    
        values = fake_tunnel_metrics.get(str(metric_id))
    
        if values is None:
            return self._empty_metric(f"no fake tunnel metric found for {metric_id}")
    
        return self._build_metric(values, now, reason="fake tunnel metric for dry run")
        
    # =====================================================================================
    # Generic function to read latest metric from InfluxDB
    # =====================================================================================
    def _get_latest_metric(self, measurement, tags):
        if not tags:
            return self._empty_metric("metric tags missing")
    
        tag_filters = ""
    
        for tag_name, tag_value in tags.items():
            if tag_value is None or tag_value == "":
                return self._empty_metric(f"{tag_name} missing")
    
            tag_filters += f'  |> filter(fn: (r) => r["{tag_name}"] == "{tag_value}")\n'
    
        flux = f'''
    from(bucket: "{self.influx_bucket}")
      |> range(start: -5m)
      |> filter(fn: (r) => r["_measurement"] == "{measurement}")
    {tag_filters}  |> filter(fn: (r) =>
          r["_field"] == "latency_ms" or
          r["_field"] == "jitter_ms" or
          r["_field"] == "loss_percent" or
          r["_field"] == "available_bandwidth_kbps"
      )
      |> last()
    '''
        try:
            tables = self.query_api.query(org=self.influx_org, query=flux)
    
            values = {}
            latest_timestamp = None
    
            for table in tables:
                for record in table.records:
                    field_name = record.get_field()
                    field_value = record.get_value()
                    record_time = record.get_time()
    
                    values[field_name] = field_value
    
                    if latest_timestamp is None or record_time > latest_timestamp:
                        latest_timestamp = record_time
    
            if not values:
                return self._empty_metric(
                    f"no metric found for {measurement} with tags={tags}"
                )
    
            return self._build_metric(values, latest_timestamp)
    
        except Exception as e:
            logging.exception(
                "Failed to read metric from InfluxDB measurement=%s tags=%s: %s",
                measurement,
                tags,
                e
            )
            return self._empty_metric("influxdb query failed")
        
    # =====================================================================================
    # Read underlay traffic-class metric using flow_id/fwmark
    # =====================================================================================
    def get_flow_metric(self, flow_id, wan_link_name):
        if self.reader_mode == "fake":                                                         # if dry-run mode is enabled
            return self._get_fake_metric(flow_id, wan_link_name)                                              # return fake flow metric instead of querying InfluxDB
    
        return self._get_latest_metric(
            measurement="sdwan_flow_metrics",
            tags={
                "flow_id": str(flow_id),
                "wan_link": str(wan_link_name)
            })
    # =====================================================================================
    # Read overlay tunnel metric
    # =====================================================================================
    def get_tunnel_metric(self, name):
        if self.reader_mode == "fake":                                                         # if dry-run mode is enabled
            return self._get_fake_metric(name)                                                 # return fake tunnel metric instead of querying InfluxDB

        return self._get_latest_metric(                                               
            measurement="sdwan_tunnel_metrics",                                  
            tags={
                "flow_id": "1001",
                "wan_link": "UPL1" })

    # =====================================================================================
    # Close InfluxDB client
    # =====================================================================================
    def close(self):
        self.client.close()                                                             # close InfluxDB client connection cleanly
