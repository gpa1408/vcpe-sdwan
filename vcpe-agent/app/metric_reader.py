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

        self.stale_after_sec = int(os.getenv("METRIC_STALE_AFTER_SEC", "15"))                  # metric older than this becomes stale (15 sec)

        self.client = InfluxDBClient(                                                          # create InfluxDB client
            url=self.influx_url,                                                      
            token=self.influx_token,                                                   
            org=self.influx_org                                            
        )

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
            "source": "influxdb",                                                     
            "reason": reason                                                          
        }
    # =====================================================================================
    # Metric object expected by agent.py
    # =====================================================================================
    def _build_metric(self, values, timestamp, reason="metric read from influxdb"):
        if timestamp is None:                                                            
            return self._empty_metric("metric timestamp missing")                                   # if InfluxDB returned no timestamp, return stale metric

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
        }

    # =====================================================================================
    # Generic function to read latest metric from InfluxDB
    # =====================================================================================
    def _get_latest_metric(self, measurement, tag_name, tag_value):
        if not tag_value:                                                                           # if flow_id/tunnel_id/name is missing, return stale metric
            return self._empty_metric(f"{tag_name} missing")                            

        flux = f'''                                                                                 # Flux query string starts here
from(bucket: "{self.influx_bucket}")                                                   
  |> range(start: -5m)                                                                              # search only recent metrics from last 5 minutes
  |> filter(fn: (r) => r["_measurement"] == "{measurement}")                                        # "sdwan_flow_metrics" or "sdwan_tunnel_metrics"
  |> filter(fn: (r) => r["{tag_name}"] == "{tag_value}")                             
  |> filter(fn: (r) =>                                                                              # Filter only required fields
      r["_field"] == "latency_ms" or                                                  
      r["_field"] == "jitter_ms" or                                                     
      r["_field"] == "loss_percent" or                                                
      r["_field"] == "available_bandwidth_kbps"                                        
  )
  |> last()                                                                                         # get latest value of each field
'''
        try:
            tables = self.query_api.query(flux, org=self.influx_org)                                # ends the Flux query to InfluxDB and returns query results as tables

            values = {}                                                                             # stores returned metric values
            latest_timestamp = None                                                                 # stores the newest timestamp among all returned fields

            for table in tables:                                                                    # loop through returned InfluxDB tables
                for record in table.records:                                            
                    field_name = record.get_field()                                     
                    field_value = record.get_value()                                  
                    record_time = record.get_time()                             

                    values[field_name] = field_value                                                # save metric value in dictionary

                    if latest_timestamp is None or record_time > latest_timestamp:                  # checks whether this record is newer than the previous records
                        latest_timestamp = record_time                                              # store newest timestamp (This timestamp is later used to decide whether the metric is stale)

            if not values:                                                                         
                return self._empty_metric(f"no metric found for {measurement} where {tag_name}={tag_value}")

            return self._build_metric(values, latest_timestamp)                                  

        except Exception as e:                                                                     
            logging.exception(                                                                      
                "Failed to read metric from InfluxDB measurement=%s %s=%s: %s",
                measurement,
                tag_name,
                tag_value,
                e
            )
            return self._empty_metric("influxdb query failed")                                      

    # =====================================================================================
    # Read underlay traffic-class metric using flow_id/fwmark
    # =====================================================================================
    def get_flow_metric(self, flow_id):
        return self._get_latest_metric(                                                
            measurement="sdwan_flow_metrics",                                           
            tag_name="flow_id",                                                      
            tag_value=str(flow_id))

    # =====================================================================================
    # Read overlay tunnel metric
    # =====================================================================================
    def get_tunnel_metric(self, name):
        return self._get_latest_metric(                                               
            measurement="sdwan_tunnel_metrics",                                  
            tag_name="tunnel_id",                                                       
            tag_value=name)

    # =====================================================================================
    # Close InfluxDB client
    # =====================================================================================
    def close(self):
        self.client.close()                                                             # close InfluxDB client connection cleanly
