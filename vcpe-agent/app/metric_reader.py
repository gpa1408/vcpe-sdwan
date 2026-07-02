#!/usr/bin/env python3                                      # tells Linux to run this file using python3
# coding: utf-8                                             # allows UTF-8 characters in this file

import os                                                   # reads environment variables
import logging                                              # writes error/debug logs
from datetime import datetime, timezone                     # used to compare metric timestamp with current UTC time
from influxdb_client import InfluxDBClient                  # official InfluxDB 2.x Python client


class MetricReader:
    def __init__(self):
        self.influx_url = os.getenv("INFLUX_URL", "http://influxdb:8086")              # InfluxDB server URL
        self.influx_token = os.getenv("INFLUX_TOKEN", "sdwan-token")                   # InfluxDB access token
        self.influx_org = os.getenv("INFLUX_ORG", "sdwan")                            # InfluxDB organization name
        self.influx_bucket = os.getenv("INFLUX_BUCKET", "sdwan_metrics")              # InfluxDB bucket/database name

        self.stale_after_sec = int(os.getenv("METRIC_STALE_AFTER_SEC", "15"))          # metric becomes stale after 15 seconds by default

        self.client = InfluxDBClient(                                                  # create InfluxDB client object
            url=self.influx_url,                                                       # pass InfluxDB URL
            token=self.influx_token,                                                   # pass InfluxDB token
            org=self.influx_org                                                        # pass organization name
        )

        self.query_api = self.client.query_api()                                       # create query API object to run Flux queries

    # =====================================================================================
    # Return empty/stale metric when there is no valid metric
    # =====================================================================================
    def _empty_metric(self, reason):
        return {
            "latency_ms": None,                                                        # no latency value available
            "jitter_ms": None,                                                         # no jitter value available
            "loss_percent": None,                                                      # no packet loss value available
            "available_bandwidth_kbps": None,                                          # no bandwidth value available
            "timestamp": None,                                                         # no timestamp available
            "stale": True,                                                             # metric is treated as stale/unusable
            "source": "influxdb",                                                      # metric source is InfluxDB
            "reason": reason                                                           # explains why metric is empty/stale
        }

    # =====================================================================================
    # Build metric object expected by agent.py
    # =====================================================================================
    def _build_metric(self, values, timestamp, reason="metric read from influxdb"):
        if timestamp is None:                                                          # if InfluxDB returned no timestamp
            return self._empty_metric("metric timestamp missing")                       # return stale metric

        now = datetime.now(timezone.utc)                                                # get current time in UTC

        if timestamp.tzinfo is None:                                                    # if timestamp has no timezone
            timestamp = timestamp.replace(tzinfo=timezone.utc)                          # assume it is UTC

        age_sec = (now - timestamp).total_seconds()                                     # calculate how old the metric is
        stale = age_sec > self.stale_after_sec                                          # decide whether metric is stale

        return {
            "latency_ms": values.get("latency_ms"),                                     # latest latency value from InfluxDB
            "jitter_ms": values.get("jitter_ms"),                                       # latest jitter value from InfluxDB
            "loss_percent": values.get("loss_percent"),                                # latest packet loss value from InfluxDB
            "available_bandwidth_kbps": values.get("available_bandwidth_kbps"),        # latest available bandwidth value from InfluxDB
            "timestamp": timestamp.isoformat(),                                         # return timestamp as ISO string
            "stale": stale,                                                            # True if metric is too old
            "source": "influxdb",                                                      # metric source
            "reason": "metric is stale" if stale else reason                           # explain whether metric is fresh or stale
        }

    # =====================================================================================
    # Generic function to read latest metric from InfluxDB
    # =====================================================================================
    def _get_latest_metric(self, measurement, tag_name, tag_value):
        if not tag_value:                                                               # if flow_id/tunnel_id/name is missing
            return self._empty_metric(f"{tag_name} missing")                            # return stale metric

        flux = f'''                                                                     # Flux query string starts here
from(bucket: "{self.influx_bucket}")                                                   
  |> range(start: -5m)                                                                  # search only recent metrics from last 5 minutes
  |> filter(fn: (r) => r["_measurement"] == "{measurement}")                            # select measurement name
  |> filter(fn: (r) => r["{tag_name}"] == "{tag_value}")                                # select metric with matching tag value
  |> filter(fn: (r) =>                                                                  
      r["_field"] == "latency_ms" or                                                    # include latency field
      r["_field"] == "jitter_ms" or                                                     # include jitter field
      r["_field"] == "loss_percent" or                                                  # include loss field
      r["_field"] == "available_bandwidth_kbps"                                         # include bandwidth field
  )
  |> last()                                                                             # get latest value of each field
'''

        try:
            tables = self.query_api.query(flux, org=self.influx_org)                   # execute Flux query

            values = {}                                                                 # stores returned metric values
            latest_timestamp = None                                                     # stores newest timestamp among returned fields

            for table in tables:                                                        # loop through returned InfluxDB tables
                for record in table.records:                                            # loop through each record in table
                    field_name = record.get_field()                                     # get field name, for example latency_ms
                    field_value = record.get_value()                                    # get field value, for example 20.5
                    record_time = record.get_time()                                     # get timestamp of this record

                    values[field_name] = field_value                                    # save metric value in dictionary

                    if latest_timestamp is None or record_time > latest_timestamp:      # check if this record is newer
                        latest_timestamp = record_time                                  # store newest timestamp

            if not values:                                                              # if query returned no metric values
                return self._empty_metric(                                              # return stale metric
                    f"no metric found for {measurement} where {tag_name}={tag_value}"   # reason for debugging
                )

            return self._build_metric(values, latest_timestamp)                         # convert InfluxDB result into agent.py format

        except Exception as e:                                                          # catch connection/query/parsing errors
            logging.exception(                                                          # log complete error with traceback
                "Failed to read metric from InfluxDB measurement=%s %s=%s: %s",
                measurement,
                tag_name,
                tag_value,
                e
            )
            return self._empty_metric("influxdb query failed")                          # return stale metric if query fails

    # =====================================================================================
    # Read WAN/underlay metric
    # =====================================================================================
    def get_wan_link_metric(self, name):
        return self._get_latest_metric(                                                 # reuse generic InfluxDB reader
            measurement="sdwan_flow_metrics",                                           # measurement used for underlay flow metrics
            tag_name="flow_id",                                                        # underlay monitoring is identified by flow_id
            tag_value=name                                                              # current agent.py passes WAN name here
        )

    # =====================================================================================
    # Read underlay traffic-class metric using flow_id/fwmark
    # =====================================================================================
    def get_flow_metric(self, flow_id):
        return self._get_latest_metric(                                                 # reuse generic InfluxDB reader
            measurement="sdwan_flow_metrics",                                           # measurement used for underlay flow metrics
            tag_name="flow_id",                                                        # tag name stored by monitoring module
            tag_value=str(flow_id)                                                      # flow_id is usually fwmark learned from forwarder
        )

    # =====================================================================================
    # Read overlay tunnel metric
    # =====================================================================================
    def get_tunnel_metric(self, name):
        return self._get_latest_metric(                                                 # reuse generic InfluxDB reader
            measurement="sdwan_tunnel_metrics",                                         # measurement used for overlay tunnel metrics
            tag_name="tunnel_id",                                                       # overlay monitoring is identified by tunnel_id
            tag_value=name                                                              # tunnel name from YANG config
        )

    # =====================================================================================
    # Close InfluxDB client
    # =====================================================================================
    def close(self):
        self.client.close()                                                             # close InfluxDB client connection cleanly
