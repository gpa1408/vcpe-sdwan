# Minimal Agent changes for vcpe-monitoring

Do not replace the Agent and do not add TCA forwarding to the Controller in this
iteration.

Apply only these changes/configurations:

1. Instantiate `MonitoringManager(..., dry_run=False)`.
2. Define a monitoring base URL from `MONITORING_URL` and append `/api/v1` in
   one place, for example:

   ```python
   monitoring_url = os.getenv("MONITORING_URL", "http://host.docker.internal:9100")
   monitoring_api_url = monitoring_url.rstrip("/") + "/api/v1"
   ```

3. Configure `METRIC_READER_MODE=influxdb`.
4. Make the metric freshness limit configurable; use 30 seconds initially,
   e.g. `METRIC_READER_MAX_AGE_SEC=30`.

The existing MetricReader should continue to read the legacy InfluxDB
measurements `sdwan_flow_metrics` and `sdwan_tunnel_metrics`. The new MEF 105-
aligned metrics and TCAs are intentionally separate. The original Agent does
not forward TCA events to the Controller; leave that as a documented future
integration item.
