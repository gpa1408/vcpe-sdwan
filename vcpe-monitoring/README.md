# vcpe-monitoring — MEF 105-aligned / OpenTelemetry revision

This folder is the monitoring container for the vCPE SD-WAN thesis prototype.
It preserves the original Agent-facing diagnostic contract while adding a
separate one-way performance model aligned with MEF 105 and an OpenTelemetry
export path.

## Important scope statement

This implementation is **aligned with MEF 105**. It does **not** claim formal
MEF 105 compliance. No real TWAMP implementation is bundled and RTT is never
converted into one-way delay.

## One container only

`vcpe-monitoring` runs three cooperating processes inside the same container:

1. `app.supervisor` (PID 1)
2. OpenTelemetry Collector Contrib (loopback `127.0.0.1:4318` / `:13133`)
3. FastAPI/Uvicorn (`:9100`)

No extra Docker Compose service is required for the Collector.

## Legacy contract preserved

The original measurements remain unchanged for the Agent MetricReader:

- `sdwan_flow_metrics`
- `sdwan_tunnel_metrics`

Fields remain:

- `latency_ms` (RTT-derived diagnostic metric)
- `jitter_ms` (diagnostic RTT variation)
- `loss_percent`
- `available_bandwidth_kbps`

The OpenTelemetry/MEF path is separate from these legacy measurements.

## MEF 105-aligned one-way model

New endpoint:

`POST /api/v1/monitoring/mef105/samples`

It accepts real one-way packet observations with UTC TX/RX timestamps, groups
them into UTC calculation intervals and computes:

- `one_way_mean_packet_delay_ms`
- `one_way_mean_inter_packet_delay_variation_ms`
- `one_way_packet_loss_ratio`

These are exported through the local OpenTelemetry SDK to the local Collector,
which writes them to the existing InfluxDB instance.

### Example input

```json
{
  "entity": {
    "entity_id": "wg-upl1-upl2",
    "entity_type": "tvc",
    "source_cpe": "cpe-1",
    "destination_cpe": "cpe-2",
    "source_uplink": "UPL1",
    "destination_uplink": "UPL2",
    "direction": "cpe1-to-cpe2"
  },
  "calculation_interval_sec": 5,
  "samples": [
    {
      "sequence_number": 1,
      "tx_timestamp_utc": "2026-10-18T00:00:00.000Z",
      "rx_timestamp_utc": "2026-10-18T00:00:00.020Z",
      "received": true
    },
    {
      "sequence_number": 2,
      "tx_timestamp_utc": "2026-10-18T00:00:00.100Z",
      "rx_timestamp_utc": "2026-10-18T00:00:00.126Z",
      "received": true
    },
    {
      "sequence_number": 3,
      "tx_timestamp_utc": "2026-10-18T00:00:00.200Z",
      "received": false
    }
  ]
}
```

The timestamps must come from an actual one-way measurement mechanism. The
container does not fabricate them from ping.

## Threshold Crossing Alerts (TCA)

Thresholds are configured with:

- `MEF105_DELAY_THRESHOLD_MS`
- `MEF105_DELAY_VARIATION_THRESHOLD_MS`
- `MEF105_LOSS_RATIO_THRESHOLD`

Only transitions are emitted (`SET` / `CLEAR`). Recent events are available at:

`GET /api/v1/monitoring/mef105/tcas`

The original Agent does **not** forward these TCAs to the Controller. That is an
explicit future control-plane integration item.

## OpenTelemetry

The Python SDK exports OTLP/HTTP to `127.0.0.1:4318/v1/metrics`. The Collector
is bundled in the same image and exports to the existing InfluxDB using the
`INFLUX_*` environment variables.

## Build and start

From the repository root:

```bash
docker compose build vcpe-monitoring
docker compose up -d vcpe-monitoring
```

Then inspect:

```bash
docker logs vcpe-monitoring --tail 100
curl -s http://127.0.0.1:9100/health | python3 -m json.tool
```

The expected processes are supervisor + otelcol-contrib + uvicorn.

## Agent integration (minimal changes only)

Do not expand Agent logic for TCA forwarding yet. The intended minimal Agent
configuration is:

- `MonitoringManager(dry_run=False)`
- Build API URL from `MONITORING_URL.rstrip('/') + '/api/v1'`
- `METRIC_READER_MODE=influxdb`
- configurable freshness / max age; start with `30` seconds

Recommended Compose environment for Agent:

```text
MONITORING_URL=http://host.docker.internal:9100
METRIC_READER_MODE=influxdb
METRIC_READER_MAX_AGE_SEC=30
```

## First validation on the CPE

1. `docker compose build vcpe-monitoring`
2. `docker compose up -d vcpe-monitoring`
3. Verify `/health` returns `healthy`.
4. Start a legacy ping-only tunnel/flow job and confirm the original InfluxDB
   series/fields still appear.
5. POST a controlled one-way sample batch to `/api/v1/monitoring/mef105/samples`.
6. Confirm the OTel Collector receives/exports the MEF metrics to InfluxDB.
7. Force a threshold crossing and verify one `SET`, then recovery and one `CLEAR`.
8. Finally enable Agent `dry_run=False` and validate MetricReader freshness.

## Known limitation

A real TWAMP client/reflector and clock synchronization strategy are still
required before one-way measurements can be produced natively by the vCPE.
