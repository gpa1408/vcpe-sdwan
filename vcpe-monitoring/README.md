# vcpe-monitoring

Implementation starter for the SD-WAN CPE monitoring module defined by Pamodi's API and Metric Reader contracts.

## Source contract implemented

Required endpoints:

- `POST /api/v1/monitoring/flows`
- `DELETE /api/v1/monitoring/flows/{flow_id}/{wan_link}`
- `POST /api/v1/monitoring/tunnels`
- `DELETE /api/v1/monitoring/tunnels/{tunnel_id}`

Underlay jobs are keyed by `(flow_id, wan_link)`. Overlay jobs are keyed by `tunnel_id`.

InfluxDB measurements:

- `sdwan_flow_metrics`
  - tags: `flow_id`, `wan_link`
  - fields: `latency_ms`, `jitter_ms`, `loss_percent`, `available_bandwidth_kbps`
- `sdwan_tunnel_metrics`
  - tag: `tunnel_id`
  - same four fields

## Important implementation decision: host networking

The monitoring process must see the real host WAN/WireGuard interfaces to bind probes to `ens6`, `ens7`, `wg01`, etc. Therefore the recommended first Raspberry/Linux implementation uses:

```yaml
network_mode: host
cap_add:
  - NET_RAW
```

No `NET_ADMIN` is required because monitoring measures paths; it does not program the dataplane.

With host networking, InfluxDB is reached through the port published on the host:

```text
INFLUX_URL=http://127.0.0.1:8086
```

If the Agent remains on Docker's `mgmt` bridge, it reaches monitoring through:

```text
http://host.docker.internal:9100
```

with `host.docker.internal:host-gateway` in `extra_hosts`.

## Logical WAN -> Linux interface mapping

Pamodi's payload sends `wan_link="UPL1"` but not the Linux interface name. Configure:

```bash
WAN_LINK_MAP_JSON='{"UPL1":"ens6","UPL2":"ens7","UPL3":"ens8"}'
```

The service refuses to start the flow job if the resolved Linux interface is not visible. This prevents silently measuring the wrong WAN.

## Probe behavior

### ping

Runs with the selected interface:

```bash
ping -I ens6 ...
```

Produces:

- `latency_ms`: mean RTT of received replies
- `loss_percent`: packet loss
- `jitter_ms`: mean absolute difference between consecutive RTT samples

Pamodi defines `jitter_ms` but not the formula, so the formula above is an implementation decision and should be kept documented.

### iperf3

Requires a reachable `iperf3 -s` server at the destination. The client binds to the selected source IP and, by default, to the selected device using `--bind-dev`.

Produces `available_bandwidth_kbps`.

### TWAMP

Pamodi includes `twamp` for overlay tunnel monitoring but does not define a TWAMP executable, reflector, command syntax, or output format. This implementation therefore includes an adapter hook rather than pretending a specific TWAMP implementation exists.

Until the team selects a TWAMP tool, ping/iperf3 still run and the job exposes a TWAMP configuration warning.

## Build

```bash
cd vcpe-monitoring
docker build -t vcpe-monitoring .
```

## First run

```bash
docker run --rm \
  --name vcpe-monitoring \
  --network host \
  --cap-add NET_RAW \
  -e WAN_LINK_MAP_JSON='{"UPL1":"ens6","UPL2":"ens7"}' \
  -e INFLUX_URL=http://127.0.0.1:8086 \
  -e INFLUX_ORG=thesis \
  -e INFLUX_BUCKET=vcpe \
  -e INFLUX_TOKEN="$INFLUX_TOKEN" \
  vcpe-monitoring
```

## Health

```bash
curl -s http://127.0.0.1:9100/health | python3 -m json.tool
```

## Start underlay monitoring

First validate path selection with ping only:

```bash
curl -s -X POST http://127.0.0.1:9100/api/v1/monitoring/flows \
  -H 'Content-Type: application/json' \
  -d '{
    "flow_id":"257",
    "wan_link":"UPL1",
    "destination_ip":"1.1.1.1",
    "probe_tools":["ping"],
    "interval_sec":10
  }' | python3 -m json.tool
```

Then add `iperf3` only when a real iperf3 server is reachable on the target path.

## Same flow on a second WAN

```bash
curl -s -X POST http://127.0.0.1:9100/api/v1/monitoring/flows \
  -H 'Content-Type: application/json' \
  -d '{
    "flow_id":"257",
    "wan_link":"UPL2",
    "destination_ip":"1.1.1.1",
    "probe_tools":["ping"],
    "interval_sec":10
  }'
```

Both jobs coexist because their identities are `257:UPL1` and `257:UPL2`.

## Debug jobs

Extra debug endpoint, not part of Pamodi's four-endpoint contract:

```bash
curl -s http://127.0.0.1:9100/api/v1/monitoring/jobs | python3 -m json.tool
```

## Stop only UPL1

```bash
curl -s -X DELETE \
  http://127.0.0.1:9100/api/v1/monitoring/flows/257/UPL1
```

The UPL2 job continues.

## Tunnel monitoring

Once `wg01` exists:

```bash
curl -s -X POST http://127.0.0.1:9100/api/v1/monitoring/tunnels \
  -H 'Content-Type: application/json' \
  -d '{
    "tunnel_id":"wg01",
    "destination_ip":"10.200.0.2",
    "probe_tools":["ping","iperf3","twamp"],
    "interval_sec":600
  }'
```

## InfluxDB contract

Flow points must use:

```text
measurement = sdwan_flow_metrics
tags:
  flow_id
  wan_link
fields:
  latency_ms
  jitter_ms
  loss_percent
  available_bandwidth_kbps
```

Tunnel points must use:

```text
measurement = sdwan_tunnel_metrics
tag:
  tunnel_id
same four fields
```

Example query:

```flux
from(bucket: "vcpe")
  |> range(start: -5m)
  |> filter(fn: (r) => r._measurement == "sdwan_flow_metrics")
  |> filter(fn: (r) => r.flow_id == "257")
  |> filter(fn: (r) => r.wan_link == "UPL1")
```

## Acceptance checklist

1. `/health` is healthy.
2. `POST flows` creates one job keyed by `(flow_id, wan_link)`.
3. Repeating the same POST updates/replaces the same job, not a duplicate.
4. Same flow ID can run UPL1 and UPL2 simultaneously.
5. UPL1 probes really leave via WAN1 and UPL2 probes via WAN2.
6. InfluxDB contains `sdwan_flow_metrics` with exact tags/fields.
7. DELETE UPL1 does not stop UPL2.
8. Tunnel POST binds to `wgXX`.
9. InfluxDB contains `sdwan_tunnel_metrics`.
10. Agent Metric Reader consumes a fresh point for the correct flow/WAN or tunnel.

## Known open items

- Select the actual TWAMP client/reflector.
- Decide where iperf3 responders will run.
- Confirm the Agent's flow-specific metric read path. Pamodi's schema is keyed by `flow_id + wan_link`; a reader that queries only by WAN name loses traffic-class identity.
- Decide whether the Agent recreates jobs after monitoring-container restart or jobs must be persisted.
