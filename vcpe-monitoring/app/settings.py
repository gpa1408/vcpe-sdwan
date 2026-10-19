from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw is not None and raw != "" else default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    return float(raw) if raw is not None and raw != "" else default


def _load_wan_map(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("WAN_LINK_MAP_JSON must be a JSON object")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ValueError("WAN_LINK_MAP_JSON keys and values must be strings")
        result[key] = item
    return result


@dataclass(slots=True)
class Settings:
    api_bind: str = "0.0.0.0"
    api_port: int = 9100

    influx_url: str = "http://127.0.0.1:8086"
    influx_org: str = "thesis"
    influx_bucket: str = "vcpe"
    influx_token: str = ""
    influx_enabled: bool = True

    wan_link_map: dict[str, str] = field(default_factory=dict)

    ping_count: int = 4
    ping_process_timeout_sec: float = 10.0

    iperf_port: int = 5201
    iperf_duration_sec: int = 3
    iperf_process_timeout_sec: float = 12.0
    iperf_bind_device: bool = True

    # TWAMP stays an external adapter until a real client/reflector is selected.
    twamp_command_template: str = ""
    twamp_process_timeout_sec: float = 15.0

    # MEF 105-aligned model. These values do not claim MEF compliance.
    mef105_calculation_interval_sec: int = 5
    mef105_delay_threshold_ms: float = 80.0
    mef105_delay_variation_threshold_ms: float = 20.0
    mef105_loss_ratio_threshold: float = 0.02
    mef105_recent_tca_limit: int = 200

    otel_enabled: bool = True
    otel_service_name: str = "vcpe-monitoring"
    otel_metrics_endpoint: str = "http://127.0.0.1:4318/v1/metrics"
    otel_export_interval_ms: int = 5000
    otel_collector_health_url: str = "http://127.0.0.1:13133/"
    otel_collector_config: str = "/etc/otel/collector-config.yaml"
    otel_collector_binary: str = "/usr/local/bin/otelcol-contrib"
    otel_collector_start_timeout_sec: float = 20.0

    run_probe_immediately: bool = True
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_bind=os.getenv("API_BIND", "0.0.0.0"),
            api_port=_env_int("API_PORT", 9100),
            influx_url=os.getenv("INFLUX_URL", "http://127.0.0.1:8086"),
            influx_org=os.getenv("INFLUX_ORG", "thesis"),
            influx_bucket=os.getenv("INFLUX_BUCKET", "vcpe"),
            influx_token=os.getenv("INFLUX_TOKEN", ""),
            influx_enabled=_env_bool("INFLUX_ENABLED", True),
            wan_link_map=_load_wan_map(os.getenv("WAN_LINK_MAP_JSON")),
            ping_count=_env_int("PING_COUNT", 4),
            ping_process_timeout_sec=_env_float("PING_PROCESS_TIMEOUT_SEC", 10.0),
            iperf_port=_env_int("IPERF_PORT", 5201),
            iperf_duration_sec=_env_int("IPERF_DURATION_SEC", 3),
            iperf_process_timeout_sec=_env_float("IPERF_PROCESS_TIMEOUT_SEC", 12.0),
            iperf_bind_device=_env_bool("IPERF_BIND_DEVICE", True),
            twamp_command_template=os.getenv("TWAMP_COMMAND_TEMPLATE", ""),
            twamp_process_timeout_sec=_env_float("TWAMP_PROCESS_TIMEOUT_SEC", 15.0),
            mef105_calculation_interval_sec=_env_int("MEF105_CALCULATION_INTERVAL_SEC", 5),
            mef105_delay_threshold_ms=_env_float("MEF105_DELAY_THRESHOLD_MS", 80.0),
            mef105_delay_variation_threshold_ms=_env_float(
                "MEF105_DELAY_VARIATION_THRESHOLD_MS", 20.0
            ),
            mef105_loss_ratio_threshold=_env_float("MEF105_LOSS_RATIO_THRESHOLD", 0.02),
            mef105_recent_tca_limit=_env_int("MEF105_RECENT_TCA_LIMIT", 200),
            otel_enabled=_env_bool("OTEL_ENABLED", True),
            otel_service_name=os.getenv("OTEL_SERVICE_NAME", "vcpe-monitoring"),
            otel_metrics_endpoint=os.getenv(
                "OTEL_METRICS_ENDPOINT", "http://127.0.0.1:4318/v1/metrics"
            ),
            otel_export_interval_ms=_env_int("OTEL_EXPORT_INTERVAL_MS", 5000),
            otel_collector_health_url=os.getenv(
                "OTEL_COLLECTOR_HEALTH_URL", "http://127.0.0.1:13133/"
            ),
            otel_collector_config=os.getenv(
                "OTEL_COLLECTOR_CONFIG", "/etc/otel/collector-config.yaml"
            ),
            otel_collector_binary=os.getenv(
                "OTEL_COLLECTOR_BINARY", "/usr/local/bin/otelcol-contrib"
            ),
            otel_collector_start_timeout_sec=_env_float(
                "OTEL_COLLECTOR_START_TIMEOUT_SEC", 20.0
            ),
            run_probe_immediately=_env_bool("RUN_PROBE_IMMEDIATELY", True),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )
