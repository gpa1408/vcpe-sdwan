from __future__ import annotations

import re
from dataclasses import dataclass
from statistics import mean

from .common import run_command


@dataclass(slots=True)
class PingResult:
    latency_ms: float | None
    jitter_ms: float | None
    loss_percent: float | None
    error: str | None = None


_TIME_RE = re.compile(r"time(?:=|<)\s*([0-9.]+)\s*ms", re.IGNORECASE)
_LOSS_RE = re.compile(r"([0-9.]+)%\s+packet loss", re.IGNORECASE)
_SUMMARY_RE = re.compile(
    r"(?:rtt|round-trip).*?=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms",
    re.IGNORECASE,
)


def parse_ping_output(output: str) -> PingResult:
    samples = [float(value) for value in _TIME_RE.findall(output)]

    loss_match = _LOSS_RE.search(output)
    loss = float(loss_match.group(1)) if loss_match else None

    latency: float | None = mean(samples) if samples else None
    if latency is None:
        summary_match = _SUMMARY_RE.search(output)
        if summary_match:
            latency = float(summary_match.group(2))

    if len(samples) >= 2:
        jitter = mean(abs(samples[index] - samples[index - 1]) for index in range(1, len(samples)))
    elif len(samples) == 1:
        jitter = 0.0
    else:
        jitter = None

    return PingResult(
        latency_ms=round(latency, 3) if latency is not None else None,
        jitter_ms=round(jitter, 3) if jitter is not None else None,
        loss_percent=loss,
    )


async def run_ping(
    destination_ip: str,
    interface: str,
    *,
    count: int,
    timeout_sec: float,
) -> PingResult:
    args = ["ping", "-n", "-I", interface, "-c", str(count), destination_ip]

    try:
        result = await run_command(args, timeout_sec)
    except Exception as exc:
        return PingResult(None, None, None, error=str(exc))

    combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
    parsed = parse_ping_output(combined)

    if result.returncode != 0 and parsed.loss_percent is None:
        parsed.error = combined.strip() or f"ping exited with {result.returncode}"

    return parsed
