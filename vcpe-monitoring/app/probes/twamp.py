from __future__ import annotations

import json
import shlex
from dataclasses import dataclass

from .common import run_command


@dataclass(slots=True)
class TwampResult:
    latency_ms: float | None = None
    jitter_ms: float | None = None
    loss_percent: float | None = None
    error: str | None = None


async def run_twamp(
    destination_ip: str,
    interface: str,
    *,
    command_template: str,
    timeout_sec: float,
) -> TwampResult:
    """Adapter hook for a future, team-selected TWAMP implementation.

    No TWAMP client/reflector is bundled and no synthetic one-way values are
    invented. If configured, this hook may still feed the legacy diagnostic
    fields used by the original Agent, but its output is never promoted to the
    MEF 105 one-way model automatically.
    """
    if not command_template.strip():
        return TwampResult(error="TWAMP adapter is not configured; no real TWAMP implementation is bundled")

    rendered = command_template.format(destination=destination_ip, interface=interface)
    args = shlex.split(rendered)

    try:
        result = await run_command(args, timeout_sec)
    except Exception as exc:
        return TwampResult(error=str(exc))

    if result.returncode != 0:
        return TwampResult(
            error=result.stderr.strip() or result.stdout.strip() or f"TWAMP exited with {result.returncode}"
        )

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return TwampResult(error=f"TWAMP command did not return JSON: {exc}")

    def number(name: str) -> float | None:
        value = payload.get(name)
        return float(value) if isinstance(value, (int, float)) else None

    return TwampResult(
        latency_ms=number("latency_ms"),
        jitter_ms=number("jitter_ms"),
        loss_percent=number("loss_percent"),
    )
