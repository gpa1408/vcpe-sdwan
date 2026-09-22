from __future__ import annotations

import asyncio
from dataclasses import dataclass


@dataclass(slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


async def run_command(args: list[str], timeout_sec: float) -> CommandResult:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_sec)
    except asyncio.CancelledError:
        if process.returncode is None:
            process.kill()
            await process.communicate()
        raise
    except asyncio.TimeoutError as exc:
        if process.returncode is None:
            process.kill()
            stdout, stderr = await process.communicate()
        else:
            stdout, stderr = b"", b""
        raise TimeoutError(f"command timed out after {timeout_sec}s: {' '.join(args)}") from exc

    return CommandResult(
        returncode=process.returncode or 0,
        stdout=stdout.decode(errors="replace"),
        stderr=stderr.decode(errors="replace"),
    )
