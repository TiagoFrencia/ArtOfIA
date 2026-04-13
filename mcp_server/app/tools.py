"""
Tool implementations — pure async business logic.
Each function receives a validated Pydantic model and returns a ToolResult envelope.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from app.core.logging import get_logger
from app.schemas import (
    PingInput,
    PingOutput,
    PortScanInput,
    PortScanOutput,
    ShellExecInput,
    ShellExecOutput,
    StatusCode,
)

log = get_logger(__name__)


# ── Ping / health ──────────────────────────────────────────────────
async def ping(params: PingInput) -> PingOutput:
    """Echo-back health check."""
    log.info("ping called with message=%s", params.message)
    return PingOutput(
        status=StatusCode.OK,
        data={"reply": f"pong:{params.message}"},
    )


# ── Async TCP port scanner ────────────────────────────────────────
async def _check_port(host: str, port: int, timeout: float) -> dict[str, Any]:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return {"port": port, "state": "open"}
    except (asyncio.TimeoutError, OSError):
        return {"port": port, "state": "closed"}


def _parse_ports(spec: str) -> list[int]:
    """Expand '80,443,8000-8005' into a sorted int list."""
    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if "-" in token:
            lo, hi = token.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(token))
    return sorted(ports)


async def port_scan(params: PortScanInput) -> PortScanOutput:
    """Async TCP-connect scan against *params.target*."""
    log.info("port_scan target=%s ports=%s", params.target, params.ports)

    try:
        resolved = socket.getaddrinfo(params.target, None)[0][4][0]
    except socket.gaierror as exc:
        return PortScanOutput(status=StatusCode.ERROR, error=f"DNS resolution failed: {exc}")

    port_list = _parse_ports(params.ports)
    tasks = [_check_port(resolved, p, params.timeout) for p in port_list]
    results: list[dict[str, Any]] = await asyncio.gather(*tasks)

    open_ports = [r for r in results if r["state"] == "open"]
    log.info("port_scan complete — %d/%d open", len(open_ports), len(port_list))
    return PortScanOutput(status=StatusCode.OK, data=results)


# ── Sandboxed shell execution ─────────────────────────────────────
async def shell_exec(params: ShellExecInput) -> ShellExecOutput:
    """Run a shell command asynchronously and capture output."""
    log.info("shell_exec command=%s timeout=%.1fs", params.command, params.timeout)

    try:
        proc = await asyncio.create_subprocess_shell(
            params.command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=params.timeout,
        )
        return ShellExecOutput(
            status=StatusCode.OK if proc.returncode == 0 else StatusCode.ERROR,
            data={
                "returncode": proc.returncode,
                "stdout": stdout_bytes.decode(errors="replace"),
                "stderr": stderr_bytes.decode(errors="replace"),
            },
        )
    except asyncio.TimeoutError:
        proc.kill()
        return ShellExecOutput(status=StatusCode.ERROR, error="Command timed out")
    except Exception as exc:  # noqa: BLE001
        return ShellExecOutput(status=StatusCode.ERROR, error=str(exc))
