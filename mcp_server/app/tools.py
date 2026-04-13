"""
Tool implementations — pure async business logic.
Each function receives a validated Pydantic model and returns a ToolResult envelope.
"""

from __future__ import annotations

import asyncio
import socket
import os
import docker
from typing import Any

from app.core.logging import get_logger
from app.schemas import (
    PingInput,
    PingOutput,
    PortScanInput,
    PortScanOutput,
    ShellExecInput,
    ShellExecOutput,
    NucleiInput,
    NucleiOutput,
    ReadFileInput,
    ReadFileOutput,
    WriteExploitInput,
    WriteExploitOutput,
    StatusCode,
)

log = get_logger(__name__)

# Docker setup for remote execution
DOCKER_HOST = os.getenv("DOCKER_HOST", "unix://var/run/docker.sock")
WORKER_CONTAINER = os.getenv("WORKER_CONTAINER", "ai-worker")
client = docker.DockerClient(base_url=DOCKER_HOST)

def _run_in_worker(cmd: str | list[str]) -> str:
    container = client.containers.get(WORKER_CONTAINER)
    exec_id = client.api.exec_create(container.id, cmd=cmd, tty=False)["Id"]
    output = client.api.exec_start(exec_id, detach=False)
    return output.decode("utf-8", errors="replace").strip()


# ── Recon Tools ──────────────────────────────────────────────────
async def run_nmap(params: PortScanInput) -> PortScanOutput:
    """Run nmap in the worker container."""
    log.info("run_nmap target=%s ports=%s", params.target, params.ports)
    cmd = f"nmap -p {params.ports} {params.target}"
    try:
        output = await asyncio.to_thread(_run_in_worker, ["/bin/bash", "-c", cmd])
        return PortScanOutput(status=StatusCode.OK, data=[{"output": output}])
    except Exception as exc:
        return PortScanOutput(status=StatusCode.ERROR, error=str(exc))


async def run_nuclei(params: NucleiInput) -> NucleiOutput:
    """Run nuclei in the worker container."""
    log.info("run_nuclei target=%s", params.target)
    template_flag = f"-t {params.template}" if params.template else ""
    cmd = f"nuclei -u {params.target} {template_flag} -silent"
    try:
        output = await asyncio.to_thread(_run_in_worker, ["/bin/bash", "-c", cmd])
        return NucleiOutput(status=StatusCode.OK, data=[{"output": output}])
    except Exception as exc:
        return NucleiOutput(status=StatusCode.ERROR, error=str(exc))


# ── File System Tools ──────────────────────────────────────────────
async def read_file(params: ReadFileInput) -> ReadFileOutput:
    """Read a file in the worker container."""
    log.info("read_file path=%s", params.path)
    cmd = f"cat {params.path}"
    try:
        output = await asyncio.to_thread(_run_in_worker, ["/bin/bash", "-c", cmd])
        return ReadFileOutput(status=StatusCode.OK, data={"content": output})
    except Exception as exc:
        return ReadFileOutput(status=StatusCode.ERROR, error=str(exc))


async def write_exploit(params: WriteExploitInput) -> WriteExploitOutput:
    """Write an exploit script in the worker container."""
    log.info("write_exploit path=%s", params.path)
    # Using python to write to avoid shell escaping issues with complex content
    content_escaped = params.content.replace("'", "'\\''")
    cmd = f"printf '%s' '{content_escaped}' > {params.path}"
    try:
        await asyncio.to_thread(_run_in_worker, ["/bin/bash", "-c", cmd])
        return WriteExploitOutput(status=StatusCode.OK, data={"path": params.path})
    except Exception as exc:
        return WriteExploitOutput(status=StatusCode.ERROR, error=str(exc))


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
