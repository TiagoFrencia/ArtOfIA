"""
MCP Server entry-point.
Registers all tools on a FastMCP instance and selects transport from config.
"""

from __future__ import annotations
from typing import Optional

from mcp.server.fastmcp import FastMCP

from app.core.config import settings, TransportMode
from app.core.logging import get_logger
from app.schemas import (
    PingInput,
    PortScanInput,
    ShellExecInput,
    NucleiInput,
    ReadFileInput,
    WriteExploitInput,
)
from app.tools import ping, port_scan, shell_exec, run_nmap, run_nuclei, read_file, write_exploit

log = get_logger(__name__)

# ── FastMCP instance ───────────────────────────────────────────────
mcp = FastMCP(
    name=settings.server_name,
)


# ── Tool registration ─────────────────────────────────────────────
@mcp.tool(name="ping", description="Health-check echo. Returns pong:<message>.")
async def _ping(message: str = "ping") -> dict:
    result = await ping(PingInput(message=message))
    return result.model_dump()


@mcp.tool(
    name="port_scan",
    description="Async TCP-connect port scanner. Accepts host, port spec, and timeout.",
)
async def _port_scan(target: str, ports: str = "80,443", timeout: float = 2.0) -> dict:
    result = await port_scan(PortScanInput(target=target, ports=ports, timeout=timeout))
    return result.model_dump()


@mcp.tool(
    name="shell_exec",
    description="Execute a shell command in a sandboxed subprocess and return stdout/stderr.",
)
async def _shell_exec(command: str, timeout: float = 30.0) -> dict:
    result = await shell_exec(ShellExecInput(command=command, timeout=timeout))
    return result.model_dump()


@mcp.tool(name="run_nmap", description="Run nmap scan in the worker container.")
async def _run_nmap(target: str, ports: str = "80,443") -> dict:
    result = await run_nmap(PortScanInput(target=target, ports=ports))
    return result.model_dump()


@mcp.tool(name="run_nuclei", description="Run nuclei vulnerability scan in the worker container.")
async def _run_nuclei(target: str, template: Optional[str] = None) -> dict:
    result = await run_nuclei(NucleiInput(target=target, template=template))
    return result.model_dump()


@mcp.tool(name="read_file", description="Read a file inside the worker container sandbox.")
async def _read_file(path: str) -> dict:
    result = await read_file(ReadFileInput(path=path))
    return result.model_dump()


@mcp.tool(name="write_exploit", description="Write content to a file inside the worker container sandbox.")
async def _write_exploit(path: str, content: str) -> dict:
    result = await write_exploit(WriteExploitInput(path=path, content=content))
    return result.model_dump()


# ── Entrypoint ─────────────────────────────────────────────────────
def main() -> None:
    log.info(
        "Starting %s v%s  transport=%s",
        settings.server_name,
        settings.version,
        settings.transport.value,
    )

    if settings.transport == TransportMode.SSE:
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
