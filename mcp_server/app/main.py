"""
MCP Server entry-point.
Registers all tools on a FastMCP instance and selects transport from config.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from app.core.config import settings, TransportMode
from app.core.logging import get_logger
from app.schemas import (
    PingInput,
    PortScanInput,
    ShellExecInput,
)
from app.tools import ping, port_scan, shell_exec

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
