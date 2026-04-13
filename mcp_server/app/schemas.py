"""
Pydantic v2 schemas — strict validation for every tool's I/O contract.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Generic envelope ────────────────────────────────────────────────
class StatusCode(str, Enum):
    OK = "ok"
    ERROR = "error"


class ToolResult(BaseModel):
    """Canonical envelope returned by every tool."""

    status: StatusCode = Field(default=StatusCode.OK)
    data: dict[str, Any] | list[Any] | None = Field(default=None)
    error: str | None = Field(default=None)


# ── Ping / health ──────────────────────────────────────────────────
class PingInput(BaseModel):
    message: str = Field(default="ping", max_length=256)


class PingOutput(ToolResult):
    data: dict[str, str] = Field(default_factory=dict)


# ── Recon: port-scan request ───────────────────────────────────────
class PortScanInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, description="Hostname or IPv4/IPv6 address")
    ports: str = Field(
        default="80,443",
        max_length=512,
        description="Comma-separated ports or range (e.g. '1-1024')",
    )
    timeout: float = Field(default=2.0, gt=0, le=30, description="Per-port timeout in seconds")


class PortScanOutput(ToolResult):
    data: list[dict[str, Any]] = Field(default_factory=list)


# ── Execute shell command (sandboxed) ──────────────────────────────
class ShellExecInput(BaseModel):
    command: str = Field(..., min_length=1, max_length=4096)
    timeout: float = Field(default=30.0, gt=0, le=300)


class ShellExecOutput(ToolResult):
    data: dict[str, Any] = Field(default_factory=dict)
