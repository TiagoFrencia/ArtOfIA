"""
Centralised configuration via Pydantic Settings.
Loads .env automatically; every value is strictly typed.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Final

from pydantic import Field
from pydantic_settings import BaseSettings


class TransportMode(str, Enum):
    STDIO = "stdio"
    SSE = "sse"


class ServerSettings(BaseSettings):
    """Runtime configuration – environment variables take precedence."""

    model_config = {"env_prefix": "MCP_", "env_file": ".env", "env_file_encoding": "utf-8"}

    server_name: str = Field(default="artof-mcp", description="Human-readable server identifier")
    version: str = Field(default="0.1.0")
    transport: TransportMode = Field(default=TransportMode.STDIO)
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000, ge=1024, le=65535)
    log_level: str = Field(default="INFO")
    debug: bool = Field(default=False)


settings: Final[ServerSettings] = ServerSettings()
