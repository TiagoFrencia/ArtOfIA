"""
Structured JSON logging with correlation-id support.
"""

from __future__ import annotations

import logging
import sys
from typing import Final

from app.core.config import settings

_FMT: Final[str] = (
    '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'
)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger bound to the server's configured level."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(_FMT, datefmt="%Y-%m-%dT%H:%M:%S"))
        logger.addHandler(handler)
    logger.setLevel(settings.log_level.upper())
    return logger
