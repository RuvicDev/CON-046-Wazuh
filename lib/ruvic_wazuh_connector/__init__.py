"""Conector Ruvic para Wazuh (alertas y agentes)."""

from .client import WazuhClient
from .config import ENV_PREFIX, WazuhConfig
from .exceptions import (
    WazuhAuthError,
    WazuhConfigError,
    WazuhConnectorError,
    WazuhDataError,
    WazuhNetworkError,
)
from .logging_utils import setup_logging

__all__ = [
    "ENV_PREFIX",
    "WazuhAuthError",
    "WazuhClient",
    "WazuhConfig",
    "WazuhConfigError",
    "WazuhConnectorError",
    "WazuhDataError",
    "WazuhNetworkError",
    "setup_logging",
]

__version__ = "1.0.0"
