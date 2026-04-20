"""Environment-based configuration for phishing-surface-monitor.

This module centralizes runtime settings so monitoring behavior can be tuned
without code changes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List


def _get_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_list(name: str, default: List[str]) -> List[str]:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Config:
    """Application configuration loaded from environment variables."""

    # API endpoints
    ct_api_endpoint: str

    # Network/monitoring behavior
    request_timeout_seconds: float
    monitor_interval_seconds: int

    # Domains to monitor by default
    monitoring_domains: List[str]


DEFAULT_CT_API_ENDPOINT = "https://crt.sh/"
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
DEFAULT_MONITOR_INTERVAL_SECONDS = 300
DEFAULT_MONITORING_DOMAINS = ["example.com"]


def load_config() -> Config:
    """Load configuration from environment variables with sensible defaults.

    Environment variables:
    - PHISHING_MONITOR_CT_API_ENDPOINT
    - PHISHING_MONITOR_REQUEST_TIMEOUT_SECONDS
    - PHISHING_MONITOR_MONITOR_INTERVAL_SECONDS
    - PHISHING_MONITOR_DOMAINS (comma-separated)
    """

    return Config(
        ct_api_endpoint=os.getenv(
            "PHISHING_MONITOR_CT_API_ENDPOINT", DEFAULT_CT_API_ENDPOINT
        ),
        request_timeout_seconds=_get_float(
            "PHISHING_MONITOR_REQUEST_TIMEOUT_SECONDS",
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
        ),
        monitor_interval_seconds=_get_int(
            "PHISHING_MONITOR_MONITOR_INTERVAL_SECONDS",
            DEFAULT_MONITOR_INTERVAL_SECONDS,
        ),
        monitoring_domains=_get_list(
            "PHISHING_MONITOR_DOMAINS",
            DEFAULT_MONITORING_DOMAINS,
        ),
    )


config = load_config()
