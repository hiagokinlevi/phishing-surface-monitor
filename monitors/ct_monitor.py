import time
from typing import Any

import requests

from config import settings
from logger import get_logger

logger = get_logger(__name__)


CRT_SH_URL = "https://crt.sh/"


def _crtsh_query(domain: str) -> list[dict[str, Any]]:
    params = {"q": domain, "output": "json"}
    timeout = (
        settings.ct_poll_connect_timeout_seconds,
        settings.ct_poll_read_timeout_seconds,
    )
    max_retries = max(1, settings.ct_poll_max_retries)
    backoff = max(0.0, settings.ct_poll_retry_backoff_seconds)

    last_error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(CRT_SH_URL, params=params, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, list):
                return data
            logger.warning(
                "ct_poll_unexpected_payload",
                extra={
                    "event": "ct_poll_unexpected_payload",
                    "domain": domain,
                    "payload_type": type(data).__name__,
                },
            )
            return []
        except (requests.RequestException, ValueError) as exc:
            last_error = exc
            if attempt < max_retries and backoff > 0:
                time.sleep(backoff * attempt)

    logger.warning(
        "ct_poll_failed",
        extra={
            "event": "ct_poll_failed",
            "domain": domain,
            "attempts": max_retries,
            "error": str(last_error) if last_error else "unknown",
        },
    )
    return []


def monitor_ct(domain: str) -> list[dict[str, Any]]:
    return _crtsh_query(domain)
