import os
from dataclasses import dataclass


def _get_env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    ct_poll_connect_timeout_seconds: float = _get_env_float("CT_POLL_CONNECT_TIMEOUT_SECONDS", 5.0)
    ct_poll_read_timeout_seconds: float = _get_env_float("CT_POLL_READ_TIMEOUT_SECONDS", 10.0)
    ct_poll_max_retries: int = _get_env_int("CT_POLL_MAX_RETRIES", 3)
    ct_poll_retry_backoff_seconds: float = _get_env_float("CT_POLL_RETRY_BACKOFF_SECONDS", 1.0)


settings = Settings()
