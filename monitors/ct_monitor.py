from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import requests


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except Exception:
            return None

    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    # ISO-ish handling
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass

    # Common CT/crt.sh formats
    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(text, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def _event_timestamp(event: dict[str, Any]) -> datetime | None:
    for key in ("observed_at", "entry_timestamp", "not_before", "logged_at", "timestamp"):
        dt = _parse_ts(event.get(key))
        if dt is not None:
            return dt
    return None


def monitor_ct(domain: str, since_hours: int = 24) -> dict[str, Any]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()

    try:
        raw = resp.json()
    except ValueError:
        raw = []

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=max(0, since_hours))

    events: list[dict[str, Any]] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue

        name_value = item.get("name_value") or item.get("common_name") or ""
        cert_domain = str(name_value).split("\n")[0].strip() if name_value else domain

        event = {
            "domain": cert_domain,
            "common_name": item.get("common_name") or "",
            "observed_at": item.get("entry_timestamp") or item.get("not_before") or "",
            "entry_timestamp": item.get("entry_timestamp") or "",
            "not_before": item.get("not_before") or "",
        }

        ts = _event_timestamp(event)
        if ts is not None and ts < cutoff:
            continue

        events.append(event)

    return {
        "target": domain,
        "since_hours": since_hours,
        "generated_at": now.isoformat(),
        "count": len(events),
        "events": events,
    }
