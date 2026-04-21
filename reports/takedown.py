"""Takedown evidence bundle generator.

Formats suspicious domain findings into a structured text report suitable
for registrar/abuse reporting workflows.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


def _normalize_timestamp(value: Any) -> str:
    """Return an ISO-8601 UTC timestamp string.

    Accepts:
    - datetime objects
    - ISO-8601 strings
    - None (falls back to current UTC time)
    """
    if value is None:
        return datetime.now(timezone.utc).isoformat()

    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return datetime.now(timezone.utc).isoformat()

        # Support common "Z" suffix.
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(cleaned)
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            return datetime.now(timezone.utc).isoformat()

    return datetime.now(timezone.utc).isoformat()


def generate_takedown_evidence_report(
    findings: Iterable[Dict[str, Any]],
    generated_at: datetime | str | None = None,
) -> str:
    """Generate a structured text evidence bundle for abuse reporting.

    Each finding should include:
    - domain (required)
    - detection_source (optional, defaults to "unknown")
    - timestamp (optional, defaults to current UTC time)
    """
    generated_ts = _normalize_timestamp(generated_at)

    normalized: List[Dict[str, str]] = []
    for finding in findings:
        domain = str(finding.get("domain", "")).strip()
        if not domain:
            # Skip malformed findings to keep output reporter-safe.
            continue

        detection_source = str(finding.get("detection_source", "unknown")).strip() or "unknown"
        ts = _normalize_timestamp(finding.get("timestamp"))

        normalized.append(
            {
                "domain": domain,
                "detection_source": detection_source,
                "timestamp": ts,
            }
        )

    lines: List[str] = [
        "TAKEDOWN EVIDENCE BUNDLE",
        f"Generated At (UTC): {generated_ts}",
        f"Total Findings: {len(normalized)}",
        "",
    ]

    if not normalized:
        lines.append("No valid suspicious domain findings provided.")
        return "\n".join(lines)

    lines.append("Suspicious Domain Findings")
    lines.append("--------------------------")

    for idx, item in enumerate(normalized, start=1):
        lines.extend(
            [
                f"{idx}. Domain: {item['domain']}",
                f"   Detection Source: {item['detection_source']}",
                f"   Timestamp (UTC): {item['timestamp']}",
                "",
            ]
        )

    lines.extend(
        [
            "Usage Note:",
            "Submit this evidence bundle to registrar or hosting abuse channels",
            "alongside supporting screenshots, headers, and internal case references.",
        ]
    )

    return "\n".join(lines).rstrip() + "\n"
