from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from typing import Any

from analyzers.ct_analyzer import analyze_ct_findings
from logger import get_logger

logger = get_logger(__name__)


DEFAULT_CT_DAYS = 7


def _parse_iso_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None


def _extract_event_time(finding: dict[str, Any]) -> datetime | None:
    for field in ("not_before", "logged_at", "entry_timestamp", "timestamp"):
        dt = _parse_iso_dt(finding.get(field))
        if dt is not None:
            return dt
    return None


def filter_ct_findings_by_days(
    findings: list[dict[str, Any]],
    ct_days: int = DEFAULT_CT_DAYS,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    if ct_days <= 0:
        return findings

    now_utc = now.astimezone(timezone.utc) if now else datetime.now(timezone.utc)
    cutoff = now_utc - timedelta(days=ct_days)

    filtered: list[dict[str, Any]] = []
    for finding in findings:
        event_time = _extract_event_time(finding)
        if event_time is None:
            # Keep undated findings to avoid accidental data loss.
            filtered.append(finding)
            continue
        if event_time >= cutoff:
            filtered.append(finding)
    return filtered


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("ct-monitor", help="Monitor CT logs for suspicious cert activity")
    parser.add_argument("domain", help="Domain to monitor")
    parser.add_argument("--risk-threshold", type=float, default=0.7, help="Risk threshold (0-1)")
    parser.add_argument(
        "--ct-days",
        type=int,
        default=DEFAULT_CT_DAYS,
        help="Only evaluate cert findings from the last N days (default: 7)",
    )
    parser.set_defaults(func=handle_ct_monitor)


def handle_ct_monitor(args: argparse.Namespace) -> dict[str, Any]:
    findings = analyze_ct_findings(args.domain)
    findings = filter_ct_findings_by_days(findings, ct_days=args.ct_days)

    risky = [f for f in findings if float(f.get("risk_score", 0.0)) >= args.risk_threshold]

    result = {
        "domain": args.domain,
        "ct_days": args.ct_days,
        "total_findings": len(findings),
        "risky_findings": len(risky),
        "findings": risky,
    }
    logger.info(
        "ct-monitor completed",
        extra={
            "domain": args.domain,
            "ct_days": args.ct_days,
            "total_findings": len(findings),
            "risky_findings": len(risky),
        },
    )
    return result
