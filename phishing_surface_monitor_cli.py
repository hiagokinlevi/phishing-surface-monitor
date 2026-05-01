from __future__ import annotations

import argparse
import json
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional

from monitors.ct_monitor import monitor_certificates


def _ct_event_risk_score(event: Dict[str, Any], brand_domain: str) -> float:
    domains = event.get("domains") or []
    if isinstance(domains, str):
        domains = [domains]

    score = 0.0

    # Wildcard usage is commonly abused for broad phishing infra.
    if any(isinstance(d, str) and d.startswith("*.") for d in domains):
        score += 0.40

    # Domain similarity to protected brand domain.
    best_similarity = 0.0
    for d in domains:
        if not isinstance(d, str):
            continue
        candidate = d[2:] if d.startswith("*.") else d
        best_similarity = max(
            best_similarity,
            SequenceMatcher(None, candidate.lower(), brand_domain.lower()).ratio(),
        )
    score += 0.45 * best_similarity

    # Newly seen status increases urgency.
    if bool(event.get("newly_seen", True)):
        score += 0.15

    return min(1.0, round(score, 4))


def _apply_ct_risk_threshold(
    events: Iterable[Dict[str, Any]], brand_domain: str, threshold: Optional[float]
) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    for event in events:
        e = dict(event)
        e["risk_score"] = _ct_event_risk_score(e, brand_domain)
        if threshold is None or e["risk_score"] >= threshold:
            enriched.append(e)
    return enriched


def main() -> None:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command")

    ct_parser = subparsers.add_parser("ct-monitor", help="Monitor CT logs for a domain")
    ct_parser.add_argument("domain", help="Brand domain to monitor")
    ct_parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit JSON output",
    )
    ct_parser.add_argument(
        "--risk-threshold",
        type=float,
        default=None,
        help="Only emit CT events with computed risk score >= threshold (0.0-1.0)",
    )

    args = parser.parse_args()

    if args.command == "ct-monitor":
        if args.risk_threshold is not None and not (0.0 <= args.risk_threshold <= 1.0):
            parser.error("--risk-threshold must be between 0.0 and 1.0")

        events = monitor_certificates(args.domain)
        filtered_events = _apply_ct_risk_threshold(events, args.domain, args.risk_threshold)

        if args.json_output:
            print(json.dumps(filtered_events, indent=2))
            return

        for event in filtered_events:
            domains = event.get("domains") or []
            if isinstance(domains, str):
                domains = [domains]
            joined_domains = ", ".join(domains)
            print(
                f"[risk={event.get('risk_score', 0):.2f}] "
                f"{joined_domains} | issuer={event.get('issuer', 'unknown')}"
            )
        return

    parser.print_help()


if __name__ == "__main__":
    main()
