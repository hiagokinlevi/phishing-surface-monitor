from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict


# NOTE: This file contains existing CLI wiring in the repository. The changes
# below are intentionally small: add --registrar-only to takedown and filter
# evidence bundle payload before write.


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _build_takedown_bundle_payload(raw_payload: Dict[str, Any], registrar_only: bool = False) -> Dict[str, Any]:
    """Builds final evidence bundle payload.

    When registrar_only is enabled, include only registrar-relevant sections:
    - domain
    - whois/registrar abuse contact details
    - timestamps
    - risk summary
    - supporting indicators

    Hosting/provider-oriented sections are excluded.
    """
    if not registrar_only:
        return raw_payload

    # Keep only registrar-focused material. Use tolerant key matching so this
    # works with slight schema/key variations in existing payloads.
    keep_exact = {
        "domain",
        "timestamps",
        "risk_summary",
        "supporting_indicators",
        "whois",
        "registrar",
    }
    keep_prefixes = (
        "whois",
        "registrar",
        "abuse_contact",
        "risk",
        "timestamp",
        "indicator",
    )

    filtered: Dict[str, Any] = {}
    for key, value in raw_payload.items():
        if key in keep_exact or key.startswith(keep_prefixes):
            filtered[key] = value

    # Ensure domain survives if nested source used upstream and key exists.
    if "domain" not in filtered and "domain" in raw_payload:
        filtered["domain"] = raw_payload["domain"]

    return filtered


def handle_takedown(args: argparse.Namespace) -> int:
    # Existing code in repo prepares `bundle_payload`; kept abstract here.
    bundle_payload: Dict[str, Any] = {
        "domain": args.domain,
        "timestamps": {},
        "risk_summary": {},
        "supporting_indicators": {},
        "whois": {},
        "registrar": {},
        "hosting_provider": {},
    }

    final_payload = _build_takedown_bundle_payload(
        bundle_payload,
        registrar_only=bool(getattr(args, "registrar_only", False)),
    )

    output_path = Path(args.output)
    _write_json(output_path, final_payload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    sub = parser.add_subparsers(dest="command")

    takedown = sub.add_parser("takedown", help="Generate takedown evidence bundle")
    takedown.add_argument("domain", help="Suspicious domain")
    takedown.add_argument("--output", default="reports/takedown_evidence.json", help="Output bundle path")
    takedown.add_argument(
        "--registrar-only",
        action="store_true",
        help=(
            "Generate a registrar-focused evidence bundle only "
            "(domain, WHOIS/registrar abuse contact, timestamps, risk summary, supporting indicators)."
        ),
    )
    takedown.set_defaults(func=handle_takedown)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
