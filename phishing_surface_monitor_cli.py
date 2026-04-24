from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reports.takedown_evidence import build_takedown_evidence_markdown, build_takedown_evidence_payload


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_scan_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _render_registrar_only_markdown(payload: dict[str, Any]) -> str:
    domain = payload.get("domain", "unknown")
    registrar = payload.get("registrar", {}) or {}
    abuse_contact = registrar.get("abuse_contact") or "unknown"
    registrar_name = registrar.get("name") or "unknown"
    timestamps = payload.get("timestamps", {}) or {}
    risk = payload.get("risk", {}) or {}
    indicators = payload.get("supporting_indicators", []) or []

    lines: list[str] = []
    lines.append(f"# Registrar Abuse Evidence - {domain}")
    lines.append("")
    lines.append("## Domain")
    lines.append(f"- **FQDN:** {domain}")
    lines.append("")
    lines.append("## Registrar Details")
    lines.append(f"- **Registrar:** {registrar_name}")
    lines.append(f"- **Abuse Contact:** {abuse_contact}")
    lines.append("")
    lines.append("## Timestamps")
    if timestamps:
        for k, v in timestamps.items():
            lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")
    else:
        lines.append("- No timestamp data available")
    lines.append("")
    lines.append("## Risk Summary")
    score = risk.get("score", "n/a")
    level = risk.get("level", "unknown")
    summary = risk.get("summary", "")
    lines.append(f"- **Score:** {score}")
    lines.append(f"- **Level:** {level}")
    if summary:
        lines.append(f"- **Summary:** {summary}")
    lines.append("")
    lines.append("## Supporting Indicators")
    if indicators:
        for item in indicators:
            lines.append(f"- {item}")
    else:
        lines.append("- No supporting indicators provided")
    lines.append("")
    lines.append(f"_Generated: {_utc_now_iso()}_")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    sub = parser.add_subparsers(dest="command")

    evidence = sub.add_parser("takedown-evidence", help="Generate takedown evidence markdown from scan JSON")
    evidence.add_argument("input", help="Path to scan JSON")
    evidence.add_argument("--output", "-o", default="takedown_evidence.md", help="Output markdown path")
    evidence.add_argument(
        "--registrar-only",
        action="store_true",
        help="Output only registrar-relevant abuse details (omits ICANN/general narrative sections)",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "takedown-evidence":
        payload = build_takedown_evidence_payload(_load_scan_json(args.input))
        markdown = (
            _render_registrar_only_markdown(payload)
            if args.registrar_only
            else build_takedown_evidence_markdown(payload)
        )
        out = Path(args.output)
        out.write_text(markdown, encoding="utf-8")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
