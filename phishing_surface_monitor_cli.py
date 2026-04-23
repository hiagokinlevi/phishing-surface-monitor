from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from analyzers.link_triage import triage_urls


def _print_link_triage_table(results: list[dict[str, Any]]) -> None:
    headers = ["URL", "VERDICT", "REASONS"]
    rows: list[list[str]] = []
    for item in results:
        reasons = item.get("reasons") or []
        reason_text = ",".join(str(r) for r in reasons) if reasons else "-"
        rows.append([
            str(item.get("url", "")),
            str(item.get("verdict", "")),
            reason_text,
        ])

    widths = [len(h) for h in headers]
    for row in rows:
        for i, col in enumerate(row):
            widths[i] = max(widths[i], len(col))

    def fmt(row: list[str]) -> str:
        return "  ".join(col.ljust(widths[i]) for i, col in enumerate(row))

    print(fmt(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt(row))


def _cmd_link_triage(args: argparse.Namespace) -> int:
    results = triage_urls(args.urls)

    if args.json:
        print(json.dumps({"results": results}, indent=2))
    else:
        _print_link_triage_table(results)

    if args.fail_on_suspicious and any(r.get("verdict") == "suspicious" for r in results):
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command")

    triage = subparsers.add_parser("link-triage", help="Analyze URLs for obfuscation patterns")
    triage.add_argument("urls", nargs="+", help="URLs to analyze")
    triage.add_argument("--json", action="store_true", help="Emit JSON output")
    triage.add_argument(
        "--fail-on-suspicious",
        action="store_true",
        help="Exit non-zero when any URL is suspicious",
    )
    triage.set_defaults(func=_cmd_link_triage)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
