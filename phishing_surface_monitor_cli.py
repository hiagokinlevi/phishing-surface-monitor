#!/usr/bin/env python3
"""CLI entrypoint for phishing-surface-monitor."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from analyzers.typosquat import scan_domain
from reports.generator import generate_markdown_report, generate_json_report


RISK_ORDER = {"low": 1, "medium": 2, "high": 3}


def _normalize_risk(value: str | None) -> str:
    if not value:
        return "low"
    return value.strip().lower()


def _risk_meets_minimum(result_risk: str | None, min_risk: str) -> bool:
    rr = RISK_ORDER.get(_normalize_risk(result_risk), 0)
    mr = RISK_ORDER.get(_normalize_risk(min_risk), 1)
    return rr >= mr


def _filter_results_by_min_risk(results: list[dict[str, Any]], min_risk: str | None) -> list[dict[str, Any]]:
    if not min_risk:
        return results
    return [r for r in results if _risk_meets_minimum(r.get("risk_level"), min_risk)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor", description="Defensive phishing surface monitoring toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan for potential typosquatting domains")
    scan_parser.add_argument("domain", help="Protected/brand domain to monitor (e.g., example.com)")
    scan_parser.add_argument("--threshold", type=float, default=0.75, help="Similarity threshold (default: 0.75)")
    scan_parser.add_argument("--report", action="store_true", help="Generate markdown report")
    scan_parser.add_argument("--json-report", action="store_true", help="Generate JSON report")
    scan_parser.add_argument(
        "--min-risk",
        choices=["low", "medium", "high"],
        default=None,
        help="Only include findings at or above this risk level in printed/report output",
    )

    return parser


def _print_scan_results(domain: str, results: list[dict[str, Any]]) -> None:
    print(f"Scan results for {domain} ({len(results)} findings):")
    for item in results:
        variant = item.get("domain", "unknown")
        score = item.get("similarity", 0)
        risk = item.get("risk_level", "unknown")
        resolvable = item.get("resolves", False)
        print(f"- {variant} | similarity={score:.2f} | resolves={resolvable} | risk={risk}")


def _write_reports(domain: str, results: list[dict[str, Any]], write_md: bool, write_json: bool) -> None:
    if write_md:
        md = generate_markdown_report(domain, results)
        out_md = Path(f"scan_report_{domain.replace('.', '_')}.md")
        out_md.write_text(md, encoding="utf-8")
        print(f"Markdown report written: {out_md}")

    if write_json:
        payload = generate_json_report(domain, results)
        out_json = Path(f"scan_report_{domain.replace('.', '_')}.json")
        out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"JSON report written: {out_json}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        results = scan_domain(args.domain, threshold=args.threshold)
        results = _filter_results_by_min_risk(results, args.min_risk)
        _print_scan_results(args.domain, results)
        _write_reports(args.domain, results, args.report, args.json_report)


if __name__ == "__main__":
    main()
