#!/usr/bin/env python3
"""CLI entrypoint for phishing-surface-monitor."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

from cli.scan import run_scan


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run phishing surface scan")
    scan_parser.add_argument("domain", help="Target brand domain")
    scan_parser.add_argument("--threshold", type=float, default=0.75)
    scan_parser.add_argument("--top", type=int, default=None)
    scan_parser.add_argument("--max-variants", type=int, default=None)
    scan_parser.add_argument("--hide-benign", action="store_true")
    scan_parser.add_argument("--known-domains-file", default=None)
    scan_parser.add_argument("--registrable-only", action="store_true")
    scan_parser.add_argument("--report", action="store_true")
    scan_parser.add_argument("--json-report", action="store_true")
    scan_parser.add_argument("--csv-report", action="store_true")
    scan_parser.add_argument("--output-dir", default="reports")
    scan_parser.add_argument("--summary-only", action="store_true")
    scan_parser.add_argument("--json-stdout", action="store_true")
    scan_parser.add_argument("--csv-stdout", action="store_true", help="Print scan findings as CSV to stdout")
    scan_parser.add_argument("--resolver", default=None)

    return parser


def _csv_row_from_finding(f: dict[str, Any]) -> dict[str, Any]:
    reason_codes = f.get("reason_codes") or []
    if isinstance(reason_codes, (list, tuple)):
        reason_codes = ";".join(str(x) for x in reason_codes)

    return {
        "candidate_domain": f.get("candidate_domain") or f.get("domain") or "",
        "similarity_score": f.get("similarity_score", ""),
        "dns_resolved": f.get("dns_resolved", ""),
        "risk_level": f.get("risk_level", ""),
        "reason_codes": reason_codes,
    }


def _print_csv_stdout(scan_payload: dict[str, Any]) -> None:
    findings = scan_payload.get("findings") or []
    fieldnames = [
        "candidate_domain",
        "similarity_score",
        "dns_resolved",
        "risk_level",
        "reason_codes",
    ]
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()
    for f in findings:
        writer.writerow(_csv_row_from_finding(f if isinstance(f, dict) else {}))


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        payload = run_scan(
            domain=args.domain,
            threshold=args.threshold,
            top=args.top,
            max_variants=args.max_variants,
            hide_benign=args.hide_benign,
            known_domains_file=args.known_domains_file,
            registrable_only=args.registrable_only,
            report=args.report,
            json_report=args.json_report,
            csv_report=args.csv_report,
            output_dir=Path(args.output_dir),
            summary_only=args.summary_only,
            resolver=args.resolver,
        )

        if args.json_stdout:
            json.dump(payload, sys.stdout, indent=2)
            sys.stdout.write("\n")

        if args.csv_stdout:
            _print_csv_stdout(payload)

        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
