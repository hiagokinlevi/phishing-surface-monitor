#!/usr/bin/env python3
"""CLI entrypoint for phishing-surface-monitor."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from analyzers.typosquat import run_typosquat_scan
from reports.writer import write_csv_report, write_json_report, write_markdown_report


def _validate_output_dir(output_dir: str | None) -> Path:
    """Return a writable output directory path, creating it when needed."""
    target = Path(output_dir or ".")
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise argparse.ArgumentTypeError(
            f"unable to create output directory '{target}': {exc}"
        ) from exc

    if not target.is_dir():
        raise argparse.ArgumentTypeError(
            f"output path '{target}' is not a directory"
        )

    if not os.access(target, os.W_OK):
        raise argparse.ArgumentTypeError(
            f"output directory '{target}' is not writable"
        )

    return target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run typosquat scan")
    scan.add_argument("domain", help="Base domain to scan")
    scan.add_argument("--threshold", type=float, default=0.75)
    scan.add_argument("--top", type=int, default=None)
    scan.add_argument("--report", action="store_true", help="Write markdown report")
    scan.add_argument("--json-report", action="store_true", help="Write JSON report")
    scan.add_argument("--csv-report", action="store_true", help="Write CSV report")
    scan.add_argument(
        "--output-dir",
        default=".",
        help="Directory where report artifacts are written (created if missing)",
    )

    return parser


def _handle_scan(args: argparse.Namespace) -> int:
    results: dict[str, Any] = run_typosquat_scan(
        domain=args.domain,
        threshold=args.threshold,
        top=args.top,
    )

    print(json.dumps(results, indent=2))

    if args.report or args.json_report or args.csv_report:
        output_dir = _validate_output_dir(args.output_dir)

        if args.report:
            write_markdown_report(results, str(output_dir / "scan_report.md"))
        if args.json_report:
            write_json_report(results, str(output_dir / "scan_report.json"))
        if args.csv_report:
            write_csv_report(results, str(output_dir / "scan_report.csv"))

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        return _handle_scan(args)

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
