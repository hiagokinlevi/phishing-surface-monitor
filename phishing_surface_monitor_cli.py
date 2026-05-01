import argparse
import json
import os
from typing import Optional

from analyzers.dmarc import check_dmarc
from analyzers.scan import run_scan
from logger import get_logger

logger = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run typosquat scan")
    scan_parser.add_argument("domain", help="Base domain to scan")
    scan_parser.add_argument("--threshold", type=float, default=0.75, help="Similarity threshold")
    scan_parser.add_argument("--top", type=int, default=None, help="Limit results")
    scan_parser.add_argument("--hide-benign", action="store_true", help="Hide benign findings")
    scan_parser.add_argument("--report", action="store_true", help="Write markdown report")
    scan_parser.add_argument("--json-report", action="store_true", help="Write JSON report")
    scan_parser.add_argument("--csv-report", action="store_true", help="Write CSV report")
    scan_parser.add_argument(
        "--resolver",
        type=str,
        default=None,
        help="Optional DNS resolver IP (e.g., 1.1.1.1). Defaults to system resolver.",
    )

    dmarc_parser = subparsers.add_parser("dmarc-check", help="Lookup DMARC record")
    dmarc_parser.add_argument("domain", help="Domain to check")
    dmarc_parser.add_argument(
        "--resolver",
        type=str,
        default=None,
        help="Optional DNS resolver IP (e.g., 1.1.1.1). Defaults to system resolver.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        results = run_scan(
            domain=args.domain,
            threshold=args.threshold,
            top=args.top,
            hide_benign=args.hide_benign,
            write_markdown=args.report,
            write_json=args.json_report,
            write_csv=args.csv_report,
            resolver=args.resolver,
        )
        print(json.dumps(results, indent=2))
        return 0

    if args.command == "dmarc-check":
        result = check_dmarc(args.domain, resolver=args.resolver)
        print(json.dumps(result, indent=2))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
