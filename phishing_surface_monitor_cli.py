from __future__ import annotations

import argparse
from typing import Any, Dict, List

from monitors.ct_monitor import run_ct_monitor


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command")

    ct_parser = subparsers.add_parser(
        "ct-monitor",
        help="Monitor Certificate Transparency entries for a domain",
    )
    ct_parser.add_argument("domain", help="Root domain to monitor")
    ct_parser.add_argument(
        "--ct-limit",
        type=_positive_int,
        default=None,
        help="Maximum number of CT entries to process/display after filtering and deduplication (min: 1)",
    )

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "ct-monitor":
        results: List[Dict[str, Any]] = run_ct_monitor(args.domain)
        if args.ct_limit is not None:
            results = results[: args.ct_limit]
        for row in results:
            print(row)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
