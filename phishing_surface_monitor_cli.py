import argparse
import json
import sys
from typing import Any, Dict, List


RISK_ORDER = {"benign": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _risk_meets_or_exceeds(level: str, minimum: str) -> bool:
    return RISK_ORDER.get(str(level).lower(), -1) >= RISK_ORDER.get(str(minimum).lower(), 999)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan domains for phishing surface")
    scan.add_argument("domain")
    scan.add_argument("--min-risk", choices=["low", "medium", "high"], help="Filter displayed results by minimum risk")
    scan.add_argument(
        "--fail-on-min-risk",
        choices=["low", "medium", "high"],
        help="Exit with code 2 if any (post-filtered) result is at or above this risk",
    )
    scan.set_defaults(func=handle_scan)

    return parser


def run_scan(_args: argparse.Namespace) -> List[Dict[str, Any]]:
    # Placeholder implementation hook; real project logic populates findings.
    return []


def _apply_min_risk_filter(results: List[Dict[str, Any]], min_risk: str | None) -> List[Dict[str, Any]]:
    if not min_risk:
        return results
    return [r for r in results if _risk_meets_or_exceeds(r.get("risk", "benign"), min_risk)]


def handle_scan(args: argparse.Namespace) -> int:
    results = run_scan(args)
    filtered_results = _apply_min_risk_filter(results, getattr(args, "min_risk", None))

    # Preserve output behavior (example JSON output path shown as existing behavior placeholder).
    if getattr(args, "json_stdout", False):
        print(json.dumps({"results": filtered_results}))
    else:
        for row in filtered_results:
            print(f"{row.get('domain', '')}\t{row.get('risk', '')}")

    fail_threshold = getattr(args, "fail_on_min_risk", None)
    if fail_threshold:
        matched = [r for r in filtered_results if _risk_meets_or_exceeds(r.get("risk", "benign"), fail_threshold)]
        if matched:
            print(
                f"FAIL: {len(matched)} result(s) met or exceeded risk '{fail_threshold}'.",
                file=sys.stderr,
            )
            return 2

    return 0


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
