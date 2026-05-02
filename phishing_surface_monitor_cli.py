from __future__ import annotations

import argparse
import csv
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, List, Set

from analyzers.domain_analyzer import analyze_domain
from analyzers.typosquat_generator import generate_typosquats
from logger import get_logger
from reports.report_generator import generate_json_report, generate_markdown_report

logger = get_logger(__name__)


def _normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value:
        return ""
    try:
        return value.encode("idna").decode("ascii")
    except Exception:
        return value


def _load_known_domains_file(path: str | None) -> Set[str]:
    if not path:
        return set()

    known: Set[str] = set()
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"known domains file not found: {path}")

    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        normalized = _normalize_domain(line)
        if normalized:
            known.add(normalized)
    return known


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan typosquatting variants")
    scan.add_argument("domain", help="Base domain to monitor")
    scan.add_argument("--threshold", type=float, default=0.75)
    scan.add_argument("--top", type=int, default=0)
    scan.add_argument("--max-variants", type=int, default=0)
    scan.add_argument("--hide-benign", action="store_true")
    scan.add_argument("--summary-only", action="store_true")
    scan.add_argument("--report", action="store_true")
    scan.add_argument("--json-report", action="store_true")
    scan.add_argument("--csv-report", action="store_true")
    scan.add_argument("--resolver", default=None)
    scan.add_argument(
        "--known-domains-file",
        default=None,
        help="Path to newline-delimited trusted/owned domains to exclude from generated variants",
    )

    return parser


def _print_scan_summary(total_variants: int, filtered_allowlist: int, remaining: int) -> None:
    print("\nScan summary")
    print(f"- Total generated variants: {total_variants}")
    print(f"- Filtered by allowlist: {filtered_allowlist}")
    print(f"- Remaining analyzed variants: {remaining}")


def _write_csv(results: Iterable, target: str = "scan_report.csv") -> None:
    rows = [asdict(r) for r in results]
    if not rows:
        return
    with open(target, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def run_scan(args: argparse.Namespace) -> int:
    base_domain = _normalize_domain(args.domain)
    known_domains = _load_known_domains_file(args.known_domains_file)

    variants: List[str] = generate_typosquats(base_domain)
    total_variants = len(variants)

    filtered_variants = [v for v in variants if _normalize_domain(v) not in known_domains]
    filtered_allowlist = total_variants - len(filtered_variants)
    remaining = len(filtered_variants)

    if args.max_variants and args.max_variants > 0:
        filtered_variants = filtered_variants[: args.max_variants]
        remaining = len(filtered_variants)

    results = [
        analyze_domain(base_domain, candidate, threshold=args.threshold, resolver=args.resolver)
        for candidate in filtered_variants
    ]

    if args.hide_benign:
        results = [r for r in results if getattr(r, "risk_level", "") != "benign"]

    if args.top and args.top > 0:
        results = sorted(results, key=lambda r: getattr(r, "risk_score", 0), reverse=True)[: args.top]

    if not args.summary_only:
        for r in results:
            print(r)

    _print_scan_summary(total_variants=total_variants, filtered_allowlist=filtered_allowlist, remaining=remaining)

    if args.report:
        generate_markdown_report(base_domain, results)
    if args.json_report:
        generate_json_report(base_domain, results)
    if args.csv_report:
        _write_csv(results)

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        return run_scan(args)

    logger.error("Unknown command")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
