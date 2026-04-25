import argparse
import json
from pathlib import Path

from analyzers.typosquat import generate_typosquat_variants, score_similarity
from monitors.dns_monitor import check_dns_resolution
from reports.generator import generate_markdown_report, generate_json_report


def _build_scan_parser(subparsers: argparse._SubParsersAction) -> None:
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan for typosquatted domains and assess risk",
        description="Generate candidate lookalike domains, run DNS checks, score risk, and optionally write reports.",
    )
    scan_parser.add_argument("domain", help="Base domain to monitor (e.g., example.com)")
    scan_parser.add_argument("--threshold", type=float, default=0.75, help="Minimum similarity threshold (default: 0.75)")
    scan_parser.add_argument("--min-risk", choices=["low", "medium", "high"], help="Only include findings at or above this risk level")
    scan_parser.add_argument(
        "--only-resolved",
        action="store_true",
        help="Only include domains with successful DNS resolution in output and reports",
    )
    scan_parser.add_argument("--report", action="store_true", help="Write Markdown report")
    scan_parser.add_argument("--json-report", action="store_true", help="Write JSON report")


def _risk_rank(level: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(level, 0)


def run_scan(args: argparse.Namespace) -> int:
    variants = generate_typosquat_variants(args.domain)
    findings = []

    for candidate in variants:
        similarity = score_similarity(args.domain, candidate)
        if similarity < args.threshold:
            continue

        dns = check_dns_resolution(candidate)
        resolved = bool(dns.get("resolved", False))

        if similarity >= 0.9 and resolved:
            risk = "high"
        elif similarity >= 0.85 or resolved:
            risk = "medium"
        else:
            risk = "low"

        findings.append(
            {
                "base_domain": args.domain,
                "candidate_domain": candidate,
                "similarity": round(similarity, 4),
                "dns": dns,
                "resolved": resolved,
                "risk": risk,
            }
        )

    if args.min_risk:
        min_rank = _risk_rank(args.min_risk)
        findings = [f for f in findings if _risk_rank(f.get("risk", "low")) >= min_rank]

    if args.only_resolved:
        findings = [f for f in findings if f.get("resolved")]

    for f in findings:
        print(f"{f['candidate_domain']} | similarity={f['similarity']} | resolved={f['resolved']} | risk={f['risk']}")

    if args.report:
        report_path = generate_markdown_report(args.domain, findings)
        print(f"Markdown report written: {report_path}")

    if args.json_report:
        json_path = generate_json_report(args.domain, findings)
        print(f"JSON report written: {json_path}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    _build_scan_parser(subparsers)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        return run_scan(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
