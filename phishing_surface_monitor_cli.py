import argparse
import json
from datetime import datetime

from analyzers.domain_analyzer import analyze_domain_candidates
from reports.markdown_report import generate_markdown_report
from reports.json_report import generate_json_report


def _print_scan_results(results):
    if not results:
        print("No candidates found.")
        return

    for r in results:
        domain = r.get("domain", "")
        score = r.get("risk_score", 0)
        risk = r.get("risk_level", "unknown")
        similarity = r.get("similarity", 0)
        dns_resolves = r.get("dns_resolves", False)
        print(
            f"{domain:35} risk={score:.2f} level={risk:8} similarity={similarity:.2f} dns={dns_resolves}"
        )


def handle_scan(args):
    results = analyze_domain_candidates(
        target_domain=args.domain,
        threshold=args.threshold,
        min_risk=args.min_risk,
    )

    # Ensure highest-risk-first ordering before applying top limit.
    results = sorted(results, key=lambda x: x.get("risk_score", 0), reverse=True)

    if args.top is not None:
        results = results[: args.top]

    _print_scan_results(results)

    if args.report:
        md_path = generate_markdown_report(
            target_domain=args.domain,
            results=results,
            generated_at=datetime.utcnow().isoformat() + "Z",
        )
        print(f"Markdown report written: {md_path}")

    if args.json_report:
        json_path = generate_json_report(
            target_domain=args.domain,
            results=results,
            generated_at=datetime.utcnow().isoformat() + "Z",
        )
        print(f"JSON report written: {json_path}")


def build_parser():
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan for potential phishing domains")
    scan_parser.add_argument("domain", help="Primary domain to protect")
    scan_parser.add_argument("--threshold", type=float, default=0.75, help="Similarity threshold")
    scan_parser.add_argument(
        "--min-risk",
        type=float,
        default=0.0,
        help="Minimum risk score to include in output",
    )
    scan_parser.add_argument(
        "--top",
        type=int,
        default=None,
        help="Return only the top N highest-risk candidates after scoring/sorting",
    )
    scan_parser.add_argument("--report", action="store_true", help="Generate Markdown report")
    scan_parser.add_argument("--json-report", action="store_true", help="Generate JSON report")
    scan_parser.set_defaults(func=handle_scan)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, "top", None) is not None and args.top < 1:
        parser.error("--top must be a positive integer")

    args.func(args)


if __name__ == "__main__":
    main()
