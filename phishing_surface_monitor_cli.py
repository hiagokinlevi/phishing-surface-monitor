import argparse
import json
import sys
from pathlib import Path

from analyzers.dmarc import lookup_dmarc
from monitors.ct_monitor import run_ct_monitor
from monitors.scan import run_scan
from reports.writer import write_csv_report, write_json_report, write_markdown_report


def _print_scan_results(results, top=None, hide_benign=False, min_risk=None, summary_only=False):
    variants_generated = results.get("variants_generated", 0)
    resolved_domains = results.get("resolved_domains", 0)
    findings = results.get("findings", [])

    risk_order = {"high": 3, "medium": 2, "low": 1, "benign": 0}

    filtered = findings
    if min_risk:
        threshold = risk_order.get(min_risk, 0)
        filtered = [f for f in filtered if risk_order.get(f.get("risk", "benign"), 0) >= threshold]

    if hide_benign:
        filtered = [f for f in filtered if f.get("risk") != "benign"]

    filtered = sorted(filtered, key=lambda f: f.get("score", 0), reverse=True)
    if top:
        filtered = filtered[:top]

    high_count = sum(1 for f in findings if f.get("risk") == "high")
    medium_count = sum(1 for f in findings if f.get("risk") == "medium")
    low_count = sum(1 for f in findings if f.get("risk") == "low")

    print(f"Variants generated: {variants_generated}")
    print(f"Resolved domains: {resolved_domains}")
    print(f"High risk: {high_count}")
    print(f"Medium risk: {medium_count}")
    print(f"Low risk: {low_count}")

    if summary_only:
        return

    if not filtered:
        print("No findings matched current filters.")
        return

    print("\nFindings:")
    for item in filtered:
        domain = item.get("domain", "")
        score = item.get("score", 0)
        risk = item.get("risk", "benign")
        resolved = item.get("resolved", False)
        print(f"- {domain} | score={score:.3f} | risk={risk} | resolved={resolved}")


def build_parser():
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run typosquat/phishing surface scan")
    scan_parser.add_argument("domain", help="Primary brand domain to monitor")
    scan_parser.add_argument("--threshold", type=float, default=0.75, help="Similarity threshold")
    scan_parser.add_argument("--top", type=int, default=None, help="Limit displayed findings")
    scan_parser.add_argument("--max-variants", type=int, default=None, help="Cap analyzed generated variants")
    scan_parser.add_argument("--hide-benign", action="store_true", help="Hide benign findings in terminal output")
    scan_parser.add_argument("--min-risk", choices=["low", "medium", "high"], default=None, help="Minimum risk level to display")
    scan_parser.add_argument("--resolver", default=None, help="Custom DNS resolver IP")
    scan_parser.add_argument("--report", action="store_true", help="Write Markdown report artifact")
    scan_parser.add_argument("--json-report", action="store_true", help="Write JSON report artifact")
    scan_parser.add_argument("--csv-report", action="store_true", help="Write CSV report artifact")
    scan_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Show only aggregate totals in terminal output (keeps report/json/csv generation)",
    )

    ct_parser = subparsers.add_parser("ct-monitor", help="Run certificate transparency monitor")
    ct_parser.add_argument("domain", help="Base domain to monitor")
    ct_parser.add_argument("--risk-threshold", type=float, default=0.70, help="Risk threshold")

    dmarc_parser = subparsers.add_parser("dmarc-check", help="Lookup DMARC record for a domain")
    dmarc_parser.add_argument("domain", help="Domain to query")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        results = run_scan(
            domain=args.domain,
            threshold=args.threshold,
            max_variants=args.max_variants,
            resolver=args.resolver,
        )

        _print_scan_results(
            results,
            top=args.top,
            hide_benign=args.hide_benign,
            min_risk=args.min_risk,
            summary_only=args.summary_only,
        )

        output_dir = Path("reports")
        if args.report:
            path = write_markdown_report(results, output_dir=output_dir)
            print(f"Markdown report: {path}")
        if args.json_report:
            path = write_json_report(results, output_dir=output_dir)
            print(f"JSON report: {path}")
        if args.csv_report:
            path = write_csv_report(results, output_dir=output_dir)
            print(f"CSV report: {path}")
        return 0

    if args.command == "ct-monitor":
        events = run_ct_monitor(args.domain, risk_threshold=args.risk_threshold)
        print(json.dumps(events, indent=2))
        return 0

    if args.command == "dmarc-check":
        record = lookup_dmarc(args.domain)
        print(record if record else "No DMARC record found")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
