import argparse
import json
import os
from datetime import datetime
from typing import Any

from analyzers.domain_analyzer import analyze_domain
from reports.report_generator import generate_json_report, generate_markdown_report


def _print_scan_table(results: list[dict[str, Any]], hide_benign: bool = False, summary_only: bool = False) -> None:
    if summary_only:
        total = len(results)
        critical = sum(1 for r in results if r.get("risk_level") == "critical")
        high = sum(1 for r in results if r.get("risk_level") == "high")
        medium = sum(1 for r in results if r.get("risk_level") == "medium")
        low = sum(1 for r in results if r.get("risk_level") == "low")
        benign = sum(1 for r in results if r.get("risk_level") == "benign")
        print(f"Scan summary: total={total} critical={critical} high={high} medium={medium} low={low} benign={benign}")
        return

    print("domain\tscore\trisk\tresolved")
    for row in results:
        if hide_benign and row.get("risk_level") == "benign":
            continue
        print(
            f"{row.get('domain', '')}\t{row.get('similarity', 0):.2f}\t{row.get('risk_level', '')}\t{row.get('dns_resolves', False)}"
        )


def run_scan(args: argparse.Namespace) -> int:
    result = analyze_domain(
        args.domain,
        threshold=args.threshold,
        top=args.top,
        max_variants=args.max_variants,
        min_risk=args.min_risk,
        resolver=args.resolver,
        known_domains_file=args.known_domains_file,
        registrable_only=args.registrable_only,
    )

    findings = result.get("findings", [])
    _print_scan_table(findings, hide_benign=args.hide_benign, summary_only=args.summary_only)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output_dir or "reports"
    os.makedirs(output_dir, exist_ok=True)

    if args.report:
        md_path = os.path.join(output_dir, f"scan_{args.domain}_{timestamp}.md")
        generate_markdown_report(result, md_path)
        print(f"Markdown report: {md_path}")

    if args.json_report:
        json_path = os.path.join(output_dir, f"scan_{args.domain}_{timestamp}.json")
        generate_json_report(result, json_path)
        print(f"JSON report: {json_path}")

    if args.csv_report:
        csv_path = os.path.join(output_dir, f"scan_{args.domain}_{timestamp}.csv")
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("domain,similarity,risk_level,dns_resolves\n")
            for row in findings:
                f.write(
                    f"{row.get('domain', '')},{row.get('similarity', 0)},{row.get('risk_level', '')},{row.get('dns_resolves', False)}\n"
                )
        print(f"CSV report: {csv_path}")

    if args.json_stdout:
        print(json.dumps(result, ensure_ascii=False))

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run typosquat scan")
    scan.add_argument("domain")
    scan.add_argument("--threshold", type=float, default=0.75)
    scan.add_argument("--top", type=int, default=25)
    scan.add_argument("--max-variants", type=int, default=None)
    scan.add_argument("--min-risk", default=None)
    scan.add_argument("--hide-benign", action="store_true")
    scan.add_argument("--summary-only", action="store_true")
    scan.add_argument("--report", action="store_true")
    scan.add_argument("--json-report", action="store_true")
    scan.add_argument("--csv-report", action="store_true")
    scan.add_argument("--json-stdout", action="store_true", help="Print final scan JSON payload to stdout")
    scan.add_argument("--output-dir", default=None)
    scan.add_argument("--resolver", default=None)
    scan.add_argument("--known-domains-file", default=None)
    scan.add_argument("--registrable-only", action="store_true")
    scan.set_defaults(func=run_scan)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
