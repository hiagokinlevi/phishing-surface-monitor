import argparse
import csv
import json
import os
import sys
from datetime import datetime

from analyzers.typosquat import generate_typosquats
from monitors.dns_monitor import resolve_domain
from reports.report_generator import generate_markdown_report
from reports.json_report import generate_json_report


def _normalize_csv_delimiter(raw_delimiter: str | None) -> str:
    if not raw_delimiter:
        return ","

    normalized = raw_delimiter
    if raw_delimiter == "\\t":
        normalized = "\t"

    if len(normalized) != 1:
        return ","

    return normalized


def _write_csv_rows(rows, output_handle, delimiter: str) -> None:
    writer = csv.DictWriter(
        output_handle,
        fieldnames=["domain", "similarity", "resolves", "risk_level"],
        delimiter=delimiter,
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("domain")
    scan_parser.add_argument("--threshold", type=float, default=0.75)
    scan_parser.add_argument("--top", type=int, default=0)
    scan_parser.add_argument("--report", action="store_true")
    scan_parser.add_argument("--json-report", action="store_true")
    scan_parser.add_argument("--csv-report", action="store_true")
    scan_parser.add_argument(
        "--csv-delimiter",
        default=",",
        help="CSV delimiter for --csv-report/--csv-stdout (default: ','). Supports values like ';' or \\t",
    )
    scan_parser.add_argument("--csv-stdout", action="store_true")
    scan_parser.add_argument("--output-dir", default="reports")

    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        return

    candidates = generate_typosquats(args.domain)
    findings = []

    for candidate in candidates:
        resolves = resolve_domain(candidate)
        similarity = 1.0 if candidate == args.domain else 0.8
        risk_level = "high" if resolves and similarity >= args.threshold else "low"
        findings.append(
            {
                "domain": candidate,
                "similarity": round(similarity, 3),
                "resolves": resolves,
                "risk_level": risk_level,
            }
        )

    findings = sorted(findings, key=lambda x: x["similarity"], reverse=True)
    if args.top and args.top > 0:
        findings = findings[: args.top]

    csv_delimiter = _normalize_csv_delimiter(args.csv_delimiter)

    if args.csv_stdout:
        _write_csv_rows(findings, sys.stdout, csv_delimiter)

    if args.report or args.json_report or args.csv_report:
        os.makedirs(args.output_dir, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        if args.report:
            md_path = os.path.join(args.output_dir, f"scan_{ts}.md")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(generate_markdown_report(args.domain, findings))

        if args.json_report:
            json_path = os.path.join(args.output_dir, f"scan_{ts}.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(generate_json_report(args.domain, findings), f, indent=2)

        if args.csv_report:
            csv_path = os.path.join(args.output_dir, f"scan_{ts}.csv")
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                _write_csv_rows(findings, f, csv_delimiter)


if __name__ == "__main__":
    main()
