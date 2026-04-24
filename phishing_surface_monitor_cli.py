import argparse
import json
from datetime import datetime

from analyzers.dmarc_check import check_dmarc
from analyzers.link_triage import triage_url
from analyzers.typosquat import find_typosquats
from monitors.ct_monitor import monitor_ct
from reports.report_generator import generate_markdown_report, generate_json_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-monitor",
        description="Defensive brand protection toolkit for phishing surface monitoring.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run typosquat scan")
    scan_parser.add_argument("domain", help="Target domain")
    scan_parser.add_argument("--threshold", type=float, default=0.75, help="Similarity threshold")
    scan_parser.add_argument("--min-risk", choices=["low", "medium", "high"], help="Minimum risk to display")
    scan_parser.add_argument("--report", action="store_true", help="Generate markdown report")
    scan_parser.add_argument("--json-report", action="store_true", help="Generate JSON report")

    ct_parser = subparsers.add_parser("ct-monitor", help="Monitor certificate transparency logs")
    ct_parser.add_argument("domain", help="Target domain")
    ct_parser.add_argument("--json", action="store_true", help="Emit JSON output")
    ct_parser.add_argument(
        "--since-hours",
        type=int,
        default=24,
        help="Only include certificate events from the last N hours (default: 24)",
    )

    dmarc_parser = subparsers.add_parser("dmarc-check", help="Check DMARC record")
    dmarc_parser.add_argument("domain", help="Domain to check")

    triage_parser = subparsers.add_parser("link-triage", help="Offline suspicious URL triage")
    triage_parser.add_argument("url", help="URL to triage")
    triage_parser.add_argument("--json", action="store_true", help="Emit JSON output")
    triage_parser.add_argument(
        "--fail-on-suspicious",
        action="store_true",
        help="Exit non-zero when URL is suspicious",
    )

    return parser


def _risk_rank(level: str) -> int:
    ranks = {"low": 1, "medium": 2, "high": 3}
    return ranks.get(level.lower(), 0)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        results = find_typosquats(args.domain, similarity_threshold=args.threshold)

        if args.min_risk:
            min_rank = _risk_rank(args.min_risk)
            results = [r for r in results if _risk_rank(r.get("risk_level", "low")) >= min_rank]

        print(f"[+] Found {len(results)} suspicious domains for {args.domain}")
        for r in results:
            print(
                f" - {r['domain']} | similarity={r['similarity']} | dns_active={r['dns_active']} | risk={r['risk_level']}"
            )

        if args.report:
            md_path = generate_markdown_report(args.domain, results)
            print(f"[+] Markdown report written: {md_path}")

        if args.json_report:
            payload = {
                "target": args.domain,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "count": len(results),
                "results": results,
            }
            json_path = generate_json_report(args.domain, payload)
            print(f"[+] JSON report written: {json_path}")

        return 0

    if args.command == "ct-monitor":
        ct_results = monitor_ct(args.domain, since_hours=args.since_hours)
        if args.json:
            print(json.dumps(ct_results, indent=2))
        else:
            print(f"[+] CT monitor for {args.domain}")
            print(f"[+] Window: last {ct_results.get('since_hours', args.since_hours)} hour(s)")
            for ev in ct_results.get("events", []):
                cn = ev.get("common_name") or "-"
                ts = ev.get("observed_at") or ev.get("entry_timestamp") or ev.get("not_before") or "-"
                print(f" - {ev.get('domain', '-')}: CN={cn}, ts={ts}")
        return 0

    if args.command == "dmarc-check":
        result = check_dmarc(args.domain)
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "link-triage":
        result = triage_url(args.url)

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            status = "suspicious" if result.get("suspicious") else "benign"
            print(f"[+] URL triage result: {status}")
            for finding in result.get("findings", []):
                print(f" - {finding.get('code')}: {finding.get('message')}")

        if args.fail_on_suspicious and result.get("suspicious"):
            return 2
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
