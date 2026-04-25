import argparse
from analyzers.typosquat import run_scan
from reports.generator import write_markdown_report, write_json_report


def _risk_rank(risk: str) -> int:
    order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "benign": 0,
    }
    return order.get((risk or "").strip().lower(), -1)


def _print_scan_results(results, min_risk=None, hide_benign=False, top=None):
    filtered = list(results)

    if min_risk:
        threshold = _risk_rank(min_risk)
        filtered = [r for r in filtered if _risk_rank(r.get("risk_level")) >= threshold]

    if hide_benign:
        filtered = [
            r for r in filtered if (r.get("risk_level") or "").strip().lower() not in {"low", "benign"}
        ]

    filtered.sort(key=lambda r: _risk_rank(r.get("risk_level")), reverse=True)

    if top is not None:
        filtered = filtered[:top]

    if not filtered:
        print("No findings to display with current output filters.")
        return

    print("domain\trisk\tsimilarity\tresolves")
    for item in filtered:
        print(
            f"{item.get('domain')}\t{item.get('risk_level')}\t{item.get('similarity')}\t{item.get('resolves')}"
        )


def main():
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run typosquat scan")
    scan_parser.add_argument("domain", help="Brand domain to monitor")
    scan_parser.add_argument("--threshold", type=float, default=0.75, help="Similarity threshold")
    scan_parser.add_argument("--top", type=int, default=None, help="Show top N results")
    scan_parser.add_argument(
        "--min-risk",
        choices=["benign", "low", "medium", "high", "critical"],
        default=None,
        help="Minimum risk level to display in terminal output",
    )
    scan_parser.add_argument(
        "--hide-benign",
        action="store_true",
        help="Hide low/benign findings from terminal output (reports are unchanged)",
    )
    scan_parser.add_argument("--report", action="store_true", help="Write markdown report")
    scan_parser.add_argument("--json-report", action="store_true", help="Write JSON report")

    args = parser.parse_args()

    if args.command == "scan":
        results = run_scan(args.domain, similarity_threshold=args.threshold)

        _print_scan_results(
            results,
            min_risk=args.min_risk,
            hide_benign=args.hide_benign,
            top=args.top,
        )

        if args.report:
            write_markdown_report(args.domain, results)
        if args.json_report:
            write_json_report(args.domain, results)


if __name__ == "__main__":
    main()
