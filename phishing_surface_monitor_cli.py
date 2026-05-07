import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from analyzers.similarity import score_domain_similarity
from analyzers.risk_model import score_risk
from monitors.typosquat import generate_typosquat_variants
from reports.writer import write_markdown_report, write_json_report


def _float_0_1(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a float between 0.0 and 1.0") from exc
    if parsed < 0.0 or parsed > 1.0:
        raise argparse.ArgumentTypeError("must be between 0.0 and 1.0")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a root domain for typosquats")
    scan.add_argument("domain", nargs="?", help="root domain to scan")
    scan.add_argument("--batch-file", help="newline-delimited file of root domains")
    scan.add_argument("--threshold", type=float, default=0.0, help="minimum risk threshold")
    scan.add_argument("--min-risk", type=float, default=None, help="minimum risk filter")
    scan.add_argument("--min-similarity", type=_float_0_1, default=None, help="minimum lexical similarity filter (0.0-1.0)")
    scan.add_argument("--top", type=int, default=None, help="limit output to top N candidates")
    scan.add_argument("--report", action="store_true", help="write markdown report")
    scan.add_argument("--json-report", action="store_true", help="write json report")
    scan.add_argument("--json-stdout", action="store_true", help="print JSON payload to stdout")
    scan.add_argument("--output-dir", default="reports", help="report output directory")

    return parser


def _scan_one_domain(domain: str, args: argparse.Namespace) -> dict[str, Any]:
    variants = generate_typosquat_variants(domain)
    results: list[dict[str, Any]] = []

    for candidate in variants:
        similarity = score_domain_similarity(domain, candidate)
        if args.min_similarity is not None and similarity < args.min_similarity:
            continue

        risk = score_risk(similarity=similarity, domain=candidate)
        item = {
            "root_domain": domain,
            "candidate_domain": candidate,
            "similarity": similarity,
            "risk_score": risk,
        }

        if args.min_risk is not None and risk < args.min_risk:
            continue
        if risk < args.threshold:
            continue

        results.append(item)

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    if args.top is not None:
        results = results[: args.top]

    payload = {"domain": domain, "findings": results}

    out_dir = Path(args.output_dir)
    if args.report:
        out_dir.mkdir(parents=True, exist_ok=True)
        write_markdown_report(payload, out_dir=out_dir)
    if args.json_report:
        out_dir.mkdir(parents=True, exist_ok=True)
        write_json_report(payload, out_dir=out_dir)

    return payload


def _iter_domains(args: argparse.Namespace) -> Iterable[str]:
    if args.batch_file:
        seen: set[str] = set()
        for line in Path(args.batch_file).read_text(encoding="utf-8").splitlines():
            d = line.strip()
            if not d or d.startswith("#") or d in seen:
                continue
            seen.add(d)
            yield d
        return
    if not args.domain:
        raise SystemExit("scan requires DOMAIN or --batch-file")
    yield args.domain


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        all_payloads = [_scan_one_domain(d, args) for d in _iter_domains(args)]
        if args.json_stdout:
            print(json.dumps(all_payloads if len(all_payloads) > 1 else all_payloads[0], indent=2))
            return
        for payload in all_payloads:
            print(f"{payload['domain']}: {len(payload['findings'])} findings")


if __name__ == "__main__":
    main()
