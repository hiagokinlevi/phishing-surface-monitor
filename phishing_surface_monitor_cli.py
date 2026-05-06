from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

# NOTE:
# This file intentionally keeps imports local for scan execution paths where possible,
# preserving existing startup behavior in environments missing optional dependencies.


def _load_batch_domains(batch_file: str) -> list[str]:
    """Load newline-delimited domains from batch file.

    Production-safe handling:
    - ignores blank lines
    - ignores comment lines beginning with '#'
    - deduplicates while preserving first-seen order
    """
    path = Path(batch_file)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Batch file not found: {batch_file}")

    seen: set[str] = set()
    domains: list[str] = []

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            domains.append(line)

    return domains


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan domain(s) for phishing surface")
    scan.add_argument("domain", nargs="?", help="Root domain to scan (e.g., example.com)")
    scan.add_argument(
        "--batch-file",
        dest="batch_file",
        help="Path to newline-delimited root domains (one per line). Supports comments with '#'.",
    )

    # Existing scan flags (kept broad-compatible with prior behavior)
    scan.add_argument("--threshold", type=float, default=0.75)
    scan.add_argument("--top", type=int)
    scan.add_argument("--max-variants", type=int)
    scan.add_argument("--hide-benign", action="store_true")
    scan.add_argument("--known-domains-file")
    scan.add_argument("--registrable-only", action="store_true")
    scan.add_argument("--report", action="store_true")
    scan.add_argument("--json-report", action="store_true")
    scan.add_argument("--csv-report", action="store_true")
    scan.add_argument("--output-dir")
    scan.add_argument("--summary-only", action="store_true")
    scan.add_argument("--json-stdout", action="store_true")
    scan.add_argument("--csv-stdout", action="store_true")
    scan.add_argument("--csv-delimiter", default=",")
    scan.add_argument("--min-risk")

    return parser


def _run_single_scan(domain: str, args: argparse.Namespace) -> int:
    """Delegate to existing scan implementation.

    This shim expects an existing `run_scan` callable in this module/repo context.
    """
    # Import locally to avoid affecting non-scan commands.
    try:
        from cli.scan import run_scan  # preferred existing location
    except Exception:
        try:
            from cli.scan_command import run_scan  # fallback for alternate naming
        except Exception:
            # Final fallback: if older code keeps function in this file namespace.
            run_scan = globals().get("run_scan")
            if run_scan is None:
                raise RuntimeError("Unable to locate existing scan runner (run_scan)")

    return int(run_scan(domain=domain, args=args) or 0)


def _iter_scan_domains(args: argparse.Namespace) -> Iterable[str]:
    if args.batch_file:
        return _load_batch_domains(args.batch_file)
    if args.domain:
        return [args.domain]
    raise ValueError("scan requires either a domain argument or --batch-file")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 1

    if args.domain and args.batch_file:
        print("error: provide either <domain> or --batch-file, not both", file=sys.stderr)
        return 2

    try:
        domains = list(_iter_scan_domains(args))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not domains:
        print("No domains to scan (batch file contained no valid entries).", file=sys.stderr)
        return 2

    if len(domains) == 1:
        return _run_single_scan(domains[0], args)

    print(f"Starting batch scan for {len(domains)} domains...")
    ok = 0
    failed = 0
    failures: list[tuple[str, str]] = []

    for idx, domain in enumerate(domains, start=1):
        print(f"\n=== [{idx}/{len(domains)}] {domain} ===")
        try:
            rc = _run_single_scan(domain, args)
            if rc == 0:
                ok += 1
            else:
                failed += 1
                failures.append((domain, f"exit_code={rc}"))
        except Exception as exc:
            failed += 1
            failures.append((domain, str(exc)))
            print(f"[error] scan failed for {domain}: {exc}", file=sys.stderr)
            continue

    print("\n=== Batch scan summary ===")
    print(f"Total domains: {len(domains)}")
    print(f"Succeeded: {ok}")
    print(f"Failed: {failed}")
    if failures:
        print("Failures:")
        for domain, reason in failures:
            print(f"- {domain}: {reason}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
