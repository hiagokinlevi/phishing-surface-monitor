from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from cli.scan import run_scan


COMMON_REGISTRABLE_SUFFIXES = {
    "com",
    "net",
    "org",
    "io",
    "co",
    "ai",
    "app",
    "dev",
    "info",
    "biz",
    "us",
    "uk",
    "co.uk",
    "ca",
    "au",
    "co.au",
    "de",
    "fr",
    "nl",
    "jp",
    "in",
    "ch",
    "it",
    "es",
}


def _extract_suffix(domain: str) -> str:
    d = (domain or "").strip(".").lower()
    if not d or "." not in d:
        return ""
    labels = d.split(".")
    if len(labels) < 2:
        return ""
    # support common 2-label public suffixes in allowlist (e.g., co.uk)
    if len(labels) >= 3:
        two = ".".join(labels[-2:])
        if two in COMMON_REGISTRABLE_SUFFIXES:
            return two
    return labels[-1]


def _is_registrable_suffix(domain: str) -> bool:
    suffix = _extract_suffix(domain)
    return suffix in COMMON_REGISTRABLE_SUFFIXES


@click.group()
def cli() -> None:
    """phishing-surface-monitor CLI"""


@cli.command("scan")
@click.argument("target_domain")
@click.option("--threshold", default=0.75, show_default=True, type=float, help="Minimum similarity threshold.")
@click.option("--top", default=None, type=int, help="Limit output to top N risk-ranked candidates.")
@click.option("--max-variants", default=None, type=int, help="Cap analyzed generated variants.")
@click.option("--hide-benign", is_flag=True, help="Hide low/benign findings in terminal output.")
@click.option("--known-domains-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None, help="Newline-delimited trusted/owned domains to exclude.")
@click.option("--report", is_flag=True, help="Write Markdown report artifact.")
@click.option("--json-report", is_flag=True, help="Write JSON report artifact.")
@click.option("--csv-report", is_flag=True, help="Write CSV report artifact.")
@click.option("--output-dir", type=click.Path(file_okay=False, path_type=Path), default=None, help="Output directory for report artifacts.")
@click.option("--summary-only", is_flag=True, help="Print aggregate-only terminal summary.")
@click.option("--resolver", default=None, type=str, help="Custom DNS resolver IP.")
@click.option(
    "--registrable-only",
    is_flag=True,
    help="Exclude generated variants with TLD/public suffixes outside a maintained registrable allowlist (reduces low-value noise).",
)
def scan(
    target_domain: str,
    threshold: float,
    top: Optional[int],
    max_variants: Optional[int],
    hide_benign: bool,
    known_domains_file: Optional[Path],
    report: bool,
    json_report: bool,
    csv_report: bool,
    output_dir: Optional[Path],
    summary_only: bool,
    resolver: Optional[str],
    registrable_only: bool,
) -> None:
    known_domains = None
    if known_domains_file:
        known_domains = {
            line.strip().lower()
            for line in known_domains_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }

    results = run_scan(
        target_domain=target_domain,
        threshold=threshold,
        top=top,
        max_variants=max_variants,
        hide_benign=hide_benign,
        known_domains=known_domains,
        report=report,
        json_report=json_report,
        csv_report=csv_report,
        output_dir=output_dir,
        summary_only=summary_only,
        resolver=resolver,
    )

    if registrable_only and isinstance(results, dict) and "findings" in results:
        findings = results.get("findings") or []
        results["findings"] = [f for f in findings if _is_registrable_suffix(str(f.get("domain", "")))]

    click.echo(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    cli()
