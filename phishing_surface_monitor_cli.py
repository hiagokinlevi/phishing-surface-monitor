from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from analyzers.dmarc import check_dmarc
from analyzers.typosquat import generate_typosquat_variants
from monitors.ct_monitor import monitor_ct_logs
from reports.writer import write_json_report, write_markdown_report, write_csv_report
from schemas.scan_result import ScanResult

app = typer.Typer(help="Defensive brand protection toolkit for phishing surface monitoring.")


@app.command("scan")
def scan_command(
    domain: str = typer.Argument(..., help="Primary brand domain to monitor (e.g., example.com)"),
    threshold: float = typer.Option(0.75, "--threshold", help="Similarity threshold (0.0-1.0)"),
    top: Optional[int] = typer.Option(None, "--top", help="Show only top N risk-ranked results"),
    min_risk: Optional[str] = typer.Option(None, "--min-risk", help="Filter output by minimum risk level"),
    hide_benign: bool = typer.Option(False, "--hide-benign", help="Hide benign findings from terminal output"),
    max_variants: Optional[int] = typer.Option(
        None,
        "--max-variants",
        min=1,
        help="Cap generated typosquatting variants analyzed (applied before DNS/similarity checks)",
    ),
    resolver: Optional[str] = typer.Option(None, "--resolver", help="Custom DNS resolver IP (e.g., 1.1.1.1)"),
    report: bool = typer.Option(False, "--report", help="Write Markdown report artifact"),
    json_report: bool = typer.Option(False, "--json-report", help="Write JSON report artifact"),
    csv_report: bool = typer.Option(False, "--csv-report", help="Write CSV report artifact"),
) -> None:
    """Run typosquatting scan and optional report generation."""
    variants = generate_typosquat_variants(domain)
    if max_variants is not None:
        variants = variants[:max_variants]

    # Existing downstream scan/analyze behavior should remain unchanged; only input candidate set is reduced.
    result = ScanResult.run(
        domain=domain,
        variants=variants,
        threshold=threshold,
        resolver=resolver,
        top=top,
        min_risk=min_risk,
        hide_benign=hide_benign,
    )

    typer.echo(result.to_table())

    if report:
        path = write_markdown_report(result)
        typer.echo(f"Markdown report written: {path}")
    if json_report:
        path = write_json_report(result)
        typer.echo(f"JSON report written: {path}")
    if csv_report:
        path = write_csv_report(result)
        typer.echo(f"CSV report written: {path}")


@app.command("ct-monitor")
def ct_monitor_command(
    domain: str = typer.Argument(..., help="Domain to monitor in CT logs"),
    risk_threshold: float = typer.Option(0.70, "--risk-threshold", help="Risk threshold for alerts"),
) -> None:
    findings = monitor_ct_logs(domain, risk_threshold=risk_threshold)
    typer.echo(json.dumps(findings, indent=2))


@app.command("dmarc-check")
def dmarc_check_command(domain: str = typer.Argument(..., help="Domain to inspect DMARC policy for")) -> None:
    result = check_dmarc(domain)
    typer.echo(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
