"""
CLI entry point for phishing-surface-monitor.

Commands:
  scan BRAND_DOMAIN   Generate typosquat candidates, perform DNS checks,
                      display results, and optionally write a report file.
  ct-monitor BRAND_DOMAIN  Monitor CT logs for new registrations and wildcard alerts.
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

# Ensure project root is importable when running directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzers.typosquatting.detector import generate_typosquats
from analyzers.dns_checker import check_dns
from analyzers.ct_monitor import query_ct_logs
from analyzers.ct_alerts import (
    evaluate_ct_alerts,
    load_ct_state,
    merge_known_certificate_ids,
    save_ct_state,
)
from schemas.case import BrandFinding, compute_risk
from reports.generator import generate_markdown_report, generate_json_report

console = Console()

# Risk-level colour mapping for the rich table
_RISK_COLOURS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


@click.group()
def cli() -> None:
    """Phishing Surface Monitor — brand domain lookalike detection toolkit."""


@cli.command()
@click.argument("brand_domain")
@click.option(
    "--threshold",
    "-t",
    default=0.70,
    show_default=True,
    type=float,
    help="Minimum similarity score (0.0–1.0) to include a candidate.",
)
@click.option(
    "--report",
    "-r",
    is_flag=False,
    flag_value="",
    default=None,
    help="Write a Markdown report. Optionally provide a path; defaults to ./reports-output/<brand>.md.",
)
@click.option(
    "--json-report",
    "-j",
    is_flag=True,
    default=False,
    help="Also write a JSON report alongside the Markdown report.",
)
@click.option(
    "--dns/--no-dns",
    default=True,
    show_default=True,
    help="Toggle DNS resolution checks (disable for offline/dry-run mode).",
)
def scan(
    brand_domain: str,
    threshold: float,
    report: str | None,
    json_report: bool,
    dns: bool,
) -> None:
    """
    Scan BRAND_DOMAIN for lookalike typosquatting candidates.

    Generates domain variants, scores similarity, optionally checks DNS,
    and prints a rich summary table. Use --report to persist results.

    Example:

        phishing-monitor scan example.com --threshold 0.75 --report
    """
    console.rule(f"[bold blue]Scanning: {brand_domain}[/bold blue]")

    # 1. Generate all typosquat variants
    console.print(f"[dim]Generating typosquat candidates for [bold]{brand_domain}[/bold]...[/dim]")
    variants = generate_typosquats(brand_domain)

    # 2. Filter by similarity threshold
    above_threshold = [v for v in variants if v.similarity_score >= threshold]
    console.print(
        f"[dim]{len(variants)} total variants — [bold]{len(above_threshold)}[/bold] "
        f"above threshold ({threshold:.2f})[/dim]\n"
    )

    if not above_threshold:
        console.print("[green]No candidates above threshold. Brand looks clean.[/green]")
        return

    findings: list[BrandFinding] = []

    # 3. DNS checks and finding construction
    with console.status("[bold cyan]Checking DNS...[/bold cyan]") as status:
        for variant in above_threshold:
            if dns:
                dns_result = check_dns(variant.domain)
                resolves = dns_result.resolves
                a_records = dns_result.a_records
            else:
                # Offline mode: skip actual resolution
                resolves = False
                a_records = []

            risk = compute_risk(variant.similarity_score, resolves)

            findings.append(BrandFinding(
                brand_domain=brand_domain,
                lookalike_domain=variant.domain,
                technique=variant.technique,
                similarity_score=variant.similarity_score,
                resolves=resolves,
                a_records=a_records,
                risk_level=risk,
            ))

    # 4. Build and print rich table
    table = Table(
        title=f"Lookalike Candidates for {brand_domain}",
        box=box.ROUNDED,
        show_lines=False,
        highlight=True,
    )
    table.add_column("Domain", style="bold white", no_wrap=True)
    table.add_column("Technique", style="dim")
    table.add_column("Similarity", justify="right")
    table.add_column("Resolves", justify="center")
    table.add_column("IPs", style="dim")
    table.add_column("Risk", justify="center")

    # Sort by risk severity then similarity
    _risk_order = ["critical", "high", "medium", "low", "info"]
    findings_sorted = sorted(
        findings,
        key=lambda f: (_risk_order.index(f.risk_level.value), -f.similarity_score),
    )

    for f in findings_sorted:
        colour = _RISK_COLOURS.get(f.risk_level.value, "white")
        resolves_str = "[green]YES[/green]" if f.resolves else "[dim]no[/dim]"
        ips_str = ", ".join(f.a_records) if f.a_records else "—"
        table.add_row(
            f.lookalike_domain,
            f.technique,
            f"{f.similarity_score:.3f}",
            resolves_str,
            ips_str,
            f"[{colour}]{f.risk_level.value.upper()}[/{colour}]",
        )

    console.print(table)

    # Summary counts
    resolving_count = sum(1 for f in findings if f.resolves)
    console.print(
        f"\n[bold]Summary:[/bold] {len(findings)} findings — "
        f"[red]{resolving_count} actively resolving[/red]\n"
    )

    # 5. Write reports if requested
    if report is not None:
        # Determine output path
        if report == "":
            # Default output location
            out_dir_env = os.environ.get("REPORT_OUTPUT_DIR", "./reports-output")
            out_dir = Path(out_dir_env)
        else:
            out_dir = Path(report).parent
            # If user passed a directory path, use it directly
            if Path(report).is_dir():
                out_dir = Path(report)

        out_dir.mkdir(parents=True, exist_ok=True)

        # Sanitise domain for filename
        safe_domain = brand_domain.replace(".", "_")
        md_path = out_dir / f"{safe_domain}_report.md"
        md_path.write_text(generate_markdown_report(findings, brand_domain), encoding="utf-8")
        console.print(f"[green]Markdown report written:[/green] {md_path}")

        if json_report:
            json_path = out_dir / f"{safe_domain}_report.json"
            json_path.write_text(generate_json_report(findings), encoding="utf-8")
            console.print(f"[green]JSON report written:[/green] {json_path}")


@cli.command("ct-monitor")
@click.argument("brand_domain")
@click.option(
    "--state-file",
    default=None,
    help="Path to state file with known CT certificate IDs (default: .ct-state/<brand>.json).",
)
@click.option(
    "--include-subdomains/--root-only",
    default=True,
    show_default=True,
    help="Query crt.sh using wildcard subdomain pattern (%.brand.tld) or root-only.",
)
@click.option(
    "--timeout",
    default=10.0,
    show_default=True,
    type=float,
    help="HTTP timeout for crt.sh query.",
)
@click.option(
    "--output-json",
    default=None,
    help="Optional output path for JSON alert report.",
)
@click.option(
    "--fail-on-alerts",
    is_flag=True,
    default=False,
    help="Return exit code 1 if any alert is detected.",
)
def ct_monitor(
    brand_domain: str,
    state_file: str | None,
    include_subdomains: bool,
    timeout: float,
    output_json: str | None,
    fail_on_alerts: bool,
) -> None:
    """Monitor CT logs for new registrations and wildcard certificate alerts."""
    safe_domain = brand_domain.replace(".", "_")
    state_path = Path(state_file) if state_file else Path(".ct-state") / f"{safe_domain}.json"

    console.rule(f"[bold blue]CT Monitor: {brand_domain}[/bold blue]")
    console.print("[dim]Querying crt.sh public CT logs...[/dim]")
    certs = query_ct_logs(
        brand_domain,
        include_subdomains=include_subdomains,
        timeout=timeout,
        deduplicate=True,
    )
    if not certs:
        console.print("[yellow]No CT records returned (or query failed).[/yellow]")
        return

    known_ids = load_ct_state(state_path)
    batch = evaluate_ct_alerts(
        brand_domain=brand_domain,
        certs=certs,
        known_certificate_ids=known_ids,
    )
    merged_ids = merge_known_certificate_ids(known_ids, certs)
    save_ct_state(
        state_path,
        brand_domain=brand_domain,
        known_certificate_ids=merged_ids,
        checked_at=batch.checked_at,
    )

    table = Table(
        title=f"CT Alerts for {brand_domain}",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("Type", style="bold white")
    table.add_column("Severity", justify="center")
    table.add_column("CN", style="dim")
    table.add_column("Cert ID", justify="right")
    table.add_column("Issuer", style="dim")

    severity_colours = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
    }

    for alert in batch.all_alerts():
        colour = severity_colours.get(alert.severity, "white")
        table.add_row(
            alert.alert_type,
            f"[{colour}]{alert.severity.upper()}[/{colour}]",
            alert.common_name or "—",
            str(alert.cert_id),
            alert.issuer or "—",
        )

    if batch.all_alerts():
        console.print(table)
    else:
        console.print("[green]No CT alerts detected for lookalike certificates.[/green]")

    console.print(
        "[bold]Summary:[/bold] "
        f"total={batch.total_certificates}, "
        f"lookalikes={batch.lookalike_certificates}, "
        f"new={len(batch.new_registration_alerts)}, "
        f"wildcard={len(batch.wildcard_alerts)}"
    )
    console.print(f"[dim]State updated: {state_path}[/dim]")

    if output_json:
        output_path = Path(output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(batch.to_dict(), indent=2),
            encoding="utf-8",
        )
        console.print(f"[green]JSON alert report written:[/green] {output_path}")

    if fail_on_alerts and batch.all_alerts():
        sys.exit(1)


def main() -> None:
    """Package entry point."""
    cli()


if __name__ == "__main__":
    main()
