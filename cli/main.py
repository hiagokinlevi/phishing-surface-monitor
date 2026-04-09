"""
CLI entry point for phishing-surface-monitor.

Commands:
  scan BRAND_DOMAIN   Generate typosquat candidates, perform DNS checks,
                      display results, and optionally write a report file.
"""
from __future__ import annotations
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
    """k1n Phishing Surface Monitor — brand domain lookalike detection toolkit."""


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


def main() -> None:
    """Package entry point."""
    cli()


if __name__ == "__main__":
    main()
