"""
CLI entry point for phishing-surface-monitor.

Commands:
  scan BRAND_DOMAIN   Generate typosquat candidates, perform DNS checks,
                      display results, and optionally write a report file.
  ct-monitor BRAND_DOMAIN  Monitor CT logs for new registrations and wildcard alerts.
  email-posture BRAND_DOMAIN [CANDIDATE_DOMAINS...]  Analyze lookalike email-abuse posture.
"""
from __future__ import annotations
import json
import os
import re
import sys
from pathlib import Path

import click
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
except ModuleNotFoundError:  # pragma: no cover - exercised via CLI tests
    class _PlainStatus:
        def __init__(self, console: "Console", message: str) -> None:
            self.console = console
            self.message = message

        def __enter__(self) -> "_PlainStatus":
            self.console.print(self.message)
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    class Console:
        def print(self, *args, **kwargs) -> None:
            parts = []
            for arg in args:
                parts.append(re.sub(r"\[/?[^\]]+\]", "", str(arg)))
            print(*parts)

        def rule(self, text: str) -> None:
            self.print(text)

        def status(self, message: str) -> _PlainStatus:
            return _PlainStatus(self, message)

    class Table:
        def __init__(self, title: str | None = None, **kwargs) -> None:
            self.title = title
            self.columns: list[str] = []
            self.rows: list[list[str]] = []

        def add_column(self, label: str, **kwargs) -> None:
            self.columns.append(label)

        def add_row(self, *values: str) -> None:
            self.rows.append([re.sub(r"\[/?[^\]]+\]", "", str(value)) for value in values])

        def __str__(self) -> str:
            lines: list[str] = []
            if self.title:
                lines.append(self.title)
            if self.columns:
                lines.append(" | ".join(self.columns))
                lines.append("-+-".join("-" * len(col) for col in self.columns))
            for row in self.rows:
                lines.append(" | ".join(row))
            return "\n".join(lines)

    class _Box:
        ROUNDED = None

    box = _Box()

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
from analyzers.hostname_validation import normalize_hostname
from analyzers.email_security.mx_spf_checker import (
    DEFAULT_DKIM_SELECTORS,
    check_email_posture,
)
from analyzers.url_deobfuscator import analyze_many as analyze_urls
from reports.generator import generate_markdown_report, generate_json_report
from reports.takedown_case import (
    create_takedown_case_bundle,
    load_findings_json,
    update_takedown_case_status,
)
from schemas.case import BrandFinding, CaseStatus, compute_risk

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
    try:
        normalized_brand_domain = normalize_hostname(brand_domain)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="brand_domain") from exc

    safe_domain = normalized_brand_domain.replace(".", "_")
    state_path = Path(state_file) if state_file else Path(".ct-state") / f"{safe_domain}.json"

    console.rule(f"[bold blue]CT Monitor: {normalized_brand_domain}[/bold blue]")
    console.print("[dim]Querying crt.sh public CT logs...[/dim]")
    try:
        certs = query_ct_logs(
            normalized_brand_domain,
            include_subdomains=include_subdomains,
            timeout=timeout,
            deduplicate=True,
        )
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--timeout") from exc
    if not certs:
        console.print("[yellow]No CT records returned (or query failed).[/yellow]")
        return

    known_ids = load_ct_state(state_path)
    batch = evaluate_ct_alerts(
        brand_domain=normalized_brand_domain,
        certs=certs,
        known_certificate_ids=known_ids,
    )
    merged_ids = merge_known_certificate_ids(known_ids, certs)
    save_ct_state(
        state_path,
        brand_domain=normalized_brand_domain,
        known_certificate_ids=merged_ids,
        checked_at=batch.checked_at,
    )

    table = Table(
        title=f"CT Alerts for {normalized_brand_domain}",
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


@cli.command("email-posture")
@click.argument("brand_domain")
@click.argument("candidate_domains", nargs=-1)
@click.option(
    "--threshold",
    default=0.78,
    show_default=True,
    type=float,
    help="Minimum similarity score when auto-generating lookalike domains.",
)
@click.option(
    "--limit",
    default=12,
    show_default=True,
    type=int,
    help="Maximum number of auto-generated lookalike domains to analyze.",
)
@click.option(
    "--timeout",
    default=3.0,
    show_default=True,
    type=float,
    help="DNS timeout for each lookup.",
)
@click.option(
    "--selector",
    "selectors",
    multiple=True,
    help="Additional DKIM selector to test. Can be provided multiple times.",
)
@click.option(
    "--output-json",
    default=None,
    help="Optional output path for a JSON posture report.",
)
def email_posture(
    brand_domain: str,
    candidate_domains: tuple[str, ...],
    threshold: float,
    limit: int,
    timeout: float,
    selectors: tuple[str, ...],
    output_json: str | None,
) -> None:
    """Analyze MX/SPF/DKIM/DMARC gaps on explicit or generated lookalike domains."""
    if candidate_domains:
        similarity_map = {domain: None for domain in candidate_domains}
    else:
        generated = [
            variant for variant in generate_typosquats(brand_domain)
            if variant.similarity_score >= threshold
        ][:limit]
        similarity_map = {variant.domain: variant.similarity_score for variant in generated}

    if not similarity_map:
        console.print("[yellow]No candidate domains selected for email posture analysis.[/yellow]")
        return

    selector_list = list(selectors) if selectors else list(DEFAULT_DKIM_SELECTORS)
    console.rule(f"[bold blue]Email Posture: {brand_domain}[/bold blue]")
    console.print(
        f"[dim]Analyzing {len(similarity_map)} candidate domains with {len(selector_list)} DKIM selector checks.[/dim]"
    )

    results = []
    for domain, similarity in similarity_map.items():
        posture = check_email_posture(domain, timeout=timeout, dkim_selectors=selector_list)
        results.append({
            "domain": domain,
            "similarity": similarity,
            "posture": posture,
        })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    results.sort(
        key=lambda item: (
            severity_order.get(item["posture"].risk_level, 99),
            -(item["similarity"] or 0.0),
            item["domain"],
        ),
    )

    table = Table(
        title=f"Email Abuse Posture for {brand_domain}",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("Domain", style="bold white")
    table.add_column("Similarity", justify="right")
    table.add_column("MX", justify="center")
    table.add_column("SPF", justify="center")
    table.add_column("DMARC", justify="center")
    table.add_column("DKIM", justify="center")
    table.add_column("Risk", justify="center")

    severity_colours = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }

    for item in results:
        posture = item["posture"]
        similarity = item["similarity"]
        colour = severity_colours.get(posture.risk_level, "white")
        table.add_row(
            item["domain"],
            "manual" if similarity is None else f"{similarity:.3f}",
            "YES" if posture.has_mx else "no",
            posture.spf_posture,
            posture.dmarc_posture,
            str(len(posture.dkim_records)),
            f"[{colour}]{posture.risk_level}[/{colour}]",
        )

    console.print(table)
    total_gaps = sum(len(item["posture"].gaps) for item in results)
    risky_domains = sum(1 for item in results if item["posture"].risk_level in {"CRITICAL", "HIGH", "MEDIUM"})
    console.print(
        "[bold]Summary:[/bold] "
        f"analyzed={len(results)}, risky={risky_domains}, total_gaps={total_gaps}"
    )

    for item in results[:5]:
        posture = item["posture"]
        if not posture.gaps:
            continue
        console.print(f"[bold]{item['domain']}[/bold]")
        for gap in posture.gaps[:3]:
            console.print(f"  - [{gap.severity}] {gap.summary}")

    if output_json:
        output_path = Path(output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "brand_domain": brand_domain,
            "tested_dkim_selectors": selector_list,
            "results": [
                {
                    "domain": item["domain"],
                    "similarity_score": item["similarity"],
                    "posture": item["posture"].to_dict(),
                }
                for item in results
            ],
        }
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]JSON posture report written:[/green] {output_path}")


@cli.command("url-triage")
@click.argument("urls", nargs=-1)
@click.option(
    "--input-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Optional newline-delimited URL file. Blank lines and # comments are skipped.",
)
@click.option(
    "--output-json",
    default=None,
    help="Optional output path for a JSON URL triage report.",
)
@click.option(
    "--fail-on-suspicious",
    is_flag=True,
    default=False,
    help="Return exit code 1 when one or more URLs are suspicious.",
)
def url_triage(
    urls: tuple[str, ...],
    input_file: Path | None,
    output_json: str | None,
    fail_on_suspicious: bool,
) -> None:
    """Analyze phishing URLs for offline obfuscation and redirect signals."""
    selected_urls = list(urls)
    if input_file:
        selected_urls.extend(
            line.strip()
            for line in input_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

    if not selected_urls:
        raise click.UsageError("Provide at least one URL or --input-file.")

    results = analyze_urls(selected_urls)
    results_sorted = sorted(results, key=lambda result: (-result.risk_score, result.original_url))

    table = Table(
        title="URL Triage",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("URL", style="bold white")
    table.add_column("Risk", justify="right")
    table.add_column("Suspicious", justify="center")
    table.add_column("Checks", style="dim")

    for result in results_sorted:
        checks = ", ".join(finding.check_id for finding in result.findings) or "-"
        table.add_row(
            result.original_url,
            str(result.risk_score),
            "YES" if result.is_suspicious else "no",
            checks,
        )

    console.print(table)
    suspicious_count = sum(1 for result in results if result.is_suspicious)
    console.print(
        "[bold]Summary:[/bold] "
        f"analyzed={len(results)}, suspicious={suspicious_count}"
    )

    for result in results_sorted:
        if not result.findings:
            continue
        console.print(f"[bold]{result.original_url}[/bold]")
        for finding in result.findings:
            console.print(f"  - [{finding.severity}] {finding.check_id}: {finding.title}")

    if output_json:
        output_path = Path(output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "total_urls": len(results),
            "suspicious_urls": suspicious_count,
            "results": [result.to_dict() for result in results_sorted],
        }
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]JSON URL triage report written:[/green] {output_path}")

    if fail_on_suspicious and suspicious_count:
        sys.exit(1)


@cli.group("takedown-case")
def takedown_case_group() -> None:
    """Create or update a defensive takedown case bundle."""


@takedown_case_group.command("create")
@click.argument("brand_domain")
@click.option(
    "--findings-json",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON file containing BrandFinding-compatible records.",
)
@click.option(
    "--output-dir",
    default="case-output",
    show_default=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory where the case bundle will be written.",
)
@click.option("--case-id", default=None, help="Optional override for the case identifier.")
@click.option("--brand-name", default="", help="Optional brand display name.")
@click.option("--brand-owner", default="", help="Optional brand owner / legal entity.")
@click.option("--reporter-name", default="", help="Optional analyst or reporter name.")
@click.option("--reporter-email", default="", help="Optional analyst contact email.")
@click.option("--registrar-name", default="", help="Registrar name for the abuse template.")
@click.option(
    "--registrar-abuse-email",
    default="",
    help="Registrar abuse contact email for the template.",
)
def takedown_case_create(
    brand_domain: str,
    findings_json: Path,
    output_dir: Path,
    case_id: str | None,
    brand_name: str,
    brand_owner: str,
    reporter_name: str,
    reporter_email: str,
    registrar_name: str,
    registrar_abuse_email: str,
) -> None:
    """Create a case bundle with evidence ZIP and takedown request templates."""
    findings = load_findings_json(findings_json)
    bundle = create_takedown_case_bundle(
        findings=findings,
        brand_domain=brand_domain,
        output_dir=output_dir,
        case_id=case_id,
        brand_name=brand_name,
        brand_owner=brand_owner,
        reporter_name=reporter_name,
        reporter_email=reporter_email,
        registrar_name=registrar_name,
        registrar_abuse_email=registrar_abuse_email,
    )
    console.print(f"[green]Case bundle written:[/green] {bundle['case_dir']}")
    console.print(
        "[bold]Summary:[/bold] "
        f"case_id={bundle['case_id']}, findings={bundle['total_findings']}, "
        f"status={bundle['status']}"
    )
    console.print(f"[dim]Evidence package:[/dim] {bundle['evidence_package']}")


@takedown_case_group.command("update")
@click.argument("case_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--status",
    "status_value",
    required=True,
    type=click.Choice([status.value for status in CaseStatus], case_sensitive=False),
    help="New case status.",
)
@click.option("--note", default="", help="Optional case note for the status change.")
def takedown_case_update(case_file: Path, status_value: str, note: str) -> None:
    """Update a case JSON file with a new workflow status."""
    case = update_takedown_case_status(
        case_file=case_file,
        status=CaseStatus(status_value),
        note=note,
    )
    console.print(f"[green]Case updated:[/green] {case_file}")
    console.print(
        "[bold]Summary:[/bold] "
        f"case_id={case['case_id']}, status={case['status']}, "
        f"history_entries={len(case['status_history'])}"
    )


def main() -> None:
    """Package entry point."""
    cli()


if __name__ == "__main__":
    main()
