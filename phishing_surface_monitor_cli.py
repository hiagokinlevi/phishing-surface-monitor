from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

import click

from analyzers.typosquat import run_typosquat_scan
from reports.markdown import generate_markdown_report


def _timestamp_slug() -> str:
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")


def _default_report_base(domain: str) -> Path:
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_domain = domain.replace("/", "_")
    return reports_dir / f"scan-{safe_domain}-{_timestamp_slug()}"


def _write_json_report(path: Path, findings: list[dict]) -> None:
    path.write_text(json.dumps(findings, indent=2), encoding="utf-8")


def _write_csv_report(path: Path, findings: list[dict]) -> None:
    fieldnames = [
        "domain",
        "normalized_domain",
        "similarity_score",
        "dns_resolves",
        "risk_level",
        "reasons",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in findings:
            writer.writerow(
                {
                    "domain": row.get("domain", ""),
                    "normalized_domain": row.get("normalized_domain", ""),
                    "similarity_score": row.get("similarity_score", ""),
                    "dns_resolves": row.get("dns_resolves", ""),
                    "risk_level": row.get("risk_level", ""),
                    "reasons": "; ".join(row.get("reasons", []) or []),
                }
            )


@click.group()
def cli() -> None:
    pass


@cli.command("scan")
@click.argument("domain")
@click.option("--threshold", default=0.75, type=float, show_default=True)
@click.option("--top", default=None, type=int)
@click.option("--report", is_flag=True, help="Write Markdown report artifact")
@click.option("--json-report", is_flag=True, help="Write JSON report artifact")
@click.option("--csv-report", is_flag=True, help="Write CSV report artifact")
@click.option("--hide-benign", is_flag=True, help="Hide benign findings in terminal output")
def scan_command(
    domain: str,
    threshold: float,
    top: int | None,
    report: bool,
    json_report: bool,
    csv_report: bool,
    hide_benign: bool,
) -> None:
    findings = run_typosquat_scan(domain=domain, threshold=threshold)

    if hide_benign:
        findings = [f for f in findings if str(f.get("risk_level", "")).lower() != "benign"]

    if top is not None:
        findings = findings[:top]

    for item in findings:
        click.echo(
            f"- {item.get('domain')} | score={item.get('similarity_score')} | "
            f"dns={item.get('dns_resolves')} | risk={item.get('risk_level')}"
        )

    if report or json_report or csv_report:
        base = _default_report_base(domain)

        if report:
            md_path = base.with_suffix(".md")
            md_path.write_text(generate_markdown_report(domain, findings), encoding="utf-8")
            click.echo(f"[report] Markdown: {md_path}")

        if json_report:
            json_path = base.with_suffix(".json")
            _write_json_report(json_path, findings)
            click.echo(f"[report] JSON: {json_path}")

        if csv_report:
            csv_path = base.with_suffix(".csv")
            _write_csv_report(csv_path, findings)
            click.echo(f"[report] CSV: {csv_path}")


if __name__ == "__main__":
    cli()
