from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from analyzers.typosquat import scan_domain
from reports.writer import write_json_report, write_markdown_report

app = typer.Typer(help="Defensive brand protection toolkit for phishing surface monitoring.")


def _ensure_output_dir(output_dir: Optional[Path]) -> Path:
    target = output_dir or Path.cwd()
    target.mkdir(parents=True, exist_ok=True)
    return target


@app.command("scan")
def scan(
    domain: str,
    threshold: float = typer.Option(0.75, "--threshold", help="Similarity threshold for candidate variants."),
    report: bool = typer.Option(False, "--report", help="Write Markdown report artifact."),
    json_report: bool = typer.Option(False, "--json-report", help="Write JSON report artifact."),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        help="Directory where report files are written.",
        file_okay=False,
        dir_okay=True,
        writable=True,
        resolve_path=False,
      ),
):
    results = scan_domain(domain=domain, threshold=threshold)
    typer.echo(json.dumps(results, indent=2))

    if report or json_report:
        target_dir = _ensure_output_dir(output_dir)
        if report:
            md_path = target_dir / f"{domain}_scan_report.md"
            write_markdown_report(results, md_path)
            typer.echo(f"Markdown report written: {md_path}")
        if json_report:
            json_path = target_dir / f"{domain}_scan_report.json"
            write_json_report(results, json_path)
            typer.echo(f"JSON report written: {json_path}")
