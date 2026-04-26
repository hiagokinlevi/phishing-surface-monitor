import json
from typing import List, Dict, Any

import click

from analyzers.typosquat import generate_typosquat_variants
from analyzers.risk import score_domain_risk
from reports.generator import generate_markdown_report, generate_json_report


@click.group()
def cli() -> None:
    pass


@cli.command("scan")
@click.argument("domain")
@click.option("--threshold", default=0.75, show_default=True, type=float)
@click.option("--top", default=20, show_default=True, type=int)
@click.option("--hide-benign", is_flag=True, default=False)
@click.option("--min-risk", default=None, type=float)
@click.option("--report", is_flag=True, default=False)
@click.option("--json-report", is_flag=True, default=False)
@click.option("--sort-by-risk", is_flag=True, default=False, help="Sort findings by descending risk score before rendering/output.")
def scan(
    domain: str,
    threshold: float,
    top: int,
    hide_benign: bool,
    min_risk: float | None,
    report: bool,
    json_report: bool,
    sort_by_risk: bool,
) -> None:
    variants = generate_typosquat_variants(domain)

    findings: List[Dict[str, Any]] = []
    for candidate in variants:
        finding = score_domain_risk(domain, candidate, threshold=threshold)
        if hide_benign and finding.get("risk_level") == "benign":
            continue
        if min_risk is not None and float(finding.get("risk_score", 0.0)) < min_risk:
            continue
        findings.append(finding)

    if sort_by_risk:
        findings = sorted(findings, key=lambda f: float(f.get("risk_score", 0.0)), reverse=True)

    findings = findings[:top]

    for f in findings:
        click.echo(
            f"{f.get('candidate_domain','-')}\t"
            f"score={float(f.get('risk_score', 0.0)):.3f}\t"
            f"level={f.get('risk_level','unknown')}"
        )

    if report:
        md = generate_markdown_report(target_domain=domain, findings=findings)
        click.echo(md)

    if json_report:
        payload = generate_json_report(target_domain=domain, findings=findings)
        click.echo(json.dumps(payload, indent=2))


if __name__ == "__main__":
    cli()
