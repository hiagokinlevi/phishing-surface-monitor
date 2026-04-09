"""
Brand monitoring report generator.

Produces Markdown and JSON reports from a list of BrandFindings.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from schemas.case import BrandFinding, RiskLevel


def generate_markdown_report(findings: list[BrandFinding], brand_domain: str) -> str:
    """
    Generate a Markdown brand monitoring report.

    Args:
        findings:     List of BrandFinding objects to include.
        brand_domain: The monitored brand domain.

    Returns:
        Markdown string.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(findings)
    active = [f for f in findings if f.resolves]

    lines = [
        f"# Brand Monitoring Report — {brand_domain}",
        f"\n**Generated:** {now}  ",
        f"**Total lookalike candidates:** {total}  ",
        f"**Actively resolving:** {len(active)}\n",
        "---\n",
    ]

    for level in RiskLevel:
        bucket = [f for f in findings if f.risk_level == level]
        if not bucket:
            continue
        lines.append(f"## {level.value.upper()} ({len(bucket)})\n")
        for f in sorted(bucket, key=lambda x: x.similarity_score, reverse=True):
            resolves_str = "✓ resolves" if f.resolves else "✗ no DNS"
            lines.append(f"- **{f.lookalike_domain}** — similarity {f.similarity_score:.2f} — {resolves_str} — technique: {f.technique}\n")
        lines.append("\n")

    return "".join(lines)


def generate_json_report(findings: list[BrandFinding]) -> str:
    """
    Serialize a list of BrandFinding objects to a JSON string.

    Args:
        findings: List of BrandFinding objects.

    Returns:
        Pretty-printed JSON string.
    """
    return json.dumps([f.model_dump(mode="json") for f in findings], indent=2)
