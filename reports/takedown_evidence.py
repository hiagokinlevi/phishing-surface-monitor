"""
Takedown Evidence Package Generator
=====================================
Compiles brand protection takedown evidence into a self-contained ZIP archive
suitable for submission to hosting providers, domain registrars, or legal teams.

Each evidence package contains:
  - manifest.json      : metadata for all included findings
  - summary.md         : human-readable case summary
  - findings/          : per-finding directories, each containing:
      finding.json     : full finding details (similarity, DNS, risk level, etc.)
      dns_records.txt  : DNS A/MX/NS record observations
      whois_note.txt   : WHOIS investigation note (links to lookup services)

DNS record data is populated from the a_records field on each BrandFinding.
WHOIS data is represented as a reference note — live WHOIS requires network
access and a third-party library that is not a hard dependency.

Usage:
    from schemas.case import BrandFinding, RiskLevel
    from reports.takedown_evidence import generate_evidence_package

    findings = [...]  # list[BrandFinding]
    path = generate_evidence_package(
        findings=findings,
        brand_domain="example.com",
        output_dir=Path("./evidence"),
    )
    print(f"Evidence package: {path}")
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from schemas.case import BrandFinding, RiskLevel


# ---------------------------------------------------------------------------
# Evidence content builders
# ---------------------------------------------------------------------------

_RISK_PRIORITY = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 3,
    RiskLevel.INFO: 4,
}

_WHOIS_SERVICES = [
    "https://www.whois.com/whois/{domain}",
    "https://whois.domaintools.com/{domain}",
    "https://rdap.org/domain/{domain}",
]


def _finding_slug(finding: BrandFinding, index: int) -> str:
    """Build a filesystem-safe identifier for a finding directory."""
    safe_domain = finding.lookalike_domain.replace(".", "_").replace("-", "_")
    return f"finding_{index:03d}_{safe_domain}"


def _finding_to_dict(finding: BrandFinding) -> dict:
    """Serialise a BrandFinding to a plain dict suitable for JSON."""
    return {
        "id":               finding.id,
        "brand_domain":     finding.brand_domain,
        "lookalike_domain": finding.lookalike_domain,
        "technique":        finding.technique,
        "similarity_score": round(finding.similarity_score, 4),
        "resolves":         finding.resolves,
        "a_records":        finding.a_records,
        "risk_level":       finding.risk_level.value,
        "status":           finding.status.value,
        "detected_at":      finding.detected_at.isoformat(),
        "notes":            finding.notes,
    }


def _build_manifest(
    findings: list[BrandFinding],
    brand_domain: str,
    package_id: str,
    created_at: datetime,
) -> dict:
    """Build the manifest.json content for the evidence package."""
    risk_counts = {r.value: 0 for r in RiskLevel}
    for f in findings:
        risk_counts[f.risk_level.value] += 1

    return {
        "schema_version":   "1.0",
        "package_id":       package_id,
        "brand_domain":     brand_domain,
        "created_at":       created_at.isoformat(),
        "total_findings":   len(findings),
        "risk_counts":      risk_counts,
        "resolving_count":  sum(1 for f in findings if f.resolves),
        "highest_risk":     (
            min((f.risk_level for f in findings),
                key=lambda r: _RISK_PRIORITY.get(r, 99)).value
            if findings else "none"
        ),
        "findings_index": [
            {
                "index":            i,
                "slug":             _finding_slug(f, i),
                "lookalike_domain": f.lookalike_domain,
                "risk_level":       f.risk_level.value,
                "resolves":         f.resolves,
            }
            for i, f in enumerate(findings)
        ],
    }


def _build_dns_records_text(finding: BrandFinding) -> str:
    """Build the dns_records.txt content for a single finding."""
    lines = [
        f"DNS Record Observations — {finding.lookalike_domain}",
        f"Brand domain: {finding.brand_domain}",
        f"Observed at: {finding.detected_at.isoformat()}",
        "-" * 60,
        "",
    ]

    if finding.resolves:
        lines.append("STATUS: RESOLVES (active domain)")
    else:
        lines.append("STATUS: DOES NOT RESOLVE (inactive / parked)")

    lines.append("")

    if finding.a_records:
        lines.append("A Records (IP addresses):")
        for ip in finding.a_records:
            lines.append(f"  {finding.lookalike_domain}.  IN  A  {ip}")
    else:
        lines.append("A Records: none observed")

    lines += [
        "",
        "-" * 60,
        "Note: For full DNS record sets, query the authoritative nameserver:",
        f"  dig +short {finding.lookalike_domain} A",
        f"  dig +short {finding.lookalike_domain} MX",
        f"  dig +short {finding.lookalike_domain} NS",
        f"  dig +short {finding.lookalike_domain} TXT",
        "",
    ]
    return "\n".join(lines)


def _build_whois_note(finding: BrandFinding) -> str:
    """Build the whois_note.txt content for a single finding."""
    lines = [
        f"WHOIS Investigation Note — {finding.lookalike_domain}",
        f"Brand domain: {finding.brand_domain}",
        f"Generated at: {finding.detected_at.isoformat()}",
        "-" * 60,
        "",
        "WHOIS data must be retrieved from a live registry lookup.",
        "Use one of the following services to obtain current registrant data:",
        "",
    ]
    for svc in _WHOIS_SERVICES:
        lines.append(f"  {svc.format(domain=finding.lookalike_domain)}")

    lines += [
        "",
        "Key fields to document for a takedown request:",
        "  - Registrant name and organisation",
        "  - Registrant email (or privacy-shielded proxy service)",
        "  - Registrar name and abuse contact",
        "  - Registration date",
        "  - Expiry date",
        "  - Name servers",
        "",
        "Abuse contacts for common registrars can be found at:",
        "  https://www.icann.org/registrar-reports/accreditation-qualified-list.html",
        "",
        "-" * 60,
        "IMPORTANT: Screenshot the WHOIS output and attach it to this package.",
        "Timestamp all screenshots and preserve them in original format.",
        "",
    ]
    return "\n".join(lines)


def _build_summary_markdown(
    findings: list[BrandFinding],
    brand_domain: str,
    package_id: str,
    created_at: datetime,
) -> str:
    """Build the summary.md content for the evidence package."""
    risk_counts = {r.value: 0 for r in RiskLevel}
    for f in findings:
        risk_counts[f.risk_level.value] += 1

    resolving = [f for f in findings if f.resolves]

    lines = [
        f"# Takedown Evidence Package",
        f"",
        f"**Brand domain:** {brand_domain}",
        f"**Package ID:** {package_id}",
        f"**Generated:** {created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"",
        f"## Summary",
        f"",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total lookalike domains | {len(findings)} |",
        f"| Actively resolving | {len(resolving)} |",
        f"| CRITICAL risk | {risk_counts.get('critical', 0)} |",
        f"| HIGH risk | {risk_counts.get('high', 0)} |",
        f"| MEDIUM risk | {risk_counts.get('medium', 0)} |",
        f"| LOW risk | {risk_counts.get('low', 0)} |",
        f"",
        f"## Findings",
        f"",
        f"| # | Lookalike Domain | Risk | Resolves | Similarity | Technique |",
        f"|---|-----------------|------|----------|------------|-----------|",
    ]

    sorted_findings = sorted(
        findings,
        key=lambda f: _RISK_PRIORITY.get(f.risk_level, 99),
    )
    for i, f in enumerate(sorted_findings):
        resolves_str = "YES" if f.resolves else "no"
        sim_pct = f"{f.similarity_score * 100:.1f}%"
        lines.append(
            f"| {i + 1} | `{f.lookalike_domain}` "
            f"| **{f.risk_level.value.upper()}** "
            f"| {resolves_str} | {sim_pct} | {f.technique} |"
        )

    lines += [
        f"",
        f"## Next Steps",
        f"",
        f"1. Review each finding in the `findings/` directory",
        f"2. Complete WHOIS lookups using the links in each `whois_note.txt`",
        f"3. Screenshot active domains (HTTP/HTTPS) as additional evidence",
        f"4. Submit takedown requests to registrar abuse contacts",
        f"5. File abuse reports with hosting providers for IPs in `dns_records.txt`",
        f"",
        f"## Legal",
        f"",
        f"This evidence package was generated for authorised brand protection purposes.",
        f"Consult legal counsel before submitting formal takedown requests.",
        f"",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Package hash
# ---------------------------------------------------------------------------

def _sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_evidence_package(
    findings: list[BrandFinding],
    brand_domain: str,
    output_dir: Path,
    package_id: Optional[str] = None,
    created_at: Optional[datetime] = None,
) -> Path:
    """
    Compile a takedown evidence package as a ZIP archive.

    The archive is written to output_dir and named:
      takedown_evidence_{brand_domain}_{YYYYMMDD_HHMMSS}.zip

    Args:
        findings:    List of BrandFinding objects to include.
        brand_domain: The brand being protected.
        output_dir:  Directory where the ZIP file will be written.
        package_id:  Optional override for the package identifier.
        created_at:  Optional override for the creation timestamp.

    Returns:
        Path to the generated ZIP file.
    """
    if created_at is None:
        created_at = datetime.now(tz=timezone.utc)
    if package_id is None:
        ts_slug = created_at.strftime("%Y%m%d%H%M%S")
        safe_brand = brand_domain.replace(".", "_")
        package_id = f"k1n-tdp-{safe_brand}-{ts_slug}"

    # Sort findings: highest risk first
    sorted_findings = sorted(
        findings,
        key=lambda f: _RISK_PRIORITY.get(f.risk_level, 99),
    )

    # Build ZIP in memory
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # --- manifest.json ---
        manifest = _build_manifest(sorted_findings, brand_domain, package_id, created_at)
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        zf.writestr("manifest.json", manifest_bytes)

        # --- summary.md ---
        summary_md = _build_summary_markdown(sorted_findings, brand_domain, package_id, created_at)
        zf.writestr("summary.md", summary_md.encode("utf-8"))

        # --- Per-finding files ---
        for i, finding in enumerate(sorted_findings):
            slug = _finding_slug(finding, i)

            finding_json = json.dumps(_finding_to_dict(finding), indent=2).encode("utf-8")
            zf.writestr(f"findings/{slug}/finding.json", finding_json)

            dns_text = _build_dns_records_text(finding).encode("utf-8")
            zf.writestr(f"findings/{slug}/dns_records.txt", dns_text)

            whois_note = _build_whois_note(finding).encode("utf-8")
            zf.writestr(f"findings/{slug}/whois_note.txt", whois_note)

        # --- checksums.json ---
        checksums: dict[str, str] = {}
        for item in zf.infolist():
            if item.filename != "checksums.json":
                checksums[item.filename] = _sha256_digest(zf.read(item.filename))
        zf.writestr("checksums.json", json.dumps(checksums, indent=2).encode("utf-8"))

    # Write to disk
    output_dir.mkdir(parents=True, exist_ok=True)
    ts_slug = created_at.strftime("%Y%m%d_%H%M%S")
    safe_brand = brand_domain.replace(".", "_")
    archive_name = f"takedown_evidence_{safe_brand}_{ts_slug}.zip"
    archive_path = output_dir / archive_name

    archive_path.write_bytes(buffer.getvalue())
    return archive_path


def list_package_contents(archive_path: Path) -> list[str]:
    """Return a list of filenames in an evidence package ZIP."""
    with zipfile.ZipFile(archive_path, "r") as zf:
        return sorted(zf.namelist())


def read_package_manifest(archive_path: Path) -> dict:
    """Read and parse the manifest.json from an evidence package ZIP."""
    with zipfile.ZipFile(archive_path, "r") as zf:
        return json.loads(zf.read("manifest.json").decode("utf-8"))
