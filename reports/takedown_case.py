"""Defensive takedown case bundle generation and status tracking."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reports.takedown_evidence import generate_evidence_package
from schemas.case import BrandFinding, CaseStatus, RiskLevel

_RISK_SORT = {
    RiskLevel.CRITICAL.value: 0,
    RiskLevel.HIGH.value: 1,
    RiskLevel.MEDIUM.value: 2,
    RiskLevel.LOW.value: 3,
    RiskLevel.INFO.value: 4,
}


def load_findings_json(path: Path) -> list[BrandFinding]:
    """Load BrandFinding records from a JSON file."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("findings JSON must contain a list of finding objects")
    return [BrandFinding.model_validate(item) for item in payload]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _default_case_id(brand_domain: str, created_at: datetime) -> str:
    safe_brand = brand_domain.replace(".", "_")
    return f"k1n-psm-case-{safe_brand}-{created_at.strftime('%Y%m%d%H%M%S')}"


def _highest_risk(findings: list[BrandFinding]) -> str:
    if not findings:
        return "none"
    return min((finding.risk_level.value for finding in findings), key=lambda value: _RISK_SORT[value])


def _render_registrar_template(case: dict[str, Any]) -> str:
    lines = [
        f"Subject: Abuse report for {case['brand_domain']} lookalike domain activity",
        "",
        f"To: {case['registrar_abuse_email'] or '[registrar abuse contact]'}",
        "",
        f"Registrar: {case['registrar_name'] or '[registrar name]'}",
        f"Brand owner: {case['brand_owner'] or case['brand_name'] or '[brand owner]'}",
        f"Reporter: {case['reporter_name'] or '[analyst name]'}",
        f"Contact email: {case['reporter_email'] or '[analyst email]'}",
        f"Case ID: {case['case_id']}",
        "",
        "This is an authorised defensive abuse report regarding lookalike domains",
        f"targeting the protected brand {case['brand_domain']}.",
        "",
        "Observed domains:",
    ]
    lines.extend(
        f"- {entry['lookalike_domain']} ({entry['risk_level']}, resolves={entry['resolves']})"
        for entry in case["findings"]
    )
    lines.extend(
        [
            "",
            f"Highest risk observed: {case['highest_risk']}",
            f"Evidence package: {case['evidence_package']}",
            "",
            "Requested actions:",
            "1. Review the attached evidence package and registration details.",
            "2. Preserve registration records and relevant abuse telemetry.",
            "3. Suspend or otherwise disable the abusive domain if your investigation confirms misuse.",
            "",
            "The package includes DNS observations, WHOIS lookup guidance, and a per-domain finding ledger.",
            "Please confirm receipt and advise on next steps for the investigation.",
        ]
    )
    return "\n".join(lines)


def _render_icann_template(case: dict[str, Any]) -> str:
    lines = [
        f"Subject: ICANN registrar compliance referral for {case['brand_domain']} lookalike domains",
        "",
        f"Brand owner: {case['brand_owner'] or case['brand_name'] or '[brand owner]'}",
        f"Reporter: {case['reporter_name'] or '[analyst name]'}",
        f"Contact email: {case['reporter_email'] or '[analyst email]'}",
        f"Case ID: {case['case_id']}",
        "",
        "This referral is prepared for defensive brand-protection escalation when registrar",
        "abuse contacts do not respond or when registrar identification remains incomplete.",
        "",
        f"Protected brand domain: {case['brand_domain']}",
        f"Highest risk observed: {case['highest_risk']}",
        f"Evidence package: {case['evidence_package']}",
        "",
        "Domains requiring review:",
    ]
    lines.extend(f"- {entry['lookalike_domain']} ({entry['risk_level']})" for entry in case["findings"])
    lines.extend(
        [
            "",
            "Recommended attachments and references:",
            "- The generated evidence ZIP from this case bundle",
            "- WHOIS / RDAP screenshots for each resolving lookalike domain",
            "- Screenshots of any phishing or brand-impersonation content",
            "- Prior registrar abuse requests and response timestamps",
            "",
            "ICANN references:",
            "- https://lookup.icann.org/en",
            "- https://www.icann.org/compliance/complaint",
        ]
    )
    return "\n".join(lines)


def create_takedown_case_bundle(
    findings: list[BrandFinding],
    brand_domain: str,
    output_dir: Path,
    *,
    case_id: str | None = None,
    brand_name: str = "",
    brand_owner: str = "",
    reporter_name: str = "",
    reporter_email: str = "",
    registrar_name: str = "",
    registrar_abuse_email: str = "",
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Create a bundle with case JSON, evidence ZIP, and request templates."""
    created_at = created_at or _utc_now()
    case_id = case_id or _default_case_id(brand_domain, created_at)
    case_dir = output_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    evidence_package = generate_evidence_package(
        findings=findings,
        brand_domain=brand_domain,
        output_dir=case_dir,
        package_id=case_id,
        created_at=created_at,
    )

    findings_summary = [
        {
            "lookalike_domain": finding.lookalike_domain,
            "risk_level": finding.risk_level.value,
            "resolves": finding.resolves,
            "status": finding.status.value,
            "similarity_score": round(finding.similarity_score, 4),
        }
        for finding in sorted(
            findings,
            key=lambda item: (_RISK_SORT[item.risk_level.value], -item.similarity_score, item.lookalike_domain),
        )
    ]

    case = {
        "schema_version": "1.0",
        "case_id": case_id,
        "brand_domain": brand_domain,
        "brand_name": brand_name,
        "brand_owner": brand_owner,
        "reporter_name": reporter_name,
        "reporter_email": reporter_email,
        "registrar_name": registrar_name,
        "registrar_abuse_email": registrar_abuse_email,
        "created_at": created_at.isoformat(),
        "updated_at": created_at.isoformat(),
        "status": CaseStatus.OPEN.value,
        "highest_risk": _highest_risk(findings),
        "total_findings": len(findings),
        "resolving_count": sum(1 for finding in findings if finding.resolves),
        "evidence_package": evidence_package.name,
        "findings": findings_summary,
        "status_history": [
            {
                "status": CaseStatus.OPEN.value,
                "changed_at": created_at.isoformat(),
                "note": "Case bundle created",
            }
        ],
    }

    (case_dir / "registrar_request.md").write_text(
        _render_registrar_template(case),
        encoding="utf-8",
    )
    (case_dir / "icann_complaint.md").write_text(
        _render_icann_template(case),
        encoding="utf-8",
    )
    case_file = case_dir / "case.json"
    case_file.write_text(json.dumps(case, indent=2), encoding="utf-8")

    return {
        **case,
        "case_dir": str(case_dir),
        "case_file": str(case_file),
    }


def update_takedown_case_status(
    *,
    case_file: Path,
    status: CaseStatus,
    note: str = "",
    changed_at: datetime | None = None,
) -> dict[str, Any]:
    """Update the workflow status for a stored case JSON file."""
    changed_at = changed_at or _utc_now()
    case = json.loads(case_file.read_text(encoding="utf-8"))
    case["status"] = status.value
    case["updated_at"] = changed_at.isoformat()
    history = case.setdefault("status_history", [])
    history.append(
        {
            "status": status.value,
            "changed_at": changed_at.isoformat(),
            "note": note,
        }
    )
    case_file.write_text(json.dumps(case, indent=2), encoding="utf-8")
    return case
