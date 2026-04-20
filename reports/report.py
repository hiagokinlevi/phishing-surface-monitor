from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _infer_severity(item: Dict[str, Any], default: str = "medium") -> str:
    for key in ("severity", "risk", "risk_level", "level"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return default


def _normalize_typosquat_findings(findings: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for item in findings or []:
        domain = item.get("domain") or item.get("candidate") or item.get("variant")
        if not domain:
            continue

        severity = _infer_severity(item, default="medium")
        normalized.append(
            {
                "type": "typosquat",
                "severity": severity,
                "domain": domain,
                "details": {
                    "similarity": item.get("similarity"),
                    "dns_resolves": item.get("resolves") if "resolves" in item else item.get("dns_resolves"),
                    "source": item,
                },
            }
        )
    return normalized


def _normalize_ct_findings(findings: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for item in findings or []:
        domain = item.get("domain") or item.get("name_value") or item.get("common_name")
        if not domain:
            continue

        is_wildcard = bool(item.get("wildcard") or str(domain).startswith("*."))
        severity = _infer_severity(item, default="high" if is_wildcard else "medium")

        normalized.append(
            {
                "type": "ct",
                "severity": severity,
                "domain": domain,
                "details": {
                    "wildcard": is_wildcard,
                    "issuer": item.get("issuer_name") or item.get("issuer"),
                    "logged_at": item.get("entry_timestamp") or item.get("not_before"),
                    "source": item,
                },
            }
        )
    return normalized


def _normalize_dmarc_result(result: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not result:
        return []

    missing = bool(result.get("missing"))
    record = result.get("record")
    policy = result.get("policy")

    if not missing and record:
        return []

    severity = "high" if missing else "medium"
    return [
        {
            "type": "dmarc",
            "severity": severity,
            "domain": result.get("domain"),
            "details": {
                "missing": missing,
                "policy": policy,
                "record": record,
                "source": result,
            },
        }
    ]


def generate_json_monitoring_report(
    target_domain: str,
    typosquat_findings: Optional[Iterable[Dict[str, Any]]] = None,
    ct_findings: Optional[Iterable[Dict[str, Any]]] = None,
    dmarc_result: Optional[Dict[str, Any]] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a structured JSON monitoring report.

    Args:
        target_domain: Primary monitored brand domain.
        typosquat_findings: Findings from typosquat checks.
        ct_findings: Findings from CT scans/monitoring.
        dmarc_result: DMARC lookup output for target or candidate domain.
        generated_at: Optional timestamp override.

    Returns:
        A report dictionary ready for JSON serialization.
    """

    risks: List[Dict[str, Any]] = []
    risks.extend(_normalize_typosquat_findings(typosquat_findings))
    risks.extend(_normalize_ct_findings(ct_findings))
    risks.extend(_normalize_dmarc_result(dmarc_result))

    return {
        "timestamp": generated_at or _utc_timestamp(),
        "target_domain": target_domain,
        "summary": {
            "total_risks": len(risks),
            "typosquat_risks": sum(1 for r in risks if r["type"] == "typosquat"),
            "ct_risks": sum(1 for r in risks if r["type"] == "ct"),
            "dmarc_risks": sum(1 for r in risks if r["type"] == "dmarc"),
        },
        "risks": risks,
    }
