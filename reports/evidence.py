from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ABUSE_EMAIL_KEYS = {
    "registrar abuse contact email",
    "registrar_abuse_contact_email",
    "abuse contact email",
    "abuse_email",
    "abuse email",
}

ABUSE_PHONE_KEYS = {
    "registrar abuse contact phone",
    "registrar_abuse_contact_phone",
    "abuse contact phone",
    "abuse_phone",
    "abuse phone",
}

_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
_PHONE_RE = re.compile(r"\+?[0-9][0-9\-().\s]{6,}[0-9]")


def _normalize_key(key: str) -> str:
    return " ".join(str(key).strip().lower().replace("_", " ").split())


def extract_registrar_abuse_contacts(raw_metadata: Any) -> dict[str, str | None]:
    """Extract registrar abuse contact email/phone from WHOIS/raw metadata.

    Accepts nested dict/list/scalar structures and tries key-based extraction first,
    then falls back to regex-based extraction from free-form text.
    """
    email: str | None = None
    phone: str | None = None

    def walk(node: Any) -> None:
        nonlocal email, phone
        if node is None:
            return

        if isinstance(node, dict):
            for k, v in node.items():
                key = _normalize_key(str(k))
                if email is None and key in ABUSE_EMAIL_KEYS and v:
                    m = _EMAIL_RE.search(str(v))
                    if m:
                        email = m.group(0)
                if phone is None and key in ABUSE_PHONE_KEYS and v:
                    m = _PHONE_RE.search(str(v))
                    if m:
                        phone = m.group(0).strip()
                walk(v)
            return

        if isinstance(node, list):
            for item in node:
                walk(item)
            return

        text = str(node)
        if email is None:
            m = _EMAIL_RE.search(text)
            if m and "abuse" in text.lower():
                email = m.group(0)
        if phone is None:
            m = _PHONE_RE.search(text)
            if m and "abuse" in text.lower():
                phone = m.group(0).strip()

    walk(raw_metadata)
    return {
        "registrar_abuse_contact_email": email,
        "registrar_abuse_contact_phone": phone,
    }


def build_takedown_evidence(
    domain: str,
    risk_level: str,
    similarity_score: float,
    dns_resolves: bool,
    reasons: list[str],
    whois_raw: Any | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "risk_level": risk_level,
        "similarity_score": similarity_score,
        "dns_resolves": dns_resolves,
        "reasons": reasons,
    }

    if whois_raw is not None:
        evidence["whois_raw"] = whois_raw
        evidence["registrar_abuse_contact"] = extract_registrar_abuse_contacts(whois_raw)

    if extra:
        evidence.update(extra)

    return evidence


def write_takedown_evidence_bundle(output_path: str | Path, evidence: dict[str, Any]) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    return output
