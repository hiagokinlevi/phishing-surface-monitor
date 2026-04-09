"""
Certificate Transparency (CT) log monitor.

Queries the crt.sh Certificate Transparency log search API for certificates
issued to a domain pattern. Used to detect newly registered lookalike domains
that have obtained TLS certificates — a strong indicator of active use.

All data comes from public CT logs via the crt.sh read-only API.
No active connections are made to the monitored domains.
"""
from __future__ import annotations
import json
import urllib.request
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class CtCertificate:
    cert_id: int
    logged_at: Optional[datetime]
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    common_name: str
    issuer: str
    name_value: str  # May contain SANs with multiple domain names


def _parse_dt(dt_str: str | None) -> Optional[datetime]:
    """Parse ISO-format datetime strings from crt.sh."""
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def query_ct_logs(
    domain: str,
    include_subdomains: bool = True,
    timeout: float = 10.0,
    deduplicate: bool = True,
) -> list[CtCertificate]:
    """
    Query crt.sh for certificates issued to a domain or its wildcard.

    Args:
        domain:             Domain to search for (e.g. "example.com").
        include_subdomains: If True, search for "%.example.com" (all subdomains).
        timeout:            HTTP request timeout in seconds.
        deduplicate:        If True, return only unique common_name + issuer pairs.

    Returns:
        List of CtCertificate objects sorted by logged_at descending.
    """
    query = f"%.{domain}" if include_subdomains else domain
    encoded = urllib.parse.quote(query)
    url = f"https://crt.sh/?q={encoded}&output=json"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "phishing-surface-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []

    certs: list[CtCertificate] = []
    seen: set[tuple[str, str]] = set()

    for entry in data:
        cn = entry.get("common_name", "")
        issuer = entry.get("issuer_name", "")

        if deduplicate:
            key = (cn, issuer)
            if key in seen:
                continue
            seen.add(key)

        certs.append(CtCertificate(
            cert_id=int(entry.get("id", 0)),
            logged_at=_parse_dt(entry.get("entry_timestamp")),
            not_before=_parse_dt(entry.get("not_before")),
            not_after=_parse_dt(entry.get("not_after")),
            common_name=cn,
            issuer=issuer,
            name_value=entry.get("name_value", ""),
        ))

    # Sort by logged_at descending (most recent first)
    certs.sort(key=lambda c: c.logged_at or datetime.min, reverse=True)
    return certs


def filter_lookalikes(certs: list[CtCertificate], brand_domain: str) -> list[CtCertificate]:
    """
    Filter CT certificates to those that do NOT belong to the brand domain itself.

    Useful when scanning for brand lookalikes: strips out legitimate brand certificates
    and returns only external domains that match the search pattern.

    Args:
        certs:        List of CT certificates from query_ct_logs.
        brand_domain: The legitimate brand domain to exclude.

    Returns:
        Certificates whose common_name does not end with the brand domain.
    """
    return [
        c for c in certs
        if not c.common_name.endswith(f".{brand_domain}") and c.common_name != brand_domain
    ]
