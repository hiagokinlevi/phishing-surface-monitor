"""DMARC DNS TXT record lookup utility.

Queries ``_dmarc.<domain>`` and reports whether a DMARC policy exists,
along with the discovered record value.
"""

from __future__ import annotations

from typing import Dict, Optional


try:
    import dns.resolver  # type: ignore
    import dns.exception  # type: ignore
except Exception:  # pragma: no cover - handled at runtime
    dns = None  # type: ignore


def _normalize_domain(domain: str) -> str:
    value = (domain or "").strip().lower().rstrip(".")
    if not value:
        raise ValueError("domain must be a non-empty string")
    return value


def _extract_txt_value(rdata: object) -> str:
    """Convert dnspython TXT rdata to a plain string."""
    strings = getattr(rdata, "strings", None)
    if strings:
        parts = []
        for part in strings:
            if isinstance(part, bytes):
                parts.append(part.decode("utf-8", errors="replace"))
            else:
                parts.append(str(part))
        return "".join(parts).strip()
    return str(rdata).strip().strip('"')


def lookup_dmarc(domain: str) -> Dict[str, Optional[str]]:
    """Lookup DMARC policy for a domain.

    Returns:
        dict with keys:
        - domain: normalized queried domain
        - query_name: DNS name queried (_dmarc.<domain>)
        - has_dmarc: True when a valid DMARC policy TXT is found
        - policy: the DMARC TXT value when present, else None
        - error: optional error string when lookup failed or dependency missing
    """
    normalized = _normalize_domain(domain)
    query_name = f"_dmarc.{normalized}"

    result: Dict[str, Optional[str]] = {
        "domain": normalized,
        "query_name": query_name,
        "has_dmarc": False,  # type: ignore[typeddict-item]
        "policy": None,
        "error": None,
    }

    if dns is None:
        result["error"] = "dnspython not available"
        return result

    try:
        answers = dns.resolver.resolve(query_name, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return result
    except dns.exception.DNSException as exc:
        result["error"] = str(exc)
        return result

    for rdata in answers:
        value = _extract_txt_value(rdata)
        if value.lower().startswith("v=dmarc1"):
            result["has_dmarc"] = True  # type: ignore[typeddict-item]
            result["policy"] = value
            return result

    return result
