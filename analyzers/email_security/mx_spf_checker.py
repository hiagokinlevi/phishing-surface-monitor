"""
Email security posture analysis for lookalike domains.

This module evaluates whether a domain can receive mail and whether it exposes
common spoofing gaps across SPF, DKIM, and DMARC. It uses DNS lookups only and
never sends mail or probes remote services.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from math import isfinite
import ipaddress
import re
from typing import Optional, Sequence


DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "mail",
    "smtp",
    "dkim",
)

_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

_SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


@dataclass
class EmailGap:
    """A single email-authentication or abuse-path gap."""

    control: str
    severity: str
    summary: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "control": self.control,
            "severity": self.severity,
            "summary": self.summary,
            "recommendation": self.recommendation,
        }


@dataclass
class EmailPosture:
    """Aggregated email-abuse posture for one domain."""

    domain: str
    has_mx: bool
    mx_records: list[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dkim_records: dict[str, str] = field(default_factory=dict)
    tested_dkim_selectors: list[str] = field(default_factory=list)
    gaps: list[EmailGap] = field(default_factory=list)

    @property
    def has_spf(self) -> bool:
        return self.spf_record is not None

    @property
    def has_dmarc(self) -> bool:
        return self.dmarc_record is not None

    @property
    def has_dkim(self) -> bool:
        return bool(self.dkim_records)

    @property
    def spf_posture(self) -> str:
        return _classify_spf_posture(self.spf_record)

    @property
    def dmarc_posture(self) -> str:
        return _classify_dmarc_posture(self.dmarc_record)

    @property
    def risk_level(self) -> str:
        if self.gaps:
            return max(self.gaps, key=lambda gap: _SEVERITY_ORDER.get(gap.severity, -1)).severity
        if self.has_mx:
            return "LOW"
        return "INFO"

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "has_mx": self.has_mx,
            "mx_records": list(self.mx_records),
            "spf_record": self.spf_record,
            "spf_posture": self.spf_posture,
            "dmarc_record": self.dmarc_record,
            "dmarc_posture": self.dmarc_posture,
            "dkim_records": dict(self.dkim_records),
            "tested_dkim_selectors": list(self.tested_dkim_selectors),
            "risk_level": self.risk_level,
            "gaps": [gap.to_dict() for gap in self.gaps],
        }


def _txt_lookup(domain: str, timeout: float = 3.0) -> list[str]:
    """Perform a TXT lookup and return record text values."""
    try:
        import dns.resolver  # type: ignore[import]

        answers = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
        return [r.to_text().strip('"') for r in answers]
    except ImportError:
        return []
    except Exception:
        return []


def _mx_lookup(domain: str, timeout: float = 3.0) -> list[str]:
    """Perform an MX lookup and return exchange hostnames."""
    try:
        import dns.resolver  # type: ignore[import]

        answers = dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return [str(r.exchange).rstrip(".") for r in answers]
    except ImportError:
        return []
    except Exception:
        return []


def _extract_matching_record(records: Sequence[str], prefix: str) -> Optional[str]:
    for record in records:
        if record.lower().startswith(prefix):
            return record
    return None


def _classify_spf_posture(record: Optional[str]) -> str:
    if record is None:
        return "missing"

    normalised = " ".join(record.lower().split())
    if "+all" in normalised:
        return "permissive"
    if "?all" in normalised:
        return "neutral"
    if "~all" in normalised:
        return "softfail"
    if "-all" in normalised:
        return "strict"
    return "present"


def _classify_dmarc_posture(record: Optional[str]) -> str:
    if record is None:
        return "missing"

    normalised = record.lower()
    for segment in normalised.split(";"):
        token = segment.strip()
        if token.startswith("p="):
            policy = token.split("=", 1)[1].strip()
            if policy in {"reject", "quarantine", "none"}:
                return policy
            return "invalid"
    return "invalid"


def _lookup_dkim_records(
    domain: str,
    selectors: Sequence[str],
    timeout: float,
) -> dict[str, str]:
    discovered: dict[str, str] = {}
    for selector in selectors:
        records = _txt_lookup(f"{selector}._domainkey.{domain}", timeout=timeout)
        dkim_record = _extract_matching_record(records, "v=dkim1")
        if dkim_record:
            discovered[selector] = dkim_record
    return discovered


def _normalize_domain(domain: str) -> str:
    """Normalize a domain and reject URL-like or invalid host input."""
    candidate = domain.strip().rstrip(".").lower()
    if not candidate:
        raise ValueError("domain must be a non-empty hostname")
    if any(separator in candidate for separator in ("://", "/", "?", "#", "@")):
        raise ValueError("domain must be a hostname without URL components")
    if ".." in candidate:
        raise ValueError("domain must not contain empty labels")

    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise ValueError("domain must be a hostname, not an IP address")

    try:
        ascii_candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("domain contains invalid IDNA characters") from exc

    if len(ascii_candidate) > 253:
        raise ValueError("domain must be 253 characters or fewer")

    labels = ascii_candidate.split(".")
    if any(not label for label in labels):
        raise ValueError("domain must not contain empty labels")
    if any(len(label) > 63 for label in labels):
        raise ValueError("domain labels must be 63 characters or fewer")
    if any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
        raise ValueError("domain contains invalid hostname characters")
    return ascii_candidate


def _normalize_selector(selector: str) -> str:
    """Normalize a DKIM selector and reject invalid DNS-label input."""
    candidate = selector.strip().rstrip(".").lower()
    if not candidate:
        raise ValueError("DKIM selector must be a non-empty DNS label")
    if any(separator in candidate for separator in ("://", "/", "?", "#", "@")):
        raise ValueError("DKIM selector must be a DNS label without URL components")
    if "." in candidate:
        raise ValueError("DKIM selector must be a single DNS label")

    try:
        ascii_candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("DKIM selector contains invalid IDNA characters") from exc

    if len(ascii_candidate) > 63:
        raise ValueError("DKIM selector must be 63 characters or fewer")
    if _DNS_LABEL_RE.fullmatch(ascii_candidate) is None:
        raise ValueError("DKIM selector contains invalid hostname characters")
    return ascii_candidate


def _normalize_selector_list(selectors: Sequence[str]) -> list[str]:
    """Normalize selectors while preserving order and removing duplicates."""
    normalized: list[str] = []
    seen: set[str] = set()
    for selector in selectors:
        canonical = _normalize_selector(selector)
        if canonical in seen:
            continue
        seen.add(canonical)
        normalized.append(canonical)
    return normalized


def _validate_timeout(timeout: float) -> float:
    """Reject non-finite or non-positive DNS resolver lifetimes."""
    if not isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a finite number greater than 0")
    return timeout


def _build_gaps(posture: EmailPosture) -> list[EmailGap]:
    gaps: list[EmailGap] = []

    if posture.has_mx:
        gaps.append(EmailGap(
            control="mx",
            severity="MEDIUM",
            summary="Domain publishes MX records and can receive phishing or BEC replies.",
            recommendation="Review the MX host ownership and monitor mailbox abuse on this lookalike domain.",
        ))

    spf_posture = posture.spf_posture
    if spf_posture == "missing":
        gaps.append(EmailGap(
            control="spf",
            severity="HIGH",
            summary="No SPF record was found.",
            recommendation="Treat mail from this lookalike as ungoverned and prioritize abuse monitoring.",
        ))
    elif spf_posture in {"permissive", "neutral"}:
        gaps.append(EmailGap(
            control="spf",
            severity="CRITICAL" if spf_posture == "permissive" else "HIGH",
            summary=f"SPF policy is {spf_posture} and does not strongly restrict spoofed senders.",
            recommendation="Escalate because the domain can present weak sender-authentication controls.",
        ))

    dmarc_posture = posture.dmarc_posture
    if dmarc_posture == "missing":
        gaps.append(EmailGap(
            control="dmarc",
            severity="HIGH",
            summary="No DMARC policy was found.",
            recommendation="Assume downstream receivers will have no domain-owner enforcement guidance.",
        ))
    elif dmarc_posture == "none":
        gaps.append(EmailGap(
            control="dmarc",
            severity="MEDIUM",
            summary="DMARC policy is set to monitor-only (`p=none`).",
            recommendation="Track this domain because mailbox providers may still accept unauthenticated mail.",
        ))
    elif dmarc_posture == "invalid":
        gaps.append(EmailGap(
            control="dmarc",
            severity="MEDIUM",
            summary="DMARC TXT record exists but its policy is missing or invalid.",
            recommendation="Verify whether the domain is intentionally misconfigured or abandoned.",
        ))

    if not posture.has_dkim:
        gaps.append(EmailGap(
            control="dkim",
            severity="MEDIUM" if posture.has_mx else "LOW",
            summary="No DKIM record was observed for the tested selectors.",
            recommendation=(
                "Check additional selectors if known. Absence across common selectors is a useful abuse signal."
            ),
        ))

    return gaps


def check_email_posture(
    domain: str,
    timeout: float = 3.0,
    dkim_selectors: Sequence[str] | None = None,
) -> EmailPosture:
    """
    Evaluate email-security posture for a domain.

    The DKIM check is heuristic-based: it tests a caller-provided selector list
    or a curated default set of commonly observed selectors.
    """
    normalized_domain = _normalize_domain(domain)
    validated_timeout = _validate_timeout(timeout)
    selectors = _normalize_selector_list(dkim_selectors or DEFAULT_DKIM_SELECTORS)
    posture = EmailPosture(
        domain=normalized_domain,
        has_mx=False,
        tested_dkim_selectors=selectors,
    )

    mx_records = _mx_lookup(normalized_domain, validated_timeout)
    posture.has_mx = bool(mx_records)
    posture.mx_records = mx_records

    txt_records = _txt_lookup(normalized_domain, validated_timeout)
    posture.spf_record = _extract_matching_record(txt_records, "v=spf1")

    dmarc_records = _txt_lookup(f"_dmarc.{normalized_domain}", validated_timeout)
    posture.dmarc_record = _extract_matching_record(dmarc_records, "v=dmarc1")

    posture.dkim_records = _lookup_dkim_records(normalized_domain, selectors, validated_timeout)
    posture.gaps = _build_gaps(posture)
    return posture
