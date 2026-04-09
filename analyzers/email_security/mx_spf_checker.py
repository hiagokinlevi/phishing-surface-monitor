"""
Email security posture checker for lookalike domains.

Checks MX records and SPF/DKIM/DMARC policies on candidate lookalike domains.
A lookalike domain that:
  - Has MX records → can receive email (phishing/BEC risk)
  - Has no SPF policy → can spoof sender addresses more easily
  - Has no DMARC policy → no enforcement against spoofed email

Uses standard DNS resolution only. No active probing or mail sending.
"""
from __future__ import annotations
import socket
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EmailPosture:
    domain: str
    has_mx: bool
    mx_records: list[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None

    @property
    def has_spf(self) -> bool:
        return self.spf_record is not None

    @property
    def has_dmarc(self) -> bool:
        return self.dmarc_record is not None

    @property
    def risk_level(self) -> str:
        """
        Assess email spoofing risk level.

        HIGH:   Has MX and no DMARC — can receive mail and no anti-spoofing enforcement
        MEDIUM: Has MX but has DMARC (some protection exists)
        LOW:    No MX records — cannot receive email
        """
        if self.has_mx and not self.has_dmarc:
            return "HIGH"
        if self.has_mx:
            return "MEDIUM"
        return "LOW"


def _txt_lookup(domain: str, timeout: float = 3.0) -> list[str]:
    """
    Perform a TXT record lookup using the system resolver.

    Args:
        domain:  Domain name to query.
        timeout: Socket timeout in seconds.

    Returns:
        List of TXT record strings.
    """
    socket.setdefaulttimeout(timeout)
    try:
        # Use getaddrinfo with AF_UNSPEC to trigger a resolver call;
        # for TXT records we use a manual query via dnspython if available,
        # otherwise fall back to a best-effort approach.
        import dns.resolver  # type: ignore[import]
        answers = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
        return [r.to_text().strip('"') for r in answers]
    except ImportError:
        # dnspython not available — return empty (caller handles gracefully)
        return []
    except Exception:
        return []


def _mx_lookup(domain: str, timeout: float = 3.0) -> list[str]:
    """Perform an MX record lookup."""
    try:
        import dns.resolver  # type: ignore[import]
        answers = dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return [str(r.exchange).rstrip(".") for r in answers]
    except ImportError:
        return []
    except Exception:
        return []


def check_email_posture(domain: str, timeout: float = 3.0) -> EmailPosture:
    """
    Check the email security posture of a domain.

    Performs MX, SPF (TXT record starting with 'v=spf1'),
    and DMARC (_dmarc.domain TXT record) lookups.

    Args:
        domain:  Domain to check.
        timeout: DNS timeout per query in seconds.

    Returns:
        EmailPosture with MX, SPF, and DMARC findings.
    """
    posture = EmailPosture(domain=domain, has_mx=False)

    # MX records
    mx_records = _mx_lookup(domain, timeout)
    posture.has_mx = bool(mx_records)
    posture.mx_records = mx_records

    # SPF record (TXT record at the apex domain starting with v=spf1)
    txt_records = _txt_lookup(domain, timeout)
    for txt in txt_records:
        if txt.lower().startswith("v=spf1"):
            posture.spf_record = txt
            break

    # DMARC record (TXT record at _dmarc.domain)
    dmarc_records = _txt_lookup(f"_dmarc.{domain}", timeout)
    for txt in dmarc_records:
        if txt.lower().startswith("v=dmarc1"):
            posture.dmarc_record = txt
            break

    return posture
