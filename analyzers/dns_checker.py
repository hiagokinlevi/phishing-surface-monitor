"""
DNS resolution checker for domain monitoring.

Checks whether a candidate domain resolves and records its A records.
Uses standard DNS resolution — no active scanning or port probing.
"""
from __future__ import annotations
import ipaddress
import re
import socket
from dataclasses import dataclass

_HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


@dataclass
class DnsResult:
    domain: str
    resolves: bool
    a_records: list[str]


def _normalize_domain(domain: str) -> str:
    """Return a normalized hostname or raise ValueError for invalid input."""
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
    if any(_HOSTNAME_LABEL_RE.fullmatch(label) is None for label in labels):
        raise ValueError("domain contains invalid hostname characters")

    return ascii_candidate


def check_dns(domain: str, timeout: float = 3.0) -> DnsResult:
    """
    Attempt to resolve a domain and collect its A records.

    Args:
        domain:  Domain name to resolve.
        timeout: Socket timeout in seconds.

    Returns:
        DnsResult with resolution status and A records.
    """
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0")

    normalized_domain = _normalize_domain(domain)
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        info = socket.getaddrinfo(normalized_domain, None, socket.AF_INET)
        a_records = list({r[4][0] for r in info})
        return DnsResult(domain=normalized_domain, resolves=True, a_records=a_records)
    except (socket.gaierror, socket.timeout, OSError):
        return DnsResult(domain=normalized_domain, resolves=False, a_records=[])
    finally:
        socket.setdefaulttimeout(previous_timeout)
