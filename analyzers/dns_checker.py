"""
DNS resolution checker for domain monitoring.

Checks whether a candidate domain resolves and records its A records.
Uses standard DNS resolution — no active scanning or port probing.
"""
from __future__ import annotations
import socket
from dataclasses import dataclass


@dataclass
class DnsResult:
    domain: str
    resolves: bool
    a_records: list[str]


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

    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        info = socket.getaddrinfo(domain, None, socket.AF_INET)
        a_records = list({r[4][0] for r in info})
        return DnsResult(domain=domain, resolves=True, a_records=a_records)
    except (socket.gaierror, socket.timeout, OSError):
        return DnsResult(domain=domain, resolves=False, a_records=[])
    finally:
        socket.setdefaulttimeout(previous_timeout)
