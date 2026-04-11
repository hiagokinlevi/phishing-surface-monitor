"""
Hostname validation helpers shared by network-facing analyzers.
"""
from __future__ import annotations

import ipaddress
import re

_HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def normalize_hostname(hostname: str) -> str:
    """Return a normalized hostname or raise ValueError for invalid input."""
    candidate = hostname.strip().rstrip(".").lower()
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
