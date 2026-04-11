# Copyright 2024 Cyber Port contributors
#
# Licensed under the Creative Commons Attribution 4.0 International License
# (CC BY 4.0). You may obtain a copy of the License at:
#   https://creativecommons.org/licenses/by/4.0/
#
# You are free to share and adapt this material for any purpose, provided you
# give appropriate credit, indicate if changes were made, and distribute your
# contributions under the same license.
"""
URL Deobfuscator
================
Detects URL obfuscation techniques commonly used in phishing attacks.

Checks performed:
  URLO-001  Percent-encoded hostname characters (suspicious encoding in host)
  URLO-002  Unicode homoglyph hostname (NFKC normalization changes the string)
  URLO-003  Non-standard IP encoding (hex, octal, DWORD / integer IP addresses)
  URLO-004  data: URI scheme
  URLO-005  Nested URL / open-redirect pattern in path, query, or fragment
  URLO-006  Double-encoded percent sequences (e.g. %2527 -> %27)
  URLO-007  Embedded credentials in URL userinfo component

All checks run fully offline — no DNS, HTTP, or external calls are made.

Usage::

    from analyzers.url_deobfuscator import analyze, analyze_many

    result = analyze("http://user:pass@0x7f000001/login?url=https://evil.com")
    print(result.summary())
    print(result.to_dict())
"""

import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weight registry
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "URLO-001": 25,  # Percent-encoded hostname
    "URLO-002": 45,  # Unicode homoglyph hostname (CRITICAL)
    "URLO-003": 40,  # Non-standard IP encoding (CRITICAL)
    "URLO-004": 30,  # data: URI scheme
    "URLO-005": 25,  # Nested URL / open-redirect
    "URLO-006": 25,  # Double-encoded characters
    "URLO-007": 40,  # Embedded credentials (CRITICAL)
}

# Severity mapping per check ID
_CHECK_SEVERITY: Dict[str, str] = {
    "URLO-001": "HIGH",
    "URLO-002": "CRITICAL",
    "URLO-003": "CRITICAL",
    "URLO-004": "HIGH",
    "URLO-005": "HIGH",
    "URLO-006": "HIGH",
    "URLO-007": "CRITICAL",
}

_CHECK_TITLE: Dict[str, str] = {
    "URLO-001": "Percent-encoded hostname",
    "URLO-002": "Unicode homoglyph hostname",
    "URLO-003": "Non-standard IP address encoding",
    "URLO-004": "data: URI scheme detected",
    "URLO-005": "Nested URL / open-redirect pattern",
    "URLO-006": "Double-encoded characters",
    "URLO-007": "Embedded credentials in URL",
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class URLOFinding:
    """A single obfuscation finding for a URL."""

    check_id: str
    severity: str    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int


@dataclass
class URLOResult:
    """Aggregated result of all obfuscation checks for one URL."""

    original_url: str
    decoded_url: str          # best-effort single-pass URL decode for display
    findings: List[URLOFinding] = field(default_factory=list)
    risk_score: int = 0       # min(100, sum of weights for fired checks)
    is_suspicious: bool = False  # True if risk_score > 0

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return the result as a plain dictionary (JSON-serialisable)."""
        return {
            "original_url": self.original_url,
            "decoded_url": self.decoded_url,
            "risk_score": self.risk_score,
            "is_suspicious": self.is_suspicious,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary of the result."""
        if not self.is_suspicious:
            return f"[CLEAN] {self.original_url} — no obfuscation detected"
        check_ids = ", ".join(f.check_id for f in self.findings)
        return (
            f"[SUSPICIOUS] {self.original_url} "
            f"— risk_score={self.risk_score} checks=[{check_ids}]"
        )

    def by_severity(self) -> Dict[str, List[URLOFinding]]:
        """Return findings grouped by severity level."""
        groups: Dict[str, List[URLOFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helper: IP address format detection
# ---------------------------------------------------------------------------

# Matches a single hex octet like 0xff or 0x0
_HEX_OCTET_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
# Matches a single octal octet like 0177 (leading zero, pure digits)
_OCT_OCTET_RE = re.compile(r"^0[0-7]+$")
# Matches a bare integer (no dots) that could be a DWORD IP
_INT_IP_RE = re.compile(r"^\d+$")
# Matches a single hex integer IP like 0x7f000001
_HEX_INT_IP_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")


def _is_nonstandard_ip(hostname: str) -> bool:
    """
    Return True when the hostname looks like an IP address but uses a
    non-standard encoding format (hex octets, octal octets, DWORD integer,
    or mixed formats).

    Standard dotted-decimal (e.g. 192.168.1.1) returns False.
    """
    if not hostname:
        return False

    # Strip surrounding brackets for IPv6 literals — IPv6 is not an
    # obfuscation technique by itself, skip it.
    if hostname.startswith("[") and hostname.endswith("]"):
        return False

    # ---- Single-token formats (no dots) --------------------------------
    if "." not in hostname:
        # Hex integer IP: 0x7f000001
        if _HEX_INT_IP_RE.match(hostname):
            return True
        # DWORD / integer IP: a plain integer in the IPv4 address space
        # (> 16777216 = 0x01000000, < 4294967296 = 0x100000000)
        if _INT_IP_RE.match(hostname):
            val = int(hostname)
            if 16777216 < val < 4294967296:
                return True
        return False

    # ---- Dotted formats ------------------------------------------------
    parts = hostname.split(".")

    # Standard dotted-decimal — all parts must be plain decimal integers
    # in 0-255 with no leading zeros.  An octet like "0177" has a leading
    # zero which signals octal notation, not standard decimal.
    def _is_plain_decimal_octet(p: str) -> bool:
        if not re.match(r"^\d+$", p):
            return False
        # Leading zero on a multi-digit token means octal — not plain decimal
        if len(p) > 1 and p.startswith("0"):
            return False
        return 0 <= int(p) <= 255

    all_decimal = all(_is_plain_decimal_octet(p) for p in parts if p)
    if all_decimal and len([p for p in parts if p]) == 4:
        # Pure standard dotted-decimal — not obfuscated
        return False

    # Check for hex octets (0xff.0x0.0x0.0x1)
    has_hex = any(_HEX_OCTET_RE.match(p) for p in parts if p)
    if has_hex:
        return True

    # Check for octal octets (0177.0.0.1) — leading zero + pure digits
    # Note: "0" alone is valid decimal zero, so require length > 1
    has_octal = any(
        _OCT_OCTET_RE.match(p) and len(p) > 1
        for p in parts
        if p
    )
    if has_octal:
        return True

    return False


# ---------------------------------------------------------------------------
# Internal helpers: individual checks
# ---------------------------------------------------------------------------

# Regex for double-encoding: %25 followed by exactly two hex digits
_DOUBLE_ENC_RE = re.compile(r"%25[0-9a-fA-F]{2}", re.IGNORECASE)


def _looks_like_schemeless_authority(url: str) -> bool:
    """
    Return True when a scheme-less string still looks like it starts with an
    authority section (host or userinfo@host) rather than an arbitrary path.

    ``urllib.parse.urlparse`` only treats the leading token as a netloc when
    the input includes ``//``. Many analyst-provided indicators omit the
    scheme, so a value such as ``user:pass@evil.com/login`` would otherwise be
    parsed as a custom scheme plus path and silently miss hostname checks.
    """
    stripped = url.lstrip()
    if not stripped or stripped.startswith(("/", "?", "#")):
        return False
    if stripped.startswith("//"):
        return True

    boundary = len(stripped)
    for delim in "/?#":
        idx = stripped.find(delim)
        if idx != -1:
            boundary = min(boundary, idx)

    # A bare token such as ``mailto:user@example.com`` should not be reparsed
    # as authority-bearing input. We only reinterpret values that continue into
    # a path/query/fragment, which is how scheme-less phishing URLs are
    # typically shared in triage notes.
    if boundary == len(stripped):
        return False

    candidate = urllib.parse.urlparse(f"//{stripped}")
    hostname = candidate.hostname or ""
    if not hostname:
        return False

    return (
        "." in hostname
        or "%" in candidate.netloc
        or _is_nonstandard_ip(hostname)
        or hostname.startswith("xn--")
        or any(ord(ch) > 127 for ch in hostname)
        or ("@" in candidate.netloc and stripped[boundary] == "/")
    )


def _parse_url(url: str) -> urllib.parse.ParseResult:
    """
    Parse a URL while recovering common scheme-less indicators.

    The primary parse is preserved whenever it already exposes a hostname or
    when the input does not look authority-bearing.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc or parsed.hostname or not _looks_like_schemeless_authority(url):
        return parsed
    reparsed = urllib.parse.urlparse(f"//{url.lstrip()}")
    if reparsed.netloc or reparsed.hostname:
        return reparsed
    return parsed


def _check_urlo001(hostname: str) -> Optional[URLOFinding]:
    """URLO-001: Percent-encoded characters in hostname."""
    if "%" not in hostname:
        return None
    decoded = urllib.parse.unquote(hostname)
    if decoded == hostname:
        # Nothing actually decoded — no real encoding present
        return None
    return URLOFinding(
        check_id="URLO-001",
        severity=_CHECK_SEVERITY["URLO-001"],
        title=_CHECK_TITLE["URLO-001"],
        detail=(
            f"Hostname contains percent-encoded sequences: "
            f"'{hostname}' decodes to '{decoded}'"
        ),
        weight=_CHECK_WEIGHTS["URLO-001"],
    )


def _check_urlo002(hostname: str) -> Optional[URLOFinding]:
    """URLO-002: Unicode homoglyph hostname."""
    if not hostname:
        return None
    # Only fire when there are actual non-ASCII characters present
    if not any(ord(ch) > 127 for ch in hostname):
        return None
    normalized = unicodedata.normalize("NFKC", hostname)
    if normalized == hostname:
        return None
    return URLOFinding(
        check_id="URLO-002",
        severity=_CHECK_SEVERITY["URLO-002"],
        title=_CHECK_TITLE["URLO-002"],
        detail=(
            f"Hostname '{hostname}' contains Unicode characters that normalise "
            f"to '{normalized}' under NFKC — possible homoglyph spoofing"
        ),
        weight=_CHECK_WEIGHTS["URLO-002"],
    )


def _check_urlo003(hostname: str) -> Optional[URLOFinding]:
    """URLO-003: Non-standard IP address encoding."""
    if not _is_nonstandard_ip(hostname):
        return None
    return URLOFinding(
        check_id="URLO-003",
        severity=_CHECK_SEVERITY["URLO-003"],
        title=_CHECK_TITLE["URLO-003"],
        detail=(
            f"Hostname '{hostname}' appears to be an IP address encoded in a "
            "non-standard format (hex, octal, DWORD, or mixed)"
        ),
        weight=_CHECK_WEIGHTS["URLO-003"],
    )


def _check_urlo004(scheme: str) -> Optional[URLOFinding]:
    """URLO-004: data: URI scheme."""
    if scheme.lower() != "data":
        return None
    return URLOFinding(
        check_id="URLO-004",
        severity=_CHECK_SEVERITY["URLO-004"],
        title=_CHECK_TITLE["URLO-004"],
        detail="URL uses the 'data:' URI scheme, commonly abused to embed phishing pages",
        weight=_CHECK_WEIGHTS["URLO-004"],
    )


def _check_urlo005(path: str, query: str, fragment: str) -> Optional[URLOFinding]:
    """URLO-005: Nested URL / open-redirect in path, query, or fragment."""
    combined = path + ("?" + query if query else "") + ("#" + fragment if fragment else "")
    lower = combined.lower()
    # Look for an embedded http:// or https:// anywhere in path/query/fragment
    if "http://" in lower or "https://" in lower:
        # Extract a snippet around the first match for the detail message
        idx = lower.find("http")
        snippet = combined[max(0, idx - 10): idx + 40]
        return URLOFinding(
            check_id="URLO-005",
            severity=_CHECK_SEVERITY["URLO-005"],
            title=_CHECK_TITLE["URLO-005"],
            detail=(
                f"Nested URL detected in path/query/fragment near: '...{snippet}...'"
            ),
            weight=_CHECK_WEIGHTS["URLO-005"],
        )
    return None


def _check_urlo006(url: str) -> Optional[URLOFinding]:
    """URLO-006: Double-encoded percent sequences."""
    match = _DOUBLE_ENC_RE.search(url)
    if not match:
        return None
    return URLOFinding(
        check_id="URLO-006",
        severity=_CHECK_SEVERITY["URLO-006"],
        title=_CHECK_TITLE["URLO-006"],
        detail=(
            f"Double-encoded sequence found: '{match.group()}' in URL — "
            "a single decode pass leaves a raw percent-encoded character"
        ),
        weight=_CHECK_WEIGHTS["URLO-006"],
    )


def _check_urlo007(parsed: urllib.parse.ParseResult) -> Optional[URLOFinding]:
    """URLO-007: Embedded credentials in URL userinfo."""
    # urllib.parse exposes .username and .password
    username = parsed.username  # None when absent
    if username:
        credential_hint = username
        if parsed.password:
            credential_hint = f"{username}:***"
        return URLOFinding(
            check_id="URLO-007",
            severity=_CHECK_SEVERITY["URLO-007"],
            title=_CHECK_TITLE["URLO-007"],
            detail=(
                f"URL embeds credentials in the userinfo component: '{credential_hint}@...'"
            ),
            weight=_CHECK_WEIGHTS["URLO-007"],
        )

    # Fallback: check netloc directly for an @ that urllib may have missed
    # (e.g. when scheme is absent and we still want to catch `user@host/path`)
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo = netloc.split("@", 1)[0]
        return URLOFinding(
            check_id="URLO-007",
            severity=_CHECK_SEVERITY["URLO-007"],
            title=_CHECK_TITLE["URLO-007"],
            detail=(
                f"URL embeds credentials in the netloc component: '{userinfo}@...'"
            ),
            weight=_CHECK_WEIGHTS["URLO-007"],
        )

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(url: str) -> URLOResult:
    """
    Analyze a URL for obfuscation techniques.

    Parameters
    ----------
    url:
        The raw URL string to inspect.

    Returns
    -------
    URLOResult
        Aggregated findings, risk score, and metadata.
    """
    # Best-effort single-pass decode for display
    decoded_url = urllib.parse.unquote(url)

    # Parse the URL; be lenient so that unusual schemes (data:) still parse
    parsed = _parse_url(url)

    # Normalise the hostname — strip brackets from IPv6 literals
    hostname: str = parsed.hostname or ""  # .hostname is already lowercased

    findings: List[URLOFinding] = []

    # Run all checks and collect findings
    f001 = _check_urlo001(hostname)
    if f001:
        findings.append(f001)

    f002 = _check_urlo002(hostname)
    if f002:
        findings.append(f002)

    f003 = _check_urlo003(hostname)
    if f003:
        findings.append(f003)

    f004 = _check_urlo004(parsed.scheme)
    if f004:
        findings.append(f004)

    f005 = _check_urlo005(parsed.path, parsed.query, parsed.fragment)
    if f005:
        findings.append(f005)

    f006 = _check_urlo006(url)
    if f006:
        findings.append(f006)

    f007 = _check_urlo007(parsed)
    if f007:
        findings.append(f007)

    # Compute risk score (capped at 100)
    risk_score = min(100, sum(f.weight for f in findings))

    return URLOResult(
        original_url=url,
        decoded_url=decoded_url,
        findings=findings,
        risk_score=risk_score,
        is_suspicious=risk_score > 0,
    )


def analyze_many(urls: List[str]) -> List[URLOResult]:
    """
    Analyze a list of URLs for obfuscation techniques.

    Parameters
    ----------
    urls:
        An iterable of raw URL strings.

    Returns
    -------
    List[URLOResult]
        One result per input URL, in the same order.
    """
    return [analyze(url) for url in urls]
