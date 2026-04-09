# phishing_kit_detector.py — Cyber Port / phishing-surface-monitor
#
# Detects phishing kit characteristics in raw HTML content:
# cloned login pages, cloaking/anti-bot techniques, C2 data exfiltration
# patterns, and anti-analysis evasion.
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
# Copyright (c) 2026 hiagokinlevi — Cyber Port

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weights registry
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "PKIT-001": 45,  # Cloned legitimate login page indicators
    "PKIT-002": 30,  # Cloaking / anti-bot detection code
    "PKIT-003": 30,  # Data exfiltration via POST to external domain
    "PKIT-004": 25,  # Redirect to legitimate site after credential capture
    "PKIT-005": 25,  # Obfuscated JavaScript
    "PKIT-006": 15,  # Anti-indexing techniques
    "PKIT-007": 15,  # Favicon / logo references to legitimate brand
}

# ---------------------------------------------------------------------------
# Brand / domain lists used across multiple checks
# ---------------------------------------------------------------------------

_LOGIN_BRANDS: List[str] = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "twitter",
    "chase",
    "wells fargo",
    "bank of america",
    "citibank",
]

_REDIRECT_DOMAINS: List[str] = [
    r"paypal\.com",
    r"microsoft\.com",
    r"google\.com",
    r"apple\.com",
    r"amazon\.com",
]

_FAVICON_BRANDS: List[str] = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "twitter",
]

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class PKITFinding:
    """Single check result with matched evidence."""

    check_id: str
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int
    evidence: List[str] = field(default_factory=list)  # truncated snippets


@dataclass
class PKITResult:
    """Aggregated result for one analyzed page."""

    url: str
    findings: List[PKITFinding] = field(default_factory=list)
    risk_score: int = 0       # min(100, sum of weights for unique fired checks)
    kit_detected: bool = False  # True when risk_score >= 45

    # --- convenience methods ------------------------------------------------

    def to_dict(self) -> dict:
        """Return a fully serialisable dict representation."""
        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "kit_detected": self.kit_detected,
            "findings": [asdict(f) for f in self.findings],
        }

    def summary(self) -> str:
        """One-line human-readable summary."""
        status = "KIT DETECTED" if self.kit_detected else "clean"
        count = len(self.findings)
        checks = ", ".join(f.check_id for f in self.findings) if self.findings else "none"
        return (
            f"[{status}] url={self.url!r} risk_score={self.risk_score} "
            f"findings={count} checks_fired={checks}"
        )

    def by_severity(self) -> Dict[str, List[PKITFinding]]:
        """Group findings by severity label."""
        groups: Dict[str, List[PKITFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_MAX_EVIDENCE_LEN = 200   # truncate each evidence snippet to this length
_MAX_EVIDENCE_ITEMS = 5   # keep at most this many evidence items per check


def _truncate(text: str, max_len: int = _MAX_EVIDENCE_LEN) -> str:
    """Truncate *text* to *max_len* chars and append an ellipsis if clipped."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def _dedup_evidence(items: List[str]) -> List[str]:
    """Deduplicate while preserving insertion order, then cap the list."""
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
        if len(out) >= _MAX_EVIDENCE_ITEMS:
            break
    return out


# ---------------------------------------------------------------------------
# Per-check detector functions
# ---------------------------------------------------------------------------


def _check_pkit001(html_lower: str, html_raw: str) -> Optional[PKITFinding]:
    """PKIT-001 — Cloned legitimate login page indicators.

    Fires when a known brand keyword appears in <title> or <img alt="...">
    AND a password input field is present.
    """
    # --- part 1: brand keyword in <title> or <img alt="..."> ----------------
    matched_brand: Optional[str] = None

    # Extract <title>...</title> text
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html_lower, re.DOTALL)
    title_text = title_match.group(1) if title_match else ""

    # Extract all img alt attribute values
    img_alts = re.findall(r'<img[^>]+alt\s*=\s*["\']([^"\']*)["\']', html_lower)
    img_alt_text = " ".join(img_alts)

    candidate_text = title_text + " " + img_alt_text

    for brand in _LOGIN_BRANDS:
        if brand in candidate_text:
            matched_brand = brand
            break

    if matched_brand is None:
        return None

    # --- part 2: password input present -------------------------------------
    has_password = bool(
        re.search(r'type\s*=\s*["\']password["\']', html_lower)
    )
    if not has_password:
        return None

    evidence = [
        f"Brand keyword found: '{matched_brand}'",
        "Password input field confirmed",
    ]
    return PKITFinding(
        check_id="PKIT-001",
        severity="CRITICAL",
        title="Cloned legitimate login page indicators",
        detail=(
            f"Brand '{matched_brand}' detected in page title/image alt text "
            "alongside a password input field — strong indicator of a cloned "
            "credential-harvesting page."
        ),
        weight=_CHECK_WEIGHTS["PKIT-001"],
        evidence=evidence,
    )


def _check_pkit002(html_lower: str, html_raw: str) -> Optional[PKITFinding]:
    """PKIT-002 — Cloaking / anti-bot detection code."""
    # Literal string patterns (already lowercased where appropriate)
    literal_patterns: List[str] = [
        "navigator.webdriver",
        "__phantomjs__",
        "callphantom",
        "_phantom",
        "window._phantom",
        "selenium",
    ]

    # Regex patterns for bot/crawler/spider/headless keyword usage —
    # matches both standalone words (word-boundary) and as substrings of
    # identifiers (e.g. "isCrawler", "botDetection") inside script context.
    regex_patterns: List[re.Pattern] = [  # type: ignore[type-arg]
        # word-boundary match inside an if() condition
        re.compile(r"if\s*\(.*\b(bot|crawler|spider|headless)\b", re.IGNORECASE),
        # pattern after "detection" keyword
        re.compile(r"\b(bot|crawler|spider|headless)\b.*detection", re.IGNORECASE),
        # substring match — catches function/variable names like isCrawler, botCheck
        re.compile(r"(bot|crawler|spider|headless).*detection", re.IGNORECASE),
        re.compile(r"is\s*(bot|crawler|spider|headless)", re.IGNORECASE),
        re.compile(r"(bot|crawler|spider|headless)\s*\(", re.IGNORECASE),
    ]

    evidence: List[str] = []

    for pat in literal_patterns:
        if pat in html_lower:
            evidence.append(f"Literal pattern found: '{pat}'")

    for rx in regex_patterns:
        m = rx.search(html_raw)
        if m:
            evidence.append(f"Regex pattern matched: '{_truncate(m.group(0))}'")

    if not evidence:
        return None

    return PKITFinding(
        check_id="PKIT-002",
        severity="HIGH",
        title="Cloaking / anti-bot detection code",
        detail=(
            "JavaScript anti-bot or cloaking patterns detected. "
            "Phishing kits use these to serve benign content to security scanners."
        ),
        weight=_CHECK_WEIGHTS["PKIT-002"],
        evidence=_dedup_evidence(evidence),
    )


def _check_pkit003(html_lower: str, html_raw: str) -> Optional[PKITFinding]:
    """PKIT-003 — Data exfiltration via POST to external domain."""
    evidence: List[str] = []

    # Form action pointing to an absolute HTTP/HTTPS URL
    form_rx = re.compile(
        r'<form[^>]+action\s*=\s*["\']https?://',
        re.IGNORECASE,
    )
    for m in form_rx.finditer(html_raw):
        evidence.append(f"Form exfiltration: '{_truncate(m.group(0))}'")

    # XMLHttpRequest or fetch() followed within 200 chars by an http(s) URL
    xhr_fetch_rx = re.compile(
        r'(XMLHttpRequest|fetch\s*\().{0,200}https?://',
        re.IGNORECASE | re.DOTALL,
    )
    for m in xhr_fetch_rx.finditer(html_raw):
        evidence.append(f"XHR/fetch exfiltration: '{_truncate(m.group(0))}'")

    if not evidence:
        return None

    return PKITFinding(
        check_id="PKIT-003",
        severity="HIGH",
        title="Data exfiltration via POST to external domain",
        detail=(
            "HTML form or JavaScript XHR/fetch sends data to an external absolute URL. "
            "Captured credentials may be transmitted to an attacker-controlled server."
        ),
        weight=_CHECK_WEIGHTS["PKIT-003"],
        evidence=_dedup_evidence(evidence),
    )


def _check_pkit004(html_lower: str, html_raw: str) -> Optional[PKITFinding]:
    """PKIT-004 — Redirect to legitimate site after credential capture."""
    # Redirect JS patterns
    redirect_rx = re.compile(
        r'(window\.location|location\.href\s*=|location\.replace\s*\()',
        re.IGNORECASE,
    )
    # Legitimate brand domains nearby
    domain_rx = re.compile(
        r'(' + "|".join(_REDIRECT_DOMAINS) + r')',
        re.IGNORECASE,
    )

    # Check whether redirect AND domain patterns co-exist in the document
    has_redirect = redirect_rx.search(html_raw) is not None
    domain_match = domain_rx.search(html_raw)

    if not has_redirect or domain_match is None:
        return None

    evidence: List[str] = []
    for m in redirect_rx.finditer(html_raw):
        evidence.append(f"Redirect pattern: '{_truncate(m.group(0))}'")
    evidence.append(f"Legitimate domain found: '{domain_match.group(0)}'")

    return PKITFinding(
        check_id="PKIT-004",
        severity="HIGH",
        title="Redirect to legitimate site after credential capture",
        detail=(
            "JavaScript redirect directive combined with a reference to a known "
            "legitimate domain. This is a classic post-harvest redirect technique."
        ),
        weight=_CHECK_WEIGHTS["PKIT-004"],
        evidence=_dedup_evidence(evidence),
    )


def _check_pkit005(html_lower: str, html_raw: str) -> Optional[PKITFinding]:
    """PKIT-005 — Obfuscated JavaScript."""
    evidence: List[str] = []

    # Named obfuscation technique patterns
    named_patterns: List[tuple] = [
        (re.compile(r'eval\s*\(', re.IGNORECASE), "eval()"),
        (re.compile(r'unescape\s*\(', re.IGNORECASE), "unescape()"),
        (re.compile(r'String\.fromCharCode\s*\(', re.IGNORECASE), "String.fromCharCode()"),
        (re.compile(r'atob\s*\(', re.IGNORECASE), "atob()"),
    ]

    for rx, label in named_patterns:
        if rx.search(html_raw):
            evidence.append(f"Obfuscation technique: {label}")

    # Base64 strings 100+ chars inside <script> blocks
    script_blocks = re.findall(
        r'<script[^>]*>(.*?)</script>',
        html_raw,
        re.IGNORECASE | re.DOTALL,
    )
    b64_rx = re.compile(r'[A-Za-z0-9+/]{100,}={0,2}')
    for block in script_blocks:
        m = b64_rx.search(block)
        if m:
            evidence.append(f"Long base64 string in <script>: '{_truncate(m.group(0), 60)}…'")
            break  # one example is sufficient

    if not evidence:
        return None

    return PKITFinding(
        check_id="PKIT-005",
        severity="HIGH",
        title="Obfuscated JavaScript",
        detail=(
            "JavaScript obfuscation techniques detected. "
            "Phishing kits obfuscate code to evade static analysis and page scanners."
        ),
        weight=_CHECK_WEIGHTS["PKIT-005"],
        evidence=_dedup_evidence(evidence),
    )


def _check_pkit006(html_lower: str, html_raw: str) -> Optional[PKITFinding]:
    """PKIT-006 — Anti-indexing techniques (robots noindex)."""
    patterns: List[re.Pattern] = [  # type: ignore[type-arg]
        # <meta name="robots" content="...noindex...">  (attribute order 1)
        re.compile(
            r'<meta[^>]+name\s*=\s*["\']robots["\'][^>]+content\s*=\s*["\'][^"\']*noindex',
            re.IGNORECASE,
        ),
        # <meta content="...noindex..." name="robots">  (attribute order 2)
        re.compile(
            r'<meta[^>]+content\s*=\s*["\'][^"\']*noindex[^"\']*["\'][^>]+name\s*=\s*["\']robots',
            re.IGNORECASE,
        ),
        # X-Robots-Tag meta http-equiv
        re.compile(r'x-robots-tag', re.IGNORECASE),
    ]

    evidence: List[str] = []
    for rx in patterns:
        m = rx.search(html_raw)
        if m:
            evidence.append(f"Anti-indexing pattern: '{_truncate(m.group(0))}'")

    if not evidence:
        return None

    return PKITFinding(
        check_id="PKIT-006",
        severity="MEDIUM",
        title="Anti-indexing techniques",
        detail=(
            "Robots noindex directive or X-Robots-Tag found. "
            "Phishing pages hide themselves from search engine crawlers to avoid detection."
        ),
        weight=_CHECK_WEIGHTS["PKIT-006"],
        evidence=_dedup_evidence(evidence),
    )


def _check_pkit007(html_lower: str, html_raw: str) -> Optional[PKITFinding]:
    """PKIT-007 — Favicon / logo references to legitimate brand."""
    # Match <link rel="icon" ...> or <link rel="shortcut icon" ...> with href
    link_rx = re.compile(
        r'<link[^>]+rel\s*=\s*["\'][^"\']*(icon|shortcut)[^"\']*["\'][^>]+href\s*=\s*["\']([^"\']*)["\']',
        re.IGNORECASE,
    )
    # Also try reversed attribute order: href before rel
    link_rx_rev = re.compile(
        r'<link[^>]+href\s*=\s*["\']([^"\']*)["\'][^>]+rel\s*=\s*["\'][^"\']*(icon|shortcut)[^"\']*["\']',
        re.IGNORECASE,
    )

    evidence: List[str] = []

    def _check_href(href: str) -> Optional[str]:
        href_lower = href.lower()
        for brand in _FAVICON_BRANDS:
            if brand in href_lower:
                return brand
        # Also flag if it looks like a known brand domain pattern (e.g. paypal.com/favicon.ico)
        for domain in ["paypal.com", "microsoft.com", "google.com", "apple.com",
                       "amazon.com", "netflix.com", "facebook.com", "twitter.com"]:
            if domain in href_lower:
                return domain
        return None

    for m in link_rx.finditer(html_raw):
        href = m.group(2)
        brand = _check_href(href)
        if brand:
            evidence.append(f"Brand favicon href '{_truncate(href)}' (brand: {brand})")

    for m in link_rx_rev.finditer(html_raw):
        href = m.group(1)
        brand = _check_href(href)
        if brand:
            evidence.append(f"Brand favicon href '{_truncate(href)}' (brand: {brand})")

    if not evidence:
        return None

    return PKITFinding(
        check_id="PKIT-007",
        severity="MEDIUM",
        title="Favicon / logo references to legitimate brand",
        detail=(
            "Favicon or icon link points to a legitimate brand domain or contains "
            "a brand keyword. Phishing kits reuse real brand favicons for visual authenticity."
        ),
        weight=_CHECK_WEIGHTS["PKIT-007"],
        evidence=_dedup_evidence(evidence),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_DETECTORS = [
    _check_pkit001,
    _check_pkit002,
    _check_pkit003,
    _check_pkit004,
    _check_pkit005,
    _check_pkit006,
    _check_pkit007,
]


def analyze(html_content: str, page_url: str = "") -> PKITResult:
    """Analyze HTML content for phishing kit characteristics.

    Args:
        html_content: Raw HTML string of the page to inspect.
        page_url:     Optional URL of the page (used for context only).

    Returns:
        A :class:`PKITResult` instance with all findings and a risk score.
    """
    html_lower = html_content.lower()

    findings: List[PKITFinding] = []
    for detector in _DETECTORS:
        finding = detector(html_lower, html_content)
        if finding is not None:
            findings.append(finding)

    # Compute risk score: sum of unique check weights, capped at 100
    risk_score = min(100, sum(_CHECK_WEIGHTS[f.check_id] for f in findings))
    kit_detected = risk_score >= 45

    return PKITResult(
        url=page_url,
        findings=findings,
        risk_score=risk_score,
        kit_detected=kit_detected,
    )


def analyze_many(pages: List[dict]) -> List[PKITResult]:
    """Analyze a list of page dicts for phishing kit characteristics.

    Each dict must have the key ``html_content`` (str) and may optionally
    include ``url`` (str).

    Args:
        pages: List of page descriptor dicts.

    Returns:
        List of :class:`PKITResult` instances in the same order as *pages*.
    """
    results: List[PKITResult] = []
    for page in pages:
        html = page.get("html_content", "")
        url = page.get("url", "")
        results.append(analyze(html, url))
    return results
