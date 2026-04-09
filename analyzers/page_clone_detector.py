# page_clone_detector.py — Cyber Port / phishing-surface-monitor
#
# Detects signals that a web page is a phishing clone or brand impersonation
# attempt by analyzing HTML content metadata, structural signals, and
# behavioral patterns defensively.
#
# Check IDs: PCLN-001 through PCLN-007
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
# Copyright (c) 2026 hiagokinlevi — Cyber Port

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_EVIDENCE_LEN = 200  # truncate evidence snippets to this many characters

# Social media platform hostnames checked by PCLN-003
_SOCIAL_PLATFORMS: List[str] = [
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "youtube.com",
    "tiktok.com",
    "x.com",
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PageSignals:
    """Input bundle describing a single page to analyse."""

    page_id: str
    domain: str       # observed domain e.g. "login-secure-bank.xyz"
    brand_name: str   # brand being impersonated e.g. "bank"
    html_content: str # raw HTML content (may be large)
    url: str = ""     # full URL if known


@dataclass
class PCLNCheck:
    """Result of a single PCLN check that fired."""

    check_id: str
    severity: str    # CRITICAL / HIGH / MEDIUM
    description: str
    evidence: str    # matched excerpt truncated to 200 chars
    weight: int


@dataclass
class CloneDetectionResult:
    """Aggregated clone-detection result for a single page."""

    page_id: str
    domain: str
    brand_name: str
    checks_fired: List[PCLNCheck] = field(default_factory=list)
    risk_score: int = 0         # min(100, sum of weights for checks that fired)
    clone_likelihood: str = "MINIMAL"  # HIGH / MEDIUM / LOW / MINIMAL
    kit_signals: int = 0        # number of checks that fired

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a fully serialisable dict representation."""
        return {
            "page_id": self.page_id,
            "domain": self.domain,
            "brand_name": self.brand_name,
            "risk_score": self.risk_score,
            "clone_likelihood": self.clone_likelihood,
            "kit_signals": self.kit_signals,
            "checks_fired": [asdict(c) for c in self.checks_fired],
        }

    def summary(self) -> str:
        """One-line human-readable summary."""
        checks = (
            ", ".join(c.check_id for c in self.checks_fired)
            if self.checks_fired
            else "none"
        )
        return (
            f"[{self.clone_likelihood}] page_id={self.page_id!r} "
            f"domain={self.domain!r} risk_score={self.risk_score} "
            f"kit_signals={self.kit_signals} checks_fired={checks}"
        )

    def by_severity(self) -> Dict[str, List[PCLNCheck]]:
        """Group fired checks by severity label."""
        groups: Dict[str, List[PCLNCheck]] = {}
        for check in self.checks_fired:
            groups.setdefault(check.severity, []).append(check)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _truncate(text: str, max_len: int = _MAX_EVIDENCE_LEN) -> str:
    """Truncate *text* to *max_len* chars and append an ellipsis if clipped."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def _extract_domain(url: str) -> str:
    """Return the lowercase netloc (host) from *url*, or empty string on failure."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def _likelihood(score: int) -> str:
    """Map a numeric risk score to a likelihood label."""
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score >= 10:
        return "LOW"
    return "MINIMAL"


# ---------------------------------------------------------------------------
# Per-check detector functions
# ---------------------------------------------------------------------------


def _check_pcln001(signals: PageSignals) -> PCLNCheck | None:
    """PCLN-001 — Login form on non-brand domain (CRITICAL, weight=45).

    Fires when the page contains a <form> block with a password input AND
    either the form has no action attribute OR the action does not contain
    the observed domain.
    """
    html = signals.html_content
    domain_lower = signals.domain.lower()

    # Find all <form ...> ... </form> blocks (non-greedy, case-insensitive)
    form_blocks = re.findall(
        r'<form[\s\S]*?</form>',
        html,
        re.IGNORECASE,
    )

    # If no </form> closing tags exist, also try to capture everything from
    # each <form to the next opening tag or end-of-string (handles unclosed forms)
    if not form_blocks:
        form_blocks = re.findall(r'<form[^>]*>', html, re.IGNORECASE)

    for block in form_blocks:
        block_lower = block.lower()

        # Check for password input: type=password or name containing "password"
        has_password_type = bool(
            re.search(r'type\s*=\s*["\']?\s*password', block_lower)
        )
        has_password_name = bool(
            re.search(r'name\s*=\s*["\']?[^"\'>\s]*password', block_lower)
        )
        if not (has_password_type or has_password_name):
            continue

        # Extract action attribute value
        action_match = re.search(
            r'action\s*=\s*["\']([^"\']*)["\']',
            block,
            re.IGNORECASE,
        )
        if action_match:
            action_val = action_match.group(1).strip()
        else:
            action_val = ""

        # Fire if action is empty or action does not contain the observed domain
        if not action_val or domain_lower not in action_val.lower():
            evidence_snippet = _truncate(block)
            return PCLNCheck(
                check_id="PCLN-001",
                severity="CRITICAL",
                description=(
                    "Login form with password field present on non-brand domain. "
                    "Form action is absent or points outside the observed domain — "
                    "high-confidence credential-harvesting page."
                ),
                evidence=evidence_snippet,
                weight=45,
            )

    return None


def _check_pcln002(signals: PageSignals) -> PCLNCheck | None:
    """PCLN-002 — Brand keyword in page title but domain doesn't contain brand (HIGH, weight=30).

    Fires when brand_name appears in <title> text (case-insensitive) but
    NOT in the observed domain (case-insensitive).
    """
    html = signals.html_content
    brand_lower = signals.brand_name.lower()
    domain_lower = signals.domain.lower()

    # Skip if domain already contains the brand (legitimate site)
    if brand_lower in domain_lower:
        return None

    title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if not title_match:
        return None

    title_text = title_match.group(1)
    if brand_lower not in title_text.lower():
        return None

    evidence_snippet = _truncate(title_match.group(0))
    return PCLNCheck(
        check_id="PCLN-002",
        severity="HIGH",
        description=(
            f"Brand keyword '{signals.brand_name}' found in page <title> "
            f"but not present in observed domain '{signals.domain}'. "
            "Possible brand impersonation via title spoofing."
        ),
        evidence=evidence_snippet,
        weight=30,
    )


def _check_pcln003(signals: PageSignals) -> PCLNCheck | None:
    """PCLN-003 — Social media link farming (MEDIUM, weight=15).

    Fires when ≥4 distinct social media platforms are referenced in href
    attributes. Common in phishing templates copying legitimate site footers.
    """
    html = signals.html_content

    hrefs = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE)

    matched_platforms = set()
    for href in hrefs:
        href_lower = href.lower()
        for platform in _SOCIAL_PLATFORMS:
            if platform in href_lower:
                matched_platforms.add(platform)

    if len(matched_platforms) < 4:
        return None

    platforms_found = ", ".join(sorted(matched_platforms))
    evidence_snippet = _truncate(f"Social platforms detected: {platforms_found}")
    return PCLNCheck(
        check_id="PCLN-003",
        severity="MEDIUM",
        description=(
            f"Page contains links to {len(matched_platforms)} distinct social media "
            "platforms. Phishing templates often copy legitimate footers to appear authentic."
        ),
        evidence=evidence_snippet,
        weight=15,
    )


def _check_pcln004(signals: PageSignals) -> PCLNCheck | None:
    """PCLN-004 — Obfuscated JavaScript (HIGH, weight=25).

    Fires when any of: eval(, unescape(, atob(, String.fromCharCode(
    appear in the HTML (case-sensitive for function names).
    """
    html = signals.html_content

    # Ordered list of (pattern, label) — case-sensitive as these are JS function names
    obfuscation_patterns = [
        (r'eval\s*\(', "eval("),
        (r'unescape\s*\(', "unescape("),
        (r'atob\s*\(', "atob("),
        (r'String\.fromCharCode\s*\(', "String.fromCharCode("),
    ]

    for pattern, label in obfuscation_patterns:
        m = re.search(pattern, html)
        if m:
            # Use up to _MAX_EVIDENCE_LEN chars starting slightly before the match
            start = max(0, m.start() - 20)
            end = min(len(html), m.start() + 80)
            snippet = html[start:end]
            return PCLNCheck(
                check_id="PCLN-004",
                severity="HIGH",
                description=(
                    f"Obfuscated JavaScript pattern '{label}' detected. "
                    "Script obfuscation is commonly used to evade static analysis in phishing kits."
                ),
                evidence=_truncate(snippet),
                weight=25,
            )

    return None


def _check_pcln005(signals: PageSignals) -> PCLNCheck | None:
    """PCLN-005 — Anti-indexing meta tag (MEDIUM, weight=20).

    Fires when <meta name="robots" content="noindex..."> is present.
    Phishing pages often hide from search engines to avoid detection.
    """
    html = signals.html_content

    # Allow combined directives e.g. "noindex, nofollow"
    # Pattern: <meta with name=robots AND content containing noindex (both attribute orders)
    patterns = [
        # name before content
        re.compile(
            r'<meta[^>]+name\s*=\s*["\']?\s*robots\s*["\']?[^>]+content\s*=\s*["\']?[^"\'>\s]*noindex',
            re.IGNORECASE,
        ),
        # content before name
        re.compile(
            r'<meta[^>]+content\s*=\s*["\']?[^"\'>\s]*noindex[^"\'>\s]*["\']?[^>]+name\s*=\s*["\']?\s*robots',
            re.IGNORECASE,
        ),
    ]

    for rx in patterns:
        m = rx.search(html)
        if m:
            return PCLNCheck(
                check_id="PCLN-005",
                severity="MEDIUM",
                description=(
                    "Anti-indexing <meta name='robots' content='noindex'> directive found. "
                    "Phishing pages commonly hide from search engines to evade detection."
                ),
                evidence=_truncate(m.group(0)),
                weight=20,
            )

    return None


def _check_pcln006(signals: PageSignals) -> PCLNCheck | None:
    """PCLN-006 — External form exfiltration (HIGH, weight=30).

    Fires when a <form action="..."> attribute points to a domain different
    from the observed domain. Relative paths (starting with /) are skipped.
    """
    html = signals.html_content
    domain_lower = signals.domain.lower()

    # Find all form tags and extract action attribute values
    form_tags = re.findall(r'<form[^>]*>', html, re.IGNORECASE)

    for tag in form_tags:
        action_match = re.search(
            r'action\s*=\s*["\']([^"\']*)["\']',
            tag,
            re.IGNORECASE,
        )
        if not action_match:
            continue

        action_val = action_match.group(1).strip()

        # Skip empty actions and relative paths (start with / or have no protocol)
        if not action_val:
            continue
        if action_val.startswith("/"):
            continue
        if not re.match(r'https?://', action_val, re.IGNORECASE):
            # No protocol — treat as relative reference, skip
            continue

        # Extract domain from the action URL
        action_domain = _extract_domain(action_val)
        if not action_domain:
            continue

        # Fire if the action domain differs from the observed domain
        if domain_lower not in action_domain and action_domain not in domain_lower:
            evidence_snippet = _truncate(tag)
            return PCLNCheck(
                check_id="PCLN-006",
                severity="HIGH",
                description=(
                    f"Form action '{action_val[:100]}' submits data to an external domain "
                    f"'{action_domain}' different from observed domain '{signals.domain}'. "
                    "Indicates form-based credential exfiltration."
                ),
                evidence=evidence_snippet,
                weight=30,
            )

    return None


def _check_pcln007(signals: PageSignals) -> PCLNCheck | None:
    """PCLN-007 — Favicon from brand domain (MEDIUM, weight=20).

    Fires when a <link rel="icon"> or <link rel="shortcut icon"> href
    points to a domain that contains brand_name (case-insensitive) but
    differs from the observed domain.
    """
    html = signals.html_content
    brand_lower = signals.brand_name.lower()
    domain_lower = signals.domain.lower()

    # Match <link rel="icon" ...> and <link rel="shortcut icon" ...>
    # Both attribute orders (rel before href and href before rel)
    link_patterns = [
        # rel before href
        re.compile(
            r'<link[^>]+rel\s*=\s*["\'](?:shortcut\s+)?icon["\'][^>]+href\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        ),
        # href before rel
        re.compile(
            r'<link[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]+rel\s*=\s*["\'](?:shortcut\s+)?icon["\']',
            re.IGNORECASE,
        ),
    ]

    hrefs_checked: set = set()

    for rx in link_patterns:
        for m in rx.finditer(html):
            href = m.group(1).strip()
            if href in hrefs_checked:
                continue
            hrefs_checked.add(href)

            href_lower = href.lower()
            # Only interested in absolute URLs pointing to a different domain
            if not re.match(r'https?://', href_lower):
                continue

            href_domain = _extract_domain(href)
            if not href_domain:
                continue

            # Fire if the href domain contains the brand name but is NOT the observed domain
            if brand_lower in href_domain and href_domain != domain_lower:
                return PCLNCheck(
                    check_id="PCLN-007",
                    severity="MEDIUM",
                    description=(
                        f"Favicon href '{href[:100]}' points to a domain '{href_domain}' "
                        f"containing brand name '{signals.brand_name}' "
                        f"but differs from observed domain '{signals.domain}'. "
                        "Phishing pages reuse real brand favicons for visual authenticity."
                    ),
                    evidence=_truncate(m.group(0)),
                    weight=20,
                )

    return None


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

_DETECTORS = [
    _check_pcln001,
    _check_pcln002,
    _check_pcln003,
    _check_pcln004,
    _check_pcln005,
    _check_pcln006,
    _check_pcln007,
]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(signals: PageSignals) -> CloneDetectionResult:
    """Analyze a single page for phishing clone / brand impersonation signals.

    Args:
        signals: A :class:`PageSignals` instance describing the page.

    Returns:
        A :class:`CloneDetectionResult` with all fired checks and aggregate scores.
    """
    checks_fired: List[PCLNCheck] = []

    for detector in _DETECTORS:
        result = detector(signals)
        if result is not None:
            checks_fired.append(result)

    # risk_score: sum of weights capped at 100
    risk_score = min(100, sum(c.weight for c in checks_fired))
    clone_likelihood = _likelihood(risk_score)
    kit_signals = len(checks_fired)

    return CloneDetectionResult(
        page_id=signals.page_id,
        domain=signals.domain,
        brand_name=signals.brand_name,
        checks_fired=checks_fired,
        risk_score=risk_score,
        clone_likelihood=clone_likelihood,
        kit_signals=kit_signals,
    )


def analyze_many(pages: List[PageSignals]) -> List[CloneDetectionResult]:
    """Analyze a list of :class:`PageSignals` instances.

    Args:
        pages: Ordered list of page signal bundles.

    Returns:
        List of :class:`CloneDetectionResult` in the same order as *pages*.
    """
    return [analyze(s) for s in pages]


def high_likelihood_clones(
    results: List[CloneDetectionResult],
) -> List[CloneDetectionResult]:
    """Return results where clone_likelihood is HIGH, sorted by risk_score descending.

    Args:
        results: List of :class:`CloneDetectionResult` to filter.

    Returns:
        Filtered and sorted list of high-likelihood clones.
    """
    return sorted(
        [r for r in results if r.clone_likelihood == "HIGH"],
        key=lambda r: r.risk_score,
        reverse=True,
    )
