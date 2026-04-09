# Social Engineering Detector — Cyber Port Portfolio
# Detects urgency manipulation, authority impersonation, credential harvesting,
# fear tactics, reward lures, deceptive links, and excessive PII collection
# in web page HTML or plain-text email body content.
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
# Copyright 2026 Cyber Port — github.com/hiagokinlevi

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Check weight registry — single source of truth for all check IDs
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "SENG-001": 25,  # Urgency language
    "SENG-002": 25,  # Authority impersonation
    "SENG-003": 45,  # Credential harvesting (CRITICAL)
    "SENG-004": 25,  # Fear / threat language
    "SENG-005": 15,  # Reward / prize language
    "SENG-006": 25,  # Deceptive link pattern
    "SENG-007": 20,  # Excessive PII collection
}

# ---------------------------------------------------------------------------
# Pattern tables — compiled once at import time for performance
# ---------------------------------------------------------------------------

# SENG-001: urgency phrases
_URGENCY_PHRASES: List[str] = [
    "expires today",
    "act now",
    "limited time",
    "your account will be suspended",
    "within 24 hours",
    "immediate action required",
    "respond immediately",
    "last chance",
]

# SENG-002: brand names and account-language patterns
_BRAND_NAMES: List[str] = [
    "apple",
    "microsoft",
    "google",
    "paypal",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "twitter",
    "irs",
    "hmrc",
]

_ACCOUNT_PATTERNS: List[str] = [
    r"your .{0,20}account",
    r"security team",
    r"account .{0,20}information",
    r"verify your",
    r"update your",
]

# SENG-003: credential harvesting — HTML attribute patterns
_CREDENTIAL_HTML_PATTERNS: List[str] = [
    r'type=["\']password["\']',
    r'name=["\']password["\']',
    r'name=["\']passwd["\']',
    r'id=["\']password["\']',
]

# SENG-003: credential harvesting — text phrase patterns
_CREDENTIAL_TEXT_PHRASES: List[str] = [
    "enter your password",
    "verify your account",
    "confirm your credentials",
    "update your payment",
    "re-enter your password",
]

# SENG-004: fear / threat phrases
_FEAR_PHRASES: List[str] = [
    "account has been compromised",
    "unauthorized access",
    "suspicious activity",
    "account suspended",
    "account will be terminated",
    "security breach",
    "illegal activity",
    "fraudulent activity",
]

# SENG-005: reward / prize phrases
_REWARD_PHRASES: List[str] = [
    "you have won",
    "you've won",
    "selected for a reward",
    "claim your prize",
    "you have been chosen",
    "congratulations",
    "free gift",
    "exclusive offer",
    "special reward",
]

# SENG-007: PII category patterns (each entry = one distinct category)
_PII_CATEGORY_PATTERNS: List[Tuple[str, str]] = [
    ("ssn_social_security",      r"ssn|social.{0,5}security"),
    ("date_of_birth",            r"date.{0,5}birth|birthday"),
    ("full_name",                r"first.{0,5}name|last.{0,5}name|full.{0,5}name"),
    ("address",                  r"address|street"),
    ("phone",                    r"phone|telephone|mobile"),
    ("email_address",            r"email.{0,5}address|e-mail"),
]

# Pre-compiled regex objects
_RE_ANCHOR = re.compile(
    r'<a\s[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
# Domain-like pattern inside anchor display text (word.tld, at least 2 chars each)
_RE_DOMAIN_IN_TEXT = re.compile(r'\b([\w-]{2,}\.(?:com|net|org|io|co|gov|edu|uk|de|fr|au|ca|app|info|biz|me|us|ly|cc|tv))\b', re.IGNORECASE)

_RE_ACCOUNT_COMPILED: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in _ACCOUNT_PATTERNS
]
_RE_PII_COMPILED: List[Tuple[str, re.Pattern]] = [
    (label, re.compile(pat, re.IGNORECASE)) for label, pat in _PII_CATEGORY_PATTERNS
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SENGFinding:
    """A single social-engineering check result."""
    check_id: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int
    evidence: List[str]  # matched phrases / patterns (may be truncated to 10 items)


@dataclass
class SENGResult:
    """Aggregated result for one piece of content."""
    findings: List[SENGFinding]
    risk_score: int          # min(100, sum of weights for unique fired check IDs)
    phishing_likelihood: str  # "HIGH" / "MEDIUM" / "LOW"

    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary representation."""
        return {
            "risk_score": self.risk_score,
            "phishing_likelihood": self.phishing_likelihood,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary."""
        fired = len(self.findings)
        checks = ", ".join(f.check_id for f in self.findings) if self.findings else "none"
        return (
            f"Phishing likelihood: {self.phishing_likelihood} "
            f"(risk_score={self.risk_score}, checks fired: {checks}, "
            f"total findings: {fired})"
        )

    def by_severity(self) -> Dict[str, List[SENGFinding]]:
        """Group findings by severity level."""
        groups: Dict[str, List[SENGFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helper utilities
# ---------------------------------------------------------------------------

def _truncate_evidence(items: List[str], limit: int = 10) -> List[str]:
    """Keep at most *limit* evidence strings to avoid bloated output."""
    return items[:limit]


def _extract_href_domain(href: str) -> Optional[str]:
    """
    Extract the hostname from a URL string.

    Returns None if the URL has no recognisable scheme+host (e.g. relative URLs,
    mailto:, javascript:, etc.).
    """
    # Only handle http / https URLs
    match = re.match(r'https?://([^/?#\s]+)', href, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def _compute_risk_score(findings: List[SENGFinding]) -> int:
    """Sum weights for unique fired check IDs, capped at 100."""
    seen: set = set()
    total = 0
    for f in findings:
        if f.check_id not in seen:
            seen.add(f.check_id)
            total += f.weight
    return min(100, total)


def _phishing_likelihood(score: int) -> str:
    """Map a numeric risk score to a likelihood label."""
    if score >= 60:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------

def _check_seng001(content_lower: str) -> Optional[SENGFinding]:
    """SENG-001: Urgency language."""
    matched = [p for p in _URGENCY_PHRASES if p in content_lower]
    if not matched:
        return None
    return SENGFinding(
        check_id="SENG-001",
        severity="HIGH",
        title="Urgency language detected",
        detail=(
            "The content uses urgency-inducing phrases designed to pressure the "
            "reader into taking immediate action without careful consideration."
        ),
        weight=_CHECK_WEIGHTS["SENG-001"],
        evidence=_truncate_evidence(matched),
    )


def _check_seng002(content_lower: str) -> Optional[SENGFinding]:
    """SENG-002: Authority impersonation."""
    # Step 1 — find any brand mention
    matched_brands = [b for b in _BRAND_NAMES if b in content_lower]
    if not matched_brands:
        return None

    # Step 2 — find any account-language phrase near the brand
    matched_account: List[str] = []
    for pattern in _RE_ACCOUNT_COMPILED:
        m = pattern.search(content_lower)
        if m:
            matched_account.append(m.group(0))

    if not matched_account:
        return None

    evidence = [f"brand: {b}" for b in matched_brands] + [f"phrase: {a}" for a in matched_account]
    return SENGFinding(
        check_id="SENG-002",
        severity="HIGH",
        title="Authority impersonation detected",
        detail=(
            "The content combines a well-known brand name with account-related language, "
            "a common pattern in phishing attacks that impersonate trusted organisations."
        ),
        weight=_CHECK_WEIGHTS["SENG-002"],
        evidence=_truncate_evidence(evidence),
    )


def _check_seng003(content: str, content_lower: str, content_type: str) -> Optional[SENGFinding]:
    """SENG-003: Credential harvesting indicators."""
    matched: List[str] = []

    # HTML-specific attribute patterns
    if content_type == "html":
        for pat in _CREDENTIAL_HTML_PATTERNS:
            hits = re.findall(pat, content, re.IGNORECASE)
            matched.extend(hits)

    # Text phrases work for both html and plain text
    for phrase in _CREDENTIAL_TEXT_PHRASES:
        if phrase in content_lower:
            matched.append(phrase)

    if not matched:
        return None

    return SENGFinding(
        check_id="SENG-003",
        severity="CRITICAL",
        title="Credential harvesting indicators detected",
        detail=(
            "The content contains password field indicators or phrases that solicit "
            "credentials from users, a hallmark of phishing and credential-theft attacks."
        ),
        weight=_CHECK_WEIGHTS["SENG-003"],
        evidence=_truncate_evidence(matched),
    )


def _check_seng004(content_lower: str) -> Optional[SENGFinding]:
    """SENG-004: Fear / threat language."""
    matched = [p for p in _FEAR_PHRASES if p in content_lower]
    if not matched:
        return None
    return SENGFinding(
        check_id="SENG-004",
        severity="HIGH",
        title="Fear or threat language detected",
        detail=(
            "The content uses fear-inducing or threatening language intended to alarm "
            "the reader and compel compliance without rational evaluation."
        ),
        weight=_CHECK_WEIGHTS["SENG-004"],
        evidence=_truncate_evidence(matched),
    )


def _check_seng005(content_lower: str) -> Optional[SENGFinding]:
    """SENG-005: Reward / prize language."""
    matched = [p for p in _REWARD_PHRASES if p in content_lower]
    if not matched:
        return None
    return SENGFinding(
        check_id="SENG-005",
        severity="MEDIUM",
        title="Reward or prize language detected",
        detail=(
            "The content uses reward or prize language to entice the reader into "
            "clicking links or providing personal information."
        ),
        weight=_CHECK_WEIGHTS["SENG-005"],
        evidence=_truncate_evidence(matched),
    )


def _check_seng006(content: str) -> Optional[SENGFinding]:
    """SENG-006: Deceptive link pattern (HTML only)."""
    evidence: List[str] = []

    for m in _RE_ANCHOR.finditer(content):
        href = m.group(1).strip()
        display_text = re.sub(r'<[^>]+>', '', m.group(2)).strip()  # strip inner tags

        href_domain = _extract_href_domain(href)
        if not href_domain:
            # Relative or non-http URL — skip
            continue

        # Find domain-like patterns in the display text
        text_domain_matches = _RE_DOMAIN_IN_TEXT.findall(display_text)
        for text_domain in text_domain_matches:
            text_domain_lower = text_domain.lower()
            # Mismatch: display text shows a different domain from the href
            if text_domain_lower != href_domain and not href_domain.endswith("." + text_domain_lower):
                evidence.append(
                    f"displayed='{text_domain}' but href points to '{href_domain}'"
                )

    if not evidence:
        return None

    return SENGFinding(
        check_id="SENG-006",
        severity="HIGH",
        title="Deceptive link pattern detected",
        detail=(
            "One or more hyperlinks display a legitimate-looking domain in their visible "
            "text while the actual href points to a different, potentially malicious domain."
        ),
        weight=_CHECK_WEIGHTS["SENG-006"],
        evidence=_truncate_evidence(evidence),
    )


def _check_seng007(content_lower: str) -> Optional[SENGFinding]:
    """SENG-007: Excessive PII collection (3+ distinct categories)."""
    matched_categories: List[str] = []

    for label, pattern in _RE_PII_COMPILED:
        if pattern.search(content_lower):
            matched_categories.append(label)

    if len(matched_categories) < 3:
        return None

    return SENGFinding(
        check_id="SENG-007",
        severity="HIGH",
        title="Excessive PII collection detected",
        detail=(
            f"The content requests {len(matched_categories)} distinct categories of "
            "personally identifiable information simultaneously, which is consistent "
            "with identity theft and phishing campaigns."
        ),
        weight=_CHECK_WEIGHTS["SENG-007"],
        evidence=_truncate_evidence(matched_categories),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(content: str, content_type: str = "html") -> SENGResult:
    """Analyze web page or email content for social engineering patterns.

    Parameters
    ----------
    content:
        Raw HTML markup or plain-text email body.
    content_type:
        ``"html"`` (default) or ``"text"``.  Certain checks (SENG-003 HTML
        attribute scan, SENG-006 link analysis) are only active for HTML.

    Returns
    -------
    SENGResult
        Aggregated findings, numeric risk score, and likelihood label.
    """
    if not isinstance(content, str):
        raise TypeError(f"content must be a str, got {type(content).__name__!r}")
    if content_type not in ("html", "text"):
        raise ValueError(f"content_type must be 'html' or 'text', got {content_type!r}")

    content_lower = content.lower()
    findings: List[SENGFinding] = []

    # Run all checks — order determines the list order in the result
    result_001 = _check_seng001(content_lower)
    if result_001:
        findings.append(result_001)

    result_002 = _check_seng002(content_lower)
    if result_002:
        findings.append(result_002)

    result_003 = _check_seng003(content, content_lower, content_type)
    if result_003:
        findings.append(result_003)

    result_004 = _check_seng004(content_lower)
    if result_004:
        findings.append(result_004)

    result_005 = _check_seng005(content_lower)
    if result_005:
        findings.append(result_005)

    # SENG-006 only applies to HTML content
    if content_type == "html":
        result_006 = _check_seng006(content)
        if result_006:
            findings.append(result_006)

    result_007 = _check_seng007(content_lower)
    if result_007:
        findings.append(result_007)

    score = _compute_risk_score(findings)
    likelihood = _phishing_likelihood(score)

    return SENGResult(
        findings=findings,
        risk_score=score,
        phishing_likelihood=likelihood,
    )


def analyze_many(contents: List[str], content_type: str = "html") -> List[SENGResult]:
    """Analyze a batch of content strings for social engineering patterns.

    Parameters
    ----------
    contents:
        List of raw HTML or plain-text strings to analyse.
    content_type:
        Applied uniformly to every item in *contents*.

    Returns
    -------
    List[SENGResult]
        One result per input string, in the same order.
    """
    return [analyze(c, content_type) for c in contents]
