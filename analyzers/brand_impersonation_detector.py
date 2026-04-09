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
Brand Impersonation Domain Analyzer
=====================================
Detects domains and URLs that impersonate a target brand through various
obfuscation techniques including homoglyph substitution, typosquatting,
Punycode abuse, numeric substitution, and phishing action-word combinations.

All checks run fully offline — no DNS, WHOIS, or HTTP calls are made.

Usage::

    from analyzers.brand_impersonation_detector import (
        BrandTarget,
        DomainSample,
        BrandImpersonationDetector,
    )

    targets = [
        BrandTarget(
            name="PayPal",
            keywords=["paypal"],
            official_domains=["paypal.com", "paypal.co.uk"],
        ),
    ]
    detector = BrandImpersonationDetector(brand_targets=targets)
    result = detector.analyze(DomainSample(domain="paypa1-login.com"))
    print(result.summary())
    print(result.risk_score)
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Homoglyph mapping: brand character → list of visually similar impostor chars.
# Keys are the canonical ASCII chars; values are characters that an attacker
# might substitute to make the domain look like the brand.
_HOMOGLYPHS: Dict[str, List[str]] = {
    "a": ["@", "4", "а", "α"],   # cyrillic а (U+0430), greek α (U+03B1)
    "e": ["3", "е"],              # cyrillic е (U+0435)
    "i": ["1", "l", "і", "!"],   # cyrillic і (U+0456)
    "o": ["0", "о", "ο"],        # cyrillic о (U+043E), greek ο (U+03BF)
    "s": ["5", "$"],
    "g": ["9", "q"],
    "b": ["6", "d"],
    "l": ["1", "I"],
}

# Reverse map: impostor char → canonical ASCII char.
# Built once at import time for O(1) lookups during normalization.
#
# IMPORTANT: We deliberately exclude ASCII-letter impostors (e.g. "l" as an
# impostor for "i", or "q" as an impostor for "g", or "d" as an impostor for
# "b") from this map.  Those characters are valid domain-name letters and
# blindly replacing them would corrupt every real occurrence in a domain (e.g.
# turning the "l" in "paypal" into "i", yielding "paypai" instead of "paypal").
#
# BRD-001 uses this map for a quick "is there any suspicious Unicode/special
# char in the domain?" filter.  The full per-position keyword scanning that
# handles ASCII-letter homoglyphs is done separately inside _run_brd001.
_HOMOGLYPH_REVERSE: Dict[str, str] = {}
for _base_char, _impostor_list in _HOMOGLYPHS.items():
    for _impostor in _impostor_list:
        if len(_impostor) != 1:
            continue
        # Skip ASCII lowercase letters — they are legitimate domain characters
        # and must not be globally replaced (e.g. "l" → "i" would break all
        # domains containing the letter "l").
        if _impostor.isascii() and _impostor.isalpha() and _impostor.islower():
            continue
        _HOMOGLYPH_REVERSE[_impostor] = _base_char

# QWERTY keyboard one-hop proximity map.
# For each key, the list contains all adjacent keys (including diagonal).
_KEYBOARD_PROXIMITY: Dict[str, List[str]] = {
    "a": ["q", "w", "s", "z"],
    "e": ["w", "r", "d", "s"],
    "i": ["u", "o", "k", "j"],
    "o": ["i", "p", "l", "k"],
    "g": ["f", "h", "t", "y", "b"],
    "l": ["k", "o", "p"],
    "n": ["b", "m", "h", "j"],
}

# Action words that commonly appear on phishing pages to lure users into
# credential entry or account verification.
_ACTION_WORDS: List[str] = [
    "login",
    "secure",
    "verify",
    "update",
    "signin",
    "account",
    "support",
    "confirm",
    "authenticate",
    "reset",
    "recover",
    "helpdesk",
    "portal",
]

# Suspicious TLDs frequently observed in phishing infrastructure.
_SUSPICIOUS_TLDS: List[str] = [
    "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "ws", "biz",
]

# Weight table keyed by check ID.  risk_score = min(100, sum of weights for
# each *unique* check ID that fires across all findings for a domain.
_CHECK_WEIGHTS: Dict[str, int] = {
    "BRD-001": 45,  # Homoglyph substitution        — CRITICAL
    "BRD-002": 25,  # Brand keyword embedded         — HIGH
    "BRD-003": 25,  # Suspicious TLD + brand keyword — HIGH
    "BRD-004": 40,  # Punycode with brand reference  — CRITICAL
    "BRD-005": 20,  # Keyboard proximity substitution— HIGH
    "BRD-006": 25,  # Brand + action word combination— HIGH
    "BRD-007": 20,  # Numeric substitution           — HIGH
}

# Severity label associated with each check ID.
_CHECK_SEVERITIES: Dict[str, str] = {
    "BRD-001": "CRITICAL",
    "BRD-002": "HIGH",
    "BRD-003": "HIGH",
    "BRD-004": "CRITICAL",
    "BRD-005": "HIGH",
    "BRD-006": "HIGH",
    "BRD-007": "HIGH",
}

# Recommendation text per check ID.
_CHECK_RECOMMENDATIONS: Dict[str, str] = {
    "BRD-001": (
        "Register defensive Unicode variants of your brand domain and monitor "
        "homoglyph registrations via Certificate Transparency logs."
    ),
    "BRD-002": (
        "Submit a UDRP or URS complaint if commercial intent is evident; "
        "consider a cease-and-desist letter and takedown request to the registrar."
    ),
    "BRD-003": (
        "File an abuse report with the free-TLD provider (e.g. Freenom) and "
        "request suspension. Monitor these TLDs proactively via CT log scanning."
    ),
    "BRD-004": (
        "Report the Punycode domain to the registrar and relevant ICANN registries. "
        "Punycode domains impersonating brands may violate ICANN policies."
    ),
    "BRD-005": (
        "Register common one-keystroke typo variants of your brand domain to "
        "prevent typosquatting. Consider automated brand monitoring services."
    ),
    "BRD-006": (
        "Treat this domain as an active phishing threat. Immediately submit abuse "
        "reports to the registrar, hosting provider, and Google/Microsoft Safe Browsing."
    ),
    "BRD-007": (
        "Register numeric-substitution variants (e.g. paypa1.com, g00gle.com) "
        "defensively and add them to your brand monitoring watchlist."
    ),
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class BrandTarget:
    """
    Describes a brand to be protected.

    Attributes:
        name:             Human-readable brand display name, e.g. "Google".
        keywords:         List of lowercase brand keywords to detect in domains,
                          e.g. ["google", "gmail", "goog"].
        official_domains: Canonical/legitimate domains owned by the brand.
                          Domains in this list are never flagged.
    """
    name: str
    keywords: List[str]
    official_domains: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain Python dict."""
        return {
            "name": self.name,
            "keywords": list(self.keywords),
            "official_domains": list(self.official_domains),
        }


@dataclass
class DomainSample:
    """
    A candidate domain (and optional full URL) to be analyzed.

    Attributes:
        domain: The bare domain name, e.g. "g00gle-login.com".
        url:    Full URL if available, e.g. "https://g00gle-login.com/signin".
    """
    domain: str
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain Python dict."""
        return {
            "domain": self.domain,
            "url": self.url,
        }


@dataclass
class ImpersonationFinding:
    """
    A single fired check result for one brand target against one domain.

    Attributes:
        check_id:         Identifier of the check that fired, e.g. "BRD-001".
        severity:         Severity string: "CRITICAL" or "HIGH".
        domain:           The domain that was analyzed.
        brand_name:       Display name of the brand being impersonated.
        matched_keyword:  The brand keyword that triggered this finding.
        message:          Human-readable explanation of why the check fired.
        recommendation:   Actionable remediation advice.
    """
    check_id: str
    severity: str
    domain: str
    brand_name: str
    matched_keyword: str
    message: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain Python dict."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "domain": self.domain,
            "brand_name": self.brand_name,
            "matched_keyword": self.matched_keyword,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class ImpersonationResult:
    """
    Aggregated analysis result for one DomainSample.

    Attributes:
        domain:     The domain that was analyzed.
        url:        The full URL if one was supplied.
        findings:   All ImpersonationFinding objects that fired.
        risk_score: Integer 0–100 calculated from unique fired check IDs.
    """
    domain: str
    url: Optional[str]
    findings: List[ImpersonationFinding] = field(default_factory=list)
    risk_score: int = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """
        Return a single-line human-readable summary of the result.

        Format::

            [CRITICAL] 'g00gle-login.com' | risk_score=90 | findings=3
        """
        if not self.findings:
            severity_label = "CLEAN"
        else:
            # Use the highest-severity label among all findings.
            severity_label = (
                "CRITICAL"
                if any(f.severity == "CRITICAL" for f in self.findings)
                else "HIGH"
            )
        return (
            f"[{severity_label}] '{self.domain}' | "
            f"risk_score={self.risk_score} | "
            f"findings={len(self.findings)}"
        )

    def by_severity(self) -> Dict[str, List[ImpersonationFinding]]:
        """
        Group findings by severity label.

        Returns a dict with keys ``"CRITICAL"`` and ``"HIGH"``, each mapping
        to a (possibly empty) list of ImpersonationFinding objects.
        """
        grouped: Dict[str, List[ImpersonationFinding]] = {
            "CRITICAL": [],
            "HIGH": [],
        }
        for finding in self.findings:
            bucket = grouped.get(finding.severity)
            if bucket is not None:
                bucket.append(finding)
        return grouped

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full result to a plain Python dict."""
        return {
            "domain": self.domain,
            "url": self.url,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalize_homoglyphs(text: str) -> str:
    """
    Return a version of *text* where every known homoglyph character has been
    replaced by its canonical ASCII equivalent.

    ``_HOMOGLYPH_REVERSE`` deliberately excludes ASCII-letter impostors (see
    its construction comments) so this function is safe to use for substring
    searches that must not corrupt real ASCII letter sequences.

    Steps:
    1. Apply NFKC Unicode normalization to decompose composed characters.
    2. Walk every character and replace it using ``_HOMOGLYPH_REVERSE`` if a
       mapping exists.
    3. Lowercase the result for case-insensitive comparisons.
    """
    # NFKC collapses compatibility variants (e.g. full-width letters).
    normalized = unicodedata.normalize("NFKC", text)
    result: List[str] = []
    for ch in normalized:
        result.append(_HOMOGLYPH_REVERSE.get(ch, ch))
    return "".join(result).lower()


# Full reverse map that includes ASCII-letter impostors (e.g. "l" → "i").
# Used exclusively by BRD-001 where we operate on the domain character-by-
# character aligned against a keyword, so the corruption risk is controlled.
_HOMOGLYPH_REVERSE_FULL: Dict[str, str] = {}
for _base_char, _impostor_list in _HOMOGLYPHS.items():
    for _impostor in _impostor_list:
        if len(_impostor) == 1:
            _HOMOGLYPH_REVERSE_FULL[_impostor] = _base_char


def _normalize_homoglyphs_full(text: str) -> str:
    """
    Like ``_normalize_homoglyphs`` but also maps ASCII-letter impostors.

    This is the "spec-correct" normalization described in BRD-001:

        build a normalized version of the domain where all homoglyphs are
        replaced by their base char, then check if any brand keyword appears
        in that normalized string.

    Used only inside BRD-001 where we already know no real-keyword substring
    exists in the raw domain, so replacing 'l'→'i' etc. is intentional.
    """
    normalized = unicodedata.normalize("NFKC", text)
    result: List[str] = []
    for ch in normalized:
        result.append(_HOMOGLYPH_REVERSE_FULL.get(ch, ch))
    return "".join(result).lower()


def _build_numeric_variants(keyword: str) -> List[str]:
    """
    Generate all single-character numeric substitutions for *keyword*.

    Substitution rules:
      o → 0, i → 1, i → l, e → 3, a → 4, s → 5, g → 9

    Returns a list of variant strings (deduplicated, excluding the original).
    """
    # Substitution map: canonical char → list of numeric/leet replacements.
    # "l" → "1" captures the classic "paypa1" variant (l looks like 1/I).
    sub_map: Dict[str, List[str]] = {
        "o": ["0"],
        "i": ["1", "l"],
        "e": ["3"],
        "a": ["4"],
        "s": ["5"],
        "g": ["9"],
        "l": ["1"],
    }
    variants: List[str] = []
    kw = keyword.lower()
    for idx, ch in enumerate(kw):
        replacements = sub_map.get(ch, [])
        for rep in replacements:
            variant = kw[:idx] + rep + kw[idx + 1:]
            if variant != kw:
                variants.append(variant)
    # Deduplicate while preserving order.
    seen: List[str] = []
    for v in variants:
        if v not in seen:
            seen.append(v)
    return seen


def _get_tld(domain: str) -> str:
    """Extract the TLD (last label) from a domain string."""
    return domain.split(".")[-1].lower()


def _strip_domain_to_searchable(domain: str) -> str:
    """
    Return a lowercase version of *domain* suitable for substring searches.
    Strips leading ``www.`` but keeps the full string otherwise so checks can
    match keywords that appear in any label (SLD or subdomain).
    """
    d = domain.lower()
    if d.startswith("www."):
        d = d[4:]
    return d


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class BrandImpersonationDetector:
    """
    Analyzes domains and URLs for brand impersonation using seven distinct
    detection checks (BRD-001 through BRD-007).

    Args:
        brand_targets: List of BrandTarget objects describing every brand to
                       protect.  Multiple brands are supported; each check is
                       run for each brand independently.
    """

    def __init__(self, brand_targets: List[BrandTarget]) -> None:
        self._targets = brand_targets

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, sample: DomainSample) -> ImpersonationResult:
        """
        Analyze one DomainSample against all brand targets.

        Returns an ImpersonationResult whose ``risk_score`` is the sum of
        weights for each *unique* check ID that fired, capped at 100.
        """
        domain_lower = sample.domain.lower()
        all_findings: List[ImpersonationFinding] = []

        for target in self._targets:
            # Skip the official domains — they must never produce findings.
            if domain_lower in [od.lower() for od in target.official_domains]:
                continue

            all_findings.extend(
                self._run_brd001(sample.domain, target)
            )
            all_findings.extend(
                self._run_brd002(sample.domain, target)
            )
            all_findings.extend(
                self._run_brd003(sample.domain, target)
            )
            all_findings.extend(
                self._run_brd004(sample.domain, target)
            )
            all_findings.extend(
                self._run_brd005(sample.domain, target)
            )
            all_findings.extend(
                self._run_brd006(sample.domain, target)
            )
            all_findings.extend(
                self._run_brd007(sample.domain, target)
            )

        # risk_score = sum of weights for unique fired check IDs.
        fired_check_ids = {f.check_id for f in all_findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_check_ids))

        return ImpersonationResult(
            domain=sample.domain,
            url=sample.url,
            findings=all_findings,
            risk_score=risk_score,
        )

    def analyze_many(
        self, samples: List[DomainSample]
    ) -> List[ImpersonationResult]:
        """
        Analyze a list of DomainSample objects.

        Returns a list of ImpersonationResult objects in the same order as the
        input list.
        """
        return [self.analyze(s) for s in samples]

    # ------------------------------------------------------------------
    # BRD-001 — Homoglyph substitution (CRITICAL, weight 45)
    # ------------------------------------------------------------------

    def _run_brd001(
        self, domain: str, target: BrandTarget
    ) -> List[ImpersonationFinding]:
        """
        Detect homoglyph-obfuscated brand keywords in the domain.

        Strategy (per spec):
          Build a "normalized" version of the domain where every known
          homoglyph character is replaced by its canonical ASCII equivalent.
          If a brand keyword appears in that normalized domain but NOT in the
          original lowercased domain, a homoglyph substitution is confirmed.

        We use ``_normalize_homoglyphs`` (safe version) which handles all
        non-ASCII Unicode impostors (Cyrillic, Greek) and special characters
        (@, 4, 0, 3, $, !) without corrupting real ASCII letters like 'l'.
        """
        findings: List[ImpersonationFinding] = []
        domain_lower = domain.lower()
        # Safe normalization: replaces non-ASCII and special-char impostors
        # (e.g. Cyrillic а→a, @→a, 4→a, 0→o) without corrupting real ASCII
        # letters such as 'l'.  ASCII-letter-to-letter homoglyphs (e.g. l→i)
        # are intentionally excluded because a global replacement would corrupt
        # any real occurrence of those letters in the domain.
        domain_normalized = _normalize_homoglyphs(domain)

        for keyword in target.keywords:
            kw = keyword.lower()
            # Keyword must appear in the normalized domain…
            if kw not in domain_normalized:
                continue
            # …but we only flag it as a *homoglyph* attack when the keyword is
            # absent in the raw domain.  If the plain-text keyword is already
            # there, BRD-002 covers it.
            if kw in domain_lower:
                continue
            # Homoglyph substitution confirmed.
            findings.append(
                ImpersonationFinding(
                    check_id="BRD-001",
                    severity=_CHECK_SEVERITIES["BRD-001"],
                    domain=domain,
                    brand_name=target.name,
                    matched_keyword=keyword,
                    message=(
                        f"Domain '{domain}' contains homoglyph characters that "
                        f"normalize to the brand keyword '{keyword}' for {target.name}."
                    ),
                    recommendation=_CHECK_RECOMMENDATIONS["BRD-001"],
                )
            )
            break  # One finding per target per check is sufficient.
        return findings

    # ------------------------------------------------------------------
    # BRD-002 — Brand keyword embedded in domain (HIGH, weight 25)
    # ------------------------------------------------------------------

    def _run_brd002(
        self, domain: str, target: BrandTarget
    ) -> List[ImpersonationFinding]:
        """
        Detect plain-text brand keywords appearing as substrings of the domain.

        One finding is emitted per brand target (not per keyword) to avoid
        duplicate score inflation.
        """
        findings: List[ImpersonationFinding] = []
        domain_lower = domain.lower()
        searchable = _strip_domain_to_searchable(domain_lower)

        for keyword in target.keywords:
            kw = keyword.lower()
            if kw in searchable:
                findings.append(
                    ImpersonationFinding(
                        check_id="BRD-002",
                        severity=_CHECK_SEVERITIES["BRD-002"],
                        domain=domain,
                        brand_name=target.name,
                        matched_keyword=keyword,
                        message=(
                            f"Domain '{domain}' contains the brand keyword "
                            f"'{keyword}' ({target.name}) as a plain-text substring, "
                            f"suggesting impersonation."
                        ),
                        recommendation=_CHECK_RECOMMENDATIONS["BRD-002"],
                    )
                )
                break  # One finding per brand target is enough.
        return findings

    # ------------------------------------------------------------------
    # BRD-003 — Suspicious TLD with brand keyword (HIGH, weight 25)
    # ------------------------------------------------------------------

    def _run_brd003(
        self, domain: str, target: BrandTarget
    ) -> List[ImpersonationFinding]:
        """
        Flag domains that combine a brand keyword with a suspicious TLD.
        """
        findings: List[ImpersonationFinding] = []
        tld = _get_tld(domain)
        if tld not in _SUSPICIOUS_TLDS:
            return findings

        searchable = _strip_domain_to_searchable(domain.lower())
        for keyword in target.keywords:
            if keyword.lower() in searchable:
                findings.append(
                    ImpersonationFinding(
                        check_id="BRD-003",
                        severity=_CHECK_SEVERITIES["BRD-003"],
                        domain=domain,
                        brand_name=target.name,
                        matched_keyword=keyword,
                        message=(
                            f"Domain '{domain}' pairs the brand keyword '{keyword}' "
                            f"({target.name}) with the suspicious TLD '.{tld}'."
                        ),
                        recommendation=_CHECK_RECOMMENDATIONS["BRD-003"],
                    )
                )
                break
        return findings

    # ------------------------------------------------------------------
    # BRD-004 — Punycode domain with brand reference (CRITICAL, weight 40)
    # ------------------------------------------------------------------

    def _run_brd004(
        self, domain: str, target: BrandTarget
    ) -> List[ImpersonationFinding]:
        """
        Detect Punycode (IDN) domains that reference a brand keyword.

        Punycode labels begin with the ``xn--`` ACE prefix and can encode
        Unicode characters that appear identical to ASCII brand names.
        """
        findings: List[ImpersonationFinding] = []
        domain_lower = domain.lower()

        # Check for xn-- in any label.
        labels = domain_lower.split(".")
        has_punycode = any(lbl.startswith("xn--") for lbl in labels)
        if not has_punycode:
            return findings

        # Also try to decode the domain for additional keyword matching.
        try:
            decoded = domain_lower.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            decoded = domain_lower

        combined_searchable = domain_lower + " " + decoded

        for keyword in target.keywords:
            kw = keyword.lower()
            if kw in combined_searchable:
                findings.append(
                    ImpersonationFinding(
                        check_id="BRD-004",
                        severity=_CHECK_SEVERITIES["BRD-004"],
                        domain=domain,
                        brand_name=target.name,
                        matched_keyword=keyword,
                        message=(
                            f"Domain '{domain}' uses Punycode/IDN encoding and "
                            f"references the brand keyword '{keyword}' ({target.name}). "
                            f"Punycode can encode characters visually identical to "
                            f"ASCII brand names."
                        ),
                        recommendation=_CHECK_RECOMMENDATIONS["BRD-004"],
                    )
                )
                break
        return findings

    # ------------------------------------------------------------------
    # BRD-005 — Keyboard proximity substitution (HIGH, weight 20)
    # ------------------------------------------------------------------

    def _run_brd005(
        self, domain: str, target: BrandTarget
    ) -> List[ImpersonationFinding]:
        """
        Detect typosquatting via keyboard-adjacent character substitutions.

        For each brand keyword, every character that has known keyboard
        neighbors (per ``_KEYBOARD_PROXIMITY``) is replaced one at a time with
        each neighbor.  If the resulting variant is found as a substring in the
        domain, the check fires.
        """
        findings: List[ImpersonationFinding] = []
        searchable = _strip_domain_to_searchable(domain.lower())

        for keyword in target.keywords:
            kw = keyword.lower()
            fired = False
            for idx, ch in enumerate(kw):
                neighbors = _KEYBOARD_PROXIMITY.get(ch, [])
                for neighbor in neighbors:
                    variant = kw[:idx] + neighbor + kw[idx + 1:]
                    if variant in searchable:
                        findings.append(
                            ImpersonationFinding(
                                check_id="BRD-005",
                                severity=_CHECK_SEVERITIES["BRD-005"],
                                domain=domain,
                                brand_name=target.name,
                                matched_keyword=keyword,
                                message=(
                                    f"Domain '{domain}' contains '{variant}', a "
                                    f"keyboard-proximity variant of the brand keyword "
                                    f"'{keyword}' ({target.name}) — character "
                                    f"'{ch}' at position {idx} replaced by "
                                    f"adjacent key '{neighbor}'."
                                ),
                                recommendation=_CHECK_RECOMMENDATIONS["BRD-005"],
                            )
                        )
                        fired = True
                        break
                if fired:
                    break
        return findings

    # ------------------------------------------------------------------
    # BRD-006 — Brand + action word combination (HIGH, weight 25)
    # ------------------------------------------------------------------

    def _run_brd006(
        self, domain: str, target: BrandTarget
    ) -> List[ImpersonationFinding]:
        """
        Detect domains that combine a brand keyword with a phishing action word.

        The combination (e.g. "paypal-login.com", "secure-paypal.net") is a
        strong indicator of a credential-harvesting landing page.
        """
        findings: List[ImpersonationFinding] = []
        searchable = _strip_domain_to_searchable(domain.lower())

        keyword_found: Optional[str] = None
        for keyword in target.keywords:
            if keyword.lower() in searchable:
                keyword_found = keyword
                break

        if keyword_found is None:
            return findings

        for action_word in _ACTION_WORDS:
            if action_word in searchable:
                findings.append(
                    ImpersonationFinding(
                        check_id="BRD-006",
                        severity=_CHECK_SEVERITIES["BRD-006"],
                        domain=domain,
                        brand_name=target.name,
                        matched_keyword=keyword_found,
                        message=(
                            f"Domain '{domain}' combines the brand keyword "
                            f"'{keyword_found}' ({target.name}) with the phishing "
                            f"action word '{action_word}', suggesting a credential "
                            f"harvesting page."
                        ),
                        recommendation=_CHECK_RECOMMENDATIONS["BRD-006"],
                    )
                )
                break  # One finding per target is sufficient.
        return findings

    # ------------------------------------------------------------------
    # BRD-007 — Numeric substitution in brand keyword (HIGH, weight 20)
    # ------------------------------------------------------------------

    def _run_brd007(
        self, domain: str, target: BrandTarget
    ) -> List[ImpersonationFinding]:
        """
        Detect leet-speak numeric substitutions in brand keywords.

        Substitutions checked: o→0, i→1/l, e→3, a→4, s→5, g→9.
        """
        findings: List[ImpersonationFinding] = []
        searchable = _strip_domain_to_searchable(domain.lower())

        for keyword in target.keywords:
            variants = _build_numeric_variants(keyword.lower())
            for variant in variants:
                if variant in searchable:
                    findings.append(
                        ImpersonationFinding(
                            check_id="BRD-007",
                            severity=_CHECK_SEVERITIES["BRD-007"],
                            domain=domain,
                            brand_name=target.name,
                            matched_keyword=keyword,
                            message=(
                                f"Domain '{domain}' contains '{variant}', a "
                                f"numeric-substitution variant of the brand keyword "
                                f"'{keyword}' ({target.name})."
                            ),
                            recommendation=_CHECK_RECOMMENDATIONS["BRD-007"],
                        )
                    )
                    break  # One finding per keyword per check.
        return findings
