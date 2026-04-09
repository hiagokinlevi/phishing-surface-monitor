"""
Lookalike Domain Risk Scorer
================================
Scores domain names for their likelihood of being lookalike / phishing
domains targeting a protected brand. Combines multiple similarity signals
to produce a 0–100 risk score with categorical risk level.

Signals Used
-------------
- Character substitution (leet-speak, common typos: rn→m, cl→d, vv→w)
- Homoglyph substitution (Unicode visually-similar characters mapped to ASCII)
- Keyboard proximity (adjacent keys on QWERTY layout)
- Edit distance (Levenshtein) relative to brand length
- Suspicious TLD (e.g. .tk, .ml, .ga, .cf, .gq, .xyz, .top, .click)
- Brand as subdomain (brand.attacker.com)
- Brand embedded in longer domain (brandbank.com, getbrand.io)
- Punycode / IDN encoding (xn-- prefix)

Usage::

    from analyzers.lookalike_scorer import LookalikeScorer, DomainRiskResult

    scorer = LookalikeScorer(brand="example")
    result = scorer.score("examp1e.com")
    print(result.summary())

    # Batch
    results = scorer.score_many(["examp1e.com", "exаmple.com", "example.tk"])
    for r in results:
        print(r.summary())
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"   # score >= 80
    HIGH     = "HIGH"       # score >= 60
    MEDIUM   = "MEDIUM"     # score >= 35
    LOW      = "LOW"        # score >= 15
    INFO     = "INFO"       # score < 15


# ---------------------------------------------------------------------------
# Character substitution tables
# ---------------------------------------------------------------------------

# Leet-speak and common OCR-confusion substitutions (single char → target char)
_LEET_MAP: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
    "!": "i",
}

# Multi-character → single character substitutions (e.g. "rn" looks like "m")
_MULTI_CHAR_SUBS: list[tuple[str, str]] = [
    ("rn", "m"),
    ("cl", "d"),
    ("vv", "w"),
    ("ii", "n"),
    ("nn", "m"),
    ("lI", "ll"),
    ("mn", "m"),
]

# Homoglyph map: Unicode lookalike chars → ASCII equivalent
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a",  # U+0430
    "е": "e",  # U+0435
    "о": "o",  # U+043E
    "р": "p",  # U+0440
    "с": "c",  # U+0441
    "х": "x",  # U+0445
    "у": "y",  # U+0443
    "і": "i",  # U+0456
    "ı": "i",  # U+0131
    "ο": "o",  # U+03BF Greek
    "ρ": "p",  # U+03C1 Greek
    "ν": "v",  # U+03BD Greek
    "α": "a",  # U+03B1 Greek
    "ε": "e",  # U+03B5 Greek
    # Latin lookalikes
    "ó": "o",
    "ó": "o",
    "à": "a",
    "é": "e",
    "ì": "i",
    "ú": "u",
    "ñ": "n",
    "ç": "c",
    "ł": "l",
    "ℓ": "l",
    "ⅼ": "l",
    "ⅰ": "i",
    "ꓸ": ".",
}

# QWERTY keyboard adjacency map
_QWERTY_NEIGHBORS: dict[str, set[str]] = {
    "q": {"w", "a"},
    "w": {"q", "e", "a", "s"},
    "e": {"w", "r", "s", "d"},
    "r": {"e", "t", "d", "f"},
    "t": {"r", "y", "f", "g"},
    "y": {"t", "u", "g", "h"},
    "u": {"y", "i", "h", "j"},
    "i": {"u", "o", "j", "k"},
    "o": {"i", "p", "k", "l"},
    "p": {"o", "l"},
    "a": {"q", "w", "s", "z"},
    "s": {"a", "w", "e", "d", "z", "x"},
    "d": {"s", "e", "r", "f", "x", "c"},
    "f": {"d", "r", "t", "g", "c", "v"},
    "g": {"f", "t", "y", "h", "v", "b"},
    "h": {"g", "y", "u", "j", "b", "n"},
    "j": {"h", "u", "i", "k", "n", "m"},
    "k": {"j", "i", "o", "l", "m"},
    "l": {"k", "o", "p"},
    "z": {"a", "s", "x"},
    "x": {"z", "s", "d", "c"},
    "c": {"x", "d", "f", "v"},
    "v": {"c", "f", "g", "b"},
    "b": {"v", "g", "h", "n"},
    "n": {"b", "h", "j", "m"},
    "m": {"n", "j", "k"},
}

# Suspicious TLDs often used in phishing
_SUSPICIOUS_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq",    # free TLDs
    "xyz", "top", "click", "link",
    "online", "site", "website",
    "live", "stream",
    "zip", "mov",                      # new confusing TLDs
    "ru", "cn", "pw", "cc",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ScoringSignal:
    """An individual signal that contributed to the risk score."""
    name:   str
    weight: int
    detail: str


@dataclass
class DomainRiskResult:
    """
    Risk assessment for a single candidate domain.

    Attributes:
        candidate:    The domain being evaluated.
        brand:        The protected brand string.
        normalized:   The ASCII-normalized form of the candidate SLD.
        risk_score:   Aggregate 0–100 risk score.
        risk_level:   Categorical risk level.
        signals:      List of ScoringSignals that fired.
        is_lookalike: True if risk_score >= 35 (MEDIUM or higher).
    """
    candidate:    str
    brand:        str
    normalized:   str = ""
    risk_score:   int = 0
    risk_level:   RiskLevel = RiskLevel.INFO
    signals:      list[ScoringSignal] = field(default_factory=list)
    is_lookalike: bool = False

    def summary(self) -> str:
        sigs = ", ".join(s.name for s in self.signals[:4])
        return (
            f"[{self.risk_level.value}] '{self.candidate}' | "
            f"score={self.risk_score} | "
            f"signals=[{sigs}]"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate":    self.candidate,
            "brand":        self.brand,
            "normalized":   self.normalized,
            "risk_score":   self.risk_score,
            "risk_level":   self.risk_level.value,
            "is_lookalike": self.is_lookalike,
            "signals":      [
                {"name": s.name, "weight": s.weight, "detail": s.detail}
                for s in self.signals
            ],
        }


# ---------------------------------------------------------------------------
# LookalikeScorer
# ---------------------------------------------------------------------------

class LookalikeScorer:
    """
    Scores candidate domains against a protected brand for lookalike risk.

    Args:
        brand:                 The brand name to protect (e.g. ``"example"``).
        max_edit_distance:     Maximum edit distance to consider as similar.
                               Defaults to max(2, len(brand) // 4).
        subdomain_check:       If True, check if brand appears as a subdomain
                               (default True).
        embedded_check:        If True, check if brand is embedded in longer
                               domain names (default True).
        keyboard_typo_check:   If True, check keyboard-proximity mutations
                               (default True).
    """

    def __init__(
        self,
        brand: str,
        max_edit_distance: Optional[int] = None,
        subdomain_check: bool = True,
        embedded_check: bool = True,
        keyboard_typo_check: bool = True,
    ) -> None:
        self._brand = brand.lower().strip()
        self._max_edit = (
            max_edit_distance
            if max_edit_distance is not None
            else max(2, len(self._brand) // 4)
        )
        self._subdomain_check  = subdomain_check
        self._embedded_check   = embedded_check
        self._keyboard_check   = keyboard_typo_check

    @property
    def brand(self) -> str:
        return self._brand

    def score(self, domain: str) -> DomainRiskResult:
        """
        Score a single candidate domain.

        Returns a DomainRiskResult with all signals and risk score.
        """
        domain_lower = domain.lower().strip()

        # Split into parts
        parts = domain_lower.split(".")
        tld  = parts[-1] if len(parts) >= 2 else ""
        sld  = parts[-2] if len(parts) >= 2 else parts[0]  # second-level domain

        # For subdomain check use the full domain sans TLD
        # e.g. "brand.evil.com" → check if brand appears in subdomain
        full_sans_tld = ".".join(parts[:-1]) if len(parts) >= 2 else domain_lower

        # Normalize the SLD (apply homoglyphs + leet decoding)
        normalized = _normalize_domain(sld)

        result = DomainRiskResult(
            candidate=domain,
            brand=self._brand,
            normalized=normalized,
        )
        signals: list[ScoringSignal] = []
        score = 0

        # --- Exact match on normalized SLD (suspicious if TLD differs)
        if normalized == self._brand:
            # If SLD exactly matches brand after normalization, very suspicious
            sig = ScoringSignal(
                name="exact_normalized_match",
                weight=50,
                detail=f"SLD '{sld}' normalizes to exact brand '{self._brand}'",
            )
            signals.append(sig)
            score += sig.weight

        else:
            # --- Levenshtein / edit distance
            edit = _levenshtein(normalized, self._brand)
            if 0 < edit <= self._max_edit:
                weight = max(5, 38 - (edit - 1) * 12)
                sig = ScoringSignal(
                    name="edit_distance",
                    weight=weight,
                    detail=f"edit_distance({normalized!r}, {self._brand!r}) = {edit}",
                )
                signals.append(sig)
                score += weight

            # --- Character substitution (leet / multi-char)
            leet_decoded = _apply_leet(sld)
            if leet_decoded != sld and _levenshtein(leet_decoded, self._brand) == 0:
                sig = ScoringSignal(
                    name="leet_substitution",
                    weight=45,
                    detail=f"'{sld}' decodes to brand via leet substitution",
                )
                signals.append(sig)
                score += sig.weight

            # --- Homoglyph detection
            has_homoglyph = any(c in _HOMOGLYPH_MAP for c in sld)
            if has_homoglyph and _levenshtein(normalized, self._brand) <= 1:
                sig = ScoringSignal(
                    name="homoglyph_substitution",
                    weight=55,
                    detail=(
                        f"'{sld}' contains Unicode lookalike characters; "
                        f"normalizes within 1 edit of brand"
                    ),
                )
                signals.append(sig)
                score += sig.weight

            # --- Keyboard proximity typos
            if self._keyboard_check:
                kbd_score = _keyboard_proximity_score(sld, self._brand)
                if kbd_score > 0:
                    weight = min(25, kbd_score * 8)
                    sig = ScoringSignal(
                        name="keyboard_proximity",
                        weight=weight,
                        detail=(
                            f"{kbd_score} keyboard-adjacent substitution(s) "
                            f"from brand to '{sld}'"
                        ),
                    )
                    signals.append(sig)
                    score += weight

            # --- Brand embedded in longer SLD
            if self._embedded_check and len(sld) > len(self._brand):
                if self._brand in normalized and normalized != self._brand:
                    sig = ScoringSignal(
                        name="brand_embedded",
                        weight=20,
                        detail=f"Brand '{self._brand}' embedded in SLD '{sld}'",
                    )
                    signals.append(sig)
                    score += sig.weight

        # --- Punycode / IDN
        if domain_lower.startswith("xn--") or any(p.startswith("xn--") for p in parts):
            sig = ScoringSignal(
                name="punycode_idn",
                weight=30,
                detail="Domain uses Punycode/IDN encoding — possible homoglyph attack",
            )
            signals.append(sig)
            score += sig.weight

        # --- Suspicious TLD
        if tld in _SUSPICIOUS_TLDS:
            sig = ScoringSignal(
                name="suspicious_tld",
                weight=15,
                detail=f"TLD '.{tld}' is commonly used in phishing campaigns",
            )
            signals.append(sig)
            score += sig.weight

        # --- Brand as subdomain
        if self._subdomain_check and len(parts) >= 3:
            subdomain_part = ".".join(parts[:-2])
            if self._brand in _normalize_domain(subdomain_part).split("."):
                sig = ScoringSignal(
                    name="brand_as_subdomain",
                    weight=35,
                    detail=(
                        f"Brand '{self._brand}' appears as a subdomain of "
                        f"'{'.'.join(parts[-2:])}'  — typical phishing pattern"
                    ),
                )
                signals.append(sig)
                score += sig.weight

        result.risk_score   = min(100, score)
        result.signals      = signals
        result.risk_level   = _score_to_level(result.risk_score)
        result.is_lookalike = result.risk_score >= 35
        return result

    def score_many(self, domains: list[str]) -> list[DomainRiskResult]:
        """Score a list of candidate domains. Returns results sorted by risk_score descending."""
        results = [self.score(d) for d in domains]
        results.sort(key=lambda r: r.risk_score, reverse=True)
        return results

    def filter_lookalikes(self, domains: list[str]) -> list[DomainRiskResult]:
        """Return only results where is_lookalike is True."""
        return [r for r in self.score_many(domains) if r.is_lookalike]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalize_domain(s: str) -> str:
    """Apply homoglyph normalization + NFKD decomposition to a domain part."""
    # Replace known homoglyphs
    result = []
    for ch in s:
        result.append(_HOMOGLYPH_MAP.get(ch, ch))
    joined = "".join(result)
    # NFKD decompose and keep only ASCII letters/digits/hyphen
    nfkd = unicodedata.normalize("NFKD", joined)
    ascii_only = "".join(c for c in nfkd if c.isascii() and (c.isalnum() or c == "-"))
    return ascii_only.lower()


def _apply_leet(s: str) -> str:
    """Apply leet-speak and multi-char substitutions."""
    result = s
    # Multi-char first (longer patterns take precedence)
    for pattern, replacement in _MULTI_CHAR_SUBS:
        result = result.replace(pattern, replacement)
    # Single char
    return "".join(_LEET_MAP.get(c, c) for c in result)


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    m, n = len(a), len(b)
    # Use two rows for memory efficiency
    prev = list(range(n + 1))
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        curr[0] = i
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(prev[j], curr[j - 1], prev[j - 1])
        prev, curr = curr, [0] * (n + 1)
    return prev[n]


def _keyboard_proximity_score(candidate: str, brand: str) -> int:
    """
    Count positions where candidate differs from brand by exactly one
    keyboard-adjacent key. Returns the count of such positions.
    """
    if len(candidate) != len(brand):
        return 0
    count = 0
    for c, b in zip(candidate, brand):
        if c != b:
            neighbors = _QWERTY_NEIGHBORS.get(b, set())
            if c in neighbors:
                count += 1
    return count


def _score_to_level(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 35:
        return RiskLevel.MEDIUM
    if score >= 15:
        return RiskLevel.LOW
    return RiskLevel.INFO
