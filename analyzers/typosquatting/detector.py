"""
Typosquatting domain variant generator and similarity scorer.

Generates candidate lookalike domains using common typo techniques:
character omission, doubling, adjacent-key swaps, hyphen insertion,
prefix/suffix addition, and TLD variations.

Similarity scoring uses SequenceMatcher (edit-distance based).
No external network calls are made by this module.
"""
from __future__ import annotations
from difflib import SequenceMatcher
from dataclasses import dataclass

# Common TLD alternatives used in lookalike registrations
_COMMON_TLDS = [".com", ".net", ".org", ".io", ".co", ".app", ".dev", ".xyz", ".info"]

# Adjacent key map for QWERTY keyboard transpositions
_ADJACENT_KEYS: dict[str, str] = {
    "a": "sqzw", "b": "vghn", "c": "xdfv", "d": "erfcs",
    "e": "wrsdf", "f": "rtgdc", "g": "tyhfv", "h": "yujgb",
    "i": "uojk", "j": "uikhn", "k": "iolmj", "l": "opk",
    "m": "njk", "n": "bhjm", "o": "iklp", "p": "ol",
    "q": "wa", "r": "etdf", "s": "waedxz", "t": "ryfg",
    "u": "yhij", "v": "cfgb", "w": "qase", "x": "zsdc",
    "y": "tghu", "z": "asx",
}


@dataclass
class DomainVariant:
    domain: str
    technique: str
    similarity_score: float  # SequenceMatcher ratio vs brand domain (0.0–1.0)


def score_domain_similarity(brand: str, observed: str) -> float:
    """
    Compute edit-distance similarity between two domain names.

    Uses SequenceMatcher for a character-level ratio.
    Both inputs are lowercased before comparison.

    Args:
        brand:    The legitimate brand domain (e.g., "example.com").
        observed: The candidate lookalike domain.

    Returns:
        Float in [0.0, 1.0] — higher means more similar.
    """
    return SequenceMatcher(None, brand.lower(), observed.lower()).ratio()


def generate_typosquats(brand_domain: str) -> list[DomainVariant]:
    """
    Generate candidate lookalike domains for a brand domain.

    Techniques applied:
    - char_omission:      Remove each character from the name part
    - char_doubling:      Double each character in the name part
    - adjacent_swap:      Replace each char with its keyboard-adjacent neighbor
    - hyphen_insertion:   Insert a hyphen between each pair of adjacent chars
    - prefix_addition:    Add common prefixes (www-, my-, get-, app-, secure-)
    - suffix_addition:    Add common suffixes (-app, -login, -secure, -portal)
    - tld_variation:      Swap TLD with common alternatives

    Returns results sorted by similarity_score descending.

    Args:
        brand_domain: The legitimate brand domain, e.g. "example.com".

    Returns:
        List of DomainVariant objects sorted by similarity descending.
    """
    variants: list[DomainVariant] = []

    # Split into name and TLD
    parts = brand_domain.rsplit(".", 1)
    if len(parts) != 2:
        return []
    name, tld = parts[0].lower(), "." + parts[1].lower()

    def _add(domain: str, technique: str) -> None:
        if domain != brand_domain:
            variants.append(DomainVariant(
                domain=domain,
                technique=technique,
                similarity_score=score_domain_similarity(brand_domain, domain),
            ))

    # Char omission
    for i in range(len(name)):
        _add(name[:i] + name[i+1:] + tld, "char_omission")

    # Char doubling
    for i, ch in enumerate(name):
        _add(name[:i] + ch + ch + name[i+1:] + tld, "char_doubling")

    # Adjacent key swaps
    for i, ch in enumerate(name):
        for neighbor in _ADJACENT_KEYS.get(ch, ""):
            _add(name[:i] + neighbor + name[i+1:] + tld, "adjacent_swap")

    # Hyphen insertion
    for i in range(1, len(name)):
        _add(name[:i] + "-" + name[i:] + tld, "hyphen_insertion")

    # Prefix/suffix additions
    for prefix in ["www-", "my", "get", "app", "secure"]:
        _add(prefix + name + tld, "prefix_addition")
    for suffix in ["-app", "-login", "-secure", "-portal"]:
        _add(name + suffix + tld, "suffix_addition")

    # TLD variations
    for alt_tld in _COMMON_TLDS:
        if alt_tld != tld:
            _add(name + alt_tld, "tld_variation")

    # Sort by similarity descending, deduplicate by domain
    seen: set[str] = set()
    unique: list[DomainVariant] = []
    for v in sorted(variants, key=lambda x: x.similarity_score, reverse=True):
        if v.domain not in seen:
            seen.add(v.domain)
            unique.append(v)

    return unique
