from difflib import SequenceMatcher


def normalize_domain(domain: str) -> str:
    """Normalize a domain for consistent similarity scoring.

    Steps:
    1) Trim whitespace and lowercase.
    2) Decode punycode labels (IDN) to Unicode.
    3) Re-encode using IDNA to canonical ASCII.

    Returns best-effort normalized ASCII domain; falls back to lowercase input
    if IDN processing fails.
    """
    if not domain:
        return ""

    value = domain.strip().lower().rstrip(".")
    try:
        # Decode any punycoded labels to Unicode, then canonicalize back to ASCII.
        unicode_domain = value.encode("ascii").decode("idna")
        return unicode_domain.encode("idna").decode("ascii")
    except Exception:
        return value


def similarity_score(domain_a: str, domain_b: str) -> float:
    """Compute normalized similarity between two domains."""
    a = normalize_domain(domain_a)
    b = normalize_domain(domain_b)
    return SequenceMatcher(None, a, b).ratio()
