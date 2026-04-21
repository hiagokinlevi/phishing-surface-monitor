from analyzers.typosquatting import normalize_domain, similarity_score


def test_punycode_domain_normalizes_to_canonical_ascii():
    # bücher.de in punycode form
    puny = "xn--bcher-kva.de"
    normalized = normalize_domain(puny)
    assert normalized == "xn--bcher-kva.de"


def test_similarity_uses_normalized_forms_for_idn_equivalence():
    # Unicode and punycode representations of the same domain should match.
    unicode_domain = "bücher.de"
    puny_domain = "xn--bcher-kva.de"
    assert similarity_score(unicode_domain, puny_domain) == 1.0
