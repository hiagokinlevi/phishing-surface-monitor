from analyzers.typosquatting.detector import generate_typosquats, score_domain_similarity


def test_score_similarity_identical():
    assert score_domain_similarity("example.com", "example.com") == 1.0


def test_score_similarity_different():
    score = score_domain_similarity("example.com", "totally-different.net")
    assert score < 0.5


def test_generate_typosquats_nonempty():
    variants = generate_typosquats("example.com")
    assert len(variants) > 10


def test_generate_typosquats_sorted():
    variants = generate_typosquats("example.com")
    scores = [v.similarity_score for v in variants]
    assert scores == sorted(scores, reverse=True)


def test_generate_typosquats_no_original():
    variants = generate_typosquats("example.com")
    domains = [v.domain for v in variants]
    assert "example.com" not in domains


def test_tld_variation_present():
    variants = generate_typosquats("example.com")
    tld_variants = [v for v in variants if v.technique == "tld_variation"]
    assert len(tld_variants) > 0
