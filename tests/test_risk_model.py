from schemas.case import compute_risk, RiskLevel


def test_critical_resolves_high_similarity():
    assert compute_risk(0.90, True) == RiskLevel.CRITICAL


def test_high_resolves_medium_similarity():
    assert compute_risk(0.75, True) == RiskLevel.HIGH


def test_medium_not_resolves_high_similarity():
    assert compute_risk(0.85, False) == RiskLevel.MEDIUM


def test_info_low_similarity():
    assert compute_risk(0.30, False) == RiskLevel.INFO
