"""Unit tests for email security posture (no DNS calls)."""
from analyzers.email_security.mx_spf_checker import EmailPosture


def _posture(has_mx=False, spf=None, dmarc=None) -> EmailPosture:
    return EmailPosture(domain="test.com", has_mx=has_mx, spf_record=spf, dmarc_record=dmarc)


def test_high_risk_mx_no_dmarc():
    p = _posture(has_mx=True, spf=None, dmarc=None)
    assert p.risk_level == "HIGH"
    assert p.has_spf is False
    assert p.has_dmarc is False


def test_medium_risk_mx_with_dmarc():
    p = _posture(has_mx=True, dmarc="v=DMARC1; p=reject")
    assert p.risk_level == "MEDIUM"
    assert p.has_dmarc is True


def test_low_risk_no_mx():
    p = _posture(has_mx=False)
    assert p.risk_level == "LOW"


def test_spf_present():
    p = _posture(has_mx=True, spf="v=spf1 include:example.com ~all")
    assert p.has_spf is True
