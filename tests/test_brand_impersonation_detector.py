# Copyright 2024 Cyber Port contributors
#
# Licensed under the Creative Commons Attribution 4.0 International License
# (CC BY 4.0).  https://creativecommons.org/licenses/by/4.0/
"""
Tests for brand_impersonation_detector.py
==========================================
All tests use the PayPal brand target and optionally a Google brand target.
Tests are organized by check ID, followed by cross-cutting concerns such as
risk_score cap, result accessors, and serialization.
"""
from __future__ import annotations

import pytest

from analyzers.brand_impersonation_detector import (
    BrandImpersonationDetector,
    BrandTarget,
    DomainSample,
    ImpersonationFinding,
    ImpersonationResult,
    _CHECK_WEIGHTS,
    _build_numeric_variants,
    _normalize_homoglyphs,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

PAYPAL = BrandTarget(
    name="PayPal",
    keywords=["paypal"],
    official_domains=["paypal.com", "paypal.co.uk"],
)

GOOGLE = BrandTarget(
    name="Google",
    keywords=["google", "gmail"],
    official_domains=["google.com"],
)


def make_detector(*targets: BrandTarget) -> BrandImpersonationDetector:
    return BrandImpersonationDetector(brand_targets=list(targets))


def analyze(domain: str, *targets: BrandTarget) -> ImpersonationResult:
    det = make_detector(*targets)
    return det.analyze(DomainSample(domain=domain))


def has_check(result: ImpersonationResult, check_id: str) -> bool:
    return any(f.check_id == check_id for f in result.findings)


# ===========================================================================
# Official domains — no findings expected
# ===========================================================================

class TestOfficialDomains:
    def test_paypal_com_no_findings(self):
        r = analyze("paypal.com", PAYPAL)
        assert r.findings == []

    def test_paypal_co_uk_no_findings(self):
        r = analyze("paypal.co.uk", PAYPAL)
        assert r.findings == []

    def test_google_com_no_findings(self):
        r = analyze("google.com", GOOGLE)
        assert r.findings == []

    def test_official_domain_risk_score_zero(self):
        r = analyze("paypal.com", PAYPAL)
        assert r.risk_score == 0

    def test_official_domain_case_insensitive(self):
        # Domains are compared case-insensitively.
        r = analyze("PayPal.com", PAYPAL)
        assert r.findings == []

    def test_official_domain_summary_clean(self):
        r = analyze("paypal.com", PAYPAL)
        assert "CLEAN" in r.summary()


# ===========================================================================
# Unrelated clean domains — no findings expected
# ===========================================================================

class TestCleanDomains:
    def test_unrelated_domain_no_findings(self):
        r = analyze("example.com", PAYPAL)
        assert r.findings == []

    def test_another_unrelated_domain(self):
        r = analyze("openai.com", PAYPAL)
        assert r.findings == []

    def test_short_domain_no_findings(self):
        r = analyze("abc.io", PAYPAL)
        assert r.findings == []

    def test_clean_domain_zero_risk(self):
        r = analyze("legitimate-bank.com", PAYPAL)
        assert r.risk_score == 0

    def test_clean_domain_no_google(self):
        r = analyze("example.net", GOOGLE)
        assert r.findings == []


# ===========================================================================
# BRD-001 — Homoglyph substitution
# ===========================================================================

class TestBRD001:
    """
    BRD-001 fires when a domain contains homoglyph characters that, after
    normalization, reveal a brand keyword.
    """

    def test_at_sign_homoglyph_for_a(self):
        # payp@l.com — '@' is a homoglyph of 'a', normalizes to 'paypal'
        r = analyze("payp@l.com", PAYPAL)
        assert has_check(r, "BRD-001"), r.findings

    def test_cyrillic_a_in_paypal(self):
        # 'р' is Cyrillic.  Build domain with Cyrillic 'а' to replace 'a'.
        # paypal with Cyrillic а (U+0430) replacing the first 'a'
        domain = "p\u0430ypal.com"  # pаypal.com (Cyrillic а)
        r = analyze(domain, PAYPAL)
        assert has_check(r, "BRD-001"), r.findings

    def test_digit_4_homoglyph_for_a(self):
        # payp4l.com — '4' is mapped as homoglyph of 'a'
        r = analyze("payp4l.com", PAYPAL)
        assert has_check(r, "BRD-001"), r.findings

    def test_zero_homoglyph_for_o(self):
        # g00gle — '0' is homoglyph of 'o'
        r = analyze("g00gle.com", GOOGLE)
        assert has_check(r, "BRD-001"), r.findings

    def test_cyrillic_e_in_google(self):
        # goog\u043Ble.com — Cyrillic е replacing 'e'
        domain = "googl\u0435.com"
        r = analyze(domain, GOOGLE)
        assert has_check(r, "BRD-001"), r.findings

    def test_official_domain_no_brd001(self):
        r = analyze("paypal.com", PAYPAL)
        assert not has_check(r, "BRD-001")

    def test_brd001_severity_is_critical(self):
        r = analyze("payp4l.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-001"]
        assert all(f.severity == "CRITICAL" for f in findings)

    def test_brd001_weight_in_score(self):
        r = analyze("payp4l.com", PAYPAL)
        assert r.risk_score >= _CHECK_WEIGHTS["BRD-001"]

    def test_brd001_finding_brand_name(self):
        r = analyze("payp4l.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-001"]
        assert findings[0].brand_name == "PayPal"

    def test_brd001_recommendation_not_empty(self):
        r = analyze("payp4l.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-001"]
        assert len(findings[0].recommendation) > 0

    def test_cyrillic_i_homoglyph(self):
        # payp\u0456l.com — Cyrillic і replacing 'i' in 'paypal' is not
        # directly in 'paypal', but test with a keyword containing 'i'.
        # Use Google keyword 'gmail': gma\u0456l.com
        domain = "gma\u0456l.com"
        r = analyze(domain, GOOGLE)
        assert has_check(r, "BRD-001"), r.findings

    def test_greek_alpha_homoglyph(self):
        # p\u03B1ypal.com — Greek α replacing 'a'
        domain = "p\u03B1ypal.com"
        r = analyze(domain, PAYPAL)
        assert has_check(r, "BRD-001"), r.findings


# ===========================================================================
# BRD-002 — Brand keyword embedded in domain
# ===========================================================================

class TestBRD002:
    def test_paypal_in_subdomain_label(self):
        r = analyze("secure-paypal-login.com", PAYPAL)
        assert has_check(r, "BRD-002"), r.findings

    def test_paypal_as_prefix(self):
        r = analyze("paypalicious.com", PAYPAL)
        assert has_check(r, "BRD-002"), r.findings

    def test_paypal_as_suffix(self):
        r = analyze("get-paypal.net", PAYPAL)
        assert has_check(r, "BRD-002"), r.findings

    def test_official_domain_no_brd002(self):
        r = analyze("paypal.com", PAYPAL)
        assert not has_check(r, "BRD-002")

    def test_paypal_co_uk_no_brd002(self):
        r = analyze("paypal.co.uk", PAYPAL)
        assert not has_check(r, "BRD-002")

    def test_unrelated_domain_no_brd002(self):
        r = analyze("example.com", PAYPAL)
        assert not has_check(r, "BRD-002")

    def test_brd002_severity_high(self):
        r = analyze("secure-paypal-login.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-002"]
        assert all(f.severity == "HIGH" for f in findings)

    def test_brd002_keyword_recorded(self):
        r = analyze("paypal-info.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-002"]
        assert any(f.matched_keyword == "paypal" for f in findings)

    def test_brd002_google_keyword(self):
        r = analyze("my-google-account.com", GOOGLE)
        assert has_check(r, "BRD-002"), r.findings

    def test_brd002_gmail_keyword(self):
        r = analyze("gmail-secure.com", GOOGLE)
        assert has_check(r, "BRD-002"), r.findings

    def test_brd002_case_insensitive(self):
        r = analyze("PAYPAL-verification.com", PAYPAL)
        assert has_check(r, "BRD-002"), r.findings


# ===========================================================================
# BRD-003 — Suspicious TLD with brand keyword
# ===========================================================================

class TestBRD003:
    def test_paypal_xyz(self):
        r = analyze("paypal.xyz", PAYPAL)
        assert has_check(r, "BRD-003"), r.findings

    def test_paypal_top(self):
        r = analyze("paypal.top", PAYPAL)
        assert has_check(r, "BRD-003"), r.findings

    def test_paypal_click(self):
        r = analyze("paypal.click", PAYPAL)
        assert has_check(r, "BRD-003"), r.findings

    def test_paypal_tk(self):
        r = analyze("paypal.tk", PAYPAL)
        assert has_check(r, "BRD-003"), r.findings

    def test_paypal_ml(self):
        r = analyze("paypal.ml", PAYPAL)
        assert has_check(r, "BRD-003"), r.findings

    def test_paypal_com_no_brd003(self):
        # .com is not a suspicious TLD
        r = analyze("paypal-info.com", PAYPAL)
        assert not has_check(r, "BRD-003")

    def test_paypal_net_no_brd003(self):
        r = analyze("paypal.net", PAYPAL)
        assert not has_check(r, "BRD-003")

    def test_brd003_severity_high(self):
        r = analyze("paypal.xyz", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-003"]
        assert all(f.severity == "HIGH" for f in findings)

    def test_brd003_google_xyz(self):
        r = analyze("google.xyz", GOOGLE)
        assert has_check(r, "BRD-003"), r.findings

    def test_brd003_gmail_top(self):
        r = analyze("gmail.top", GOOGLE)
        assert has_check(r, "BRD-003"), r.findings

    def test_brd003_cc_tld(self):
        r = analyze("paypal.cc", PAYPAL)
        assert has_check(r, "BRD-003"), r.findings

    def test_brd003_biz_tld(self):
        r = analyze("paypal.biz", PAYPAL)
        assert has_check(r, "BRD-003"), r.findings


# ===========================================================================
# BRD-004 — Punycode domain with brand reference
# ===========================================================================

class TestBRD004:
    def test_xn_prefix_with_paypal(self):
        # xn--pypl-hoa.com — contains xn-- and substring references paypal-ish
        # We craft a domain that has xn-- and the brand in it.
        r = analyze("xn--paypal-fxa.com", PAYPAL)
        assert has_check(r, "BRD-004"), r.findings

    def test_xn_prefix_explicit(self):
        # Craft a Punycode domain that explicitly contains the full keyword.
        # "xn--paypal-abc.com" has both xn-- and the substring "paypal".
        r2 = analyze("xn--paypal-abc.com", PAYPAL)
        assert has_check(r2, "BRD-004"), r2.findings

    def test_no_xn_prefix_no_brd004(self):
        r = analyze("paypal-secure.com", PAYPAL)
        assert not has_check(r, "BRD-004")

    def test_xn_prefix_without_brand_no_brd004(self):
        # Has xn-- but no brand keyword reference
        r = analyze("xn--exmple-cua.com", PAYPAL)
        assert not has_check(r, "BRD-004")

    def test_brd004_severity_critical(self):
        r = analyze("xn--paypal-fxa.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-004"]
        assert all(f.severity == "CRITICAL" for f in findings)

    def test_brd004_weight_applied(self):
        r = analyze("xn--paypal-fxa.com", PAYPAL)
        assert r.risk_score >= _CHECK_WEIGHTS["BRD-004"]

    def test_brd004_google_punycode(self):
        r = analyze("xn--google-xqa.com", GOOGLE)
        assert has_check(r, "BRD-004"), r.findings

    def test_brd004_label_with_xn(self):
        # Punycode label in subdomain position.
        r = analyze("xn--paypal-abc.evil.com", PAYPAL)
        assert has_check(r, "BRD-004"), r.findings


# ===========================================================================
# BRD-005 — Keyboard proximity substitution
# ===========================================================================

class TestBRD005:
    def test_paypai_triggers_l_neighbor(self):
        # 'i' is a neighbor of 'l' — "paypai" for "paypal"
        # _KEYBOARD_PROXIMITY["l"] = ["k", "o", "p"]
        # 'i' is in _KEYBOARD_PROXIMITY["o"] = ["i", "p", "l", "k"]
        # Actually for brd005: we substitute chars of the keyword.
        # keyword = "paypal"; char 'l' (idx 5): neighbors = ["k", "o", "p"]
        # -> "paypak", "paypao", "paypap"
        # keyword = "paypal"; char 'a' (idx 1): neighbors = ["q","w","s","z"]
        # -> "pqypal", "pwypal", etc.
        # The check fires when the VARIANT is found in the domain.
        # "paypak.com" would trigger on char 'l' replaced with 'k'.
        r = analyze("paypak.com", PAYPAL)
        assert has_check(r, "BRD-005"), r.findings

    def test_peypal_triggers_keyboard_proximity(self):
        # 'e' is a neighbor of 'a' via _KEYBOARD_PROXIMITY["a"] = ["q","w","s","z"]
        # Not directly.  But _KEYBOARD_PROXIMITY["e"] = ["w","r","d","s"]
        # keyword "paypal" char 'a' at idx 1 → neighbors ["q","w","s","z"]
        # → "pwypal" in domain?  Let's test "pwypal.com"
        r = analyze("pwypal.com", PAYPAL)
        assert has_check(r, "BRD-005"), r.findings

    def test_paypap_triggers_l_neighbor(self):
        # 'p' is in neighbors of 'l': _KEYBOARD_PROXIMITY["l"] = ["k","o","p"]
        r = analyze("paypap.com", PAYPAL)
        assert has_check(r, "BRD-005"), r.findings

    def test_payleo_triggers_a_neighbor(self):
        # keyword "paypal" char 'a' idx 4 (second 'a') neighbors ["q","w","s","z"]
        # → "payspal" wait that doesn't make sense. Let's use index correctly.
        # "paypal" indexes: p=0,a=1,y=2,p=3,a=4,l=5
        # char 'a' at idx 4 neighbors: q,w,s,z → "paypql", "paypwl", "paypsl", "paypzl"
        r = analyze("paypsl.com", PAYPAL)
        assert has_check(r, "BRD-005"), r.findings

    def test_giogle_triggers_o_neighbor(self):
        # "google" — char 'o' at idx 1 neighbors: i,p,l,k → "giogle"
        r = analyze("giogle.com", GOOGLE)
        assert has_check(r, "BRD-005"), r.findings

    def test_clean_domain_no_brd005(self):
        r = analyze("example.com", PAYPAL)
        assert not has_check(r, "BRD-005")

    def test_brd005_severity_high(self):
        r = analyze("paypak.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-005"]
        assert all(f.severity == "HIGH" for f in findings)

    def test_brd005_matched_keyword_paypal(self):
        r = analyze("paypak.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-005"]
        assert findings[0].matched_keyword == "paypal"

    def test_brd005_googlp_triggers(self):
        # "google" char 'l' idx 5... wait "google" is g-o-o-g-l-e
        # char 'l' at idx 4: neighbors ["k","o","p"] → "googke","googoe","googpe"
        r = analyze("googke.com", GOOGLE)
        assert has_check(r, "BRD-005"), r.findings


# ===========================================================================
# BRD-006 — Brand + action word combination
# ===========================================================================

class TestBRD006:
    def test_paypal_login(self):
        r = analyze("paypal-login.com", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings

    def test_paypal_secure(self):
        r = analyze("paypal-secure.com", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings

    def test_paypal_verify(self):
        r = analyze("paypal-verify.net", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings

    def test_paypal_account(self):
        r = analyze("paypal-account.com", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings

    def test_paypal_support(self):
        r = analyze("paypal-support.com", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings

    def test_paypal_confirm(self):
        r = analyze("paypal-confirm.io", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings

    def test_paypal_reset(self):
        r = analyze("paypal-reset.com", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings

    def test_paypal_update(self):
        r = analyze("paypal-update.net", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings

    def test_paypal_info_no_brd006(self):
        # "info" is NOT in _ACTION_WORDS
        r = analyze("paypal-info.com", PAYPAL)
        assert not has_check(r, "BRD-006")

    def test_paypal_news_no_brd006(self):
        # "news" is NOT in _ACTION_WORDS
        r = analyze("paypal-news.com", PAYPAL)
        assert not has_check(r, "BRD-006")

    def test_brd006_severity_high(self):
        r = analyze("paypal-login.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-006"]
        assert all(f.severity == "HIGH" for f in findings)

    def test_brd006_google_login(self):
        r = analyze("google-login.com", GOOGLE)
        assert has_check(r, "BRD-006"), r.findings

    def test_brd006_gmail_helpdesk(self):
        r = analyze("gmail-helpdesk.net", GOOGLE)
        assert has_check(r, "BRD-006"), r.findings

    def test_brd006_paypal_portal(self):
        r = analyze("paypal-portal.com", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings

    def test_brd006_paypal_signin(self):
        r = analyze("paypal-signin.com", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings

    def test_brd006_paypal_recover(self):
        r = analyze("paypal-recover.com", PAYPAL)
        assert has_check(r, "BRD-006"), r.findings


# ===========================================================================
# BRD-007 — Numeric substitution in brand keyword
# ===========================================================================

class TestBRD007:
    def test_paypa1_triggers(self):
        # 'l' → '1': "paypa1"
        r = analyze("paypa1.com", PAYPAL)
        assert has_check(r, "BRD-007"), r.findings

    def test_g0ogle_triggers(self):
        # 'o' at idx 1 → '0': "g0ogle" — single numeric substitution for BRD-007
        r = analyze("g0ogle.com", GOOGLE)
        assert has_check(r, "BRD-007"), r.findings

    def test_paypa1_login_triggers(self):
        r = analyze("paypa1-login.com", PAYPAL)
        assert has_check(r, "BRD-007"), r.findings

    def test_official_paypal_no_brd007(self):
        r = analyze("paypal.com", PAYPAL)
        assert not has_check(r, "BRD-007")

    def test_unrelated_numeric_no_brd007(self):
        r = analyze("example123.com", PAYPAL)
        assert not has_check(r, "BRD-007")

    def test_brd007_severity_high(self):
        r = analyze("paypa1.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-007"]
        assert all(f.severity == "HIGH" for f in findings)

    def test_brd007_matched_keyword(self):
        r = analyze("paypa1.com", PAYPAL)
        findings = [f for f in r.findings if f.check_id == "BRD-007"]
        assert findings[0].matched_keyword == "paypal"

    def test_paypai_triggers_i_to_1(self):
        # 'i' → 'l' is in _build_numeric_variants but 'paypal' has no 'i'.
        # For "paypal": sub map hits 'a'→4, 'l'→1 (via i→1/l)
        # "paypa1" has l→1 substitution. "p4ypal" has a→4 at idx 1.
        r = analyze("p4ypal.com", PAYPAL)
        assert has_check(r, "BRD-007"), r.findings

    def test_g009le_triggers_o_to_9_not_in_map(self):
        # Our numeric map for 'g' is g→9. "9oogle" should trigger.
        r = analyze("9oogle.com", GOOGLE)
        assert has_check(r, "BRD-007"), r.findings


# ===========================================================================
# Multiple brand targets
# ===========================================================================

class TestMultipleBrands:
    def test_paypal_finding_with_multi_target(self):
        det = make_detector(PAYPAL, GOOGLE)
        r = det.analyze(DomainSample(domain="paypal-login.com"))
        paypal_findings = [f for f in r.findings if f.brand_name == "PayPal"]
        assert len(paypal_findings) > 0

    def test_google_finding_with_multi_target(self):
        det = make_detector(PAYPAL, GOOGLE)
        r = det.analyze(DomainSample(domain="google-login.com"))
        google_findings = [f for f in r.findings if f.brand_name == "Google"]
        assert len(google_findings) > 0

    def test_both_brands_in_findings(self):
        # A domain that (somehow) triggers both brands.
        det = make_detector(PAYPAL, GOOGLE)
        r1 = det.analyze(DomainSample(domain="paypal-support.com"))
        r2 = det.analyze(DomainSample(domain="google-account.com"))
        assert any(f.brand_name == "PayPal" for f in r1.findings)
        assert any(f.brand_name == "Google" for f in r2.findings)

    def test_google_official_not_flagged_in_multi(self):
        det = make_detector(PAYPAL, GOOGLE)
        r = det.analyze(DomainSample(domain="google.com"))
        google_findings = [f for f in r.findings if f.brand_name == "Google"]
        assert google_findings == []

    def test_paypal_official_not_flagged_in_multi(self):
        det = make_detector(PAYPAL, GOOGLE)
        r = det.analyze(DomainSample(domain="paypal.com"))
        paypal_findings = [f for f in r.findings if f.brand_name == "PayPal"]
        assert paypal_findings == []

    def test_gmail_keyword_detected(self):
        det = make_detector(GOOGLE)
        r = det.analyze(DomainSample(domain="gmail-login.com"))
        assert len(r.findings) > 0

    def test_analyze_many_returns_list(self):
        det = make_detector(PAYPAL, GOOGLE)
        samples = [
            DomainSample(domain="paypal-login.com"),
            DomainSample(domain="google.com"),
            DomainSample(domain="example.com"),
        ]
        results = det.analyze_many(samples)
        assert isinstance(results, list)
        assert len(results) == 3

    def test_analyze_many_order_preserved(self):
        det = make_detector(PAYPAL)
        samples = [
            DomainSample(domain="paypal-login.com"),
            DomainSample(domain="example.com"),
        ]
        results = det.analyze_many(samples)
        assert results[0].domain == "paypal-login.com"
        assert results[1].domain == "example.com"

    def test_analyze_many_clean_domains(self):
        det = make_detector(PAYPAL)
        samples = [DomainSample(domain="example.com"), DomainSample(domain="openai.com")]
        results = det.analyze_many(samples)
        assert all(r.risk_score == 0 for r in results)


# ===========================================================================
# risk_score calculation and cap
# ===========================================================================

class TestRiskScore:
    def test_risk_score_capped_at_100(self):
        # A domain that triggers many checks should cap at 100.
        det = make_detector(PAYPAL)
        # This domain triggers BRD-002 (25) + BRD-006 (25) + BRD-007 (20) = 70+
        # Adding BRD-001 (45) via homoglyph would push past 100.
        # "p4ypal-login.com" → BRD-001(45) + BRD-007(20) + BRD-006(25) + BRD-002(25) = 115 → capped
        r = det.analyze(DomainSample(domain="p4ypal-login.com"))
        assert r.risk_score <= 100

    def test_risk_score_zero_clean(self):
        r = analyze("example.com", PAYPAL)
        assert r.risk_score == 0

    def test_risk_score_is_int(self):
        r = analyze("paypal-login.com", PAYPAL)
        assert isinstance(r.risk_score, int)

    def test_risk_score_non_negative(self):
        r = analyze("example.com", PAYPAL)
        assert r.risk_score >= 0

    def test_risk_score_uses_unique_check_ids(self):
        # Multiple findings with the same check_id must only count the weight once.
        det = make_detector(PAYPAL, GOOGLE)
        # Craft a domain that triggers BRD-002 for both PayPal and Google.
        # "paypal-google.com" → BRD-002 fires for PayPal AND Google, but weight
        # for BRD-002 should only be added once (unique check IDs).
        r = det.analyze(DomainSample(domain="paypal-google.com"))
        brd002_count = sum(1 for f in r.findings if f.check_id == "BRD-002")
        # May fire for both brands; weight still only counted once.
        assert r.risk_score == min(
            100,
            sum(_CHECK_WEIGHTS[cid] for cid in {f.check_id for f in r.findings}),
        )

    def test_risk_score_additive_across_checks(self):
        # A domain triggering both BRD-002 and BRD-006 should score sum of both.
        r = analyze("paypal-login.com", PAYPAL)
        assert r.risk_score == min(
            100,
            sum(_CHECK_WEIGHTS[cid] for cid in {f.check_id for f in r.findings}),
        )


# ===========================================================================
# ImpersonationResult.summary()
# ===========================================================================

class TestSummary:
    def test_summary_contains_domain(self):
        r = analyze("paypal-login.com", PAYPAL)
        assert "paypal-login.com" in r.summary()

    def test_summary_contains_risk_score(self):
        r = analyze("paypal-login.com", PAYPAL)
        assert str(r.risk_score) in r.summary()

    def test_summary_contains_findings_count(self):
        r = analyze("paypal-login.com", PAYPAL)
        assert str(len(r.findings)) in r.summary()

    def test_summary_clean_label(self):
        r = analyze("example.com", PAYPAL)
        assert "CLEAN" in r.summary()

    def test_summary_critical_label(self):
        # BRD-001 is CRITICAL — any domain triggering it should show CRITICAL.
        r = analyze("payp4l.com", PAYPAL)
        assert "CRITICAL" in r.summary()

    def test_summary_high_label(self):
        # BRD-002 alone is HIGH.
        r = analyze("paypal-info.com", PAYPAL)
        # Only BRD-002 fires (no action word, not official domain, no homoglyph).
        if r.findings and all(f.severity == "HIGH" for f in r.findings):
            assert "HIGH" in r.summary()

    def test_summary_returns_string(self):
        r = analyze("paypal-login.com", PAYPAL)
        assert isinstance(r.summary(), str)


# ===========================================================================
# ImpersonationResult.by_severity()
# ===========================================================================

class TestBySeverity:
    def test_by_severity_has_critical_key(self):
        r = analyze("paypal-login.com", PAYPAL)
        grouped = r.by_severity()
        assert "CRITICAL" in grouped

    def test_by_severity_has_high_key(self):
        r = analyze("paypal-login.com", PAYPAL)
        grouped = r.by_severity()
        assert "HIGH" in grouped

    def test_by_severity_critical_list(self):
        r = analyze("payp4l.com", PAYPAL)
        grouped = r.by_severity()
        assert isinstance(grouped["CRITICAL"], list)

    def test_by_severity_high_list(self):
        r = analyze("paypal-login.com", PAYPAL)
        grouped = r.by_severity()
        assert isinstance(grouped["HIGH"], list)

    def test_by_severity_critical_findings_correct(self):
        r = analyze("payp4l.com", PAYPAL)
        grouped = r.by_severity()
        assert all(f.severity == "CRITICAL" for f in grouped["CRITICAL"])

    def test_by_severity_high_findings_correct(self):
        r = analyze("paypal-login.com", PAYPAL)
        grouped = r.by_severity()
        assert all(f.severity == "HIGH" for f in grouped["HIGH"])

    def test_by_severity_empty_on_clean(self):
        r = analyze("example.com", PAYPAL)
        grouped = r.by_severity()
        assert grouped["CRITICAL"] == []
        assert grouped["HIGH"] == []

    def test_by_severity_total_equals_all_findings(self):
        r = analyze("payp4l-login.com", PAYPAL)
        grouped = r.by_severity()
        total = len(grouped["CRITICAL"]) + len(grouped["HIGH"])
        assert total == len(r.findings)


# ===========================================================================
# to_dict() serialization
# ===========================================================================

class TestToDictSerialization:
    def test_brand_target_to_dict_keys(self):
        d = PAYPAL.to_dict()
        assert "name" in d
        assert "keywords" in d
        assert "official_domains" in d

    def test_brand_target_to_dict_values(self):
        d = PAYPAL.to_dict()
        assert d["name"] == "PayPal"
        assert "paypal" in d["keywords"]
        assert "paypal.com" in d["official_domains"]

    def test_domain_sample_to_dict_no_url(self):
        s = DomainSample(domain="paypal-login.com")
        d = s.to_dict()
        assert d["domain"] == "paypal-login.com"
        assert d["url"] is None

    def test_domain_sample_to_dict_with_url(self):
        s = DomainSample(domain="paypal-login.com", url="https://paypal-login.com/")
        d = s.to_dict()
        assert d["url"] == "https://paypal-login.com/"

    def test_impersonation_finding_to_dict_keys(self):
        r = analyze("paypal-login.com", PAYPAL)
        assert len(r.findings) > 0
        d = r.findings[0].to_dict()
        for key in ("check_id", "severity", "domain", "brand_name", "matched_keyword",
                    "message", "recommendation"):
            assert key in d, f"Missing key: {key}"

    def test_impersonation_result_to_dict_keys(self):
        r = analyze("paypal-login.com", PAYPAL)
        d = r.to_dict()
        for key in ("domain", "url", "risk_score", "findings"):
            assert key in d, f"Missing key: {key}"

    def test_impersonation_result_to_dict_findings_list(self):
        r = analyze("paypal-login.com", PAYPAL)
        d = r.to_dict()
        assert isinstance(d["findings"], list)

    def test_impersonation_result_to_dict_risk_score(self):
        r = analyze("paypal-login.com", PAYPAL)
        d = r.to_dict()
        assert d["risk_score"] == r.risk_score

    def test_impersonation_result_to_dict_url_none(self):
        r = analyze("paypal-login.com", PAYPAL)
        d = r.to_dict()
        assert d["url"] is None

    def test_impersonation_result_to_dict_url_set(self):
        det = make_detector(PAYPAL)
        r = det.analyze(DomainSample(domain="paypal-login.com",
                                     url="https://paypal-login.com/signin"))
        d = r.to_dict()
        assert d["url"] == "https://paypal-login.com/signin"

    def test_clean_result_to_dict_empty_findings(self):
        r = analyze("example.com", PAYPAL)
        d = r.to_dict()
        assert d["findings"] == []
        assert d["risk_score"] == 0


# ===========================================================================
# Helper function unit tests
# ===========================================================================

class TestHelpers:
    def test_normalize_homoglyphs_at_sign(self):
        assert _normalize_homoglyphs("p@ypal") == "paypal"

    def test_normalize_homoglyphs_digit_4(self):
        assert _normalize_homoglyphs("p4ypal") == "paypal"

    def test_normalize_homoglyphs_zero(self):
        assert _normalize_homoglyphs("g00gle") == "google"

    def test_normalize_homoglyphs_cyrillic_a(self):
        # Cyrillic а (U+0430) should normalize to 'a'
        assert _normalize_homoglyphs("p\u0430ypal") == "paypal"

    def test_normalize_homoglyphs_lowercase(self):
        assert _normalize_homoglyphs("PAYPAL") == "paypal"

    def test_build_numeric_variants_paypal(self):
        variants = _build_numeric_variants("paypal")
        # 'a' at idx 1 → '4': "p4ypal"
        # 'a' at idx 4 → '4': "payp4l"
        # 'l' at idx 5 → '1': "paypa1"
        assert "p4ypal" in variants
        assert "payp4l" in variants
        assert "paypa1" in variants

    def test_build_numeric_variants_google(self):
        variants = _build_numeric_variants("google")
        # 'o' at idx 1 → '0': "g0ogle"
        # 'o' at idx 2 → '0': "go0gle"
        # 'g' at idx 0 → '9': "9oogle"
        # 'e' at idx 5 → '3': "googl3"
        assert "g0ogle" in variants or "go0gle" in variants
        assert "9oogle" in variants

    def test_build_numeric_variants_no_duplicates(self):
        variants = _build_numeric_variants("aaa")
        assert len(variants) == len(set(variants))

    def test_build_numeric_variants_original_excluded(self):
        # The original keyword should not appear as a variant.
        variants = _build_numeric_variants("paypal")
        assert "paypal" not in variants

    def test_check_weights_all_present(self):
        for cid in ("BRD-001", "BRD-002", "BRD-003", "BRD-004",
                    "BRD-005", "BRD-006", "BRD-007"):
            assert cid in _CHECK_WEIGHTS

    def test_check_weights_values_positive(self):
        for cid, weight in _CHECK_WEIGHTS.items():
            assert weight > 0, f"{cid} has non-positive weight"
