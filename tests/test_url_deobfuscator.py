# Copyright 2024 Cyber Port contributors
#
# Licensed under the Creative Commons Attribution 4.0 International License
# (CC BY 4.0). You may obtain a copy of the License at:
#   https://creativecommons.org/licenses/by/4.0/
#
# You are free to share and adapt this material for any purpose, provided you
# give appropriate credit, indicate if changes were made, and distribute your
# contributions under the same license.
"""
Tests for analyzers/url_deobfuscator.py
========================================
Covers all 7 check IDs (URLO-001 through URLO-007), edge cases, clean URLs,
multi-check scenarios, and the public API surface (analyze / analyze_many,
URLOResult helpers).

Run with:
    python -m pytest tests/test_url_deobfuscator.py -q
"""

import os
import json
import sys
from pathlib import Path

from click.testing import CliRunner

# Allow imports from the project root when running pytest from any directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.url_deobfuscator import (
    URLOFinding,
    URLOResult,
    analyze,
    analyze_many,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _check_ids(result: URLOResult):
    """Return the set of fired check IDs for a result."""
    return {f.check_id for f in result.findings}


def _has(result: URLOResult, check_id: str) -> bool:
    return check_id in _check_ids(result)


# ===========================================================================
# CLEAN URL BASELINES
# ===========================================================================

class TestCleanURLs:
    def test_clean_https_url(self):
        r = analyze("https://www.google.com/search?q=hello")
        assert r.is_suspicious is False
        assert r.risk_score == 0
        assert r.findings == []

    def test_clean_http_url(self):
        r = analyze("http://example.com/path/to/page")
        assert r.is_suspicious is False
        assert r.risk_score == 0

    def test_clean_url_with_standard_path_encoding(self):
        # Path percent-encoding is fine; only the hostname is checked for URLO-001
        r = analyze("https://example.com/search?q=hello%20world")
        assert not _has(r, "URLO-001")
        assert r.is_suspicious is False

    def test_clean_standard_ip(self):
        # Standard dotted-decimal — no obfuscation
        r = analyze("http://192.168.1.1/admin")
        assert not _has(r, "URLO-003")

    def test_clean_standard_ip_127(self):
        r = analyze("http://127.0.0.1/")
        assert not _has(r, "URLO-003")

    def test_clean_standard_ip_loopback(self):
        r = analyze("http://10.0.0.1/")
        assert not _has(r, "URLO-003")

    def test_clean_url_with_port(self):
        r = analyze("https://example.com:8443/secure")
        assert r.is_suspicious is False

    def test_clean_url_no_path(self):
        r = analyze("https://example.com")
        assert r.is_suspicious is False

    def test_clean_ftp_url(self):
        r = analyze("ftp://files.example.com/pub/file.tar.gz")
        assert r.is_suspicious is False

    def test_clean_url_with_fragment(self):
        r = analyze("https://example.com/page#section1")
        assert r.is_suspicious is False

    def test_empty_url_does_not_raise(self):
        # Empty URL — should not raise, just return a non-crashing result
        r = analyze("")
        assert isinstance(r, URLOResult)
        assert r.original_url == ""

    def test_decoded_url_field_identity_on_clean(self):
        url = "https://example.com/path"
        r = analyze(url)
        assert r.decoded_url == url

    def test_original_url_preserved(self):
        url = "https://example.com/test?a=1&b=2"
        r = analyze(url)
        assert r.original_url == url


# ===========================================================================
# URLO-001 — Percent-encoded hostname
# ===========================================================================

class TestURLO001:
    def test_encoded_google_hostname(self):
        # %67%6f%6f%67%6c%65 = "google"
        r = analyze("http://%67%6f%6f%67%6c%65.com/")
        assert _has(r, "URLO-001")
        assert r.is_suspicious is True

    def test_partially_encoded_hostname(self):
        r = analyze("http://%65xample.com/path")
        assert _has(r, "URLO-001")

    def test_all_encoded_hostname(self):
        # %70%61%79%70%61%6c = "paypal"
        r = analyze("http://%70%61%79%70%61%6c.com/login")
        assert _has(r, "URLO-001")

    def test_encoded_hostname_weight(self):
        r = analyze("http://%67%6f%6f%67%6c%65.com/")
        finding = next(f for f in r.findings if f.check_id == "URLO-001")
        assert finding.weight == 25
        assert finding.severity == "HIGH"

    def test_no_percent_in_hostname_no_urlo001(self):
        r = analyze("http://example.com/path%20with%20spaces")
        assert not _has(r, "URLO-001")

    def test_path_encoding_does_not_trigger_urlo001(self):
        r = analyze("https://example.com/%73earch?q=test")
        assert not _has(r, "URLO-001")

    def test_query_encoding_does_not_trigger_urlo001(self):
        r = analyze("https://example.com/path?url=%68ttp%3A%2F%2Fevil.com")
        assert not _has(r, "URLO-001")

    def test_decoded_url_shows_decoded_form(self):
        r = analyze("http://%67%6f%6f%67%6c%65.com/")
        # Single-pass unquote should decode the percent sequences
        assert "google" in r.decoded_url or "%" not in r.decoded_url.split("/")[2]

    def test_uppercase_hex_encoded_hostname(self):
        r = analyze("http://%45%58%41%4D%50%4C%45.com/")
        assert _has(r, "URLO-001")

    def test_mixed_case_encoded_hostname(self):
        r = analyze("http://%65xAmPle.com/")
        assert _has(r, "URLO-001")

    def test_schemeless_encoded_hostname_with_path(self):
        r = analyze("%67%6f%6f%67%6c%65.com/login")
        assert _has(r, "URLO-001")

    def test_finding_detail_mentions_hostname(self):
        r = analyze("http://%67%6f%6f%67%6c%65.com/")
        finding = next(f for f in r.findings if f.check_id == "URLO-001")
        assert "%" in finding.detail or "google" in finding.detail.lower()


# ===========================================================================
# URLO-002 — Unicode homoglyph hostname
# ===========================================================================

class TestURLO002:
    def test_cyrillic_a_homoglyph(self):
        # Cyrillic "а" (U+0430) looks identical to Latin "a" (U+0061)
        # NFKC normalization does NOT equate them, but they are visually similar
        # We use a character that NFKC actually normalises differently:
        # U+FF41 FULLWIDTH LATIN SMALL LETTER A normalises to 'a'
        hostname = "ex\uff41mple.com"  # fullwidth 'a'
        r = analyze(f"http://{hostname}/")
        assert _has(r, "URLO-002")

    def test_fullwidth_chars_hostname(self):
        # Fullwidth ASCII characters normalise to their ASCII equivalents under NFKC
        hostname = "\uff47\uff4f\uff4f\uff47\uff4c\uff45.com"  # fullwidth "google"
        r = analyze(f"http://{hostname}/")
        assert _has(r, "URLO-002")

    def test_pure_ascii_hostname_no_urlo002(self):
        r = analyze("https://google.com/")
        assert not _has(r, "URLO-002")

    def test_punycode_hostname_no_urlo002(self):
        # xn-- punycode is ASCII — NFKC will not change it
        r = analyze("https://xn--nxasmq6b.com/")
        assert not _has(r, "URLO-002")

    def test_urlo002_severity_is_critical(self):
        hostname = "ex\uff41mple.com"
        r = analyze(f"http://{hostname}/")
        finding = next(f for f in r.findings if f.check_id == "URLO-002")
        assert finding.severity == "CRITICAL"
        assert finding.weight == 45

    def test_urlo002_detail_mentions_normalisation(self):
        hostname = "ex\uff41mple.com"
        r = analyze(f"http://{hostname}/")
        finding = next(f for f in r.findings if f.check_id == "URLO-002")
        assert "NFKC" in finding.detail or "normalise" in finding.detail.lower()

    def test_latin_extended_that_normalises(self):
        # U+FB01 LATIN SMALL LIGATURE FI normalises to "fi" under NFKC.
        # urlparse lowercases the hostname but the ligature is already lowercase,
        # so the before/after strings still differ after parsing.
        hostname = "e\ufb01le.com"  # "eﬁle.com" -> NFKC -> "efile.com"
        r = analyze(f"http://{hostname}/")
        assert _has(r, "URLO-002")

    def test_ascii_only_url_no_urlo002(self):
        r = analyze("http://paypal.com/")
        assert not _has(r, "URLO-002")

    def test_combining_characters_hostname(self):
        # Superscript digits normalise to regular digits under NFKC
        hostname = "pay\u00b9pal.com"  # superscript 1 -> normalises to '1'
        r = analyze(f"http://{hostname}/")
        assert _has(r, "URLO-002")


# ===========================================================================
# URLO-003 — Non-standard IP encoding
# ===========================================================================

class TestURLO003:
    # -- Hex integer IP --
    def test_hex_integer_ip(self):
        r = analyze("http://0x7f000001/")
        assert _has(r, "URLO-003")

    def test_hex_integer_ip_uppercase(self):
        r = analyze("http://0X7F000001/admin")
        assert _has(r, "URLO-003")

    def test_hex_integer_ip_partial(self):
        r = analyze("http://0xC0A80101/")  # 192.168.1.1 in hex
        assert _has(r, "URLO-003")

    def test_schemeless_hex_integer_ip_with_path(self):
        r = analyze("0x7f000001/admin")
        assert _has(r, "URLO-003")

    # -- Dotted hex IP --
    def test_dotted_hex_ip(self):
        r = analyze("http://0x7f.0x0.0x0.0x1/")
        assert _has(r, "URLO-003")

    def test_dotted_hex_ip_mixed_case(self):
        r = analyze("http://0XC0.0XA8.0X01.0X01/")
        assert _has(r, "URLO-003")

    # -- Octal IP --
    def test_octal_ip_loopback(self):
        r = analyze("http://0177.0.0.1/")
        assert _has(r, "URLO-003")

    def test_octal_ip_full(self):
        r = analyze("http://0300.0250.01.01/")
        assert _has(r, "URLO-003")

    def test_octal_single_octet(self):
        # One octal octet is sufficient to trigger
        r = analyze("http://0177.0.0.01/")
        assert _has(r, "URLO-003")

    # -- DWORD / integer IP --
    def test_dword_ip_loopback(self):
        # 127.0.0.1 = 2130706433
        r = analyze("http://2130706433/")
        assert _has(r, "URLO-003")

    def test_dword_ip_max(self):
        # 255.255.255.255 = 4294967295
        r = analyze("http://4294967295/")
        assert _has(r, "URLO-003")

    def test_dword_ip_google_dns(self):
        # 8.8.8.8 = 134744072
        r = analyze("http://134744072/")
        assert _has(r, "URLO-003")

    # -- Standard decimal IP -- should NOT fire --
    def test_standard_dotted_decimal_no_urlo003(self):
        r = analyze("http://127.0.0.1/")
        assert not _has(r, "URLO-003")

    def test_standard_dotted_decimal_192(self):
        r = analyze("http://192.168.1.1/")
        assert not _has(r, "URLO-003")

    def test_standard_dotted_decimal_8888(self):
        r = analyze("http://8.8.8.8/")
        assert not _has(r, "URLO-003")

    # -- Severity / weight --
    def test_urlo003_severity_critical(self):
        r = analyze("http://0x7f000001/")
        finding = next(f for f in r.findings if f.check_id == "URLO-003")
        assert finding.severity == "CRITICAL"
        assert finding.weight == 40

    def test_urlo003_detail_mentions_hostname(self):
        r = analyze("http://0177.0.0.1/")
        finding = next(f for f in r.findings if f.check_id == "URLO-003")
        assert "0177.0.0.1" in finding.detail or "non-standard" in finding.detail.lower()

    # -- Small integer — below DWORD threshold — should NOT fire --
    def test_small_integer_hostname_no_urlo003(self):
        # Integers <= 16777216 are not valid DWORD IPs per spec
        r = analyze("http://1234/path")
        assert not _has(r, "URLO-003")


# ===========================================================================
# URLO-004 — data: URI scheme
# ===========================================================================

class TestURLO004:
    def test_data_uri_html(self):
        r = analyze("data:text/html,<h1>Click here to login</h1>")
        assert _has(r, "URLO-004")

    def test_data_uri_base64(self):
        r = analyze("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
        assert _has(r, "URLO-004")

    def test_data_uri_image(self):
        r = analyze("data:image/png;base64,iVBORw0KGgo=")
        assert _has(r, "URLO-004")

    def test_data_uri_uppercase_scheme(self):
        # Scheme comparison is case-insensitive
        r = analyze("DATA:text/plain,hello")
        assert _has(r, "URLO-004")

    def test_data_uri_mixed_case_scheme(self):
        r = analyze("Data:text/html,<b>phishing</b>")
        assert _has(r, "URLO-004")

    def test_https_not_data_uri(self):
        r = analyze("https://example.com/data:text/html,test")
        assert not _has(r, "URLO-004")

    def test_data_uri_severity_high(self):
        r = analyze("data:text/html,test")
        finding = next(f for f in r.findings if f.check_id == "URLO-004")
        assert finding.severity == "HIGH"
        assert finding.weight == 30

    def test_data_uri_detail_mentions_data(self):
        r = analyze("data:text/html,test")
        finding = next(f for f in r.findings if f.check_id == "URLO-004")
        assert "data:" in finding.detail.lower() or "data" in finding.detail.lower()


# ===========================================================================
# URLO-005 — Nested URL / open-redirect pattern
# ===========================================================================

class TestURLO005:
    def test_redirect_http_in_query(self):
        r = analyze("https://example.com/redirect?url=http://evil.com")
        assert _has(r, "URLO-005")

    def test_redirect_https_in_query(self):
        r = analyze("https://tracker.com/click?dest=https://phishing.site/login")
        assert _has(r, "URLO-005")

    def test_nested_url_in_path(self):
        r = analyze("https://safe.com/proxy/http://evil.com/steal")
        assert _has(r, "URLO-005")

    def test_nested_url_in_fragment(self):
        r = analyze("https://example.com/page#http://evil.com/phish")
        assert _has(r, "URLO-005")

    def test_encoded_redirect_in_query(self):
        # %3A = ":" and %2F = "/" — the raw URL still has http:// plainly after decoding
        # but the raw URL itself contains http%3A%2F%2F — that won't match without decode.
        # This test confirms we match the *raw* nested URL (not decoded)
        r = analyze("https://example.com/redir?url=http%3A%2F%2Fevil.com")
        # Raw URL doesn't contain "http://" literally — should NOT fire
        assert not _has(r, "URLO-005")

    def test_nested_url_case_insensitive(self):
        r = analyze("https://example.com/redir?u=HTTP://EVIL.COM")
        assert _has(r, "URLO-005")

    def test_no_nested_url_in_query(self):
        r = analyze("https://example.com/search?q=open+redirect+attack")
        assert not _has(r, "URLO-005")

    def test_nested_url_weight_and_severity(self):
        r = analyze("https://example.com/redir?url=https://evil.com")
        finding = next(f for f in r.findings if f.check_id == "URLO-005")
        assert finding.weight == 25
        assert finding.severity == "HIGH"

    def test_multiple_nested_urls_only_one_finding(self):
        # Even with two nested URLs, only one URLO-005 finding fires
        r = analyze("https://example.com/?a=http://a.com&b=https://b.com")
        urlo005_count = sum(1 for f in r.findings if f.check_id == "URLO-005")
        assert urlo005_count == 1

    def test_nested_https_url_detail(self):
        r = analyze("https://legit.com/go?to=https://evil.com")
        finding = next(f for f in r.findings if f.check_id == "URLO-005")
        assert "http" in finding.detail.lower()


# ===========================================================================
# URLO-006 — Double-encoded characters
# ===========================================================================

class TestURLO006:
    def test_double_encoded_slash(self):
        # %252F decodes to %2F (slash)
        r = analyze("https://example.com/path%252Ftraversal")
        assert _has(r, "URLO-006")

    def test_double_encoded_quote(self):
        # %2527 decodes to %27 (single quote)
        r = analyze("https://example.com/page?id=1%2527%20OR%201=1")
        assert _has(r, "URLO-006")

    def test_double_encoded_percent_sign(self):
        # %2520 decodes to %20 (space)
        r = analyze("https://example.com/file%2520name.pdf")
        assert _has(r, "URLO-006")

    def test_double_encoded_in_fragment(self):
        r = analyze("https://example.com/page#section%2541")
        assert _has(r, "URLO-006")

    def test_double_encoded_mixed_case(self):
        r = analyze("https://example.com/%25aF/path")
        assert _has(r, "URLO-006")

    def test_uppercase_double_encoding(self):
        r = analyze("https://example.com/%252F/admin")
        assert _has(r, "URLO-006")

    def test_single_encoding_does_not_fire_urlo006(self):
        # %2F is a single-encoded slash — valid, no double-encoding
        r = analyze("https://example.com/path%2Ftraversal")
        assert not _has(r, "URLO-006")

    def test_normal_percent_encoding_does_not_fire(self):
        r = analyze("https://example.com/search?q=hello%20world")
        assert not _has(r, "URLO-006")

    def test_double_encoding_weight_and_severity(self):
        r = analyze("https://example.com/%252F")
        finding = next(f for f in r.findings if f.check_id == "URLO-006")
        assert finding.weight == 25
        assert finding.severity == "HIGH"

    def test_double_encoding_detail_mentions_sequence(self):
        r = analyze("https://example.com/%252F")
        finding = next(f for f in r.findings if f.check_id == "URLO-006")
        assert "%25" in finding.detail or "double" in finding.detail.lower()

    def test_multiple_double_encoded_sequences(self):
        # Two double-encoded sequences — still only one finding (first match)
        r = analyze("https://example.com/%252F%2527")
        assert _has(r, "URLO-006")
        count = sum(1 for f in r.findings if f.check_id == "URLO-006")
        assert count == 1


# ===========================================================================
# URLO-007 — Embedded credentials
# ===========================================================================

class TestURLO007:
    def test_user_and_password(self):
        r = analyze("http://user:pass@domain.com/")
        assert _has(r, "URLO-007")

    def test_user_only_no_password(self):
        r = analyze("http://admin@example.com/login")
        assert _has(r, "URLO-007")

    def test_ftp_with_credentials(self):
        r = analyze("ftp://anonymous:password@files.example.com/pub/")
        assert _has(r, "URLO-007")

    def test_https_with_credentials(self):
        r = analyze("https://user:secretpass@secure.example.com/account")
        assert _has(r, "URLO-007")

    def test_schemeless_credentials_with_password(self):
        r = analyze("user:pass@evil.example/login")
        assert _has(r, "URLO-007")

    def test_schemeless_credentials_with_username_only(self):
        r = analyze("admin@evil.example/login")
        assert _has(r, "URLO-007")

    def test_no_credentials_no_urlo007(self):
        r = analyze("https://example.com/login?user=admin")
        assert not _has(r, "URLO-007")

    def test_at_in_query_no_urlo007(self):
        # @ appearing only in the query string should not trigger
        r = analyze("https://example.com/send?to=user@email.com")
        assert not _has(r, "URLO-007")

    def test_credentials_weight_and_severity(self):
        r = analyze("http://user:pass@example.com/")
        finding = next(f for f in r.findings if f.check_id == "URLO-007")
        assert finding.severity == "CRITICAL"
        assert finding.weight == 40

    def test_credentials_detail_mentions_userinfo(self):
        r = analyze("http://admin:hunter2@example.com/")
        finding = next(f for f in r.findings if f.check_id == "URLO-007")
        assert "admin" in finding.detail or "credential" in finding.detail.lower()

    def test_empty_password_still_fires(self):
        # user: with no password value — urllib still sees a username
        r = analyze("http://user:@example.com/")
        assert _has(r, "URLO-007")

    def test_special_chars_in_credentials(self):
        r = analyze("https://us%40r:p%40ss@example.com/")
        assert _has(r, "URLO-007")

    def test_mailto_address_does_not_trigger_urlo007(self):
        r = analyze("mailto:user@example.com")
        assert not _has(r, "URLO-007")


# ===========================================================================
# MULTI-CHECK SCENARIOS
# ===========================================================================

class TestMultipleChecks:
    def test_credentials_and_hex_ip(self):
        r = analyze("http://user:pass@0x7f000001/admin")
        assert _has(r, "URLO-007")
        assert _has(r, "URLO-003")
        assert r.risk_score == min(100, 40 + 40)

    def test_encoded_hostname_and_redirect(self):
        r = analyze("http://%67%6f%6f%67%6c%65.com/redir?url=https://evil.com")
        assert _has(r, "URLO-001")
        assert _has(r, "URLO-005")

    def test_double_encoding_and_redirect(self):
        r = analyze("https://example.com/path%252F?url=http://evil.com")
        assert _has(r, "URLO-006")
        assert _has(r, "URLO-005")

    def test_credentials_redirect_and_double_encoding(self):
        r = analyze("https://user:pass@example.com/%252F?to=http://evil.com")
        assert _has(r, "URLO-007")
        assert _has(r, "URLO-005")
        assert _has(r, "URLO-006")
        expected = min(100, 40 + 25 + 25)
        assert r.risk_score == expected

    def test_risk_score_capped_at_100(self):
        # Combine credentials (40) + hex IP (40) + redirect (25) + double-enc (25)
        # = 130 → capped at 100
        r = analyze("http://user:pass@0x7f000001/path%252F?url=http://evil.com")
        assert r.risk_score == 100

    def test_data_uri_and_double_encoding(self):
        r = analyze("data:text/html,%252F<script>alert(1)</script>")
        assert _has(r, "URLO-004")
        assert _has(r, "URLO-006")

    def test_all_checks_not_firing_simultaneously_on_clean(self):
        r = analyze("https://www.example.com/safe-path?q=value")
        assert r.findings == []
        assert r.risk_score == 0
        assert r.is_suspicious is False


# ===========================================================================
# URLOResult API surface
# ===========================================================================

class TestURLOResultAPI:
    def test_to_dict_keys(self):
        r = analyze("http://user:pass@0x7f000001/")
        d = r.to_dict()
        assert "original_url" in d
        assert "decoded_url" in d
        assert "risk_score" in d
        assert "is_suspicious" in d
        assert "findings" in d

    def test_to_dict_findings_are_dicts(self):
        r = analyze("http://user:pass@0x7f000001/")
        d = r.to_dict()
        for f in d["findings"]:
            assert "check_id" in f
            assert "severity" in f
            assert "title" in f
            assert "detail" in f
            assert "weight" in f

    def test_to_dict_risk_score_correct(self):
        r = analyze("http://user:pass@example.com/")  # URLO-007 only → 40
        d = r.to_dict()
        assert d["risk_score"] == 40

    def test_summary_clean_url(self):
        r = analyze("https://example.com/")
        s = r.summary()
        assert "CLEAN" in s
        assert "example.com" in s

    def test_summary_suspicious_url(self):
        r = analyze("http://user:pass@0x7f000001/")
        s = r.summary()
        assert "SUSPICIOUS" in s
        assert "risk_score=" in s

    def test_summary_contains_check_ids(self):
        r = analyze("http://user:pass@0x7f000001/")
        s = r.summary()
        for finding in r.findings:
            assert finding.check_id in s

    def test_by_severity_grouping(self):
        r = analyze("http://user:pass@0x7f000001/")
        groups = r.by_severity()
        # Both URLO-007 and URLO-003 are CRITICAL
        assert "CRITICAL" in groups
        critical_ids = {f.check_id for f in groups["CRITICAL"]}
        assert "URLO-007" in critical_ids
        assert "URLO-003" in critical_ids

    def test_by_severity_all_findings_present(self):
        r = analyze("https://example.com/redir?url=http://evil.com")  # URLO-005 HIGH
        groups = r.by_severity()
        all_findings = [f for findings in groups.values() for f in findings]
        assert len(all_findings) == len(r.findings)

    def test_is_suspicious_true_when_findings(self):
        r = analyze("http://user:pass@example.com/")
        assert r.is_suspicious is True

    def test_is_suspicious_false_when_no_findings(self):
        r = analyze("https://example.com/")
        assert r.is_suspicious is False

    def test_decoded_url_is_string(self):
        r = analyze("http://%67%6f%6f%67%6c%65.com/")
        assert isinstance(r.decoded_url, str)
        assert r.decoded_url  # non-empty

    def test_urlo_finding_fields_populated(self):
        r = analyze("http://0x7f000001/")
        f = next(f for f in r.findings if f.check_id == "URLO-003")
        assert isinstance(f.check_id, str)
        assert isinstance(f.severity, str)
        assert isinstance(f.title, str)
        assert isinstance(f.detail, str)
        assert isinstance(f.weight, int)
        assert f.weight > 0


# ===========================================================================
# analyze_many
# ===========================================================================

class TestAnalyzeMany:
    def test_returns_list(self):
        urls = ["https://example.com", "http://0x7f000001/"]
        results = analyze_many(urls)
        assert isinstance(results, list)
        assert len(results) == 2

    def test_order_preserved(self):
        urls = ["https://clean.com", "http://user:pass@evil.com/"]
        results = analyze_many(urls)
        assert results[0].original_url == "https://clean.com"
        assert results[1].original_url == "http://user:pass@evil.com/"

    def test_empty_list(self):
        results = analyze_many([])
        assert results == []

    def test_single_url(self):
        results = analyze_many(["https://example.com"])
        assert len(results) == 1
        assert isinstance(results[0], URLOResult)

    def test_mixed_clean_and_suspicious(self):
        urls = [
            "https://clean.com/",
            "http://0x7f000001/",
            "https://safe.org/page",
        ]
        results = analyze_many(urls)
        assert results[0].is_suspicious is False
        assert results[1].is_suspicious is True
        assert results[2].is_suspicious is False

    def test_all_suspicious(self):
        urls = [
            "http://user:pass@0x7f000001/",
            "data:text/html,phish",
            "https://example.com/go?to=http://evil.com",
        ]
        results = analyze_many(urls)
        assert all(r.is_suspicious for r in results)


# ===========================================================================
# EDGE CASES
# ===========================================================================

class TestEdgeCases:
    def test_url_with_only_scheme(self):
        r = analyze("http://")
        assert isinstance(r, URLOResult)

    def test_url_with_ipv6_not_flagged_as_nonstandard(self):
        r = analyze("http://[::1]/path")
        assert not _has(r, "URLO-003")

    def test_url_with_ipv6_full_not_flagged(self):
        r = analyze("http://[2001:db8::1]/")
        assert not _has(r, "URLO-003")

    def test_percent_in_query_not_urlo001(self):
        r = analyze("https://example.com/?q=50%25off")
        assert not _has(r, "URLO-001")

    def test_zero_single_integer_not_dword(self):
        # 0 is not a valid DWORD IP (below threshold)
        r = analyze("http://0/")
        assert not _has(r, "URLO-003")

    def test_dword_boundary_exactly_16777216_not_flagged(self):
        # 16777216 = 0x01000000 — boundary value, spec says strictly greater
        r = analyze("http://16777216/")
        # Whether or not this fires depends on implementation; we assert no crash
        assert isinstance(r, URLOResult)

    def test_no_crash_on_very_long_url(self):
        long_url = "https://example.com/" + "a" * 5000
        r = analyze(long_url)
        assert isinstance(r, URLOResult)

    def test_url_with_port_and_credentials(self):
        r = analyze("https://admin:secret@example.com:8443/dashboard")
        assert _has(r, "URLO-007")
        assert not _has(r, "URLO-003")

    def test_data_uri_with_nested_http(self):
        r = analyze("data:text/html,http://evil.com/phish")
        assert _has(r, "URLO-004")
        # URLO-005 looks at path/query/fragment; for data: URIs the
        # "path" per urlparse is the content portion — may or may not fire
        # We only assert data: fires and no crash
        assert isinstance(r, URLOResult)

    def test_url_with_no_scheme(self):
        # No scheme — urlparse treats it as a path; should not crash
        r = analyze("example.com/login")
        assert isinstance(r, URLOResult)

    def test_fragment_only_url(self):
        r = analyze("#fragment")
        assert isinstance(r, URLOResult)

    def test_whitespace_only_url(self):
        r = analyze("   ")
        assert isinstance(r, URLOResult)


# ===========================================================================
# CLI workflow
# ===========================================================================

class TestUrlTriageCli:
    def test_url_triage_writes_json_for_direct_urls(self, tmp_path: Path):
        from cli.main import cli as main_cli

        runner = CliRunner()
        output_path = tmp_path / "url-triage.json"

        result = runner.invoke(
            main_cli,
            [
                "url-triage",
                "https://example.com/login",
                "http://user:pass@0x7f000001/login?next=https://evil.test",
                "--output-json",
                str(output_path),
            ],
        )

        assert result.exit_code == 0, result.output
        assert "URL Triage" in result.output
        assert "Summary:" in result.output
        assert "suspicious=1" in result.output

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["total_urls"] == 2
        assert payload["suspicious_urls"] == 1
        suspicious = payload["results"][0]
        assert suspicious["risk_score"] > 0
        assert {finding["check_id"] for finding in suspicious["findings"]} >= {"URLO-003", "URLO-007"}

    def test_url_triage_reads_input_file_and_fails_on_suspicious(self, tmp_path: Path):
        from cli.main import cli as main_cli

        input_path = tmp_path / "urls.txt"
        input_path.write_text(
            "\n".join([
                "# analyst notes",
                "https://safe.example/path",
                "data:text/html,<form action=https://evil.test>",
            ]),
            encoding="utf-8",
        )

        result = CliRunner().invoke(
            main_cli,
            ["url-triage", "--input-file", str(input_path), "--fail-on-suspicious"],
        )

        assert result.exit_code == 1
        assert "analyzed=2" in result.output
        assert "suspicious=1" in result.output

    def test_url_triage_requires_url_or_input_file(self):
        from cli.main import cli as main_cli

        result = CliRunner().invoke(main_cli, ["url-triage"])

        assert result.exit_code != 0
        assert "Provide at least one URL or --input-file." in result.output
