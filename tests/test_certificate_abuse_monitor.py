# test_certificate_abuse_monitor.py — pytest suite for CertificateAbuseMonitor
#
# Coverage: 90+ tests across all 7 abuse checks, edge cases, risk scoring,
# multi-cert analysis, dataclass serialisation, and multi-keyword monitors.
#
# Copyright 2024 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# SPDX-License-Identifier: CC-BY-4.0

from __future__ import annotations

import sys
import os
import time

import pytest

# ---------------------------------------------------------------------------
# Path setup — allow running from repo root or from tests/ directory
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from monitors.certificate_abuse_monitor import (
    CertAbuseFinding,
    CertAbuseResult,
    CertificateAbuseMonitor,
    CertificateInfo,
    _CHECK_WEIGHTS,
    _DEFAULT_TRUSTED_CAS,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

NOW = time.time()
FUTURE = NOW + 86400 * 100   # 100 days from now — not yet expired
PAST = NOW - 86400 * 10      # 10 days ago — already expired
FAR_FUTURE = NOW + 86400 * 500  # 500 days — exceeds 398-day limit

PAYPAL_MONITOR = CertificateAbuseMonitor(brand_keywords=["paypal"])
GOOGLE_MONITOR = CertificateAbuseMonitor(brand_keywords=["google"])
MULTI_MONITOR = CertificateAbuseMonitor(brand_keywords=["paypal", "google"])


def clean_cert(
    common_name: str = "example.com",
    sans: list = None,
    issuer: str = "Let's Encrypt",
    is_self_signed: bool = False,
    not_before: float = None,
    not_after: float = None,
    serial: str = "AABBCC",
    sig_alg: str = "sha256WithRSAEncryption",
    key_size: int = 2048,
) -> CertificateInfo:
    """Factory for a CertificateInfo with safe defaults — should produce 0 findings."""
    return CertificateInfo(
        common_name=common_name,
        subject_alt_names=sans if sans is not None else [],
        issuer_name=issuer,
        is_self_signed=is_self_signed,
        not_before=not_before if not_before is not None else NOW - 86400 * 30,
        not_after=not_after if not_after is not None else FUTURE,
        serial_number=serial,
        signature_algorithm=sig_alg,
        key_size_bits=key_size,
    )


def finding_ids(result: CertAbuseResult) -> list:
    """Extract just the check_id strings from a result."""
    return [f.check_id for f in result.findings]


# ===========================================================================
# 1. CLEAN / BASELINE
# ===========================================================================


class TestCleanCertificate:
    def test_no_findings_for_legitimate_domain(self):
        cert = clean_cert("example.com", ["www.example.com"])
        result = PAYPAL_MONITOR.analyze(cert)
        assert result.findings == []
        assert result.risk_score == 0

    def test_no_findings_non_brand_domain_trusted_ca(self):
        cert = clean_cert("acme-corp.com", ["acme-corp.com", "www.acme-corp.com"])
        result = PAYPAL_MONITOR.analyze(cert)
        assert result.findings == []

    def test_no_findings_digicert_ca(self):
        cert = clean_cert(issuer="DigiCert Inc")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-003" not in finding_ids(result)

    def test_no_findings_lets_encrypt_ca(self):
        cert = clean_cert(issuer="Let's Encrypt")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-003" not in finding_ids(result)

    def test_risk_score_zero_for_clean_cert(self):
        cert = clean_cert()
        result = PAYPAL_MONITOR.analyze(cert)
        assert result.risk_score == 0

    def test_summary_no_findings(self):
        cert = clean_cert()
        result = PAYPAL_MONITOR.analyze(cert)
        assert "No abuse findings detected" in result.summary()
        assert "0/100" in result.summary()


# ===========================================================================
# 2. CERT-ABU-001: Suspicious domain variant
# ===========================================================================


class TestCertAbu001:
    def test_paypal_login_cn_triggers(self):
        cert = clean_cert("paypal-login.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_secure_paypal_cn_triggers(self):
        cert = clean_cert("secure-paypal.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_paypal_secure_cn_triggers(self):
        cert = clean_cert("paypal-secure.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_paypal_verify_cn_triggers(self):
        cert = clean_cert("paypal-verify.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_paypal_update_triggers(self):
        cert = clean_cert("paypal-update.net")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_paypal_account_triggers(self):
        cert = clean_cert("paypal-account.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_paypal_signin_triggers(self):
        cert = clean_cert("paypal-signin.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_paypal_portal_triggers(self):
        cert = clean_cert("paypal-portal.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_paypal_support_triggers(self):
        cert = clean_cert("paypal-support.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_paypal_helpdesk_triggers(self):
        cert = clean_cert("paypal-helpdesk.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_brand_in_san_triggers(self):
        cert = clean_cert("evil.com", ["paypal-login.evil.com"])
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_paypal_com_does_not_trigger(self):
        # "paypal.com" — brand keyword is the entire second-level domain,
        # no action word present; only 2 tokens (paypal, com) — NOT suspicious
        cert = clean_cert("paypal.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" not in finding_ids(result)

    def test_case_insensitive_keyword(self):
        cert = clean_cert("PayPal-LOGIN.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_finding_severity_is_high(self):
        cert = clean_cert("paypal-login.com")
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-001")
        assert hit.severity == "HIGH"

    def test_finding_contains_cn(self):
        cert = clean_cert("paypal-login.com")
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-001")
        assert hit.common_name == "paypal-login.com"

    def test_google_login_triggers_google_monitor(self):
        cert = clean_cert("google-login.com")
        result = GOOGLE_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_paypal_san_only_triggers(self):
        cert = clean_cert("harmless.com", ["verify.paypal-id.net"])
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_weight_contributes_to_risk_score(self):
        cert = clean_cert("paypal-login.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert result.risk_score >= _CHECK_WEIGHTS["CERT-ABU-001"]


# ===========================================================================
# 3. CERT-ABU-002: Wildcard covering brand keyword domain
# ===========================================================================


class TestCertAbu002:
    def test_wildcard_paypal_verify_triggers(self):
        cert = clean_cert("*.paypal-verify.com", ["*.paypal-verify.com"])
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-002" in finding_ids(result)

    def test_wildcard_example_does_not_trigger(self):
        cert = clean_cert("*.example.com", ["*.example.com"])
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-002" not in finding_ids(result)

    def test_wildcard_paypal_in_san_triggers(self):
        cert = clean_cert("phishing.com", ["*.paypal-secure.net"])
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-002" in finding_ids(result)

    def test_non_wildcard_does_not_trigger_002(self):
        cert = clean_cert("paypal-login.com")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-002" not in finding_ids(result)

    def test_wildcard_severity_high(self):
        cert = clean_cert("*.paypal-id.com", ["*.paypal-id.com"])
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-002")
        assert hit.severity == "HIGH"

    def test_wildcard_google_triggers_google_monitor(self):
        cert = clean_cert("*.google-accounts.com", ["*.google-accounts.com"])
        result = GOOGLE_MONITOR.analyze(cert)
        assert "CERT-ABU-002" in finding_ids(result)

    def test_wildcard_weight_in_risk_score(self):
        cert = clean_cert("*.paypal-login.com", ["*.paypal-login.com"])
        result = PAYPAL_MONITOR.analyze(cert)
        # At minimum CERT-ABU-002 weight (20) should be present
        assert result.risk_score >= _CHECK_WEIGHTS["CERT-ABU-002"]


# ===========================================================================
# 4. CERT-ABU-003: Untrusted / unknown CA
# ===========================================================================


class TestCertAbu003:
    def test_sketchy_ca_triggers(self):
        cert = clean_cert(issuer="SketchyCA Ltd")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-003" in finding_ids(result)

    def test_lets_encrypt_does_not_trigger(self):
        cert = clean_cert(issuer="Let's Encrypt")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-003" not in finding_ids(result)

    def test_digicert_does_not_trigger(self):
        cert = clean_cert(issuer="DigiCert Inc")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-003" not in finding_ids(result)

    def test_sectigo_does_not_trigger(self):
        cert = clean_cert(issuer="Sectigo Limited")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-003" not in finding_ids(result)

    def test_globalsign_does_not_trigger(self):
        cert = clean_cert(issuer="GlobalSign nv-sa")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-003" not in finding_ids(result)

    def test_custom_trusted_cas_accepted(self):
        monitor = CertificateAbuseMonitor(
            brand_keywords=["paypal"],
            trusted_cas=["MyCorpCA"],
        )
        cert = clean_cert(issuer="MyCorpCA Internal Root")
        result = monitor.analyze(cert)
        assert "CERT-ABU-003" not in finding_ids(result)

    def test_custom_trusted_cas_rejects_default(self):
        # When a custom list is supplied, CAs NOT in that list should be flagged
        monitor = CertificateAbuseMonitor(
            brand_keywords=["paypal"],
            trusted_cas=["MyCorpCA"],
        )
        cert = clean_cert(issuer="Let's Encrypt")
        result = monitor.analyze(cert)
        assert "CERT-ABU-003" in finding_ids(result)

    def test_self_signed_does_not_double_trigger_003(self):
        # CERT-ABU-003 must be suppressed for self-signed certs (covered by 006)
        cert = clean_cert(issuer="Self-Signed Corp", is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-003" not in finding_ids(result)

    def test_untrusted_ca_severity_high(self):
        cert = clean_cert(issuer="RandomCA")
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-003")
        assert hit.severity == "HIGH"

    def test_untrusted_ca_message_includes_issuer(self):
        cert = clean_cert(issuer="EvilCA")
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-003")
        assert "EvilCA" in hit.message

    def test_case_insensitive_ca_match(self):
        # "digicert" lowercase in issuer should still match
        cert = clean_cert(issuer="digicert global root")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-003" not in finding_ids(result)


# ===========================================================================
# 5. CERT-ABU-004: Expired certificate
# ===========================================================================


class TestCertAbu004:
    def test_expired_cert_triggers(self):
        cert = clean_cert(not_after=PAST)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-004" in finding_ids(result)

    def test_future_cert_does_not_trigger(self):
        cert = clean_cert(not_after=FUTURE)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-004" not in finding_ids(result)

    def test_expired_severity_medium(self):
        cert = clean_cert(not_after=PAST)
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-004")
        assert hit.severity == "MEDIUM"

    def test_expired_message_mentions_days(self):
        cert = clean_cert(not_after=PAST)
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-004")
        assert "day" in hit.message.lower()

    def test_just_expired_triggers(self):
        # 1 second past expiry
        cert = clean_cert(not_after=NOW - 1)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-004" in finding_ids(result)


# ===========================================================================
# 6. CERT-ABU-005: Excessive SAN count
# ===========================================================================


class TestCertAbu005:
    def test_51_sans_triggers(self):
        cert = clean_cert(sans=[f"host{i}.example.com" for i in range(51)])
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-005" in finding_ids(result)

    def test_50_sans_does_not_trigger(self):
        cert = clean_cert(sans=[f"host{i}.example.com" for i in range(50)])
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-005" not in finding_ids(result)

    def test_0_sans_does_not_trigger(self):
        cert = clean_cert(sans=[])
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-005" not in finding_ids(result)

    def test_100_sans_triggers(self):
        cert = clean_cert(sans=[f"host{i}.example.com" for i in range(100)])
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-005" in finding_ids(result)

    def test_excessive_sans_severity_medium(self):
        cert = clean_cert(sans=[f"h{i}.example.com" for i in range(60)])
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-005")
        assert hit.severity == "MEDIUM"

    def test_excessive_sans_message_includes_count(self):
        cert = clean_cert(sans=[f"h{i}.example.com" for i in range(75)])
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-005")
        assert "75" in hit.message


# ===========================================================================
# 7. CERT-ABU-006: Self-signed certificate
# ===========================================================================


class TestCertAbu006:
    def test_self_signed_true_triggers(self):
        cert = clean_cert(is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-006" in finding_ids(result)

    def test_self_signed_false_does_not_trigger(self):
        cert = clean_cert(is_self_signed=False)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-006" not in finding_ids(result)

    def test_self_signed_severity_high(self):
        cert = clean_cert(is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-006")
        assert hit.severity == "HIGH"

    def test_self_signed_message_mentions_browser(self):
        cert = clean_cert(is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-006")
        assert "browser" in hit.message.lower() or "self-signed" in hit.message.lower()

    def test_self_signed_weight(self):
        cert = clean_cert(is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        assert result.risk_score >= _CHECK_WEIGHTS["CERT-ABU-006"]


# ===========================================================================
# 8. CERT-ABU-007: Certificate validity period too long
# ===========================================================================


class TestCertAbu007:
    def test_validity_over_398_days_triggers(self):
        not_before = NOW - 86400
        not_after = not_before + 86400 * 400  # 400 days — above 398
        cert = clean_cert(not_before=not_before, not_after=not_after)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-007" in finding_ids(result)

    def test_validity_exactly_398_days_does_not_trigger(self):
        not_before = NOW - 86400
        not_after = not_before + 86400 * 398  # exactly 398 — NOT above
        cert = clean_cert(not_before=not_before, not_after=not_after)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-007" not in finding_ids(result)

    def test_validity_365_days_does_not_trigger(self):
        not_before = NOW - 86400
        not_after = not_before + 86400 * 365
        cert = clean_cert(not_before=not_before, not_after=not_after)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-007" not in finding_ids(result)

    def test_validity_90_days_does_not_trigger(self):
        not_before = NOW - 86400
        not_after = not_before + 86400 * 90
        cert = clean_cert(not_before=not_before, not_after=not_after)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-007" not in finding_ids(result)

    def test_custom_max_validity_days_respected(self):
        monitor = CertificateAbuseMonitor(
            brand_keywords=["paypal"],
            max_validity_days=90,
        )
        not_before = NOW - 86400
        not_after = not_before + 86400 * 91  # 91 days > 90-day custom limit
        cert = clean_cert(not_before=not_before, not_after=not_after)
        result = monitor.analyze(cert)
        assert "CERT-ABU-007" in finding_ids(result)

    def test_custom_max_validity_days_boundary(self):
        monitor = CertificateAbuseMonitor(
            brand_keywords=["paypal"],
            max_validity_days=90,
        )
        not_before = NOW - 86400
        not_after = not_before + 86400 * 90  # exactly 90 — should NOT fire
        cert = clean_cert(not_before=not_before, not_after=not_after)
        result = monitor.analyze(cert)
        assert "CERT-ABU-007" not in finding_ids(result)

    def test_long_validity_severity_medium(self):
        not_before = NOW - 86400
        not_after = not_before + 86400 * 730  # 2 years
        cert = clean_cert(not_before=not_before, not_after=not_after)
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-007")
        assert hit.severity == "MEDIUM"

    def test_long_validity_message_includes_days(self):
        not_before = NOW - 86400
        not_after = not_before + 86400 * 730
        cert = clean_cert(not_before=not_before, not_after=not_after)
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-007")
        assert "730" in hit.message


# ===========================================================================
# 9. Multiple findings on the same certificate
# ===========================================================================


class TestMultipleFindings:
    def test_brand_domain_untrusted_ca_self_signed(self):
        cert = clean_cert(
            "paypal-login.com",
            is_self_signed=True,
            issuer="Shady Certs Inc",
        )
        result = PAYPAL_MONITOR.analyze(cert)
        ids = finding_ids(result)
        assert "CERT-ABU-001" in ids
        assert "CERT-ABU-006" in ids
        # Self-signed suppresses CERT-ABU-003
        assert "CERT-ABU-003" not in ids

    def test_expired_plus_self_signed(self):
        cert = clean_cert(is_self_signed=True, not_after=PAST)
        result = PAYPAL_MONITOR.analyze(cert)
        ids = finding_ids(result)
        assert "CERT-ABU-004" in ids
        assert "CERT-ABU-006" in ids

    def test_expired_untrusted_ca(self):
        cert = clean_cert(issuer="WeirdCA", not_after=PAST)
        result = PAYPAL_MONITOR.analyze(cert)
        ids = finding_ids(result)
        assert "CERT-ABU-003" in ids
        assert "CERT-ABU-004" in ids

    def test_wildcard_brand_plus_excessive_sans(self):
        cert = clean_cert(
            "*.paypal-verify.com",
            sans=["*.paypal-verify.com"] + [f"h{i}.other.com" for i in range(55)],
        )
        result = PAYPAL_MONITOR.analyze(cert)
        ids = finding_ids(result)
        assert "CERT-ABU-002" in ids
        assert "CERT-ABU-005" in ids

    def test_all_checks_except_002_fire(self):
        not_before = NOW - 86400
        not_after_ts = not_before + 86400 * 500  # long validity
        cert = CertificateInfo(
            common_name="paypal-login.com",
            subject_alt_names=[f"x{i}.fake.com" for i in range(55)],
            issuer_name="FakeCA",
            is_self_signed=False,
            not_before=not_before,
            not_after=not_after_ts,  # valid — not expired, but too long
        )
        # Manually make it expired by patching not_after
        cert.not_after = PAST  # now it IS expired, but validity window is still long
        # Override not_before so validity window is still > 398 days
        cert.not_before = PAST - 86400 * 500
        result = PAYPAL_MONITOR.analyze(cert)
        ids = finding_ids(result)
        assert "CERT-ABU-001" in ids
        assert "CERT-ABU-003" in ids
        assert "CERT-ABU-004" in ids
        assert "CERT-ABU-005" in ids
        assert "CERT-ABU-007" in ids


# ===========================================================================
# 10. Risk score computation
# ===========================================================================


class TestRiskScore:
    def test_risk_score_capped_at_100(self):
        # Fire as many high-weight checks as possible to exceed 100 naturally
        cert = CertificateInfo(
            common_name="paypal-login.com",
            subject_alt_names=["*.paypal-verify.com"] + [f"x{i}.bad.com" for i in range(55)],
            issuer_name="UnknownCA",
            is_self_signed=True,
            not_before=NOW - 86400 * 500,
            not_after=PAST,  # expired
        )
        result = PAYPAL_MONITOR.analyze(cert)
        assert result.risk_score <= 100

    def test_single_check_weight_correct(self):
        # Only CERT-ABU-006 should fire (self-signed, no brand, trusted CA suppressed)
        cert = clean_cert(is_self_signed=True, issuer="Let's Encrypt")
        result = PAYPAL_MONITOR.analyze(cert)
        assert "CERT-ABU-006" in finding_ids(result)
        # risk_score should be at least the weight of 006 (25)
        assert result.risk_score >= 25

    def test_two_checks_score_is_sum(self):
        # CERT-ABU-004 (15) + CERT-ABU-006 (25) = 40
        cert = clean_cert(is_self_signed=True, not_after=PAST, issuer="Let's Encrypt")
        result = PAYPAL_MONITOR.analyze(cert)
        ids = set(finding_ids(result))
        expected = sum(_CHECK_WEIGHTS[cid] for cid in ids)
        assert result.risk_score == min(100, expected)

    def test_duplicate_check_id_not_double_counted(self):
        # Should only ever get each check ID once regardless of how many names match
        cert = clean_cert(
            "paypal-login.com",
            sans=["paypal-verify.com", "paypal-support.com"],
        )
        result = PAYPAL_MONITOR.analyze(cert)
        # CERT-ABU-001 must appear exactly once in findings
        count = sum(1 for f in result.findings if f.check_id == "CERT-ABU-001")
        assert count == 1

    def test_zero_findings_gives_zero_score(self):
        cert = clean_cert()
        result = PAYPAL_MONITOR.analyze(cert)
        assert result.risk_score == 0


# ===========================================================================
# 11. by_severity()
# ===========================================================================


class TestBySeverity:
    def test_by_severity_structure_always_present(self):
        cert = clean_cert()
        result = PAYPAL_MONITOR.analyze(cert)
        grouped = result.by_severity()
        assert "HIGH" in grouped
        assert "MEDIUM" in grouped
        assert "LOW" in grouped

    def test_by_severity_empty_on_clean_cert(self):
        cert = clean_cert()
        result = PAYPAL_MONITOR.analyze(cert)
        grouped = result.by_severity()
        assert grouped["HIGH"] == []
        assert grouped["MEDIUM"] == []
        assert grouped["LOW"] == []

    def test_by_severity_high_populated(self):
        cert = clean_cert(is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        grouped = result.by_severity()
        assert len(grouped["HIGH"]) >= 1

    def test_by_severity_medium_populated(self):
        cert = clean_cert(not_after=PAST)
        result = PAYPAL_MONITOR.analyze(cert)
        grouped = result.by_severity()
        assert any(f.check_id == "CERT-ABU-004" for f in grouped["MEDIUM"])

    def test_by_severity_counts_match_findings(self):
        cert = clean_cert(is_self_signed=True, not_after=PAST)
        result = PAYPAL_MONITOR.analyze(cert)
        grouped = result.by_severity()
        total_grouped = sum(len(v) for v in grouped.values())
        assert total_grouped == len(result.findings)


# ===========================================================================
# 12. summary()
# ===========================================================================


class TestSummary:
    def test_summary_no_findings_message(self):
        cert = clean_cert()
        result = PAYPAL_MONITOR.analyze(cert)
        s = result.summary()
        assert "No abuse findings detected" in s

    def test_summary_includes_risk_score(self):
        cert = clean_cert(is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        s = result.summary()
        assert str(result.risk_score) in s

    def test_summary_includes_finding_count(self):
        cert = clean_cert(is_self_signed=True, not_after=PAST)
        result = PAYPAL_MONITOR.analyze(cert)
        s = result.summary()
        count = len(result.findings)
        assert str(count) in s

    def test_summary_includes_high_severity_label(self):
        cert = clean_cert(is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "HIGH" in result.summary()

    def test_summary_includes_medium_severity_label(self):
        cert = clean_cert(not_after=PAST)
        result = PAYPAL_MONITOR.analyze(cert)
        assert "MEDIUM" in result.summary()

    def test_summary_returns_string(self):
        cert = clean_cert()
        result = PAYPAL_MONITOR.analyze(cert)
        assert isinstance(result.summary(), str)


# ===========================================================================
# 13. analyze_many()
# ===========================================================================


class TestAnalyzeMany:
    def test_returns_list_of_results(self):
        certs = [clean_cert(), clean_cert(is_self_signed=True)]
        results = PAYPAL_MONITOR.analyze_many(certs)
        assert isinstance(results, list)
        assert len(results) == 2

    def test_each_result_is_cert_abuse_result(self):
        certs = [clean_cert() for _ in range(5)]
        results = PAYPAL_MONITOR.analyze_many(certs)
        for r in results:
            assert isinstance(r, CertAbuseResult)

    def test_analyze_many_empty_list(self):
        results = PAYPAL_MONITOR.analyze_many([])
        assert results == []

    def test_analyze_many_preserves_order(self):
        cert_a = clean_cert("a.com")
        cert_b = clean_cert("b.com", is_self_signed=True)
        results = PAYPAL_MONITOR.analyze_many([cert_a, cert_b])
        assert results[0].risk_score == 0
        assert "CERT-ABU-006" in finding_ids(results[1])

    def test_analyze_many_single_cert(self):
        results = PAYPAL_MONITOR.analyze_many([clean_cert(is_self_signed=True)])
        assert len(results) == 1
        assert "CERT-ABU-006" in finding_ids(results[0])


# ===========================================================================
# 14. to_dict() serialisation
# ===========================================================================


class TestToDict:
    def test_certificate_info_to_dict_keys(self):
        cert = clean_cert()
        d = cert.to_dict()
        for key in (
            "common_name", "subject_alt_names", "issuer_name",
            "is_self_signed", "not_before", "not_after",
            "serial_number", "signature_algorithm", "key_size_bits",
        ):
            assert key in d

    def test_certificate_info_to_dict_values(self):
        cert = clean_cert("test.com", ["www.test.com"], "DigiCert")
        d = cert.to_dict()
        assert d["common_name"] == "test.com"
        assert d["subject_alt_names"] == ["www.test.com"]
        assert d["issuer_name"] == "DigiCert"

    def test_cert_abuse_finding_to_dict_keys(self):
        finding = CertAbuseFinding(
            check_id="CERT-ABU-006",
            severity="HIGH",
            common_name="evil.com",
            issuer_name="Self",
            message="Self-signed",
            recommendation="Block it",
        )
        d = finding.to_dict()
        for key in ("check_id", "severity", "common_name", "issuer_name", "message", "recommendation"):
            assert key in d

    def test_cert_abuse_result_to_dict_keys(self):
        cert = clean_cert(is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        d = result.to_dict()
        for key in ("findings", "risk_score", "summary", "by_severity"):
            assert key in d

    def test_cert_abuse_result_to_dict_findings_list(self):
        cert = clean_cert(is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        d = result.to_dict()
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) >= 1

    def test_cert_abuse_result_to_dict_by_severity_structure(self):
        cert = clean_cert()
        result = PAYPAL_MONITOR.analyze(cert)
        d = result.to_dict()
        for sev in ("HIGH", "MEDIUM", "LOW"):
            assert sev in d["by_severity"]

    def test_to_dict_risk_score_type(self):
        cert = clean_cert()
        result = PAYPAL_MONITOR.analyze(cert)
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)

    def test_to_dict_clean_cert_empty_findings(self):
        cert = clean_cert()
        result = PAYPAL_MONITOR.analyze(cert)
        d = result.to_dict()
        assert d["findings"] == []
        assert d["risk_score"] == 0

    def test_finding_to_dict_values(self):
        cert = clean_cert(is_self_signed=True)
        result = PAYPAL_MONITOR.analyze(cert)
        hit = next(f for f in result.findings if f.check_id == "CERT-ABU-006")
        d = hit.to_dict()
        assert d["check_id"] == "CERT-ABU-006"
        assert d["severity"] == "HIGH"


# ===========================================================================
# 15. Multi-brand keyword monitors
# ===========================================================================


class TestMultiBrandKeywords:
    def test_paypal_keyword_fires_on_paypal_domain(self):
        cert = clean_cert("paypal-login.com")
        result = MULTI_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_google_keyword_fires_on_google_domain(self):
        cert = clean_cert("google-login.com")
        result = MULTI_MONITOR.analyze(cert)
        assert "CERT-ABU-001" in finding_ids(result)

    def test_neither_keyword_does_not_trigger_001(self):
        cert = clean_cert("legitimate-service.com")
        result = MULTI_MONITOR.analyze(cert)
        assert "CERT-ABU-001" not in finding_ids(result)

    def test_multi_keyword_wildcard_paypal(self):
        cert = clean_cert("*.paypal-accounts.com", ["*.paypal-accounts.com"])
        result = MULTI_MONITOR.analyze(cert)
        assert "CERT-ABU-002" in finding_ids(result)

    def test_multi_keyword_wildcard_google(self):
        cert = clean_cert("*.google-signin.com", ["*.google-signin.com"])
        result = MULTI_MONITOR.analyze(cert)
        assert "CERT-ABU-002" in finding_ids(result)

    def test_monitor_stores_normalised_keywords(self):
        monitor = CertificateAbuseMonitor(brand_keywords=["PayPal", "Google"])
        # Internal list should be lower-cased
        assert "paypal" in monitor._brand_keywords
        assert "google" in monitor._brand_keywords


# ===========================================================================
# 16. Constants and module-level checks
# ===========================================================================


class TestModuleConstants:
    def test_check_weights_has_all_ids(self):
        for cid in (
            "CERT-ABU-001", "CERT-ABU-002", "CERT-ABU-003",
            "CERT-ABU-004", "CERT-ABU-005", "CERT-ABU-006", "CERT-ABU-007",
        ):
            assert cid in _CHECK_WEIGHTS

    def test_default_trusted_cas_not_empty(self):
        assert len(_DEFAULT_TRUSTED_CAS) > 0

    def test_lets_encrypt_in_default_trusted_cas(self):
        assert any("Let's Encrypt" in ca for ca in _DEFAULT_TRUSTED_CAS)

    def test_digicert_in_default_trusted_cas(self):
        assert any("DigiCert" in ca for ca in _DEFAULT_TRUSTED_CAS)

    def test_check_weights_values_are_positive_ints(self):
        for cid, w in _CHECK_WEIGHTS.items():
            assert isinstance(w, int), f"{cid} weight not int"
            assert w > 0, f"{cid} weight not positive"
