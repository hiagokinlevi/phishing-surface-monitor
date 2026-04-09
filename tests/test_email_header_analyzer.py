"""
Tests for analyzers.email_header_analyzer
==========================================
Covers all eight checks (EH-001 … EH-008), edge cases, data-model helpers,
serialisation, and aggregate risk-score behaviour.

Run with::

    pytest tests/test_email_header_analyzer.py -v
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

import pytest

from analyzers.email_header_analyzer import (
    EHFinding,
    EHReport,
    EHSeverity,
    EmailHeaderAnalyzer,
    EmailHeaders,
    _BRAND_NAMES,
    _CHECK_WEIGHTS,
    _DISPOSABLE_TLDS,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

def make_clean_headers() -> Dict[str, Any]:
    """Return a header dict that passes every check without triggering findings."""
    return {
        "From": "Alice Smith <alice@legitimate.com>",
        "Reply-To": "alice@legitimate.com",
        "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        "X-Mailer": "Thunderbird 115",
        "Received": ["hop1", "hop2", "hop3"],
    }


def analyzer() -> EmailHeaderAnalyzer:
    """Return a default analyzer instance."""
    return EmailHeaderAnalyzer()


# ===========================================================================
# EmailHeaders — accessor tests
# ===========================================================================

class TestEmailHeaders:
    """Unit tests for the EmailHeaders container."""

    def test_get_returns_string_value(self) -> None:
        eh = EmailHeaders(headers={"From": "user@example.com"})
        assert eh.get("From") == "user@example.com"

    def test_get_case_insensitive_uppercase_key(self) -> None:
        eh = EmailHeaders(headers={"from": "user@example.com"})
        assert eh.get("FROM") == "user@example.com"

    def test_get_case_insensitive_mixed_key(self) -> None:
        eh = EmailHeaders(headers={"Authentication-Results": "spf=pass"})
        assert eh.get("authentication-results") == "spf=pass"
        assert eh.get("AUTHENTICATION-RESULTS") == "spf=pass"

    def test_get_returns_first_element_of_list(self) -> None:
        eh = EmailHeaders(headers={"Received": ["hop1", "hop2", "hop3"]})
        assert eh.get("Received") == "hop1"

    def test_get_returns_none_for_absent_header(self) -> None:
        eh = EmailHeaders(headers={})
        assert eh.get("X-Missing") is None

    def test_get_empty_list_returns_none(self) -> None:
        eh = EmailHeaders(headers={"Received": []})
        assert eh.get("Received") is None

    def test_get_all_returns_list_for_list_value(self) -> None:
        eh = EmailHeaders(headers={"Received": ["h1", "h2", "h3"]})
        assert eh.get_all("Received") == ["h1", "h2", "h3"]

    def test_get_all_wraps_string_in_list(self) -> None:
        eh = EmailHeaders(headers={"From": "a@b.com"})
        assert eh.get_all("From") == ["a@b.com"]

    def test_get_all_returns_empty_list_when_absent(self) -> None:
        eh = EmailHeaders(headers={})
        assert eh.get_all("X-Missing") == []

    def test_get_all_case_insensitive(self) -> None:
        eh = EmailHeaders(headers={"received": ["h1", "h2"]})
        assert eh.get_all("Received") == ["h1", "h2"]


# ===========================================================================
# EHFinding — data model tests
# ===========================================================================

class TestEHFinding:
    """Unit tests for EHFinding serialisation helpers."""

    def _sample(self) -> EHFinding:
        return EHFinding(
            check_id="EH-001",
            severity=EHSeverity.HIGH,
            title="SPF authentication fail",
            detail="SPF result is 'fail'.",
            evidence="spf=fail",
            remediation="Publish correct SPF record.",
        )

    def test_to_dict_keys(self) -> None:
        d = self._sample().to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "title", "detail", "evidence", "remediation"
        }

    def test_to_dict_severity_is_string(self) -> None:
        d = self._sample().to_dict()
        assert d["severity"] == "HIGH"

    def test_to_dict_check_id(self) -> None:
        d = self._sample().to_dict()
        assert d["check_id"] == "EH-001"

    def test_summary_contains_check_id(self) -> None:
        assert "EH-001" in self._sample().summary()

    def test_summary_contains_severity(self) -> None:
        assert "HIGH" in self._sample().summary()

    def test_summary_contains_title(self) -> None:
        assert "SPF authentication fail" in self._sample().summary()

    def test_default_evidence_and_remediation_are_empty_strings(self) -> None:
        f = EHFinding(
            check_id="EH-007",
            severity=EHSeverity.LOW,
            title="Hops",
            detail="Too many hops.",
        )
        assert f.evidence == ""
        assert f.remediation == ""


# ===========================================================================
# EHReport — data model tests
# ===========================================================================

class TestEHReport:
    """Unit tests for EHReport aggregation helpers."""

    def _make_report(self, findings: List[EHFinding]) -> EHReport:
        return EHReport(
            findings=findings,
            risk_score=50,
            headers_analyzed=5,
            generated_at=time.time(),
        )

    def test_total_findings(self) -> None:
        f1 = EHFinding("EH-001", EHSeverity.HIGH, "T", "D")
        f2 = EHFinding("EH-002", EHSeverity.MEDIUM, "T", "D")
        report = self._make_report([f1, f2])
        assert report.total_findings == 2

    def test_critical_findings_count(self) -> None:
        findings = [
            EHFinding("EH-005", EHSeverity.CRITICAL, "T", "D"),
            EHFinding("EH-001", EHSeverity.HIGH, "T", "D"),
        ]
        report = self._make_report(findings)
        assert report.critical_findings == 1

    def test_high_findings_count(self) -> None:
        findings = [
            EHFinding("EH-004", EHSeverity.HIGH, "T", "D"),
            EHFinding("EH-001", EHSeverity.HIGH, "T", "D"),
            EHFinding("EH-005", EHSeverity.CRITICAL, "T", "D"),
        ]
        report = self._make_report(findings)
        assert report.high_findings == 2

    def test_findings_by_check_grouping(self) -> None:
        findings = [
            EHFinding("EH-001", EHSeverity.HIGH, "T", "D"),
            EHFinding("EH-001", EHSeverity.HIGH, "T", "D"),
            EHFinding("EH-002", EHSeverity.MEDIUM, "T", "D"),
        ]
        report = self._make_report(findings)
        grouped = report.findings_by_check()
        assert len(grouped["EH-001"]) == 2
        assert len(grouped["EH-002"]) == 1

    def test_to_dict_structure(self) -> None:
        report = self._make_report([])
        d = report.to_dict()
        expected_keys = {
            "risk_score", "headers_analyzed", "generated_at",
            "total_findings", "critical_findings", "high_findings", "findings",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_findings_is_list_of_dicts(self) -> None:
        f = EHFinding("EH-001", EHSeverity.HIGH, "T", "D")
        report = self._make_report([f])
        d = report.to_dict()
        assert isinstance(d["findings"], list)
        assert isinstance(d["findings"][0], dict)

    def test_summary_contains_risk_score(self) -> None:
        report = self._make_report([])
        assert "50" in report.summary()

    def test_empty_report_zero_counts(self) -> None:
        report = self._make_report([])
        assert report.total_findings == 0
        assert report.critical_findings == 0
        assert report.high_findings == 0


# ===========================================================================
# Clean headers — expect zero findings
# ===========================================================================

class TestCleanHeaders:
    """All checks should pass (no findings) for a well-configured email."""

    def test_clean_headers_produce_no_findings(self) -> None:
        eh = EmailHeaders(headers=make_clean_headers())
        report = analyzer().analyze(eh)
        assert report.total_findings == 0

    def test_clean_headers_risk_score_is_zero(self) -> None:
        eh = EmailHeaders(headers=make_clean_headers())
        report = analyzer().analyze(eh)
        assert report.risk_score == 0

    def test_headers_analyzed_count_matches_dict(self) -> None:
        raw = make_clean_headers()
        eh = EmailHeaders(headers=raw)
        report = analyzer().analyze(eh)
        assert report.headers_analyzed == len(raw)


# ===========================================================================
# EH-001 — SPF
# ===========================================================================

class TestEH001SPF:
    """Tests for the SPF authentication check."""

    def test_spf_fail_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=fail; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-001" in ids

    def test_spf_softfail_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=softfail; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-001" in ids

    def test_spf_none_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=none; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-001" in ids

    def test_spf_pass_does_not_fire(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-001" not in ids

    def test_missing_auth_header_fires_eh001(self) -> None:
        eh = EmailHeaders(headers={"From": "a@example.com"})
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-001" in ids

    def test_spf_fail_severity_is_high(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=fail; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        spf_findings = [f for f in report.findings if f.check_id == "EH-001"]
        assert any(f.severity == EHSeverity.HIGH for f in spf_findings)


# ===========================================================================
# EH-002 — DKIM
# ===========================================================================

class TestEH002DKIM:
    """Tests for the DKIM authentication check."""

    def test_dkim_fail_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=fail; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-002" in ids

    def test_dkim_none_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=none; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-002" in ids

    def test_dkim_pass_does_not_fire(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-002" not in ids

    def test_missing_auth_header_fires_eh002(self) -> None:
        eh = EmailHeaders(headers={"From": "a@example.com"})
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-002" in ids

    def test_dkim_fail_severity_is_high(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=fail; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        dkim_findings = [f for f in report.findings if f.check_id == "EH-002"]
        assert any(f.severity == EHSeverity.HIGH for f in dkim_findings)


# ===========================================================================
# EH-003 — DMARC
# ===========================================================================

class TestEH003DMARC:
    """Tests for the DMARC authentication check."""

    def test_dmarc_fail_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=fail",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-003" in ids

    def test_dmarc_none_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=none",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-003" in ids

    def test_dmarc_pass_does_not_fire(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-003" not in ids

    def test_missing_auth_header_fires_eh003(self) -> None:
        eh = EmailHeaders(headers={"From": "a@example.com"})
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-003" in ids

    def test_dmarc_fail_severity_is_high(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=fail",
        })
        report = analyzer().analyze(eh)
        dmarc_findings = [f for f in report.findings if f.check_id == "EH-003"]
        assert any(f.severity == EHSeverity.HIGH for f in dmarc_findings)


# ===========================================================================
# EH-004 — From / Reply-To mismatch
# ===========================================================================

class TestEH004ReplyToMismatch:
    """Tests for the From / Reply-To domain mismatch check."""

    def test_mismatch_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "support@legitimate.com",
            "Reply-To": "evil@attacker.ru",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-004" in ids

    def test_matching_domains_do_not_fire(self) -> None:
        eh = EmailHeaders(headers={
            "From": "support@legitimate.com",
            "Reply-To": "noreply@legitimate.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-004" not in ids

    def test_no_reply_to_does_not_fire(self) -> None:
        eh = EmailHeaders(headers={
            "From": "support@legitimate.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-004" not in ids

    def test_mismatch_severity_is_high(self) -> None:
        eh = EmailHeaders(headers={
            "From": "support@legitimate.com",
            "Reply-To": "evil@attacker.ru",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        mismatch = [f for f in report.findings if f.check_id == "EH-004"]
        assert mismatch[0].severity == EHSeverity.HIGH

    def test_display_name_in_from_extracted_correctly(self) -> None:
        """Angle-bracket From should still be compared by domain."""
        eh = EmailHeaders(headers={
            "From": "Legit Corp <info@legit.com>",
            "Reply-To": "info@attacker.net",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-004" in ids


# ===========================================================================
# EH-005 — Brand display name impersonation
# ===========================================================================

class TestEH005BrandDisplayName:
    """Tests for the brand-name lookalike display-name check."""

    def test_paypal_in_display_name_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "PayPal Security <security@paypa1.com>",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-005" in ids

    def test_microsoft_in_display_name_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "Microsoft Account Team <noreply@micros0ft.xyz>",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-005" in ids

    def test_no_brand_in_display_name_does_not_fire(self) -> None:
        eh = EmailHeaders(headers={
            "From": "Alice Smith <alice@example.com>",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-005" not in ids

    def test_brand_impersonation_severity_is_critical(self) -> None:
        eh = EmailHeaders(headers={
            "From": "Apple Support <noreply@app1e.com>",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        brand_findings = [f for f in report.findings if f.check_id == "EH-005"]
        assert brand_findings[0].severity == EHSeverity.CRITICAL

    def test_irs_brand_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "IRS Refund Department <refund@irs-gov.tk>",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-005" in ids

    def test_custom_brands_override_default(self) -> None:
        custom_analyzer = EmailHeaderAnalyzer(known_brands=["acme"])
        eh = EmailHeaders(headers={
            "From": "ACME Corp <info@acme-phish.com>",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = custom_analyzer.analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-005" in ids

    def test_custom_brands_do_not_match_default(self) -> None:
        """With custom brands list, default brands should NOT trigger EH-005."""
        custom_analyzer = EmailHeaderAnalyzer(known_brands=["acme"])
        eh = EmailHeaders(headers={
            "From": "PayPal Security <security@paypa1.com>",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = custom_analyzer.analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-005" not in ids


# ===========================================================================
# EH-006 — Suspicious X-Mailer / User-Agent
# ===========================================================================

class TestEH006SuspiciousMailer:
    """Tests for the suspicious mailer header check."""

    def test_phpmailer_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "X-Mailer": "PHPMailer 6.6",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-006" in ids

    def test_emkei_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "X-Mailer": "Emkei's Fake Mailer",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-006" in ids

    def test_user_agent_pepipost_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "User-Agent": "pepipost/2.0",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-006" in ids

    def test_legitimate_mailer_does_not_fire(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "X-Mailer": "Thunderbird 115",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-006" not in ids

    def test_suspicious_mailer_severity_is_medium(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "X-Mailer": "SendBlaster 3",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        mailer_findings = [f for f in report.findings if f.check_id == "EH-006"]
        assert mailer_findings[0].severity == EHSeverity.MEDIUM

    def test_no_mailer_header_does_not_fire(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-006" not in ids

    def test_case_insensitive_pattern_match(self) -> None:
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "X-Mailer": "MASSMAILER v9",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-006" in ids


# ===========================================================================
# EH-007 — Hop count
# ===========================================================================

class TestEH007HopCount:
    """Tests for the excessive hop count check."""

    def test_exactly_max_hops_does_not_fire(self) -> None:
        hops = [f"hop{i}" for i in range(10)]
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
            "Received": hops,
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-007" not in ids

    def test_one_over_max_hops_fires(self) -> None:
        hops = [f"hop{i}" for i in range(11)]
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
            "Received": hops,
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-007" in ids

    def test_custom_max_hops_respected(self) -> None:
        strict_analyzer = EmailHeaderAnalyzer(max_hops=3)
        hops = ["h1", "h2", "h3", "h4"]  # 4 hops > threshold of 3
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
            "Received": hops,
        })
        report = strict_analyzer.analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-007" in ids

    def test_three_hops_below_threshold_do_not_fire(self) -> None:
        hops = ["h1", "h2", "h3"]
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
            "Received": hops,
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-007" not in ids

    def test_hop_count_severity_is_low(self) -> None:
        hops = [f"hop{i}" for i in range(15)]
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
            "Received": hops,
        })
        report = analyzer().analyze(eh)
        hop_findings = [f for f in report.findings if f.check_id == "EH-007"]
        assert hop_findings[0].severity == EHSeverity.LOW


# ===========================================================================
# EH-008 — Disposable TLD
# ===========================================================================

class TestEH008DisposableTLD:
    """Tests for the disposable / high-risk TLD check."""

    def test_dot_tk_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "admin@phishing.tk",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-008" in ids

    def test_dot_xyz_fires(self) -> None:
        eh = EmailHeaders(headers={
            "From": "Free Gift <prizes@winner.xyz>",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-008" in ids

    def test_dot_com_does_not_fire(self) -> None:
        eh = EmailHeaders(headers={
            "From": "alice@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-008" not in ids

    def test_dot_org_does_not_fire(self) -> None:
        eh = EmailHeaders(headers={
            "From": "news@nonprofit.org",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-008" not in ids

    def test_disposable_tld_severity_is_medium(self) -> None:
        eh = EmailHeaders(headers={
            "From": "offer@deals.click",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        tld_findings = [f for f in report.findings if f.check_id == "EH-008"]
        assert tld_findings[0].severity == EHSeverity.MEDIUM

    def test_all_disposable_tlds_covered(self) -> None:
        """Every TLD in _DISPOSABLE_TLDS should trigger EH-008."""
        for tld in _DISPOSABLE_TLDS:
            eh = EmailHeaders(headers={
                "From": f"test@phish{tld}",
                "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
            })
            report = analyzer().analyze(eh)
            ids = [f.check_id for f in report.findings]
            assert "EH-008" in ids, f"EH-008 did not fire for TLD: {tld}"


# ===========================================================================
# Risk score tests
# ===========================================================================

class TestRiskScore:
    """Tests for correct risk score calculation."""

    def test_single_check_weight(self) -> None:
        """Only EH-007 fires — risk score should equal its weight (15)."""
        hops = [f"hop{i}" for i in range(11)]
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
            "Received": hops,
        })
        report = analyzer().analyze(eh)
        # EH-007 has weight 15
        assert report.risk_score == _CHECK_WEIGHTS["EH-007"]

    def test_risk_score_capped_at_100(self) -> None:
        """Firing all high-weight checks (EH-001+EH-002+EH-003+EH-004+EH-005)
        would sum to 35+30+35+30+40=170, which must be capped at 100."""
        eh = EmailHeaders(headers={
            # EH-005 — brand display name (CRITICAL)
            "From": "PayPal Security <security@paypa1.tk>",
            # EH-004 — reply-to mismatch
            "Reply-To": "hacker@evil.ru",
            # EH-001 + EH-002 + EH-003 all fail
            "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
        })
        report = analyzer().analyze(eh)
        assert report.risk_score <= 100
        assert report.risk_score == 100

    def test_risk_score_zero_for_clean_headers(self) -> None:
        eh = EmailHeaders(headers=make_clean_headers())
        report = analyzer().analyze(eh)
        assert report.risk_score == 0

    def test_duplicate_check_id_counted_once_in_score(self) -> None:
        """Even if a check fires twice (shouldn't happen in current design),
        the weight should only be added once."""
        # Simulate by checking that findings_by_check deduplicates in score calc
        # We can verify by asserting score == weight for one unique check.
        hops = [f"hop{i}" for i in range(11)]
        eh = EmailHeaders(headers={
            "From": "a@example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
            "Received": hops,
        })
        report = analyzer().analyze(eh)
        # Only EH-007 should fire (weight=15), score must be exactly 15
        fired = {f.check_id for f in report.findings}
        expected_score = sum(_CHECK_WEIGHTS[cid] for cid in fired)
        assert report.risk_score == min(expected_score, 100)


# ===========================================================================
# Domain extraction helper (indirect via checks)
# ===========================================================================

class TestDomainExtraction:
    """Indirectly tests _extract_domain via EH-004 and EH-008."""

    def test_angle_bracket_address_domain_extracted(self) -> None:
        eh = EmailHeaders(headers={
            "From": "Display Name <user@domain.example.com>",
            "Reply-To": "user@other.example.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        # Different second-level domains → EH-004 should fire
        ids = [f.check_id for f in report.findings]
        assert "EH-004" in ids

    def test_bare_address_domain_extracted(self) -> None:
        eh = EmailHeaders(headers={
            "From": "user@legit.com",
            "Reply-To": "user@attacker.com",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        report = analyzer().analyze(eh)
        ids = [f.check_id for f in report.findings]
        assert "EH-004" in ids

    def test_no_at_sign_does_not_crash(self) -> None:
        eh = EmailHeaders(headers={
            "From": "not-an-email",
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        })
        # Should not raise; EH-008 and EH-004 simply produce no finding
        report = analyzer().analyze(eh)
        assert report is not None


# ===========================================================================
# Multi-check combined scenario
# ===========================================================================

class TestCombinedScenario:
    """Integration-style tests covering realistic phishing email combos."""

    def test_highly_suspicious_email_fires_multiple_checks(self) -> None:
        eh = EmailHeaders(headers={
            "From": "Netflix Billing <billing@netf1ix.tk>",
            "Reply-To": "collect@harvester.ru",
            "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
            "X-Mailer": "PHPMailer 5.2.1",
            "Received": [f"hop{i}" for i in range(12)],
        })
        report = analyzer().analyze(eh)
        fired = {f.check_id for f in report.findings}
        # All eight checks should fire
        assert "EH-001" in fired
        assert "EH-002" in fired
        assert "EH-003" in fired
        assert "EH-004" in fired
        assert "EH-005" in fired
        assert "EH-006" in fired
        assert "EH-007" in fired
        assert "EH-008" in fired

    def test_combined_score_is_capped(self) -> None:
        eh = EmailHeaders(headers={
            "From": "Netflix Billing <billing@netf1ix.tk>",
            "Reply-To": "collect@harvester.ru",
            "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
            "X-Mailer": "PHPMailer 5.2.1",
            "Received": [f"hop{i}" for i in range(12)],
        })
        report = analyzer().analyze(eh)
        assert report.risk_score == 100

    def test_report_generated_at_is_recent(self) -> None:
        before = time.time()
        eh = EmailHeaders(headers=make_clean_headers())
        report = analyzer().analyze(eh)
        after = time.time()
        assert before <= report.generated_at <= after
