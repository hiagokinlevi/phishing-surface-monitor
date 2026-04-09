# test_subdomain_takeover_detector.py
# Comprehensive test suite for SubdomainTakeoverDetector.
#
# Copyright (c) 2026 Cyber Port
# Licensed under Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# SPDX-License-Identifier: CC-BY-4.0

from __future__ import annotations

import sys
import os

# Ensure the monitors package is importable regardless of working directory.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from monitors.subdomain_takeover_detector import (
    SubdomainRecord,
    TakeoverFinding,
    TakeoverScanResult,
    SubdomainTakeoverDetector,
    _VULNERABLE_SERVICES,
    _CHECK_WEIGHTS,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def detector() -> SubdomainTakeoverDetector:
    return SubdomainTakeoverDetector()


def make_record(
    subdomain: str = "sub.example.com",
    record_type: str = "A",
    value: str = "1.2.3.4",
    ttl: int = 300,
    has_response: bool = True,
) -> SubdomainRecord:
    return SubdomainRecord(
        subdomain=subdomain,
        record_type=record_type,
        value=value,
        ttl=ttl,
        has_response=has_response,
    )


def ids_in(findings, check_id: str) -> bool:
    """True if any finding has the given check_id."""
    return any(f.check_id == check_id for f in findings)


def only_ids(findings, *check_ids) -> bool:
    """True if the only check_ids present are those given."""
    return {f.check_id for f in findings} == set(check_ids)


# ===========================================================================
# 1. Empty record list
# ===========================================================================

class TestEmptyInput:
    def test_empty_records_returns_no_findings(self, detector):
        result = detector.scan([])
        assert result.findings == []

    def test_empty_records_risk_score_zero(self, detector):
        result = detector.scan([])
        assert result.risk_score == 0

    def test_empty_records_summary_mentions_zero(self, detector):
        result = detector.scan([])
        assert "0" in result.summary()

    def test_empty_records_by_severity_empty(self, detector):
        result = detector.scan([])
        assert result.by_severity() == {}

    def test_empty_records_to_dict_structure(self, detector):
        result = detector.scan([])
        d = result.to_dict()
        assert d["findings"] == []
        assert d["risk_score"] == 0


# ===========================================================================
# 2. STKO-001 — Dangling CNAME to vulnerable service
# ===========================================================================

class TestSTKO001:
    def test_cname_github_io_no_response_triggers_001(self, detector):
        rec = make_record("x.example.com", "CNAME", "myorg.github.io", has_response=False)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-001")

    def test_cname_github_io_with_response_does_not_trigger_001(self, detector):
        rec = make_record("x.example.com", "CNAME", "myorg.github.io", has_response=True)
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-001")

    def test_cname_github_io_with_response_triggers_002(self, detector):
        rec = make_record("x.example.com", "CNAME", "myorg.github.io", has_response=True)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-002")

    def test_cname_safe_domain_no_response_no_001(self, detector):
        rec = make_record("x.example.com", "CNAME", "safe.example.net", has_response=False)
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-001")

    def test_001_severity_is_critical(self, detector):
        rec = make_record("x.example.com", "CNAME", "myorg.github.io", has_response=False)
        result = detector.scan([rec])
        findings = [f for f in result.findings if f.check_id == "STKO-001"]
        assert all(f.severity == "CRITICAL" for f in findings)

    def test_001_service_name_populated(self, detector):
        rec = make_record("x.example.com", "CNAME", "myorg.github.io", has_response=False)
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-001")
        assert f.service_name == "GitHub Pages"

    def test_001_cname_target_populated(self, detector):
        rec = make_record("x.example.com", "CNAME", "myorg.github.io", has_response=False)
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-001")
        assert f.cname_target == "myorg.github.io"

    def test_001_subdomain_populated(self, detector):
        rec = make_record("x.example.com", "CNAME", "myorg.github.io", has_response=False)
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-001")
        assert f.subdomain == "x.example.com"

    def test_001_risk_score_at_least_45(self, detector):
        rec = make_record("x.example.com", "CNAME", "myorg.github.io", has_response=False)
        result = detector.scan([rec])
        assert result.risk_score >= 45

    def test_001_a_record_not_triggered(self, detector):
        rec = make_record("x.example.com", "A", "1.2.3.4", has_response=False)
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-001")

    def test_cname_s3_amazonaws_no_response(self, detector):
        rec = make_record("assets.example.com", "CNAME", "mybucket.s3.amazonaws.com", has_response=False)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-001")
        f = next(f for f in result.findings if f.check_id == "STKO-001")
        assert f.service_name == "AWS S3"

    def test_cname_heroku_no_response(self, detector):
        rec = make_record("app.example.com", "CNAME", "myapp.heroku.com", has_response=False)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-001")
        f = next(f for f in result.findings if f.check_id == "STKO-001")
        assert f.service_name == "Heroku"

    def test_cname_herokuapp_no_response(self, detector):
        rec = make_record("app.example.com", "CNAME", "myapp.herokuapp.com", has_response=False)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-001")
        f = next(f for f in result.findings if f.check_id == "STKO-001")
        assert f.service_name == "Heroku"

    def test_001_one_finding_per_subdomain(self, detector):
        rec = make_record("x.example.com", "CNAME", "myorg.github.io", has_response=False)
        result = detector.scan([rec])
        count_001 = sum(1 for f in result.findings if f.check_id == "STKO-001")
        assert count_001 == 1


# ===========================================================================
# 3. STKO-002 — Responding CNAME to vulnerable service
# ===========================================================================

class TestSTKO002:
    def test_cname_heroku_with_response_triggers_002(self, detector):
        rec = make_record("app.example.com", "CNAME", "myapp.heroku.com", has_response=True)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-002")

    def test_cname_heroku_no_response_triggers_001_not_002(self, detector):
        rec = make_record("app.example.com", "CNAME", "myapp.heroku.com", has_response=False)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-001")
        assert not ids_in(result.findings, "STKO-002")

    def test_002_severity_is_high(self, detector):
        rec = make_record("app.example.com", "CNAME", "myapp.heroku.com", has_response=True)
        result = detector.scan([rec])
        findings = [f for f in result.findings if f.check_id == "STKO-002"]
        assert all(f.severity == "HIGH" for f in findings)

    def test_002_service_name_populated(self, detector):
        rec = make_record("app.example.com", "CNAME", "myapp.heroku.com", has_response=True)
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-002")
        assert f.service_name == "Heroku"

    def test_002_cname_target_populated(self, detector):
        rec = make_record("app.example.com", "CNAME", "myapp.heroku.com", has_response=True)
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-002")
        assert f.cname_target == "myapp.heroku.com"

    def test_002_safe_domain_does_not_trigger(self, detector):
        rec = make_record("app.example.com", "CNAME", "safe.example.net", has_response=True)
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-002")

    def test_002_netlify_app_with_response(self, detector):
        rec = make_record("site.example.com", "CNAME", "mysite.netlify.app", has_response=True)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-002")
        f = next(f for f in result.findings if f.check_id == "STKO-002")
        assert f.service_name == "Netlify"


# ===========================================================================
# 4. STKO-003 — Dangling NS delegation
# ===========================================================================

class TestSTKO003:
    def test_ns_no_response_triggers_003(self, detector):
        rec = make_record("zone.example.com", "NS", "ns1.orphaned.net", has_response=False)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-003")

    def test_ns_with_response_does_not_trigger_003(self, detector):
        rec = make_record("zone.example.com", "NS", "ns1.active.net", has_response=True)
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-003")

    def test_003_severity_is_high(self, detector):
        rec = make_record("zone.example.com", "NS", "ns1.orphaned.net", has_response=False)
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-003")
        assert f.severity == "HIGH"

    def test_003_subdomain_populated(self, detector):
        rec = make_record("zone.example.com", "NS", "ns1.orphaned.net", has_response=False)
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-003")
        assert f.subdomain == "zone.example.com"

    def test_003_cname_target_none(self, detector):
        rec = make_record("zone.example.com", "NS", "ns1.orphaned.net", has_response=False)
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-003")
        assert f.cname_target is None

    def test_003_a_record_does_not_trigger(self, detector):
        rec = make_record("zone.example.com", "A", "1.2.3.4", has_response=False)
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-003")


# ===========================================================================
# 5. STKO-004 — Dangling A/AAAA record
# ===========================================================================

class TestSTKO004:
    def test_a_record_no_response_triggers_004(self, detector):
        rec = make_record("stale.example.com", "A", "203.0.113.10", has_response=False)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-004")

    def test_a_record_with_response_does_not_trigger_004(self, detector):
        rec = make_record("stale.example.com", "A", "203.0.113.10", has_response=True)
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-004")

    def test_aaaa_record_no_response_triggers_004(self, detector):
        rec = make_record("stale.example.com", "AAAA", "2001:db8::1", has_response=False)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-004")

    def test_aaaa_record_with_response_no_004(self, detector):
        rec = make_record("stale.example.com", "AAAA", "2001:db8::1", has_response=True)
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-004")

    def test_004_severity_is_high(self, detector):
        rec = make_record("stale.example.com", "A", "203.0.113.10", has_response=False)
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-004")
        assert f.severity == "HIGH"

    def test_004_cname_record_does_not_trigger(self, detector):
        rec = make_record("stale.example.com", "CNAME", "safe.example.net", has_response=False)
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-004")

    def test_004_ns_record_does_not_trigger(self, detector):
        rec = make_record("stale.example.com", "NS", "ns1.example.net", has_response=True)
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-004")


# ===========================================================================
# 6. STKO-005 — Deep CNAME chain
# ===========================================================================

class TestSTKO005:
    def _chain(self, *hops: str, respond: bool = True) -> list:
        """Build CNAME records forming a chain: hops[0] → hops[1] → … → hops[-1]."""
        records = []
        for i in range(len(hops) - 1):
            records.append(make_record(hops[i], "CNAME", hops[i + 1], has_response=respond))
        return records

    def test_chain_of_3_triggers_005(self, detector):
        # a → b → c  (3 nodes = chain length 2 hops, but len(chain) == 3 >= 3)
        records = self._chain("a.example.com", "b.example.com", "c.example.com")
        result = detector.scan(records)
        assert ids_in(result.findings, "STKO-005")

    def test_chain_of_2_does_not_trigger_005(self, detector):
        # a → b  (2 nodes = chain length 1 hop)
        records = self._chain("a.example.com", "b.example.com")
        result = detector.scan(records)
        assert not ids_in(result.findings, "STKO-005")

    def test_chain_of_4_triggers_005(self, detector):
        records = self._chain("a.e.com", "b.e.com", "c.e.com", "d.e.com")
        result = detector.scan(records)
        assert ids_in(result.findings, "STKO-005")

    def test_005_severity_is_medium(self, detector):
        records = self._chain("a.example.com", "b.example.com", "c.example.com")
        result = detector.scan(records)
        f = next(f for f in result.findings if f.check_id == "STKO-005")
        assert f.severity == "MEDIUM"

    def test_005_subdomain_is_chain_root(self, detector):
        records = self._chain("a.example.com", "b.example.com", "c.example.com")
        result = detector.scan(records)
        f = next(f for f in result.findings if f.check_id == "STKO-005")
        assert f.subdomain == "a.example.com"

    def test_single_cname_no_005(self, detector):
        records = [make_record("a.example.com", "CNAME", "b.example.com")]
        result = detector.scan(records)
        assert not ids_in(result.findings, "STKO-005")

    def test_no_cnames_no_005(self, detector):
        records = [make_record("a.example.com", "A", "1.2.3.4")]
        result = detector.scan(records)
        assert not ids_in(result.findings, "STKO-005")

    def test_empty_no_005(self, detector):
        result = detector.scan([])
        assert not ids_in(result.findings, "STKO-005")


# ===========================================================================
# 7. STKO-006 — Cloud provider ephemeral IP
# ===========================================================================

class TestSTKO006:
    def test_aws_52_triggers_006(self, detector):
        rec = make_record("host.example.com", "A", "52.10.20.30")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-006")

    def test_aws_54_triggers_006(self, detector):
        rec = make_record("host.example.com", "A", "54.200.1.1")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-006")

    def test_aws_3_triggers_006(self, detector):
        rec = make_record("host.example.com", "A", "3.8.100.5")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-006")

    def test_azure_104_triggers_006(self, detector):
        rec = make_record("host.example.com", "A", "104.40.50.60")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-006")

    def test_azure_40_triggers_006(self, detector):
        rec = make_record("host.example.com", "A", "40.80.10.20")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-006")

    def test_azure_20_triggers_006(self, detector):
        rec = make_record("host.example.com", "A", "20.100.200.50")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-006")

    def test_gcp_34_triggers_006(self, detector):
        rec = make_record("host.example.com", "A", "34.90.1.5")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-006")

    def test_gcp_35_triggers_006(self, detector):
        rec = make_record("host.example.com", "A", "35.200.50.1")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-006")

    def test_safe_ip_does_not_trigger_006(self, detector):
        rec = make_record("host.example.com", "A", "1.2.3.4")
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-006")

    def test_192_168_does_not_trigger_006(self, detector):
        rec = make_record("host.example.com", "A", "192.168.1.1")
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-006")

    def test_006_severity_is_medium(self, detector):
        rec = make_record("host.example.com", "A", "52.10.20.30")
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-006")
        assert f.severity == "MEDIUM"

    def test_006_service_name_aws(self, detector):
        rec = make_record("host.example.com", "A", "52.10.20.30")
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-006")
        assert f.service_name == "AWS"

    def test_006_service_name_azure(self, detector):
        rec = make_record("host.example.com", "A", "104.40.50.60")
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-006")
        assert f.service_name == "Azure"

    def test_006_service_name_gcp(self, detector):
        rec = make_record("host.example.com", "A", "34.90.1.5")
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-006")
        assert f.service_name == "GCP"

    def test_006_cname_not_triggered(self, detector):
        rec = make_record("host.example.com", "CNAME", "52.10.20.30")
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-006")


# ===========================================================================
# 8. STKO-007 — Suspicious dev/staging subdomain
# ===========================================================================

class TestSTKO007:
    def test_dev_subdomain_netlify_app_triggers_007(self, detector):
        rec = make_record("dev.example.com", "CNAME", "dev-site.netlify.app")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-007")

    def test_dev_subdomain_safe_domain_no_007(self, detector):
        rec = make_record("dev.example.com", "CNAME", "safe.example.net")
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-007")

    def test_prod_subdomain_no_007(self, detector):
        rec = make_record("prod.example.com", "CNAME", "myapp.netlify.app")
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-007")

    def test_staging_subdomain_vercel_app_triggers_007(self, detector):
        rec = make_record("staging.example.com", "CNAME", "myapp.vercel.app")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-007")

    def test_test_subdomain_heroku_triggers_007(self, detector):
        rec = make_record("test.example.com", "CNAME", "test-app.heroku.com")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-007")

    def test_uat_subdomain_triggers_007(self, detector):
        rec = make_record("uat.example.com", "CNAME", "uat.azurewebsites.net")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-007")

    def test_demo_subdomain_triggers_007(self, detector):
        rec = make_record("demo.example.com", "CNAME", "demo.ghost.io")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-007")

    def test_beta_subdomain_triggers_007(self, detector):
        rec = make_record("beta.example.com", "CNAME", "beta.firebaseapp.com")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-007")

    def test_preview_subdomain_triggers_007(self, detector):
        rec = make_record("preview.example.com", "CNAME", "preview.netlify.com")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-007")

    def test_sandbox_subdomain_triggers_007(self, detector):
        rec = make_record("sandbox.example.com", "CNAME", "sandbox.herokuapp.com")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-007")

    def test_007_severity_is_medium(self, detector):
        rec = make_record("dev.example.com", "CNAME", "dev.netlify.app")
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-007")
        assert f.severity == "MEDIUM"

    def test_007_service_name_populated(self, detector):
        rec = make_record("dev.example.com", "CNAME", "dev.netlify.app")
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-007")
        assert f.service_name == "Netlify"

    def test_007_cname_target_populated(self, detector):
        rec = make_record("dev.example.com", "CNAME", "dev.netlify.app")
        result = detector.scan([rec])
        f = next(f for f in result.findings if f.check_id == "STKO-007")
        assert f.cname_target == "dev.netlify.app"

    def test_007_a_record_not_triggered(self, detector):
        rec = make_record("dev.example.com", "A", "52.10.20.30")
        result = detector.scan([rec])
        assert not ids_in(result.findings, "STKO-007")

    def test_keyword_in_subdomain_middle(self, detector):
        # "mydevbox.example.com" contains "dev"
        rec = make_record("mydevbox.example.com", "CNAME", "site.netlify.app")
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-007")


# ===========================================================================
# 9. Multiple findings for same subdomain
# ===========================================================================

class TestMultipleFindings:
    def test_dev_subdomain_github_no_response_fires_001_and_007(self, detector):
        # STKO-001: dangling CNAME to github.io
        # STKO-007: "dev" keyword + CNAME to vulnerable service
        rec = make_record("dev.example.com", "CNAME", "dev-site.github.io", has_response=False)
        result = detector.scan([rec])
        assert ids_in(result.findings, "STKO-001")
        assert ids_in(result.findings, "STKO-007")

    def test_two_different_bad_records_produce_multiple_findings(self, detector):
        r1 = make_record("a.example.com", "CNAME", "a.github.io", has_response=False)
        r2 = make_record("b.example.com", "NS", "ns.orphaned.net", has_response=False)
        result = detector.scan([r1, r2])
        assert ids_in(result.findings, "STKO-001")
        assert ids_in(result.findings, "STKO-003")

    def test_three_records_three_checks(self, detector):
        r1 = make_record("a.example.com", "A", "203.0.113.5", has_response=False)  # STKO-004
        r2 = make_record("b.example.com", "NS", "ns.dead.net", has_response=False)  # STKO-003
        r3 = make_record("c.example.com", "CNAME", "c.heroku.com", has_response=True)  # STKO-002
        result = detector.scan([r1, r2, r3])
        assert ids_in(result.findings, "STKO-004")
        assert ids_in(result.findings, "STKO-003")
        assert ids_in(result.findings, "STKO-002")


# ===========================================================================
# 10. Risk score calculation and cap
# ===========================================================================

class TestRiskScore:
    def test_single_001_risk_score_is_45(self, detector):
        rec = make_record("x.example.com", "CNAME", "x.github.io", has_response=False)
        result = detector.scan([rec])
        # STKO-001 (45) + possibly STKO-007 if "dev" in subdomain — "x" is safe
        assert result.risk_score >= 45

    def test_risk_score_capped_at_100(self, detector):
        # Fire as many checks as possible: 001+003+004+005+006+007 = 45+25+25+15+15+15 = 140
        records = [
            # STKO-001 + STKO-007 (dev + github.io, no response)
            make_record("dev.example.com", "CNAME", "dev.github.io", has_response=False),
            # STKO-003
            make_record("zone.example.com", "NS", "ns.dead.net", has_response=False),
            # STKO-004
            make_record("stale.example.com", "A", "203.0.113.5", has_response=False),
            # STKO-005 — chain of 3
            make_record("c1.example.com", "CNAME", "c2.example.com"),
            make_record("c2.example.com", "CNAME", "c3.example.com"),
            # STKO-006
            make_record("cloud.example.com", "A", "52.10.20.30"),
        ]
        result = detector.scan(records)
        assert result.risk_score == 100

    def test_risk_score_unique_checks_only(self, detector):
        # Two records each firing STKO-001 — weight should only count once
        r1 = make_record("a.example.com", "CNAME", "a.github.io", has_response=False)
        r2 = make_record("b.example.com", "CNAME", "b.github.io", has_response=False)
        result = detector.scan([r1, r2])
        # STKO-001 weight is 45; two findings but same check ID = only 45
        assert result.risk_score == 45

    def test_risk_score_002_is_25(self, detector):
        rec = make_record("x.example.com", "CNAME", "x.heroku.com", has_response=True)
        result = detector.scan([rec])
        assert result.risk_score == 25

    def test_risk_score_003_is_25(self, detector):
        rec = make_record("zone.example.com", "NS", "ns.dead.net", has_response=False)
        result = detector.scan([rec])
        assert result.risk_score == 25

    def test_risk_score_004_is_25(self, detector):
        rec = make_record("stale.example.com", "A", "203.0.113.5", has_response=False)
        result = detector.scan([rec])
        assert result.risk_score == 25

    def test_risk_score_zero_no_findings(self, detector):
        rec = make_record("good.example.com", "A", "1.2.3.4", has_response=True)
        result = detector.scan([rec])
        assert result.risk_score == 0

    def test_check_weights_dict_has_all_seven_keys(self):
        for cid in ["STKO-001", "STKO-002", "STKO-003", "STKO-004", "STKO-005", "STKO-006", "STKO-007"]:
            assert cid in _CHECK_WEIGHTS


# ===========================================================================
# 11. by_severity() structure
# ===========================================================================

class TestBySeverity:
    def test_by_severity_returns_dict(self, detector):
        result = detector.scan([])
        assert isinstance(result.by_severity(), dict)

    def test_by_severity_keys_are_severity_labels(self, detector):
        r1 = make_record("a.example.com", "CNAME", "a.github.io", has_response=False)
        r2 = make_record("b.example.com", "NS", "ns.dead.net", has_response=False)
        result = detector.scan([r1, r2])
        by_sev = result.by_severity()
        for key in by_sev:
            assert key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_by_severity_values_are_lists_of_findings(self, detector):
        rec = make_record("a.example.com", "CNAME", "a.github.io", has_response=False)
        result = detector.scan([rec])
        by_sev = result.by_severity()
        for findings_list in by_sev.values():
            assert isinstance(findings_list, list)
            for f in findings_list:
                assert isinstance(f, TakeoverFinding)

    def test_by_severity_critical_contains_001_finding(self, detector):
        rec = make_record("a.example.com", "CNAME", "a.github.io", has_response=False)
        result = detector.scan([rec])
        by_sev = result.by_severity()
        assert "CRITICAL" in by_sev
        assert any(f.check_id == "STKO-001" for f in by_sev["CRITICAL"])

    def test_by_severity_high_contains_002_finding(self, detector):
        rec = make_record("a.example.com", "CNAME", "a.heroku.com", has_response=True)
        result = detector.scan([rec])
        by_sev = result.by_severity()
        assert "HIGH" in by_sev
        assert any(f.check_id == "STKO-002" for f in by_sev["HIGH"])

    def test_by_severity_medium_contains_006_finding(self, detector):
        rec = make_record("host.example.com", "A", "52.10.20.30")
        result = detector.scan([rec])
        by_sev = result.by_severity()
        assert "MEDIUM" in by_sev
        assert any(f.check_id == "STKO-006" for f in by_sev["MEDIUM"])


# ===========================================================================
# 12. summary() format
# ===========================================================================

class TestSummary:
    def test_summary_returns_string(self, detector):
        result = detector.scan([])
        assert isinstance(result.summary(), str)

    def test_summary_no_findings_mentions_no_vulnerabilities(self, detector):
        result = detector.scan([])
        s = result.summary()
        assert "No" in s or "0" in s

    def test_summary_includes_risk_score(self, detector):
        result = detector.scan([])
        assert "/100" in result.summary()

    def test_summary_with_findings_includes_count(self, detector):
        rec = make_record("a.example.com", "CNAME", "a.github.io", has_response=False)
        result = detector.scan([rec])
        s = result.summary()
        # At least one finding; should mention finding count and risk score
        assert "finding" in s.lower()
        assert "/100" in s

    def test_summary_mentions_critical_when_present(self, detector):
        rec = make_record("a.example.com", "CNAME", "a.github.io", has_response=False)
        result = detector.scan([rec])
        s = result.summary()
        assert "CRITICAL" in s

    def test_summary_mentions_high_when_present(self, detector):
        rec = make_record("a.example.com", "NS", "ns.dead.net", has_response=False)
        result = detector.scan([rec])
        s = result.summary()
        assert "HIGH" in s


# ===========================================================================
# 13. scan_many()
# ===========================================================================

class TestScanMany:
    def test_scan_many_returns_list(self, detector):
        result = detector.scan_many([[]])
        assert isinstance(result, list)

    def test_scan_many_empty_input_returns_empty_list(self, detector):
        result = detector.scan_many([])
        assert result == []

    def test_scan_many_returns_correct_count(self, detector):
        results = detector.scan_many([[], [], []])
        assert len(results) == 3

    def test_scan_many_each_item_is_takeover_scan_result(self, detector):
        results = detector.scan_many([[make_record("a.com", "A", "1.2.3.4")]])
        assert isinstance(results[0], TakeoverScanResult)

    def test_scan_many_independent_scores(self, detector):
        r1 = [make_record("a.example.com", "CNAME", "a.github.io", has_response=False)]
        r2 = [make_record("b.example.com", "A", "1.2.3.4")]
        results = detector.scan_many([r1, r2])
        assert results[0].risk_score > 0
        assert results[1].risk_score == 0

    def test_scan_many_single_empty_list(self, detector):
        results = detector.scan_many([[]])
        assert len(results) == 1
        assert results[0].findings == []


# ===========================================================================
# 14. to_dict() on all dataclasses
# ===========================================================================

class TestToDict:
    def test_subdomain_record_to_dict_keys(self):
        rec = make_record()
        d = rec.to_dict()
        assert set(d.keys()) == {"subdomain", "record_type", "value", "ttl", "has_response"}

    def test_subdomain_record_to_dict_values(self):
        rec = SubdomainRecord("a.example.com", "CNAME", "b.example.com", ttl=60, has_response=False)
        d = rec.to_dict()
        assert d["subdomain"] == "a.example.com"
        assert d["record_type"] == "CNAME"
        assert d["value"] == "b.example.com"
        assert d["ttl"] == 60
        assert d["has_response"] is False

    def test_takeover_finding_to_dict_keys(self):
        f = TakeoverFinding(
            check_id="STKO-001",
            severity="CRITICAL",
            subdomain="a.example.com",
            record_type="CNAME",
            message="msg",
            recommendation="rec",
            cname_target="b.github.io",
            service_name="GitHub Pages",
        )
        d = f.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "subdomain", "record_type",
            "cname_target", "service_name", "message", "recommendation",
        }

    def test_takeover_finding_to_dict_values(self):
        f = TakeoverFinding(
            check_id="STKO-003",
            severity="HIGH",
            subdomain="zone.example.com",
            record_type="NS",
            message="msg",
            recommendation="rec",
        )
        d = f.to_dict()
        assert d["check_id"] == "STKO-003"
        assert d["severity"] == "HIGH"
        assert d["cname_target"] is None
        assert d["service_name"] is None

    def test_takeover_scan_result_to_dict_keys(self, detector):
        result = detector.scan([])
        d = result.to_dict()
        assert "findings" in d
        assert "risk_score" in d
        assert "summary" in d
        assert "by_severity" in d

    def test_takeover_scan_result_to_dict_findings_list(self, detector):
        rec = make_record("a.example.com", "CNAME", "a.github.io", has_response=False)
        result = detector.scan([rec])
        d = result.to_dict()
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) >= 1
        assert isinstance(d["findings"][0], dict)

    def test_takeover_scan_result_to_dict_risk_score(self, detector):
        rec = make_record("a.example.com", "CNAME", "a.github.io", has_response=False)
        result = detector.scan([rec])
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)
        assert 0 <= d["risk_score"] <= 100

    def test_takeover_scan_result_to_dict_by_severity_nested(self, detector):
        rec = make_record("a.example.com", "CNAME", "a.github.io", has_response=False)
        result = detector.scan([rec])
        d = result.to_dict()
        for sev, items in d["by_severity"].items():
            assert isinstance(items, list)
            for item in items:
                assert isinstance(item, dict)


# ===========================================================================
# 15. _VULNERABLE_SERVICES coverage
# ===========================================================================

class TestVulnerableServicesDict:
    def test_github_io_present(self):
        assert "github.io" in _VULNERABLE_SERVICES

    def test_s3_amazonaws_present(self):
        assert "s3.amazonaws.com" in _VULNERABLE_SERVICES

    def test_cloudfront_present(self):
        assert "cloudfront.net" in _VULNERABLE_SERVICES

    def test_azurewebsites_present(self):
        assert "azurewebsites.net" in _VULNERABLE_SERVICES

    def test_azurefd_present(self):
        assert "azurefd.net" in _VULNERABLE_SERVICES

    def test_blob_core_windows_present(self):
        assert "blob.core.windows.net" in _VULNERABLE_SERVICES

    def test_trafficmanager_present(self):
        assert "trafficmanager.net" in _VULNERABLE_SERVICES

    def test_storage_googleapis_present(self):
        assert "storage.googleapis.com" in _VULNERABLE_SERVICES

    def test_appspot_present(self):
        assert "appspot.com" in _VULNERABLE_SERVICES

    def test_firebaseapp_present(self):
        assert "firebaseapp.com" in _VULNERABLE_SERVICES

    def test_heroku_present(self):
        assert "heroku.com" in _VULNERABLE_SERVICES

    def test_herokuapp_present(self):
        assert "herokuapp.com" in _VULNERABLE_SERVICES

    def test_zendesk_present(self):
        assert "zendesk.com" in _VULNERABLE_SERVICES

    def test_netlify_com_present(self):
        assert "netlify.com" in _VULNERABLE_SERVICES

    def test_netlify_app_present(self):
        assert "netlify.app" in _VULNERABLE_SERVICES

    def test_vercel_app_present(self):
        assert "vercel.app" in _VULNERABLE_SERVICES

    def test_surge_sh_present(self):
        assert "surge.sh" in _VULNERABLE_SERVICES

    def test_myshopify_present(self):
        assert "myshopify.com" in _VULNERABLE_SERVICES

    def test_statuspage_present(self):
        assert "statuspage.io" in _VULNERABLE_SERVICES

    def test_ghost_io_present(self):
        assert "ghost.io" in _VULNERABLE_SERVICES

    def test_readme_io_present(self):
        assert "readme.io" in _VULNERABLE_SERVICES

    def test_helpscoutdocs_present(self):
        assert "helpscoutdocs.com" in _VULNERABLE_SERVICES

    def test_unbouncepages_present(self):
        assert "unbouncepages.com" in _VULNERABLE_SERVICES

    def test_s3_website_present(self):
        assert "s3-website" in _VULNERABLE_SERVICES

    def test_all_values_are_strings(self):
        for k, v in _VULNERABLE_SERVICES.items():
            assert isinstance(k, str) and isinstance(v, str)

    def test_c_storage_googleapis_present(self):
        assert "c.storage.googleapis.com" in _VULNERABLE_SERVICES
