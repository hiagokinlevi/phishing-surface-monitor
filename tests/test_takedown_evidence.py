"""
Tests for reports/takedown_evidence.py and alerting/domain_alerts.py

takedown_evidence.py:
  - generate_evidence_package creates a ZIP file
  - ZIP contains manifest.json
  - ZIP contains summary.md
  - ZIP contains findings/ directory entries
  - ZIP contains checksums.json
  - manifest has correct total_findings count
  - manifest highest_risk reflects findings
  - manifest findings_index has correct entries
  - summary.md contains brand_domain
  - summary.md contains all lookalike domains
  - per-finding finding.json is valid JSON
  - per-finding dns_records.txt contains IP from a_records
  - per-finding whois_note.txt contains WHOIS lookup links
  - checksums.json has one entry per non-checksum file
  - list_package_contents returns expected file names
  - read_package_manifest parses manifest correctly
  - empty findings list produces valid package with 0 findings
  - findings sorted by risk (critical first) in manifest
  - package_id customization respected
  - created_at customization reflected in manifest

domain_alerts.py:
  - DomainAlertConfig.meets_threshold filters by risk level
  - DomainAlertConfig defaults severity_threshold high
  - send_domain_alert dry_run=True returns success without HTTP call
  - send_domain_alert with no eligible findings returns success findings_alerted=0
  - build_slack_payload returns blocks list
  - build_slack_payload blocks are capped at MAX_SLACK_BLOCKS
  - build_slack_payload contains brand_domain in header
  - build_slack_payload shows overflow message when findings exceed cap
  - build_slack_payload sorted highest risk first
  - build_generic_payload returns findings list
  - build_generic_payload highest_risk is correct
  - build_generic_payload resolving count correct
  - send_domain_alert channel=generic uses generic payload
  - send_domain_alert dry_run result has payload_preview
  - send_domain_alert findings_alerted count matches eligible findings
"""
from __future__ import annotations

import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from alerting.domain_alerts import (
    DomainAlertConfig,
    build_generic_payload,
    build_slack_payload,
    send_domain_alert,
)
from reports.takedown_evidence import (
    generate_evidence_package,
    list_package_contents,
    read_package_manifest,
)
from schemas.case import BrandFinding, CaseStatus, RiskLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    lookalike: str = "examp1e.com",
    brand: str = "example.com",
    risk: RiskLevel = RiskLevel.HIGH,
    resolves: bool = True,
    a_records: list[str] | None = None,
    similarity: float = 0.85,
    technique: str = "homoglyph",
) -> BrandFinding:
    return BrandFinding(
        brand_domain=brand,
        lookalike_domain=lookalike,
        technique=technique,
        similarity_score=similarity,
        resolves=resolves,
        a_records=a_records or ["1.2.3.4"],
        risk_level=risk,
        status=CaseStatus.OPEN,
    )


_FIXED_TS = datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# generate_evidence_package
# ---------------------------------------------------------------------------

class TestGenerateEvidencePackage:

    def test_creates_zip_file(self, tmp_path):
        findings = [_finding()]
        path = generate_evidence_package(
            findings, "example.com", tmp_path, created_at=_FIXED_TS
        )
        assert path.exists()
        assert path.suffix == ".zip"

    def test_zip_contains_manifest(self, tmp_path):
        path = generate_evidence_package(
            [_finding()], "example.com", tmp_path, created_at=_FIXED_TS
        )
        contents = list_package_contents(path)
        assert "manifest.json" in contents

    def test_zip_contains_summary(self, tmp_path):
        path = generate_evidence_package(
            [_finding()], "example.com", tmp_path, created_at=_FIXED_TS
        )
        contents = list_package_contents(path)
        assert "summary.md" in contents

    def test_zip_contains_checksums(self, tmp_path):
        path = generate_evidence_package(
            [_finding()], "example.com", tmp_path, created_at=_FIXED_TS
        )
        contents = list_package_contents(path)
        assert "checksums.json" in contents

    def test_zip_contains_finding_json(self, tmp_path):
        path = generate_evidence_package(
            [_finding("evil.com")], "example.com", tmp_path, created_at=_FIXED_TS
        )
        contents = list_package_contents(path)
        finding_jsons = [c for c in contents if c.endswith("finding.json")]
        assert len(finding_jsons) == 1

    def test_zip_contains_dns_records(self, tmp_path):
        path = generate_evidence_package(
            [_finding()], "example.com", tmp_path, created_at=_FIXED_TS
        )
        contents = list_package_contents(path)
        dns_files = [c for c in contents if "dns_records" in c]
        assert len(dns_files) >= 1

    def test_zip_contains_whois_note(self, tmp_path):
        path = generate_evidence_package(
            [_finding()], "example.com", tmp_path, created_at=_FIXED_TS
        )
        contents = list_package_contents(path)
        whois_files = [c for c in contents if "whois_note" in c]
        assert len(whois_files) >= 1

    def test_manifest_total_findings_correct(self, tmp_path):
        findings = [_finding("a.com"), _finding("b.com")]
        path = generate_evidence_package(
            findings, "example.com", tmp_path, created_at=_FIXED_TS
        )
        manifest = read_package_manifest(path)
        assert manifest["total_findings"] == 2

    def test_manifest_highest_risk_critical(self, tmp_path):
        findings = [
            _finding(risk=RiskLevel.HIGH),
            _finding("evil.com", risk=RiskLevel.CRITICAL),
        ]
        path = generate_evidence_package(
            findings, "example.com", tmp_path, created_at=_FIXED_TS
        )
        manifest = read_package_manifest(path)
        assert manifest["highest_risk"] == "critical"

    def test_manifest_findings_index_count(self, tmp_path):
        findings = [_finding("a.com"), _finding("b.com"), _finding("c.com")]
        path = generate_evidence_package(
            findings, "example.com", tmp_path, created_at=_FIXED_TS
        )
        manifest = read_package_manifest(path)
        assert len(manifest["findings_index"]) == 3

    def test_manifest_findings_index_contains_domain(self, tmp_path):
        path = generate_evidence_package(
            [_finding("examp1e.com")], "example.com", tmp_path, created_at=_FIXED_TS
        )
        manifest = read_package_manifest(path)
        domains = [e["lookalike_domain"] for e in manifest["findings_index"]]
        assert "examp1e.com" in domains

    def test_summary_md_contains_brand_domain(self, tmp_path):
        path = generate_evidence_package(
            [_finding()], "example.com", tmp_path, created_at=_FIXED_TS
        )
        with zipfile.ZipFile(path) as zf:
            summary = zf.read("summary.md").decode("utf-8")
        assert "example.com" in summary

    def test_summary_md_contains_lookalike(self, tmp_path):
        path = generate_evidence_package(
            [_finding("examp1e.com")], "example.com", tmp_path, created_at=_FIXED_TS
        )
        with zipfile.ZipFile(path) as zf:
            summary = zf.read("summary.md").decode("utf-8")
        assert "examp1e.com" in summary

    def test_per_finding_json_valid(self, tmp_path):
        path = generate_evidence_package(
            [_finding("evil.com")], "example.com", tmp_path, created_at=_FIXED_TS
        )
        with zipfile.ZipFile(path) as zf:
            json_files = [n for n in zf.namelist() if n.endswith("finding.json")]
            data = json.loads(zf.read(json_files[0]).decode("utf-8"))
        assert data["lookalike_domain"] == "evil.com"

    def test_dns_records_contains_ip(self, tmp_path):
        path = generate_evidence_package(
            [_finding(a_records=["10.20.30.40"])], "example.com", tmp_path,
            created_at=_FIXED_TS
        )
        with zipfile.ZipFile(path) as zf:
            dns_files = [n for n in zf.namelist() if "dns_records" in n]
            txt = zf.read(dns_files[0]).decode("utf-8")
        assert "10.20.30.40" in txt

    def test_whois_note_contains_lookup_link(self, tmp_path):
        path = generate_evidence_package(
            [_finding("evil.com")], "example.com", tmp_path, created_at=_FIXED_TS
        )
        with zipfile.ZipFile(path) as zf:
            whois_files = [n for n in zf.namelist() if "whois_note" in n]
            txt = zf.read(whois_files[0]).decode("utf-8")
        assert "evil.com" in txt
        assert "http" in txt

    def test_checksums_has_one_entry_per_file(self, tmp_path):
        path = generate_evidence_package(
            [_finding()], "example.com", tmp_path, created_at=_FIXED_TS
        )
        with zipfile.ZipFile(path) as zf:
            checksums = json.loads(zf.read("checksums.json").decode("utf-8"))
            all_files = [n for n in zf.namelist() if n != "checksums.json"]
        assert set(checksums.keys()) == set(all_files)

    def test_empty_findings_valid_package(self, tmp_path):
        path = generate_evidence_package(
            [], "example.com", tmp_path, created_at=_FIXED_TS
        )
        manifest = read_package_manifest(path)
        assert manifest["total_findings"] == 0
        assert manifest["highest_risk"] == "none"

    def test_findings_sorted_critical_first(self, tmp_path):
        findings = [
            _finding("a.com", risk=RiskLevel.LOW),
            _finding("b.com", risk=RiskLevel.CRITICAL),
        ]
        path = generate_evidence_package(
            findings, "example.com", tmp_path, created_at=_FIXED_TS
        )
        manifest = read_package_manifest(path)
        index = manifest["findings_index"]
        # First entry should be the critical one
        assert index[0]["risk_level"] == "critical"

    def test_custom_package_id(self, tmp_path):
        path = generate_evidence_package(
            [_finding()], "example.com", tmp_path,
            package_id="test-pkg-001", created_at=_FIXED_TS
        )
        manifest = read_package_manifest(path)
        assert manifest["package_id"] == "test-pkg-001"

    def test_created_at_in_manifest(self, tmp_path):
        path = generate_evidence_package(
            [_finding()], "example.com", tmp_path, created_at=_FIXED_TS
        )
        manifest = read_package_manifest(path)
        assert "2026-04-06" in manifest["created_at"]


# ---------------------------------------------------------------------------
# DomainAlertConfig
# ---------------------------------------------------------------------------

class TestDomainAlertConfig:

    def test_meets_threshold_high_finding_passes_high_threshold(self):
        cfg = DomainAlertConfig(url="http://x", severity_threshold="high")
        f = _finding(risk=RiskLevel.HIGH)
        assert cfg.meets_threshold(f) is True

    def test_meets_threshold_critical_passes_high_threshold(self):
        cfg = DomainAlertConfig(url="http://x", severity_threshold="high")
        f = _finding(risk=RiskLevel.CRITICAL)
        assert cfg.meets_threshold(f) is True

    def test_meets_threshold_medium_does_not_pass_high_threshold(self):
        cfg = DomainAlertConfig(url="http://x", severity_threshold="high")
        f = _finding(risk=RiskLevel.MEDIUM)
        assert cfg.meets_threshold(f) is False

    def test_meets_threshold_info_threshold_passes_all(self):
        cfg = DomainAlertConfig(url="http://x", severity_threshold="info")
        f = _finding(risk=RiskLevel.INFO)
        assert cfg.meets_threshold(f) is True

    def test_severity_threshold_default_high(self):
        cfg = DomainAlertConfig(url="http://x")
        assert cfg.severity_threshold == "high"


# ---------------------------------------------------------------------------
# build_slack_payload
# ---------------------------------------------------------------------------

class TestBuildSlackPayload:

    def test_returns_blocks_key(self):
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        payload = build_slack_payload([_finding()], cfg)
        assert "blocks" in payload

    def test_blocks_list_is_populated(self):
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        payload = build_slack_payload([_finding()], cfg)
        assert len(payload["blocks"]) >= 1

    def test_blocks_capped_at_max(self):
        # Create many findings
        findings = [_finding(f"domain{i}.com") for i in range(20)]
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        payload = build_slack_payload(findings, cfg)
        assert len(payload["blocks"]) <= 10

    def test_header_contains_brand_domain(self):
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        payload = build_slack_payload([_finding()], cfg)
        header = payload["blocks"][0]
        assert "example.com" in str(header)

    def test_overflow_message_when_findings_exceed_cap(self):
        findings = [_finding(f"domain{i}.com") for i in range(20)]
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        payload = build_slack_payload(findings, cfg)
        # One of the blocks should mention overflow
        all_blocks_text = json.dumps(payload["blocks"])
        assert "more" in all_blocks_text or "…" in all_blocks_text

    def test_highest_risk_first_in_output(self):
        findings = [
            _finding("low.com", risk=RiskLevel.LOW),
            _finding("crit.com", risk=RiskLevel.CRITICAL),
        ]
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        payload = build_slack_payload(findings, cfg)
        # The critical finding should appear before the low one in the blocks
        blocks_str = json.dumps(payload["blocks"])
        assert blocks_str.index("crit.com") < blocks_str.index("low.com")


# ---------------------------------------------------------------------------
# build_generic_payload
# ---------------------------------------------------------------------------

class TestBuildGenericPayload:

    def test_returns_findings_list(self):
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        payload = build_generic_payload([_finding()], cfg)
        assert "findings" in payload
        assert len(payload["findings"]) == 1

    def test_highest_risk_critical(self):
        findings = [_finding(risk=RiskLevel.HIGH), _finding("x.com", risk=RiskLevel.CRITICAL)]
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        payload = build_generic_payload(findings, cfg)
        assert payload["highest_risk"] == "critical"

    def test_resolving_count_correct(self):
        findings = [
            _finding(resolves=True),
            _finding("b.com", resolves=False),
        ]
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        payload = build_generic_payload(findings, cfg)
        assert payload["resolving"] == 1

    def test_brand_domain_in_payload(self):
        cfg = DomainAlertConfig(url="http://x", brand_domain="mycompany.com")
        payload = build_generic_payload([_finding()], cfg)
        assert payload["brand_domain"] == "mycompany.com"

    def test_total_count_correct(self):
        findings = [_finding("a.com"), _finding("b.com"), _finding("c.com")]
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        payload = build_generic_payload(findings, cfg)
        assert payload["total"] == 3


# ---------------------------------------------------------------------------
# send_domain_alert
# ---------------------------------------------------------------------------

class TestSendDomainAlert:

    def test_dry_run_returns_success(self):
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        result = send_domain_alert([_finding()], cfg, dry_run=True)
        assert result.success is True
        assert result.dry_run is True

    def test_dry_run_no_http_call(self):
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        with patch("alerting.domain_alerts._post_json") as mock_post:
            send_domain_alert([_finding()], cfg, dry_run=True)
            mock_post.assert_not_called()

    def test_no_eligible_findings_returns_zero_count(self):
        cfg = DomainAlertConfig(
            url="http://x", brand_domain="example.com", severity_threshold="critical"
        )
        # Only medium findings — below critical threshold
        findings = [_finding(risk=RiskLevel.MEDIUM)]
        result = send_domain_alert(findings, cfg, dry_run=True)
        assert result.findings_alerted == 0
        assert result.success is True

    def test_findings_alerted_count_matches_eligible(self):
        cfg = DomainAlertConfig(
            url="http://x", brand_domain="example.com", severity_threshold="high"
        )
        findings = [
            _finding(risk=RiskLevel.HIGH),
            _finding("b.com", risk=RiskLevel.CRITICAL),
            _finding("c.com", risk=RiskLevel.MEDIUM),  # below threshold
        ]
        result = send_domain_alert(findings, cfg, dry_run=True)
        assert result.findings_alerted == 2   # only high + critical

    def test_dry_run_payload_preview_populated(self):
        cfg = DomainAlertConfig(url="http://x", brand_domain="example.com")
        result = send_domain_alert([_finding()], cfg, dry_run=True)
        assert len(result.payload_preview) > 0

    def test_generic_channel_uses_generic_payload(self):
        cfg = DomainAlertConfig(
            url="http://x", brand_domain="example.com", channel="generic"
        )
        result = send_domain_alert([_finding()], cfg, dry_run=True)
        # Generic payload won't have 'blocks' key
        assert "blocks" not in result.payload_preview

    def test_slack_channel_uses_slack_payload(self):
        cfg = DomainAlertConfig(
            url="http://x", brand_domain="example.com", channel="slack"
        )
        result = send_domain_alert([_finding()], cfg, dry_run=True)
        assert "blocks" in result.payload_preview
