# test_dns_monitor.py — Comprehensive test suite for dns_monitor.py
#
# Copyright 2024 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Run with:
#   python3 -m pytest tests/test_dns_monitor.py --override-ini="addopts=" -q

from __future__ import annotations

import math
import sys
import os

# Ensure the package root is on sys.path so the module is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from monitors.dns_monitor import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    DnsAlert,
    DnsMonitor,
    DnsMonitorResult,
    DnsRecord,
    DnsSnapshot,
    _CHECK_WEIGHTS,
    _shannon_entropy,
    _is_subdomain_of,
    _subdomain_label,
    _is_suspicious_subdomain,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

DOMAIN = "example.com"


def make_snapshot(records_dict: dict, domain: str = DOMAIN, captured_at: float = 0.0) -> DnsSnapshot:
    """Shorthand for DnsSnapshot.from_records_dict."""
    return DnsSnapshot.from_records_dict(domain, records_dict, captured_at)


def make_empty(domain: str = DOMAIN) -> DnsSnapshot:
    """Return an empty snapshot (no records)."""
    return DnsSnapshot(domain=domain, records=[], captured_at=0.0)


def ids_in(result: DnsMonitorResult) -> set:
    """Return the set of check IDs present in *result*."""
    return {a.check_id for a in result.alerts}


@pytest.fixture
def monitor() -> DnsMonitor:
    return DnsMonitor()


# ---------------------------------------------------------------------------
# Section 1: Helper unit tests
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        # All same characters → entropy 0
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        # "ab" → entropy 1.0
        assert abs(_shannon_entropy("ab") - 1.0) < 1e-9

    def test_high_entropy_string(self):
        # 10 unique characters → entropy = log2(10) ≈ 3.32, well above 3.2
        assert _shannon_entropy("3xk9pqvzmw") > 3.2

    def test_low_entropy_string(self):
        # Repetitive string has low entropy
        assert _shannon_entropy("aaaaabbb") < 2.0

    def test_known_value(self):
        # "abcd" has 4 equally likely characters → entropy = 2.0
        result = _shannon_entropy("abcd")
        assert abs(result - 2.0) < 1e-9


class TestIsSubdomainOf:
    def test_proper_subdomain(self):
        assert _is_subdomain_of("login.example.com", "example.com") is True

    def test_nested_subdomain(self):
        assert _is_subdomain_of("a.b.example.com", "example.com") is True

    def test_same_domain_is_not_subdomain(self):
        assert _is_subdomain_of("example.com", "example.com") is False

    def test_different_domain_not_subdomain(self):
        assert _is_subdomain_of("evil.com", "example.com") is False

    def test_partial_match_not_subdomain(self):
        # "notexample.com" should NOT match "example.com"
        assert _is_subdomain_of("notexample.com", "example.com") is False

    def test_trailing_dot_normalised(self):
        assert _is_subdomain_of("login.example.com.", "example.com.") is True

    def test_case_insensitive(self):
        assert _is_subdomain_of("LOGIN.EXAMPLE.COM", "example.com") is True


class TestSubdomainLabel:
    def test_single_label(self):
        assert _subdomain_label("login.example.com", "example.com") == "login"

    def test_multi_label(self):
        assert _subdomain_label("a.b.example.com", "example.com") == "a.b"


class TestIsSuspiciousSubdomain:
    def test_known_prefix_login(self):
        assert _is_suspicious_subdomain("login") is True

    def test_known_prefix_auth(self):
        assert _is_suspicious_subdomain("auth") is True

    def test_known_prefix_secure(self):
        assert _is_suspicious_subdomain("secure") is True

    def test_known_prefix_account(self):
        assert _is_suspicious_subdomain("account") is True

    def test_known_prefix_verify(self):
        assert _is_suspicious_subdomain("verify") is True

    def test_known_prefix_update(self):
        assert _is_suspicious_subdomain("update") is True

    def test_known_prefix_support(self):
        assert _is_suspicious_subdomain("support") is True

    def test_known_prefix_helpdesk(self):
        assert _is_suspicious_subdomain("helpdesk") is True

    def test_known_prefix_portal(self):
        assert _is_suspicious_subdomain("portal") is True

    def test_known_prefix_webmail(self):
        assert _is_suspicious_subdomain("webmail") is True

    def test_hyphenated_label_with_suspicious_token(self):
        assert _is_suspicious_subdomain("login-secure") is True

    def test_underscore_label_with_suspicious_token(self):
        assert _is_suspicious_subdomain("secure_update") is True

    def test_benign_label(self):
        assert _is_suspicious_subdomain("www") is False

    def test_benign_label_blog(self):
        assert _is_suspicious_subdomain("blog") is False

    def test_partial_token_match_is_not_suspicious(self):
        assert _is_suspicious_subdomain("blogin") is False

    def test_dga_high_entropy_with_digit(self):
        # Starts with digit; 10 unique chars → entropy ≈ 3.32 > 3.2
        label = "3xk9pqvzmw"
        assert label[0].isdigit()
        assert _shannon_entropy(label) > 3.2
        assert _is_suspicious_subdomain(label) is True

    def test_dga_ends_with_digit_high_entropy(self):
        # Ends with digit; 10 unique chars → entropy ≈ 3.32 > 3.2
        label = "abcdefghi3"
        assert label[-1].isdigit()
        assert _shannon_entropy(label) > 3.2
        assert _is_suspicious_subdomain(label) is True

    def test_not_dga_no_digit_boundary(self):
        # High entropy but no digit at start/end
        label = "abcdefgh"
        assert not label[0].isdigit() and not label[-1].isdigit()
        assert _is_suspicious_subdomain(label) is False


# ---------------------------------------------------------------------------
# Section 2: DnsRecord
# ---------------------------------------------------------------------------

class TestDnsRecord:
    def test_defaults(self):
        r = DnsRecord(record_type="A", name="example.com", value="1.2.3.4")
        assert r.ttl == 3600

    def test_to_dict_keys(self):
        r = DnsRecord(record_type="MX", name="example.com", value="10 mail.example.com", ttl=300)
        d = r.to_dict()
        assert set(d.keys()) == {"record_type", "name", "value", "ttl"}

    def test_to_dict_values(self):
        r = DnsRecord(record_type="NS", name="example.com", value="ns1.example.com", ttl=86400)
        d = r.to_dict()
        assert d["record_type"] == "NS"
        assert d["ttl"] == 86400


# ---------------------------------------------------------------------------
# Section 3: DnsSnapshot
# ---------------------------------------------------------------------------

class TestDnsSnapshot:
    def test_from_records_dict_basic(self):
        snap = make_snapshot({"A": ["1.2.3.4"], "MX": ["10 mail.example.com"]})
        assert snap.domain == DOMAIN
        assert len(snap.records) == 2

    def test_from_records_dict_multiple_values(self):
        snap = make_snapshot({"NS": ["ns1.example.com", "ns2.example.com"]})
        assert len(snap.records) == 2
        assert all(r.record_type == "NS" for r in snap.records)

    def test_from_records_dict_captured_at(self):
        snap = DnsSnapshot.from_records_dict(DOMAIN, {"A": ["1.2.3.4"]}, captured_at=12345.0)
        assert snap.captured_at == 12345.0

    def test_from_records_dict_empty(self):
        snap = DnsSnapshot.from_records_dict(DOMAIN, {}, captured_at=0.0)
        assert snap.records == []

    def test_to_dict_keys(self):
        snap = make_snapshot({"A": ["1.2.3.4"]})
        d = snap.to_dict()
        assert set(d.keys()) == {"domain", "captured_at", "records"}

    def test_to_dict_records_list(self):
        snap = make_snapshot({"A": ["1.2.3.4", "5.6.7.8"]})
        d = snap.to_dict()
        assert isinstance(d["records"], list)
        assert len(d["records"]) == 2

    def test_from_records_dict_all_record_types(self):
        snap = make_snapshot({
            "A": ["1.2.3.4"],
            "AAAA": ["::1"],
            "MX": ["10 mail.example.com"],
            "NS": ["ns1.example.com"],
            "CNAME": ["alias.example.com"],
            "TXT": ["v=spf1 -all"],
            "DS": ["12345 8 2 AABBCC"],
            "DNSKEY": ["257 3 8 AABBCC=="],
        })
        types = {r.record_type for r in snap.records}
        assert types == {"A", "AAAA", "MX", "NS", "CNAME", "TXT", "DS", "DNSKEY"}


# ---------------------------------------------------------------------------
# Section 4: DnsAlert
# ---------------------------------------------------------------------------

class TestDnsAlert:
    def test_to_dict_keys(self):
        alert = DnsAlert(
            check_id="DNS-MON-001",
            severity=HIGH,
            domain=DOMAIN,
            record_type="MX",
            record_name=DOMAIN,
            old_value=None,
            new_value="10 evil.com",
            message="Test",
            recommendation="Check it.",
        )
        d = alert.to_dict()
        expected_keys = {
            "check_id", "severity", "domain", "record_type",
            "record_name", "old_value", "new_value", "message", "recommendation",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_preserves_none(self):
        alert = DnsAlert(
            check_id="DNS-MON-004",
            severity=HIGH,
            domain=DOMAIN,
            record_type="CNAME",
            record_name="www.example.com",
            old_value=None,
            new_value="evil.com",
            message="New CNAME",
            recommendation="Investigate.",
        )
        d = alert.to_dict()
        assert d["old_value"] is None


# ---------------------------------------------------------------------------
# Section 5: DnsMonitorResult
# ---------------------------------------------------------------------------

class TestDnsMonitorResult:
    def _make_result_with_alerts(self, severities: list) -> DnsMonitorResult:
        alerts = []
        for i, sev in enumerate(severities):
            alerts.append(DnsAlert(
                check_id=f"DNS-MON-00{i+1}",
                severity=sev,
                domain=DOMAIN,
                record_type="A",
                record_name=DOMAIN,
                old_value=None,
                new_value="1.2.3.4",
                message="test",
                recommendation="test",
            ))
        fired = {a.check_id for a in alerts}
        score = min(100, sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired))
        return DnsMonitorResult(domain=DOMAIN, alerts=alerts, risk_score=score)

    def test_summary_no_alerts(self):
        result = DnsMonitorResult(domain=DOMAIN, alerts=[], risk_score=0)
        s = result.summary()
        assert DOMAIN in s
        assert "risk_score=0" in s
        assert "alerts=0" in s

    def test_summary_with_alerts(self):
        result = self._make_result_with_alerts([HIGH, MEDIUM])
        s = result.summary()
        assert "HIGH:1" in s
        assert "MEDIUM:1" in s

    def test_summary_critical_present(self):
        result = self._make_result_with_alerts([CRITICAL])
        assert "CRITICAL:1" in result.summary()

    def test_by_severity_always_has_all_keys(self):
        result = DnsMonitorResult(domain=DOMAIN, alerts=[], risk_score=0)
        by_sev = result.by_severity()
        assert CRITICAL in by_sev
        assert HIGH in by_sev
        assert MEDIUM in by_sev
        assert LOW in by_sev

    def test_by_severity_grouping(self):
        result = self._make_result_with_alerts([HIGH, HIGH, MEDIUM])
        by_sev = result.by_severity()
        assert len(by_sev[HIGH]) == 2
        assert len(by_sev[MEDIUM]) == 1
        assert len(by_sev[CRITICAL]) == 0

    def test_to_dict_keys(self):
        result = DnsMonitorResult(domain=DOMAIN, alerts=[], risk_score=0)
        d = result.to_dict()
        assert set(d.keys()) == {"domain", "risk_score", "alerts", "summary"}

    def test_to_dict_alerts_serialised(self):
        result = self._make_result_with_alerts([HIGH])
        d = result.to_dict()
        assert isinstance(d["alerts"], list)
        assert len(d["alerts"]) == 1
        assert isinstance(d["alerts"][0], dict)

    def test_to_dict_summary_is_string(self):
        result = DnsMonitorResult(domain=DOMAIN, alerts=[], risk_score=0)
        d = result.to_dict()
        assert isinstance(d["summary"], str)


# ---------------------------------------------------------------------------
# Section 6: DnsMonitor — identical snapshots produce no alerts
# ---------------------------------------------------------------------------

class TestIdenticalSnapshots:
    def test_empty_snapshots_no_alerts(self, monitor):
        base = make_empty()
        curr = make_empty()
        result = monitor.compare(base, curr)
        assert result.alerts == []
        assert result.risk_score == 0

    def test_same_a_record_no_alerts(self, monitor):
        snap = make_snapshot({"A": ["1.2.3.4"]})
        result = monitor.compare(snap, snap)
        assert result.alerts == []

    def test_same_mx_no_alerts(self, monitor):
        snap = make_snapshot({"MX": ["10 mail.example.com"]})
        result = monitor.compare(snap, snap)
        assert result.alerts == []

    def test_same_ns_no_alerts(self, monitor):
        snap = make_snapshot({"NS": ["ns1.example.com", "ns2.example.com"]})
        result = monitor.compare(snap, snap)
        assert result.alerts == []

    def test_same_all_types_no_alerts(self, monitor):
        records = {
            "A": ["1.2.3.4"],
            "MX": ["10 mail.example.com"],
            "NS": ["ns1.example.com"],
            "TXT": ["v=spf1 -all"],
            "DS": ["12345 8 2 AABB"],
        }
        snap = make_snapshot(records)
        result = monitor.compare(snap, snap)
        assert result.alerts == []
        assert result.risk_score == 0


# ---------------------------------------------------------------------------
# Section 7: DNS-MON-001 — MX record changes
# ---------------------------------------------------------------------------

class TestCheck001MX:
    def test_new_mx_triggers_001(self, monitor):
        base = make_snapshot({"MX": ["10 mail.example.com"]})
        curr = make_snapshot({"MX": ["10 mail.example.com", "20 evil.com"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-001" in ids_in(result)

    def test_new_mx_alert_contains_new_value(self, monitor):
        base = make_snapshot({"MX": ["10 mail.example.com"]})
        curr = make_snapshot({"MX": ["10 mail.example.com", "20 attacker.com"]})
        result = monitor.compare(base, curr)
        mx_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-001"]
        assert any("attacker.com" in a.new_value for a in mx_alerts)

    def test_changed_mx_value_triggers_001(self, monitor):
        base = make_snapshot({"MX": ["10 mail.example.com"]})
        curr = make_snapshot({"MX": ["10 evil.com"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-001" in ids_in(result)

    def test_added_mx_from_none_triggers_001(self, monitor):
        base = make_snapshot({})
        curr = make_snapshot({"MX": ["10 mail.example.com"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-001" in ids_in(result)

    def test_mx_unchanged_no_001(self, monitor):
        snap = make_snapshot({"MX": ["10 mail.example.com"]})
        result = monitor.compare(snap, snap)
        assert "DNS-MON-001" not in ids_in(result)

    def test_mx_removed_no_001(self, monitor):
        # Removal of MX is not flagged by 001 (001 targets new/changed values)
        base = make_snapshot({"MX": ["10 mail.example.com"]})
        curr = make_snapshot({})
        result = monitor.compare(base, curr)
        assert "DNS-MON-001" not in ids_in(result)

    def test_001_severity_is_high(self, monitor):
        base = make_snapshot({})
        curr = make_snapshot({"MX": ["10 evil.com"]})
        result = monitor.compare(base, curr)
        mx_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-001"]
        assert all(a.severity == HIGH for a in mx_alerts)


# ---------------------------------------------------------------------------
# Section 8: DNS-MON-002 — NS record changes
# ---------------------------------------------------------------------------

class TestCheck002NS:
    def test_new_ns_triggers_002(self, monitor):
        base = make_snapshot({"NS": ["ns1.example.com"]})
        curr = make_snapshot({"NS": ["ns1.example.com", "evil-ns.com"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-002" in ids_in(result)

    def test_removed_ns_triggers_002(self, monitor):
        base = make_snapshot({"NS": ["ns1.example.com", "ns2.example.com"]})
        curr = make_snapshot({"NS": ["ns1.example.com"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-002" in ids_in(result)

    def test_ns_fully_replaced_triggers_002(self, monitor):
        base = make_snapshot({"NS": ["ns1.example.com"]})
        curr = make_snapshot({"NS": ["evil-ns.com"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-002" in ids_in(result)

    def test_unchanged_ns_does_not_trigger_002(self, monitor):
        snap = make_snapshot({"NS": ["ns1.example.com", "ns2.example.com"]})
        result = monitor.compare(snap, snap)
        assert "DNS-MON-002" not in ids_in(result)

    def test_both_ns_missing_no_002(self, monitor):
        base = make_snapshot({"A": ["1.2.3.4"]})
        curr = make_snapshot({"A": ["1.2.3.4"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-002" not in ids_in(result)

    def test_002_severity_is_high(self, monitor):
        base = make_snapshot({"NS": ["ns1.example.com"]})
        curr = make_snapshot({"NS": ["evil.com"]})
        result = monitor.compare(base, curr)
        ns_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-002"]
        assert all(a.severity == HIGH for a in ns_alerts)

    def test_ns_added_from_empty_triggers_002(self, monitor):
        base = make_snapshot({})
        curr = make_snapshot({"NS": ["ns1.example.com"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-002" in ids_in(result)


# ---------------------------------------------------------------------------
# Section 9: DNS-MON-003 — A / AAAA record value changed
# ---------------------------------------------------------------------------

class TestCheck003AChanged:
    def test_changed_a_record_triggers_003(self, monitor):
        base = make_snapshot({"A": ["1.2.3.4"]})
        curr = make_snapshot({"A": ["5.6.7.8"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-003" in ids_in(result)

    def test_changed_aaaa_record_triggers_003(self, monitor):
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("AAAA", DOMAIN, "2001:db8::1"),
        ])
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("AAAA", DOMAIN, "2001:db8::2"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-003" in ids_in(result)

    def test_new_a_record_not_in_baseline_does_not_trigger_003(self, monitor):
        # Completely new name — not a value change
        base = make_snapshot({"A": ["1.2.3.4"]})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", DOMAIN, "1.2.3.4"),
            DnsRecord("A", "other.example.com", "9.9.9.9"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-003" not in ids_in(result)

    def test_unchanged_a_no_003(self, monitor):
        snap = make_snapshot({"A": ["1.2.3.4"]})
        result = monitor.compare(snap, snap)
        assert "DNS-MON-003" not in ids_in(result)

    def test_003_old_value_captured(self, monitor):
        base = make_snapshot({"A": ["1.2.3.4"]})
        curr = make_snapshot({"A": ["9.9.9.9"]})
        result = monitor.compare(base, curr)
        a_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-003"]
        assert any("1.2.3.4" in a.old_value for a in a_alerts)

    def test_003_severity_is_medium(self, monitor):
        base = make_snapshot({"A": ["1.2.3.4"]})
        curr = make_snapshot({"A": ["9.9.9.9"]})
        result = monitor.compare(base, curr)
        a_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-003"]
        assert all(a.severity == MEDIUM for a in a_alerts)

    def test_a_record_removed_not_003(self, monitor):
        # 003 only fires when name exists in both but value differs
        base = make_snapshot({"A": ["1.2.3.4"]})
        curr = make_snapshot({})
        result = monitor.compare(base, curr)
        assert "DNS-MON-003" not in ids_in(result)


# ---------------------------------------------------------------------------
# Section 10: DNS-MON-004 — New CNAME record added
# ---------------------------------------------------------------------------

class TestCheck004CNAME:
    def test_new_cname_triggers_004(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("CNAME", "www.example.com", "evil.com"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-004" in ids_in(result)

    def test_existing_cname_not_004(self, monitor):
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("CNAME", "www.example.com", "cdn.example.com"),
        ])
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("CNAME", "www.example.com", "cdn.example.com"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-004" not in ids_in(result)

    def test_004_alert_contains_new_value(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("CNAME", "login.example.com", "phishing.com"),
        ])
        result = monitor.compare(base, curr)
        cname_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-004"]
        assert any("phishing.com" in a.new_value for a in cname_alerts)

    def test_004_old_value_is_none(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("CNAME", "www.example.com", "cdn.net"),
        ])
        result = monitor.compare(base, curr)
        cname_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-004"]
        assert all(a.old_value is None for a in cname_alerts)

    def test_004_severity_is_high(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("CNAME", "www.example.com", "evil.com"),
        ])
        result = monitor.compare(base, curr)
        cname_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-004"]
        assert all(a.severity == HIGH for a in cname_alerts)

    def test_cname_removed_no_004(self, monitor):
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("CNAME", "www.example.com", "cdn.net"),
        ])
        curr = make_snapshot({})
        result = monitor.compare(base, curr)
        assert "DNS-MON-004" not in ids_in(result)


# ---------------------------------------------------------------------------
# Section 11: DNS-MON-005 — DNSSEC records removed
# ---------------------------------------------------------------------------

class TestCheck005DNSSEC:
    def test_dnssec_removed_triggers_005(self, monitor):
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("DS", DOMAIN, "12345 8 2 AABBCC"),
        ])
        curr = make_snapshot({"A": ["1.2.3.4"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-005" in ids_in(result)

    def test_dnskey_removed_triggers_005(self, monitor):
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("DNSKEY", DOMAIN, "257 3 8 AABBCC=="),
        ])
        curr = make_snapshot({})
        result = monitor.compare(base, curr)
        assert "DNS-MON-005" in ids_in(result)

    def test_dnssec_never_existed_no_005(self, monitor):
        base = make_snapshot({"A": ["1.2.3.4"]})
        curr = make_snapshot({"A": ["1.2.3.4"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-005" not in ids_in(result)

    def test_dnssec_unchanged_no_005(self, monitor):
        snap = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("DS", DOMAIN, "12345 8 2 AABBCC"),
            DnsRecord("DNSKEY", DOMAIN, "257 3 8 AABBCC=="),
        ])
        result = monitor.compare(snap, snap)
        assert "DNS-MON-005" not in ids_in(result)

    def test_dnssec_added_new_no_005(self, monitor):
        # DNSSEC being added (not in baseline) should NOT trigger 005
        base = make_snapshot({"A": ["1.2.3.4"]})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", DOMAIN, "1.2.3.4"),
            DnsRecord("DS", DOMAIN, "12345 8 2 AABBCC"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-005" not in ids_in(result)

    def test_005_severity_is_medium(self, monitor):
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("DS", DOMAIN, "12345 8 2 AABBCC"),
        ])
        curr = make_snapshot({})
        result = monitor.compare(base, curr)
        dnssec_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-005"]
        assert all(a.severity == MEDIUM for a in dnssec_alerts)

    def test_005_old_value_contains_record(self, monitor):
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("DS", DOMAIN, "12345 8 2 AABBCC"),
        ])
        curr = make_snapshot({})
        result = monitor.compare(base, curr)
        dnssec_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-005"]
        assert all(a.old_value is not None for a in dnssec_alerts)

    def test_005_new_value_is_none(self, monitor):
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("DS", DOMAIN, "12345 8 2 AABBCC"),
        ])
        curr = make_snapshot({})
        result = monitor.compare(base, curr)
        dnssec_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-005"]
        assert all(a.new_value is None for a in dnssec_alerts)


# ---------------------------------------------------------------------------
# Section 12: DNS-MON-006 — SPF permissive change
# ---------------------------------------------------------------------------

class TestCheck006SPF:
    def test_spf_changed_to_plus_all_triggers_006(self, monitor):
        base = make_snapshot({"TXT": ["v=spf1 include:spf.example.com -all"]})
        curr = make_snapshot({"TXT": ["v=spf1 include:spf.example.com +all"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-006" in ids_in(result)

    def test_spf_introduced_with_plus_all_triggers_006(self, monitor):
        # SPF changed from non-existent (or different) to +all
        base = make_snapshot({"TXT": ["v=spf1 -all"]})
        curr = make_snapshot({"TXT": ["v=spf1 +all"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-006" in ids_in(result)

    def test_spf_changed_without_plus_all_no_006(self, monitor):
        base = make_snapshot({"TXT": ["v=spf1 include:spf.example.com -all"]})
        curr = make_snapshot({"TXT": ["v=spf1 include:spf2.example.com ~all"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-006" not in ids_in(result)

    def test_spf_unchanged_no_006(self, monitor):
        snap = make_snapshot({"TXT": ["v=spf1 -all"]})
        result = monitor.compare(snap, snap)
        assert "DNS-MON-006" not in ids_in(result)

    def test_spf_no_txt_no_006(self, monitor):
        base = make_snapshot({"A": ["1.2.3.4"]})
        curr = make_snapshot({"A": ["1.2.3.4"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-006" not in ids_in(result)

    def test_006_severity_is_critical(self, monitor):
        base = make_snapshot({"TXT": ["v=spf1 -all"]})
        curr = make_snapshot({"TXT": ["v=spf1 +all"]})
        result = monitor.compare(base, curr)
        spf_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-006"]
        assert all(a.severity == CRITICAL for a in spf_alerts)

    def test_006_old_value_preserved(self, monitor):
        old_spf = "v=spf1 include:spf.example.com -all"
        new_spf = "v=spf1 +all"
        base = make_snapshot({"TXT": [old_spf]})
        curr = make_snapshot({"TXT": [new_spf]})
        result = monitor.compare(base, curr)
        spf_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-006"]
        assert any(a.old_value == old_spf for a in spf_alerts)

    def test_006_new_value_is_new_spf(self, monitor):
        new_spf = "v=spf1 +all"
        base = make_snapshot({"TXT": ["v=spf1 -all"]})
        curr = make_snapshot({"TXT": [new_spf]})
        result = monitor.compare(base, curr)
        spf_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-006"]
        assert any(a.new_value == new_spf for a in spf_alerts)

    def test_spf_removed_entirely_no_006(self, monitor):
        # SPF removed entirely — 006 only checks when new SPF exists with +all
        base = make_snapshot({"TXT": ["v=spf1 -all"]})
        curr = make_snapshot({})
        result = monitor.compare(base, curr)
        assert "DNS-MON-006" not in ids_in(result)


# ---------------------------------------------------------------------------
# Section 13: DNS-MON-007 — Suspicious subdomain
# ---------------------------------------------------------------------------

class TestCheck007SuspiciousSubdomain:
    def test_new_login_subdomain_triggers_007(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", "login.example.com", "1.2.3.4"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" in ids_in(result)

    def test_new_auth_subdomain_triggers_007(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", "auth.example.com", "1.2.3.4"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" in ids_in(result)

    def test_new_secure_subdomain_triggers_007(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", "secure.example.com", "1.2.3.4"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" in ids_in(result)

    def test_new_account_subdomain_triggers_007(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", "account.example.com", "1.2.3.4"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" in ids_in(result)

    def test_hyphenated_lure_subdomain_triggers_007(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", "login-secure.example.com", "1.2.3.4"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" in ids_in(result)

    def test_dga_like_subdomain_triggers_007(self, monitor):
        # 10 unique chars → entropy ≈ 3.32 > 3.2; starts with digit
        dga_label = "3xk9pqvzmw"
        assert _shannon_entropy(dga_label) > 3.2
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", f"{dga_label}.example.com", "1.2.3.4"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" in ids_in(result)

    def test_dga_aaaa_record_triggers_007(self, monitor):
        # Same high-entropy label, tested via an AAAA record
        dga_label = "3xk9pqvzmw"
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("AAAA", f"{dga_label}.example.com", "::1"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" in ids_in(result)

    def test_non_suspicious_www_subdomain_no_007(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", "www.example.com", "1.2.3.4"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" not in ids_in(result)

    def test_non_suspicious_api_subdomain_no_007(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", "api.example.com", "1.2.3.4"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" not in ids_in(result)

    def test_existing_subdomain_in_baseline_no_007(self, monitor):
        # login.example.com was already in baseline — should NOT fire
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("A", "login.example.com", "1.2.3.4"),
        ])
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", "login.example.com", "1.2.3.4"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" not in ids_in(result)

    def test_007_severity_is_high(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", "login.example.com", "1.2.3.4"),
        ])
        result = monitor.compare(base, curr)
        sub_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-007"]
        assert all(a.severity == HIGH for a in sub_alerts)

    def test_007_new_value_is_ip(self, monitor):
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A", "portal.example.com", "9.9.9.9"),
        ])
        result = monitor.compare(base, curr)
        sub_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-007"]
        assert any(a.new_value == "9.9.9.9" for a in sub_alerts)

    def test_007_not_fired_for_apex_record(self, monitor):
        # A record at the apex domain itself is not a subdomain
        base = make_snapshot({})
        curr = make_snapshot({"A": ["1.2.3.4"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-007" not in ids_in(result)

    def test_007_deduplicates_same_name(self, monitor):
        # Two AAAA + A records with same suspicious name should produce one alert
        base = make_snapshot({})
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A",    "login.example.com", "1.2.3.4"),
            DnsRecord("AAAA", "login.example.com", "::1"),
        ])
        result = monitor.compare(base, curr)
        sub_alerts = [a for a in result.alerts if a.check_id == "DNS-MON-007"]
        # Should deduplicate by name
        names = [a.record_name for a in sub_alerts]
        assert names.count("login.example.com") == 1


# ---------------------------------------------------------------------------
# Section 14: Risk score computation
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_no_alerts_score_zero(self, monitor):
        snap = make_snapshot({"A": ["1.2.3.4"]})
        result = monitor.compare(snap, snap)
        assert result.risk_score == 0

    def test_single_check_score_equals_weight(self, monitor):
        # Trigger only DNS-MON-001 (weight=25)
        base = make_snapshot({})
        curr = make_snapshot({"MX": ["10 evil.com"]})
        result = monitor.compare(base, curr)
        assert result.risk_score == _CHECK_WEIGHTS["DNS-MON-001"]

    def test_two_checks_score_is_sum(self, monitor):
        # Trigger DNS-MON-001 (25) + DNS-MON-002 (30) = 55
        base = make_snapshot({"NS": ["ns1.example.com"]})
        curr = make_snapshot({
            "MX": ["10 evil.com"],           # triggers 001
            "NS": ["evil-ns.com"],            # triggers 002 (both add + remove)
        })
        result = monitor.compare(base, curr)
        fired = ids_in(result)
        assert "DNS-MON-001" in fired
        assert "DNS-MON-002" in fired
        expected = _CHECK_WEIGHTS["DNS-MON-001"] + _CHECK_WEIGHTS["DNS-MON-002"]
        assert result.risk_score == expected

    def test_risk_score_capped_at_100(self, monitor):
        # Trigger all checks: combined weights exceed 100
        # 001(25) + 002(30) + 003(15) + 004(20) + 005(15) + 006(35) + 007(20) = 160
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("A",      DOMAIN, "1.2.3.4"),          # for 003
            DnsRecord("NS",     DOMAIN, "ns1.example.com"),  # for 002
            DnsRecord("TXT",    DOMAIN, "v=spf1 -all"),      # for 006
            DnsRecord("DS",     DOMAIN, "12345 8 2 AA"),     # for 005
        ])
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("A",      DOMAIN, "9.9.9.9"),                        # 003
            DnsRecord("MX",     DOMAIN, "10 evil.com"),                    # 001
            DnsRecord("NS",     DOMAIN, "evil-ns.com"),                    # 002
            DnsRecord("CNAME",  "www.example.com",  "attacker.com"),       # 004
            DnsRecord("TXT",    DOMAIN, "v=spf1 +all"),                    # 006
            DnsRecord("A",      "login.example.com", "5.5.5.5"),           # 007
        ])
        result = monitor.compare(base, curr)
        # All 7 checks should fire: 005 fires because DS was in baseline only
        assert result.risk_score == 100

    def test_multiple_alerts_same_check_counted_once(self, monitor):
        # Two new MX values both trigger 001, but weight counted only once
        base = make_snapshot({})
        curr = make_snapshot({"MX": ["10 evil1.com", "20 evil2.com"]})
        result = monitor.compare(base, curr)
        assert result.risk_score == _CHECK_WEIGHTS["DNS-MON-001"]


# ---------------------------------------------------------------------------
# Section 15: compare_many()
# ---------------------------------------------------------------------------

class TestCompareMany:
    def test_returns_list(self, monitor):
        pairs = [(make_empty(), make_empty())]
        results = monitor.compare_many(pairs)
        assert isinstance(results, list)

    def test_length_matches_input(self, monitor):
        pairs = [
            (make_empty(), make_empty()),
            (make_snapshot({"A": ["1.2.3.4"]}), make_snapshot({"A": ["9.9.9.9"]})),
        ]
        results = monitor.compare_many(pairs)
        assert len(results) == 2

    def test_each_element_is_result(self, monitor):
        pairs = [(make_empty(), make_empty())]
        results = monitor.compare_many(pairs)
        assert all(isinstance(r, DnsMonitorResult) for r in results)

    def test_empty_pairs_list(self, monitor):
        results = monitor.compare_many([])
        assert results == []

    def test_order_preserved(self, monitor):
        base1 = make_snapshot({})
        curr1 = make_snapshot({"MX": ["10 evil.com"]})  # triggers 001
        base2 = make_empty()
        curr2 = make_empty()  # no alerts
        results = monitor.compare_many([(base1, curr1), (base2, curr2)])
        assert "DNS-MON-001" in ids_in(results[0])
        assert len(results[1].alerts) == 0

    def test_different_domains(self, monitor):
        snap_a = DnsSnapshot(domain="a.com", records=[], captured_at=0.0)
        snap_b = DnsSnapshot(domain="b.com", records=[], captured_at=0.0)
        results = monitor.compare_many([(snap_a, snap_a), (snap_b, snap_b)])
        assert results[0].domain == "a.com"
        assert results[1].domain == "b.com"


# ---------------------------------------------------------------------------
# Section 16: Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_baseline_no_003(self, monitor):
        # New A record in current when baseline is empty should NOT trigger 003
        base = make_empty()
        curr = make_snapshot({"A": ["1.2.3.4"]})
        result = monitor.compare(base, curr)
        assert "DNS-MON-003" not in ids_in(result)

    def test_empty_current_no_001(self, monitor):
        base = make_snapshot({"MX": ["10 mail.example.com"]})
        curr = make_empty()
        result = monitor.compare(base, curr)
        # MX removed (not added) should not trigger 001
        assert "DNS-MON-001" not in ids_in(result)

    def test_multiple_types_only_relevant_checks_fire(self, monitor):
        # Only NS changed; no other checks should fire
        base = make_snapshot({
            "A":  ["1.2.3.4"],
            "MX": ["10 mail.example.com"],
            "NS": ["ns1.example.com"],
        })
        curr = make_snapshot({
            "A":  ["1.2.3.4"],           # unchanged
            "MX": ["10 mail.example.com"],  # unchanged
            "NS": ["evil-ns.com"],        # changed
        })
        result = monitor.compare(base, curr)
        fired = ids_in(result)
        assert "DNS-MON-002" in fired
        assert "DNS-MON-001" not in fired
        assert "DNS-MON-003" not in fired

    def test_domain_field_in_result(self, monitor):
        snap = DnsSnapshot(domain="brand.io", records=[], captured_at=0.0)
        result = monitor.compare(snap, snap)
        assert result.domain == "brand.io"

    def test_domain_field_in_alerts(self, monitor):
        base = make_snapshot({})
        curr = make_snapshot({"MX": ["10 evil.com"]})
        result = monitor.compare(base, curr)
        assert all(a.domain == DOMAIN for a in result.alerts)

    def test_dnssec_on_subdomain_not_counted_for_005(self, monitor):
        # DS record for a subdomain, not for the apex domain, should not trigger 005
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("DS", "sub.example.com", "12345 8 2 AA"),
        ])
        curr = make_snapshot({})
        result = monitor.compare(base, curr)
        assert "DNS-MON-005" not in ids_in(result)

    def test_spf_for_subdomain_not_counted_for_006(self, monitor):
        # SPF TXT on a subdomain, not apex domain — should not trigger 006
        base = DnsSnapshot(domain=DOMAIN, captured_at=0.0, records=[
            DnsRecord("TXT", "mail.example.com", "v=spf1 -all"),
        ])
        curr = DnsSnapshot(domain=DOMAIN, captured_at=1.0, records=[
            DnsRecord("TXT", "mail.example.com", "v=spf1 +all"),
        ])
        result = monitor.compare(base, curr)
        assert "DNS-MON-006" not in ids_in(result)

    def test_check_weights_dict_has_all_seven(self):
        for i in range(1, 8):
            cid = f"DNS-MON-00{i}"
            assert cid in _CHECK_WEIGHTS, f"{cid} missing from _CHECK_WEIGHTS"

    def test_all_weights_positive(self):
        for cid, weight in _CHECK_WEIGHTS.items():
            assert weight > 0, f"{cid} has non-positive weight {weight}"

    def test_result_domain_in_summary(self, monitor):
        snap = DnsSnapshot(domain="target.co.uk", records=[], captured_at=0.0)
        result = monitor.compare(snap, snap)
        assert "target.co.uk" in result.summary()
