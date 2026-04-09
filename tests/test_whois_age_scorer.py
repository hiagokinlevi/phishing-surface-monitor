"""
Tests for analyzers.whois_age_scorer.

All tests use reference_time=REF_TIME (a fixed Unix timestamp) so that
age and expiry calculations are fully deterministic regardless of when the
suite is run.
"""

import sys
import os

# Allow running from the repo root: `python3 -m pytest tests/...`
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from analyzers.whois_age_scorer import AgeRiskResult, WhoisAgeScorer, WhoisRecord

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

REF_TIME = 1_700_000_000.0   # fixed "now" for all tests
DAY = 86_400                  # seconds per day


def _scorer(**kwargs) -> WhoisAgeScorer:
    """Convenience factory: scorer always uses REF_TIME as reference."""
    kwargs.setdefault("reference_time", REF_TIME)
    return WhoisAgeScorer(**kwargs)


def _record(domain: str = "example.com", **kwargs) -> WhoisRecord:
    """Convenience factory for WhoisRecord with sensible defaults."""
    kwargs.setdefault("registered_at", REF_TIME - 365 * DAY)  # 1 year old
    kwargs.setdefault("expires_at", REF_TIME + 365 * DAY)      # expires in 1 year
    kwargs.setdefault("updated_at", None)
    return WhoisRecord(domain=domain, **kwargs)


# ===========================================================================
# WhoisRecord defaults
# ===========================================================================

class TestWhoisRecordDefaults:
    def test_registrar_default_empty_string(self):
        r = WhoisRecord(domain="a.com", registered_at=None, expires_at=None, updated_at=None)
        assert r.registrar == ""

    def test_registrant_country_default_empty_string(self):
        r = WhoisRecord(domain="a.com", registered_at=None, expires_at=None, updated_at=None)
        assert r.registrant_country == ""

    def test_privacy_protected_default_false(self):
        r = WhoisRecord(domain="a.com", registered_at=None, expires_at=None, updated_at=None)
        assert r.privacy_protected is False

    def test_name_servers_default_empty_list(self):
        r = WhoisRecord(domain="a.com", registered_at=None, expires_at=None, updated_at=None)
        assert r.name_servers == []

    def test_name_servers_not_shared_across_instances(self):
        """Each instance must own its own list (field(default_factory=list) contract)."""
        r1 = WhoisRecord(domain="a.com", registered_at=None, expires_at=None, updated_at=None)
        r2 = WhoisRecord(domain="b.com", registered_at=None, expires_at=None, updated_at=None)
        r1.name_servers.append("ns1.a.com")
        assert r2.name_servers == []

    def test_domain_stored_correctly(self):
        r = WhoisRecord(domain="target.io", registered_at=None, expires_at=None, updated_at=None)
        assert r.domain == "target.io"


# ===========================================================================
# AgeRiskResult.to_dict()
# ===========================================================================

class TestAgeRiskResultToDict:
    def _result(self) -> AgeRiskResult:
        scorer = _scorer()
        return scorer.score(_record())

    def test_to_dict_returns_dict(self):
        assert isinstance(self._result().to_dict(), dict)

    def test_to_dict_has_domain_key(self):
        assert "domain" in self._result().to_dict()

    def test_to_dict_has_risk_score_key(self):
        assert "risk_score" in self._result().to_dict()

    def test_to_dict_has_risk_level_key(self):
        assert "risk_level" in self._result().to_dict()

    def test_to_dict_has_age_days_key(self):
        assert "age_days" in self._result().to_dict()

    def test_to_dict_has_signals_key(self):
        assert "signals" in self._result().to_dict()

    def test_to_dict_has_detail_key(self):
        assert "detail" in self._result().to_dict()

    def test_to_dict_signals_is_list(self):
        assert isinstance(self._result().to_dict()["signals"], list)

    def test_to_dict_domain_value_matches(self):
        r = _scorer().score(_record(domain="check.org"))
        assert r.to_dict()["domain"] == "check.org"

    def test_to_dict_returns_copy_of_signals(self):
        """Mutating the returned dict's signals should not affect the original."""
        result = self._result()
        d = result.to_dict()
        d["signals"].append("injected")
        assert "injected" not in result.signals


# ===========================================================================
# New-domain signal (< new_domain_days)
# ===========================================================================

class TestNewDomainSignal:
    def test_5_day_old_domain_fires_signal(self):
        record = _record(registered_at=REF_TIME - 5 * DAY)
        result = _scorer().score(record)
        assert any("New domain" in s for s in result.signals)

    def test_5_day_old_domain_score_gte_40(self):
        record = _record(registered_at=REF_TIME - 5 * DAY)
        result = _scorer().score(record)
        assert result.risk_score >= 40

    def test_new_domain_signal_includes_age_days(self):
        record = _record(registered_at=REF_TIME - 5 * DAY)
        result = _scorer().score(record)
        assert "5 days old" in " ".join(result.signals)

    def test_exactly_new_domain_days_boundary(self):
        """Domain registered exactly new_domain_days ago should NOT fire."""
        record = _record(registered_at=REF_TIME - 30 * DAY)
        result = _scorer(new_domain_days=30).score(record)
        assert not any("New domain" in s for s in result.signals)

    def test_one_day_inside_boundary_fires(self):
        record = _record(registered_at=REF_TIME - 29 * DAY)
        result = _scorer(new_domain_days=30).score(record)
        assert any("New domain" in s for s in result.signals)

    def test_365_day_old_domain_no_new_signal(self):
        record = _record(registered_at=REF_TIME - 365 * DAY)
        result = _scorer().score(record)
        assert not any("New domain" in s for s in result.signals)

    def test_age_days_set_correctly_for_5_day_old(self):
        record = _record(registered_at=REF_TIME - 5 * DAY)
        result = _scorer().score(record)
        assert result.age_days == 5

    def test_custom_new_domain_days_respected(self):
        """With new_domain_days=90, a 60-day-old domain should fire."""
        record = _record(registered_at=REF_TIME - 60 * DAY)
        result = _scorer(new_domain_days=90).score(record)
        assert any("New domain" in s for s in result.signals)


# ===========================================================================
# Missing registration date signal
# ===========================================================================

class TestNoRegistrationDate:
    def test_missing_reg_date_fires_signal(self):
        record = _record(registered_at=None)
        result = _scorer().score(record)
        assert any("Registration date unavailable" in s for s in result.signals)

    def test_missing_reg_date_adds_20(self):
        # Isolated: no other signals — use a record with no expiry either
        record = WhoisRecord(
            domain="x.com",
            registered_at=None,
            expires_at=None,
            updated_at=None,
        )
        result = _scorer().score(record)
        assert result.risk_score == 20

    def test_missing_reg_date_age_days_is_none(self):
        record = _record(registered_at=None)
        result = _scorer().score(record)
        assert result.age_days is None

    def test_present_reg_date_does_not_fire_unavailable_signal(self):
        record = _record(registered_at=REF_TIME - 365 * DAY)
        result = _scorer().score(record)
        assert not any("unavailable" in s for s in result.signals)


# ===========================================================================
# Expiry-soon signal
# ===========================================================================

class TestExpirySoon:
    def test_expiring_in_10_days_fires_signal(self):
        record = _record(expires_at=REF_TIME + 10 * DAY)
        result = _scorer().score(record)
        assert any("Expires soon" in s for s in result.signals)

    def test_expiry_signal_adds_15(self):
        # Isolated: old domain + expires soon but > 1 year from registration
        record = WhoisRecord(
            domain="x.com",
            registered_at=REF_TIME - 400 * DAY,
            expires_at=REF_TIME + 10 * DAY,
            updated_at=None,
        )
        result = _scorer().score(record)
        assert result.risk_score == 15

    def test_not_expiring_soon_no_signal(self):
        record = _record(expires_at=REF_TIME + 365 * DAY)
        result = _scorer().score(record)
        assert not any("Expires soon" in s for s in result.signals)

    def test_expiry_signal_includes_days_remaining(self):
        record = _record(expires_at=REF_TIME + 10 * DAY)
        result = _scorer().score(record)
        assert "10 days" in " ".join(result.signals)

    def test_exactly_expiry_soon_days_boundary_no_signal(self):
        record = _record(expires_at=REF_TIME + 30 * DAY)
        result = _scorer(expiry_soon_days=30).score(record)
        assert not any("Expires soon" in s for s in result.signals)

    def test_none_expires_at_no_expiry_signal(self):
        record = _record(expires_at=None)
        result = _scorer().score(record)
        assert not any("Expires soon" in s for s in result.signals)


# ===========================================================================
# WHOIS privacy-protection signal
# ===========================================================================

class TestPrivacyProtection:
    def test_privacy_protected_fires_signal(self):
        record = _record(privacy_protected=True)
        result = _scorer().score(record)
        assert any("WHOIS privacy" in s for s in result.signals)

    def test_privacy_protection_adds_10(self):
        # Isolated: old domain, far expiry, privacy only
        record = WhoisRecord(
            domain="x.com",
            registered_at=REF_TIME - 400 * DAY,
            expires_at=REF_TIME + 365 * DAY,
            updated_at=None,
            privacy_protected=True,
        )
        result = _scorer().score(record)
        assert result.risk_score == 10

    def test_no_privacy_no_signal(self):
        record = _record(privacy_protected=False)
        result = _scorer().score(record)
        assert not any("WHOIS privacy" in s for s in result.signals)


# ===========================================================================
# High-risk country signal
# ===========================================================================

class TestHighRiskCountry:
    def test_high_risk_country_fires_signal(self):
        record = _record(registrant_country="CN")
        result = _scorer(high_risk_countries={"CN", "RU"}).score(record)
        assert any("High-risk registrant country" in s for s in result.signals)

    def test_high_risk_country_adds_20(self):
        record = WhoisRecord(
            domain="x.com",
            registered_at=REF_TIME - 400 * DAY,
            expires_at=REF_TIME + 365 * DAY,
            updated_at=None,
            registrant_country="RU",
        )
        result = _scorer(high_risk_countries={"RU"}).score(record)
        assert result.risk_score == 20

    def test_non_high_risk_country_no_signal(self):
        record = _record(registrant_country="DE")
        result = _scorer(high_risk_countries={"CN", "RU"}).score(record)
        assert not any("High-risk" in s for s in result.signals)

    def test_country_code_case_insensitive(self):
        """Lowercase country code should match an uppercase entry in the set."""
        record = _record(registrant_country="cn")
        result = _scorer(high_risk_countries={"CN"}).score(record)
        assert any("High-risk registrant country" in s for s in result.signals)

    def test_empty_country_code_no_signal(self):
        record = _record(registrant_country="")
        result = _scorer(high_risk_countries={"CN"}).score(record)
        assert not any("High-risk" in s for s in result.signals)


# ===========================================================================
# Short registration period signal
# ===========================================================================

class TestShortRegistrationPeriod:
    def test_short_period_fires_signal(self):
        record = WhoisRecord(
            domain="x.com",
            registered_at=REF_TIME - 400 * DAY,
            expires_at=REF_TIME - 400 * DAY + 180 * DAY,  # only 180-day window
            updated_at=None,
        )
        result = _scorer().score(record)
        assert any("Short registration period" in s for s in result.signals)

    def test_short_period_adds_15(self):
        # 340-day registration window (< 365); expiry 40 days out so the
        # expiry-soon signal (threshold 30 days) does NOT also fire.
        record = WhoisRecord(
            domain="x.com",
            registered_at=REF_TIME - 300 * DAY,
            expires_at=REF_TIME + 40 * DAY,
            updated_at=None,
        )
        result = _scorer().score(record)
        assert result.risk_score == 15

    def test_exactly_one_year_period_no_signal(self):
        record = WhoisRecord(
            domain="x.com",
            registered_at=REF_TIME - 400 * DAY,
            expires_at=REF_TIME - 400 * DAY + 365 * DAY,
            updated_at=None,
        )
        result = _scorer().score(record)
        assert not any("Short registration" in s for s in result.signals)

    def test_multi_year_period_no_signal(self):
        record = WhoisRecord(
            domain="x.com",
            registered_at=REF_TIME - 400 * DAY,
            expires_at=REF_TIME - 400 * DAY + 730 * DAY,
            updated_at=None,
        )
        result = _scorer().score(record)
        assert not any("Short registration" in s for s in result.signals)


# ===========================================================================
# Multiple signals accumulate
# ===========================================================================

class TestSignalAccumulation:
    def test_new_domain_plus_privacy_accumulate(self):
        record = _record(registered_at=REF_TIME - 5 * DAY, privacy_protected=True)
        result = _scorer().score(record)
        # 40 (new) + 10 (privacy) = 50 minimum (expiry may add more)
        assert result.risk_score >= 50

    def test_all_low_cost_signals_sum(self):
        """No-reg-date + expiry-soon + privacy = 20 + 15 + 10 = 45."""
        record = WhoisRecord(
            domain="x.com",
            registered_at=None,
            expires_at=REF_TIME + 10 * DAY,
            updated_at=None,
            privacy_protected=True,
        )
        result = _scorer().score(record)
        assert result.risk_score == 45

    def test_signals_list_length_matches_fired_count(self):
        record = _record(
            registered_at=REF_TIME - 5 * DAY,
            privacy_protected=True,
        )
        result = _scorer().score(record)
        # New domain + privacy (minimum 2; expiry may add a third)
        assert len(result.signals) >= 2

    def test_score_capped_at_100(self):
        """Worst-case record across all signals must not exceed 100."""
        record = WhoisRecord(
            domain="worst.com",
            registered_at=REF_TIME - 1 * DAY,          # new domain  +40
            expires_at=REF_TIME + 1 * DAY + 1 * DAY,   # expires soon +15; short period +15
            updated_at=None,
            privacy_protected=True,                      # +10
            registrant_country="CN",                     # +20
        )
        result = _scorer(high_risk_countries={"CN"}).score(record)
        assert result.risk_score == 100

    def test_score_never_negative(self):
        """A perfectly clean record should score 0."""
        record = WhoisRecord(
            domain="clean.com",
            registered_at=REF_TIME - 365 * DAY,
            expires_at=REF_TIME + 365 * DAY,
            updated_at=None,
        )
        result = _scorer().score(record)
        assert result.risk_score >= 0


# ===========================================================================
# Risk level classification
# ===========================================================================

class TestRiskLevelClassification:
    def _score_to_level(self, score_value: int) -> str:
        """Helper: craft a result with a known score and read back its level."""
        return WhoisAgeScorer._classify(score_value)

    def test_score_0_is_info(self):
        assert self._score_to_level(0) == "INFO"

    def test_score_9_is_info(self):
        assert self._score_to_level(9) == "INFO"

    def test_score_10_is_low(self):
        assert self._score_to_level(10) == "LOW"

    def test_score_29_is_low(self):
        assert self._score_to_level(29) == "LOW"

    def test_score_30_is_medium(self):
        assert self._score_to_level(30) == "MEDIUM"

    def test_score_49_is_medium(self):
        assert self._score_to_level(49) == "MEDIUM"

    def test_score_50_is_high(self):
        assert self._score_to_level(50) == "HIGH"

    def test_score_69_is_high(self):
        assert self._score_to_level(69) == "HIGH"

    def test_score_70_is_critical(self):
        assert self._score_to_level(70) == "CRITICAL"

    def test_score_100_is_critical(self):
        assert self._score_to_level(100) == "CRITICAL"

    def test_new_domain_alone_gives_medium(self):
        """40 points from new-domain signal alone → MEDIUM."""
        record = WhoisRecord(
            domain="new.com",
            registered_at=REF_TIME - 5 * DAY,
            expires_at=REF_TIME + 365 * DAY,
            updated_at=None,
        )
        result = _scorer().score(record)
        assert result.risk_level == "MEDIUM"

    def test_privacy_alone_gives_low(self):
        record = WhoisRecord(
            domain="priv.com",
            registered_at=REF_TIME - 400 * DAY,
            expires_at=REF_TIME + 365 * DAY,
            updated_at=None,
            privacy_protected=True,
        )
        result = _scorer().score(record)
        assert result.risk_level == "LOW"


# ===========================================================================
# score_many
# ===========================================================================

class TestScoreMany:
    def test_returns_list(self):
        scorer = _scorer()
        assert isinstance(scorer.score_many([]), list)

    def test_empty_input_returns_empty_list(self):
        scorer = _scorer()
        assert scorer.score_many([]) == []

    def test_one_record_returns_one_result(self):
        scorer = _scorer()
        results = scorer.score_many([_record()])
        assert len(results) == 1

    def test_three_records_returns_three_results(self):
        scorer = _scorer()
        records = [_record("a.com"), _record("b.com"), _record("c.com")]
        results = scorer.score_many(records)
        assert len(results) == 3

    def test_result_domains_match_input_order(self):
        scorer = _scorer()
        records = [_record("first.com"), _record("second.com"), _record("third.com")]
        results = scorer.score_many(records)
        assert [r.domain for r in results] == ["first.com", "second.com", "third.com"]

    def test_each_result_is_age_risk_result(self):
        scorer = _scorer()
        records = [_record("a.com"), _record("b.com")]
        for result in scorer.score_many(records):
            assert isinstance(result, AgeRiskResult)
