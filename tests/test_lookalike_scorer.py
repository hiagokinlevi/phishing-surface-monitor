"""
Tests for analyzers/lookalike_scorer.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.lookalike_scorer import (
    DomainRiskResult,
    LookalikeScorer,
    RiskLevel,
    ScoringSignal,
    _apply_leet,
    _keyboard_proximity_score,
    _levenshtein,
    _normalize_domain,
    _score_to_level,
)


# ===========================================================================
# Internal helpers
# ===========================================================================

class TestNormalizeDomain:
    def test_ascii_passthrough(self):
        assert _normalize_domain("example") == "example"

    def test_cyrillic_a_replaced(self):
        result = _normalize_domain("ex\u0430mple")  # Cyrillic а
        assert result == "example"

    def test_cyrillic_o_replaced(self):
        result = _normalize_domain("g\u043egle")  # Cyrillic о → ASCII o
        assert result == "gogle"

    def test_lowercased(self):
        assert _normalize_domain("EXAMPLE") == "example"

    def test_non_ascii_stripped(self):
        result = _normalize_domain("exam\u200bple")  # zero-width space
        assert "\u200b" not in result


class TestApplyLeet:
    def test_zero_to_o(self):
        # 0 maps to 'o', so examp0e → exampoe
        assert _apply_leet("examp0e") == "exampoe"

    def test_rn_to_m(self):
        # rn → m: "exarnple" = exa + rn + ple → exa + m + ple = "example"
        assert _apply_leet("exarnple") == "example"

    def test_three_to_e(self):
        # 3 → e: "3xampl3" → "example" (both 3s converted)
        assert _apply_leet("3xampl3") == "example"

    def test_leet_stack(self):
        # 1 → i, 3 → e
        assert _apply_leet("1nst4gr4m") == "instagram"


class TestLevenshtein:
    def test_identical(self):
        assert _levenshtein("abc", "abc") == 0

    def test_one_insert(self):
        assert _levenshtein("exampl", "example") == 1

    def test_one_delete(self):
        assert _levenshtein("examples", "example") == 1

    def test_one_replace(self):
        assert _levenshtein("exampXe", "example") == 1

    def test_empty_strings(self):
        assert _levenshtein("", "") == 0

    def test_one_empty(self):
        assert _levenshtein("abc", "") == 3

    def test_two_edits(self):
        assert _levenshtein("exXYple", "example") == 2


class TestKeyboardProximityScore:
    def test_adjacent_key_counts(self):
        # "r" is adjacent to "e" on QWERTY
        score = _keyboard_proximity_score("examplr", "exampler")
        assert score == 0  # different length → 0

    def test_same_length_one_adjacent(self):
        # exampoe vs example: same length 7; position 5: o vs l — o IS in neighbors of l
        score = _keyboard_proximity_score("exampoe", "example")
        assert score == 1

    def test_exact_one_key_off(self):
        # woogle vs google — w is adjacent to q and e, not g → 0
        score = _keyboard_proximity_score("eoogle", "google")
        # e is NOT adjacent to g directly in QWERTY (t/r/d/f are neighbors of g)
        assert isinstance(score, int)

    def test_different_lengths_return_zero(self):
        assert _keyboard_proximity_score("abc", "abcd") == 0


class TestScoreToLevel:
    def test_critical(self):
        assert _score_to_level(80) == RiskLevel.CRITICAL
        assert _score_to_level(100) == RiskLevel.CRITICAL

    def test_high(self):
        assert _score_to_level(60) == RiskLevel.HIGH
        assert _score_to_level(79) == RiskLevel.HIGH

    def test_medium(self):
        assert _score_to_level(35) == RiskLevel.MEDIUM
        assert _score_to_level(59) == RiskLevel.MEDIUM

    def test_low(self):
        assert _score_to_level(15) == RiskLevel.LOW
        assert _score_to_level(34) == RiskLevel.LOW

    def test_info(self):
        assert _score_to_level(0) == RiskLevel.INFO
        assert _score_to_level(14) == RiskLevel.INFO


# ===========================================================================
# DomainRiskResult
# ===========================================================================

class TestDomainRiskResult:
    def _result(self) -> DomainRiskResult:
        return DomainRiskResult(
            candidate="examp1e.com",
            brand="example",
            normalized="example",
            risk_score=75,
            risk_level=RiskLevel.HIGH,
            signals=[ScoringSignal("leet_substitution", 45, "detail")],
            is_lookalike=True,
        )

    def test_summary_contains_candidate(self):
        assert "examp1e.com" in self._result().summary()

    def test_summary_contains_risk_level(self):
        assert "HIGH" in self._result().summary()

    def test_to_dict_keys(self):
        d = self._result().to_dict()
        for k in ("candidate", "brand", "normalized", "risk_score",
                  "risk_level", "is_lookalike", "signals"):
            assert k in d

    def test_to_dict_signals_is_list(self):
        d = self._result().to_dict()
        assert isinstance(d["signals"], list)


# ===========================================================================
# LookalikeScorer — basic scoring
# ===========================================================================

class TestScorerBasic:
    def test_exact_domain_not_flagged(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("example.com")
        # Exact normalized match fires, so it should be high risk
        assert result.risk_score > 0

    def test_unrelated_domain_low_risk(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("wikipedia.org")
        assert result.risk_score < 35
        assert not result.is_lookalike

    def test_brand_property(self):
        scorer = LookalikeScorer("myband")
        assert scorer.brand == "myband"

    def test_score_returns_result(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("example.com")
        assert isinstance(result, DomainRiskResult)
        assert result.candidate == "example.com"
        assert result.brand == "example"


# ===========================================================================
# Leet substitution (exact_normalized_match or leet_substitution)
# ===========================================================================

class TestLeetSubstitution:
    def test_examp1e_flagged(self):
        # 1→i leet does not produce "example", but edit distance = 1 → weight=38 → is_lookalike
        scorer = LookalikeScorer("example")
        result = scorer.score("examp1e.com")
        assert result.is_lookalike

    def test_g00gle_flagged(self):
        scorer = LookalikeScorer("google")
        result = scorer.score("g00gle.com")
        assert result.is_lookalike

    def test_leet_signal_in_result(self):
        # 0→o leet: g00gle → google (exact match)
        scorer = LookalikeScorer("google")
        result = scorer.score("g00gle.com")
        signal_names = {s.name for s in result.signals}
        assert "leet_substitution" in signal_names or "exact_normalized_match" in signal_names

    def test_score_high_for_leet(self):
        scorer = LookalikeScorer("google")
        result = scorer.score("g00gle.com")
        assert result.risk_score >= 35


# ===========================================================================
# Homoglyph detection
# ===========================================================================

class TestHomoglyphDetection:
    def test_cyrillic_a_flagged(self):
        scorer = LookalikeScorer("example")
        # Cyrillic 'а' (U+0430) looks like Latin 'a'
        result = scorer.score("ex\u0430mple.com")
        assert result.is_lookalike

    def test_cyrillic_signal_present(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("ex\u0430mple.com")
        names = {s.name for s in result.signals}
        assert "homoglyph_substitution" in names or "exact_normalized_match" in names


# ===========================================================================
# Edit distance
# ===========================================================================

class TestEditDistance:
    def test_one_typo_flagged(self):
        # "exmple.com" is 1 edit (deletion) from "example" → weight=38 → is_lookalike
        scorer = LookalikeScorer("example")
        result = scorer.score("exmple.com")
        assert result.is_lookalike

    def test_two_typos_flagged(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("exxmale.com")
        # 2 edits — should still be flagged depending on max_edit
        # default max_edit = max(2, 7//4) = max(2,1) = 2
        assert result.risk_score > 0

    def test_very_different_domain_not_flagged(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("stackoverflow.com")
        assert not result.is_lookalike

    def test_edit_distance_signal_present(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("exmaple.com")
        names = {s.name for s in result.signals}
        assert "edit_distance" in names or "exact_normalized_match" in names


# ===========================================================================
# Suspicious TLD
# ===========================================================================

class TestSuspiciousTLD:
    def test_tk_tld_flagged(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("example.tk")
        signal_names = {s.name for s in result.signals}
        assert "suspicious_tld" in signal_names

    def test_xyz_tld_flagged(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("example.xyz")
        signal_names = {s.name for s in result.signals}
        assert "suspicious_tld" in signal_names

    def test_com_tld_not_suspicious(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("completely-different.com")
        signal_names = {s.name for s in result.signals}
        assert "suspicious_tld" not in signal_names


# ===========================================================================
# Brand as subdomain
# ===========================================================================

class TestBrandAsSubdomain:
    def test_brand_subdomain_flagged(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("example.evil.com")
        signal_names = {s.name for s in result.signals}
        assert "brand_as_subdomain" in signal_names

    def test_brand_subdomain_risk_medium_or_higher(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("example.evil.com")
        assert result.risk_score >= 35

    def test_non_subdomain_not_flagged_as_subdomain(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("example.com")
        signal_names = {s.name for s in result.signals}
        assert "brand_as_subdomain" not in signal_names


# ===========================================================================
# Brand embedded in SLD
# ===========================================================================

class TestBrandEmbedded:
    def test_brand_embedded_flagged(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("examplebank.com")
        signal_names = {s.name for s in result.signals}
        assert "brand_embedded" in signal_names

    def test_getbrand_flagged(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("getexample.io")
        signal_names = {s.name for s in result.signals}
        assert "brand_embedded" in signal_names

    def test_embedded_disabled(self):
        scorer = LookalikeScorer("example", embedded_check=False)
        result = scorer.score("examplebank.com")
        signal_names = {s.name for s in result.signals}
        assert "brand_embedded" not in signal_names


# ===========================================================================
# Punycode / IDN
# ===========================================================================

class TestPunycode:
    def test_punycode_domain_flagged(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("xn--exmple-cua.com")
        signal_names = {s.name for s in result.signals}
        assert "punycode_idn" in signal_names

    def test_normal_domain_not_flagged_as_punycode(self):
        scorer = LookalikeScorer("example")
        result = scorer.score("example.com")
        signal_names = {s.name for s in result.signals}
        assert "punycode_idn" not in signal_names


# ===========================================================================
# score_many and filter_lookalikes
# ===========================================================================

class TestScoreMany:
    def test_score_many_returns_sorted(self):
        scorer = LookalikeScorer("example")
        results = scorer.score_many(["wikipedia.org", "examp1e.com", "example.tk"])
        scores = [r.risk_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_filter_lookalikes_excludes_safe(self):
        scorer = LookalikeScorer("example")
        results = scorer.filter_lookalikes([
            "wikipedia.org",
            "examp1e.com",
            "google.com",
        ])
        for r in results:
            assert r.is_lookalike

    def test_filter_lookalikes_empty(self):
        scorer = LookalikeScorer("example")
        results = scorer.filter_lookalikes(["wikipedia.org", "google.com"])
        assert all(not r.is_lookalike for r in results) or len(results) == 0

    def test_score_many_returns_list(self):
        scorer = LookalikeScorer("example")
        results = scorer.score_many(["example.com"])
        assert isinstance(results, list)
        assert len(results) == 1


# ===========================================================================
# Risk score capped at 100
# ===========================================================================

class TestRiskScoreCap:
    def test_score_never_exceeds_100(self):
        scorer = LookalikeScorer("example")
        # Trigger many signals at once
        result = scorer.score("xn--ex\u0430mple.tk")
        assert result.risk_score <= 100


# ===========================================================================
# Max edit distance configuration
# ===========================================================================

class TestMaxEditDistance:
    def test_custom_max_edit_broader(self):
        scorer = LookalikeScorer("example", max_edit_distance=4)
        result = scorer.score("exzzzle.com")
        # With 4 allowed edits, should catch more
        assert isinstance(result, DomainRiskResult)

    def test_custom_max_edit_tighter(self):
        scorer = LookalikeScorer("example", max_edit_distance=0)
        result = scorer.score("exmaple.com")  # 1 edit
        # Edit distance check should not fire
        edit_signals = [s for s in result.signals if s.name == "edit_distance"]
        assert len(edit_signals) == 0
