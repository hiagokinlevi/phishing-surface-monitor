"""
WHOIS Domain Age Risk Scorer — evaluates domain registration recency and
suspicious registration patterns for phishing risk assessment.

Operates exclusively on structured WhoisRecord dicts — no live WHOIS lookups
are performed by this module.
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional, Set


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class WhoisRecord:
    """Structured representation of a parsed WHOIS response."""

    domain: str
    registered_at: Optional[float]   # Unix timestamp, or None if unavailable
    expires_at: Optional[float]       # Unix timestamp, or None if unavailable
    updated_at: Optional[float]       # Unix timestamp, or None if unavailable
    registrar: str = ""               # Registrar display name
    registrant_country: str = ""      # 2-letter ISO 3166-1 alpha-2 country code
    privacy_protected: bool = False   # True when a WHOIS privacy/proxy service masks contacts
    name_servers: List[str] = field(default_factory=list)


@dataclass
class AgeRiskResult:
    """Result of scoring a single WhoisRecord."""

    domain: str
    risk_score: int        # 0–100, capped
    risk_level: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    age_days: Optional[int]  # Domain age in days at evaluation time; None if unavailable
    signals: List[str]     # Human-readable descriptions of each risk signal that fired
    detail: str            # Summary sentence for display / reporting

    def to_dict(self) -> dict:
        """Return a plain dictionary representation suitable for JSON serialisation."""
        return {
            "domain": self.domain,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "age_days": self.age_days,
            "signals": list(self.signals),
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class WhoisAgeScorer:
    """
    Scores domain registration data for phishing risk.

    Args:
        new_domain_days: Domains registered within this many days are considered
            "new" and receive an elevated risk score (default 30).
        expiry_soon_days: Domains whose expiry date falls within this many days
            from the reference time are flagged (default 30).
        high_risk_countries: Set of 2-letter ISO country codes considered
            high-risk for phishing registrant origin (default empty set).
        reference_time: Unix timestamp used as "now".  Accepts a float value so
            tests can inject a fixed instant and get deterministic results.
            Defaults to ``time.time()`` at call time when ``None`` is supplied.
    """

    # Score weights — kept as class-level constants for easy override in subclasses
    WEIGHT_NEW_DOMAIN: int = 40
    WEIGHT_NO_REG_DATE: int = 20
    WEIGHT_EXPIRY_SOON: int = 15
    WEIGHT_PRIVACY: int = 10
    WEIGHT_HIGH_RISK_COUNTRY: int = 20
    WEIGHT_SHORT_PERIOD: int = 15

    # Age thresholds
    _SECONDS_PER_DAY: int = 86400
    _ONE_YEAR_DAYS: int = 365

    def __init__(
        self,
        new_domain_days: int = 30,
        expiry_soon_days: int = 30,
        high_risk_countries: Optional[Set[str]] = None,
        reference_time: Optional[float] = None,
    ) -> None:
        self.new_domain_days = new_domain_days
        self.expiry_soon_days = expiry_soon_days
        # Normalise country codes to upper-case for safe comparison
        self.high_risk_countries: Set[str] = (
            {c.upper() for c in high_risk_countries} if high_risk_countries else set()
        )
        self._reference_time = reference_time  # None means "use time.time() at call time"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, record: WhoisRecord) -> AgeRiskResult:
        """Score a single WhoisRecord and return an AgeRiskResult."""
        now = self._reference_time if self._reference_time is not None else time.time()
        raw_score = 0
        signals: List[str] = []
        age_days: Optional[int] = None

        # --- Signal 1: New domain or no registration date ---
        if record.registered_at is not None:
            age_seconds = now - record.registered_at
            age_days = int(age_seconds / self._SECONDS_PER_DAY)

            if age_days < self.new_domain_days:
                raw_score += self.WEIGHT_NEW_DOMAIN
                signals.append(f"New domain ({age_days} days old)")
        else:
            # No registration date available is itself a risk indicator
            raw_score += self.WEIGHT_NO_REG_DATE
            signals.append("Registration date unavailable")

        # --- Signal 2: Expires soon ---
        if record.expires_at is not None:
            days_until_expiry = int((record.expires_at - now) / self._SECONDS_PER_DAY)
            if days_until_expiry < self.expiry_soon_days:
                raw_score += self.WEIGHT_EXPIRY_SOON
                signals.append(f"Expires soon ({days_until_expiry} days)")

        # --- Signal 3: WHOIS privacy protection ---
        if record.privacy_protected:
            raw_score += self.WEIGHT_PRIVACY
            signals.append("WHOIS privacy protection")

        # --- Signal 4: High-risk registrant country ---
        if record.registrant_country and record.registrant_country.upper() in self.high_risk_countries:
            raw_score += self.WEIGHT_HIGH_RISK_COUNTRY
            signals.append(f"High-risk registrant country ({record.registrant_country.upper()})")

        # --- Signal 5: Short registration period (< 1 year between reg and expiry) ---
        if record.registered_at is not None and record.expires_at is not None:
            period_days = (record.expires_at - record.registered_at) / self._SECONDS_PER_DAY
            if period_days < self._ONE_YEAR_DAYS:
                raw_score += self.WEIGHT_SHORT_PERIOD
                signals.append("Short registration period (<1 year)")

        # Cap score at 100
        final_score = min(raw_score, 100)
        risk_level = self._classify(final_score)

        detail = self._build_detail(record.domain, final_score, risk_level, age_days, signals)

        return AgeRiskResult(
            domain=record.domain,
            risk_score=final_score,
            risk_level=risk_level,
            age_days=age_days,
            signals=signals,
            detail=detail,
        )

    def score_many(self, records: List[WhoisRecord]) -> List[AgeRiskResult]:
        """Score a list of WhoisRecords and return one AgeRiskResult per record."""
        return [self.score(record) for record in records]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify(score: int) -> str:
        """Map a numeric score to a risk level label."""
        if score >= 70:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        if score >= 10:
            return "LOW"
        return "INFO"

    @staticmethod
    def _build_detail(
        domain: str,
        score: int,
        risk_level: str,
        age_days: Optional[int],
        signals: List[str],
    ) -> str:
        """Compose a single human-readable summary sentence."""
        age_str = f"{age_days}d old" if age_days is not None else "age unknown"
        signal_count = len(signals)
        return (
            f"{domain} scored {score}/100 ({risk_level}); "
            f"{age_str}; {signal_count} signal(s) fired."
        )
