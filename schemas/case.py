"""
Brand monitoring case models.

A BrandFinding represents a detected lookalike domain.
Cases aggregate findings for a brand monitoring session.
"""
from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class RiskLevel(str, Enum):
    CRITICAL = "critical"   # Resolves + very high similarity
    HIGH = "high"           # Resolves + high similarity
    MEDIUM = "medium"       # Does not resolve but high similarity
    LOW = "low"             # Low similarity regardless of resolution
    INFO = "info"


class CaseStatus(str, Enum):
    OPEN = "open"
    UNDER_REVIEW = "under_review"
    TAKEDOWN_REQUESTED = "takedown_requested"
    RESOLVED = "resolved"
    MONITORING = "monitoring"


class BrandFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    brand_domain: str
    lookalike_domain: str
    technique: str
    similarity_score: float
    resolves: bool
    a_records: list[str] = Field(default_factory=list)
    risk_level: RiskLevel
    status: CaseStatus = CaseStatus.OPEN
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""


def compute_risk(similarity: float, resolves: bool) -> RiskLevel:
    """
    Determine risk level from similarity score and DNS resolution status.

    Args:
        similarity: SequenceMatcher ratio (0.0–1.0).
        resolves:   Whether the domain currently resolves in DNS.

    Returns:
        RiskLevel enum value.
    """
    if resolves and similarity >= 0.85:
        return RiskLevel.CRITICAL
    if resolves and similarity >= 0.70:
        return RiskLevel.HIGH
    if not resolves and similarity >= 0.80:
        return RiskLevel.MEDIUM
    if similarity >= 0.60:
        return RiskLevel.LOW
    return RiskLevel.INFO
