"""Basic risk scoring for discovered domains.

This module provides a small, deterministic scoring helper for triaging
potentially suspicious domains.
"""

from __future__ import annotations


def calculate_risk_score(
    *,
    similarity: float,
    dns_active: bool,
    in_ct_logs: bool,
    similarity_weight: float = 0.6,
    dns_weight: float = 0.25,
    ct_weight: float = 0.15,
) -> float:
    """Calculate a normalized risk score between 0.0 and 1.0.

    Args:
        similarity: Similarity ratio to target domain (expected 0.0..1.0).
        dns_active: Whether the candidate domain currently resolves.
        in_ct_logs: Whether domain has recent certificate transparency presence.
        similarity_weight: Weight applied to similarity contribution.
        dns_weight: Weight applied when DNS is active.
        ct_weight: Weight applied when CT presence is observed.

    Returns:
        Float risk score rounded to 4 decimals, clamped to [0.0, 1.0].
    """
    sim = max(0.0, min(1.0, float(similarity)))

    # Normalize in case custom weights do not sum to 1.0.
    total_weight = similarity_weight + dns_weight + ct_weight
    if total_weight <= 0:
        # Safe fallback: similarity-only behavior.
        total_weight = 1.0
        similarity_weight, dns_weight, ct_weight = 1.0, 0.0, 0.0

    sim_w = similarity_weight / total_weight
    dns_w = dns_weight / total_weight
    ct_w = ct_weight / total_weight

    score = (
        sim * sim_w
        + (1.0 if dns_active else 0.0) * dns_w
        + (1.0 if in_ct_logs else 0.0) * ct_w
    )

    return round(max(0.0, min(1.0, score)), 4)
