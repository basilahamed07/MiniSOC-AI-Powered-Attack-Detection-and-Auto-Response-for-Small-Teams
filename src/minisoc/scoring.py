"""Transparent risk scoring for the offline MiniSOC prototype."""

from __future__ import annotations

from .models import Alert

BASE_RISK: dict[str, int] = {
    "brute_force": 65,
    "port_scan": 50,
    "sql_injection": 85,
    "path_traversal": 75,
}


def risk_score(alert: Alert) -> int:
    """Calculate a deterministic 0-100 score from rule type and evidence size.

    The formula is deliberately small and explainable: a rule baseline plus up
    to fifteen points for additional evidence, capped at 100.
    """

    try:
        base = BASE_RISK[alert.attack_type]
    except KeyError as exc:
        raise ValueError(f"unsupported attack type: {alert.attack_type}") from exc
    evidence_bonus = min(15, max(0, len(alert.evidence) - 1) * 2)
    return min(100, base + evidence_bonus)
