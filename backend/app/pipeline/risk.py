"""Explainable risk scoring.

A risk score is computed as a weighted sum of named factors. Every factor is
recorded with its contribution and a human-readable explanation so analysts
can always see WHY a score was produced (``alerts[].risk_factors`` and the
``/risk`` endpoints).

Score formula (0..100):

    score = round(
        base(severity) * rule.weight
        + rule.priority_bonus
        + asset_criticality_bonus
        + threat_intel_bonus
        + volume_bonus
    , 1)

All contributions are clamped so the final score stays within [0, 100].
"""
from __future__ import annotations

from typing import Any

from ..models import Asset, DetectionRule, RiskFactor, RiskScore

SEVERITY_BASE = {"info": 10, "low": 20, "medium": 35, "high": 55, "critical": 75}
ASSET_CRITICALITY_BONUS = {"info": 0, "low": 2, "medium": 6, "high": 10, "critical": 15}

LEVELS = [
    (80, "critical"),
    (60, "high"),
    (40, "medium"),
    (20, "low"),
]


def level_for(score: float) -> str:
    for threshold, level in LEVELS:
        if score >= threshold:
            return level
    return "info"


def compute_alert_risk(
    *,
    severity: str,
    rule: DetectionRule | None,
    asset: Asset | None,
    is_threat_intel: bool = False,
    volume: int = 0,
    threat_count: int = 0,
) -> tuple[float, list[dict]]:
    """Return (score, factors). factors is a list of {factor, contribution, explanation}."""
    factors: list[dict] = []

    base = SEVERITY_BASE.get(severity, 20)
    factors.append({
        "factor": "severity",
        "contribution": round(base, 1),
        "explanation": f"Alert severity '{severity}' has a base score of {base}.",
    })

    weight = rule.risk_weight if rule else 1.0
    weighted = base * weight
    factors.append({
        "factor": "rule_weight",
        "contribution": round(weighted - base, 1),
        "explanation": (
            f"Detection rule '{rule.name if rule else 'unknown'}' applies a "
            f"risk multiplier of {weight} (base {base} -> {round(weighted,1)})."
        ),
    })

    priority_bonus = 0.0
    if rule:
        priority_bonus = (rule.priority / 100.0) * 20.0
        factors.append({
            "factor": "rule_priority",
            "contribution": round(priority_bonus, 1),
            "explanation": (
                f"Rule priority {rule.priority}/100 contributes up to 20 points "
                f"(got {round(priority_bonus,1)})."
            ),
        })

    asset_bonus = 0.0
    if asset:
        asset_bonus = ASSET_CRITICALITY_BONUS.get(asset.criticality, 0)
        factors.append({
            "factor": "asset_criticality",
            "contribution": round(asset_bonus, 1),
            "explanation": (
                f"Affected asset '{asset.name}' has criticality "
                f"'{asset.criticality}' (+{asset_bonus})."
            ),
        })

    intel_bonus = 15.0 if is_threat_intel else 0.0
    if is_threat_intel:
        factors.append({
            "factor": "threat_intelligence",
            "contribution": 15.0,
            "explanation": "A matching threat-intelligence indicator was found.",
        })

    volume_bonus = 0.0
    if volume > 1:
        volume_bonus = min(volume, 10) * 2.0
        factors.append({
            "factor": "event_volume",
            "contribution": round(volume_bonus, 1),
            "explanation": (
                f"The alert is backed by {volume} matching events "
                f"(+{round(volume_bonus,1)})."
            ),
        })

    if threat_count:
        factors.append({
            "factor": "threat_count",
            "contribution": min(threat_count, 5) * 2.0,
            "explanation": f"Indicator observed {threat_count} times.",
        })

    total = sum(f["contribution"] for f in factors)
    score = round(min(max(total, 0.0), 100.0), 1)
    return score, factors


def persist_alert_risk(db, alert: Any, factors: list[dict]) -> None:
    for f in factors:
        db.add(RiskFactor(
            alert_id=alert.id,
            factor=f["factor"],
            contribution=round(float(f["contribution"]), 1),
            explanation=f["explanation"],
        ))


def upsert_risk_score(
    db,
    *,
    organization_id: int,
    entity_type: str,
    entity_id: str,
    entity_label: str | None,
    score: float,
    factors: list[dict],
) -> RiskScore:
    existing = (
        db.query(RiskScore)
        .filter(
            RiskScore.organization_id == organization_id,
            RiskScore.entity_type == entity_type,
            RiskScore.entity_id == entity_id,
        )
        .first()
    )
    if existing is None:
        existing = RiskScore(
            organization_id=organization_id,
            entity_type=entity_type,
            entity_id=entity_id,
        )
        db.add(existing)
    existing.entity_label = entity_label
    existing.score = score
    existing.level = level_for(score)
    existing.factors = [
        {"factor": f["factor"], "contribution": f["contribution"], "explanation": f["explanation"]}
        for f in factors
    ]
    db.flush()
    return existing
