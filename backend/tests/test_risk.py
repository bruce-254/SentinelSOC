"""Tests for explainable risk scoring."""
from app.models import Asset, DetectionRule
from app.pipeline.risk import compute_alert_risk, level_for


def make_rule(weight=1.0, priority=50):
    return DetectionRule(
        organization_id=1, name="rule", rule_type="single_event",
        scope={}, conditions={}, enabled=True, priority=priority,
        severity="medium", risk_weight=weight,
    )


def make_asset(criticality="medium"):
    return Asset(organization_id=1, name="a", ip_address="10.0.0.1",
                 criticality=criticality)


def test_score_within_bounds():
    rule = make_rule()
    score, factors = compute_alert_risk(severity="critical", rule=rule, asset=None)
    assert 0 <= score <= 100
    assert factors, "must produce explainable factors"


def test_higher_severity_higher_score():
    low = compute_alert_risk(severity="low", rule=make_rule(), asset=None)[0]
    crit = compute_alert_risk(severity="critical", rule=make_rule(), asset=None)[0]
    assert crit > low


def test_critical_asset_increases_score():
    no_asset = compute_alert_risk(severity="high", rule=make_rule(), asset=None)[0]
    crit_asset = compute_alert_risk(
        severity="high", rule=make_rule(), asset=make_asset("critical"))[0]
    assert crit_asset > no_asset


def test_risk_weight_multiplier():
    base = compute_alert_risk(severity="high", rule=make_rule(weight=1.0), asset=None)[0]
    heavy = compute_alert_risk(severity="high", rule=make_rule(weight=2.5), asset=None)[0]
    assert heavy > base


def test_threat_intel_bonus():
    no_intel = compute_alert_risk(
        severity="medium", rule=make_rule(), asset=None, is_threat_intel=False)[0]
    with_intel = compute_alert_risk(
        severity="medium", rule=make_rule(), asset=None, is_threat_intel=True)[0]
    assert with_intel > no_intel


def test_explanations_present():
    _, factors = compute_alert_risk(
        severity="high", rule=make_rule(priority=90),
        asset=make_asset("critical"), volume=6,
    )
    names = {f["factor"] for f in factors}
    for expected in ("severity", "rule_weight", "rule_priority",
                     "asset_criticality", "event_volume"):
        assert expected in names
    for f in factors:
        assert f["contribution"] is not None
        assert f["explanation"]


def test_level_for():
    assert level_for(85) == "critical"
    assert level_for(65) == "high"
    assert level_for(10) == "info"
