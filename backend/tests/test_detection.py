"""Tests for the detection rule engine."""
from app.models import DetectionRule, NormalizedEvent
from app.pipeline.detection import (
    aggregate_group_key,
    evaluate_conditions,
    matches_scope,
    rule_matches_single,
)


def make_event(**kw):
    fields = {
        "organization_id": 1,
        "timestamp": "2024-01-01T00:00:00",
        "event_type": "authentication_failure",
        "severity": "medium",
        "src_ip": "203.0.113.10",
        "dst_ip": "10.0.0.5",
        "username": "root",
        "device": "web01",
        "application": "ssh",
        "message": "failed password",
        "source_log_type": "linux_auth",
        "success": False,
        "labels": [],
    }
    fields.update(kw)
    return NormalizedEvent(**fields)


def make_rule(**kw):
    fields = {
        "organization_id": 1,
        "name": "test",
        "rule_type": "single_event",
        "scope": {},
        "conditions": {},
        "enabled": True,
        "priority": 50,
        "severity": "medium",
        "risk_weight": 1.0,
    }
    fields.update(kw)
    return DetectionRule(**fields)


def test_single_rule_match_by_event_type():
    rule = make_rule(scope={"event_types": ["authentication_failure"]})
    ev = make_event()
    assert rule_matches_single(ev, rule)


def test_single_rule_no_match_when_disabled():
    rule = make_rule(scope={"event_types": ["authentication_failure"]}, enabled=False)
    assert not rule_matches_single(make_event(), rule)


def test_condition_equality():
    rule = make_rule(conditions={"username": {"eq": "root"}})
    assert rule_matches_single(make_event(username="root"), rule)
    assert not rule_matches_single(make_event(username="other"), rule)


def test_condition_regex():
    rule = make_rule(conditions={"message": {"regex": r"fail.*pass"}})
    assert rule_matches_single(make_event(message="failed password attempt"), rule)


def test_condition_in():
    rule = make_rule(conditions={"dst_port": {"in": [22, 3389]}})
    assert rule_matches_single(make_event(dst_port=22), rule)
    assert not rule_matches_single(make_event(dst_port=8080), rule)


def test_condition_contains_labels():
    rule = make_rule(conditions={"labels": {"contains": "threat_intel"}})
    assert rule_matches_single(make_event(labels=["threat_intel"]), rule)


def test_scope_source_log_type():
    rule = make_rule(scope={"source_log_types": ["linux_auth"]})
    assert matches_scope(make_event(), rule)
    assert not matches_scope(make_event(source_log_type="windows_event"), rule)


def test_aggregate_group_key():
    rule = make_rule(rule_type="aggregate", group_by="src_ip")
    assert aggregate_group_key(make_event(src_ip="1.2.3.4"), rule) == "1.2.3.4"


def test_evaluate_empty_conditions_true():
    assert evaluate_conditions(make_event(), None) is True
    assert evaluate_conditions(make_event(), {}) is True
