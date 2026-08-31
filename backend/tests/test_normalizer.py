"""Tests for event normalization."""
from app.pipeline.normalizer import normalize, classify_event_type


def test_normalize_common_schema():
    parsed = {
        "timestamp": "2024-06-12T08:00:00Z",
        "event_type": "authentication_failure",
        "severity": "medium",
        "src_ip": "203.0.113.10",
        "username": "root",
        "device": "web01",
        "application": "ssh",
        "message": "failed password for root",
        "source_log_type": "linux_auth",
    }
    ev = normalize(parsed, organization_id=1, raw="raw line")
    assert ev.event_type == "authentication_failure"
    assert ev.severity == "medium"
    assert ev.src_ip == "203.0.113.10"
    assert ev.username == "root"
    assert ev.device == "web01"
    assert ev.organization_id == 1
    assert ev.timestamp is not None


def test_classify_generic_privilege():
    assert classify_event_type("generic", "user added to administrators group", None) == \
        "privilege_escalation"


def test_classify_generic_scan():
    assert classify_event_type("generic", "port scan detected on host", None) == "port_scan"


def test_invalid_ip_stripped():
    parsed = {"src_ip": "not-an-ip", "event_type": "generic", "severity": "info"}
    ev = normalize(parsed, organization_id=1, raw="x")
    assert ev.src_ip is None
