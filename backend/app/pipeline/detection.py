"""Detection rule engine.

Rules are loaded from the database (``detection_rules`` table) — nothing is
hardcoded. Each rule has a scope (which events it considers) and conditions
(a small predicate grammar) evaluated against normalized events. Aggregate
rules count matching events within a sliding time window grouped by a key.

The engine is deterministic and testable: evaluation functions are pure given
an event and a rule.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..models import DetectionRule, NormalizedEvent
from .normalizer import EventRecord

CONDITION_OPS = {"eq", "neq", "contains", "in", "regex", "gt", "lt", "is_true", "is_false"}

FIELD_ALIASES = {
    "event_type": "event_type",
    "severity": "severity",
    "src_ip": "src_ip",
    "source_ip": "src_ip",
    "dst_ip": "dst_ip",
    "dest_ip": "dst_ip",
    "destination_ip": "dst_ip",
    "username": "username",
    "user": "username",
    "device": "device",
    "application": "application",
    "source_log_type": "source_log_type",
    "process_name": "process_name",
    "message": "message",
    "success": "success",
    "source_port": "source_port",
    "src_port": "source_port",
    "dst_port": "dst_port",
    "dest_port": "dst_port",
    "source": "source",
    "destination": "destination",
}


def _get_field(event: Any, field: str) -> Any:
    key = FIELD_ALIASES.get(field, field)
    value = getattr(event, key, None)
    if value is None:
        # labels is a JSON list
        value = event.labels if key == "labels" else None
    return value


def matches_scope(event: Any, rule: DetectionRule) -> bool:
    scope = rule.scope or {}
    event_types = scope.get("event_types")
    source_log_types = scope.get("source_log_types")
    if event_types:
        wanted = [e.lower() for e in event_types]
        if event.event_type.lower() not in wanted:
            return False
    if source_log_types:
        wanted = [s.lower() for s in source_log_types]
        if (event.source_log_type or "").lower() not in wanted:
            return False
    return True


def evaluate_conditions(event: Any, conditions: dict | None) -> bool:
    """Evaluate a predicate dict of the form {field: {op: value}} (AND-ed)."""
    if not conditions:
        return True
    for field, spec in conditions.items():
        if isinstance(spec, dict):
            op = next(iter(spec))
            value = spec[op]
            if not _apply_op(event, field, op, value):
                return False
        else:
            # shorthand {field: expected_value} => equality
            if not _apply_op(event, field, "eq", spec):
                return False
    return True


def _apply_op(event: Any, field: str, op: str, value: Any) -> bool:
    if op not in CONDITION_OPS:
        return False
    actual = _get_field(event, field)
    actual_str = str(actual).lower() if actual is not None else ""

    if op == "eq":
        return actual is not None and str(actual).lower() == str(value).lower()
    if op == "neq":
        return actual is None or str(actual).lower() != str(value).lower()
    if op == "contains":
        return actual is not None and str(value).lower() in actual_str
    if op == "in":
        return actual is not None and str(actual).lower() in {str(v).lower() for v in value}
    if op == "regex":
        if actual is None:
            return False
        try:
            return re.search(str(value), str(actual), re.IGNORECASE) is not None
        except re.error:
            return False
    if op in ("gt", "lt"):
        try:
            a = float(actual)
            b = float(value)
        except (TypeError, ValueError):
            return False
        return a > b if op == "gt" else a < b
    if op == "is_true":
        return actual is True
    if op == "is_false":
        return actual is False
    return False


def rule_matches_single(event: Any, rule: DetectionRule) -> bool:
    if not rule.enabled:
        return False
    if not matches_scope(event, rule):
        return False
    return evaluate_conditions(event, rule.conditions)


def aggregate_group_key(event: Any, rule: DetectionRule) -> str | None:
    gb = rule.group_by
    if gb in ("src_ip",):
        return event.src_ip
    if gb in ("dst_ip",):
        return event.dst_ip
    if gb in ("username", "user"):
        return event.username
    if gb in ("device",):
        return event.device
    if gb in ("dst_port",):
        return str(event.dst_port) if event.dst_port else None
    if gb in ("source_log_type",):
        return event.source_log_type
    return None


# --------------------------------------------------------------------------
# Built-in seed rules (installed once into the DB on first boot).
# These are configuration data, not hardcoded logic — admins can edit/disable.
# --------------------------------------------------------------------------
def seed_rules(db: Session, organization_id: int) -> int:
    existing = db.query(DetectionRule).filter(DetectionRule.organization_id == organization_id).count()
    if existing > 0:
        return 0

    rules = [
        {
            "name": "Repeated Failed Logins",
            "description": "More than 5 failed logins from the same source IP in 5 minutes.",
            "rule_type": "aggregate",
            "scope": {"event_types": ["authentication_failure"]},
            "conditions": {"success": {"is_false": True}},
            "time_window_seconds": 300,
            "threshold": 5,
            "group_by": "src_ip",
            "priority": 90,
            "severity": "high",
            "alert_title": "Repeated failed logins from {src_ip}",
            "risk_weight": 2.0,
        },
        {
            "name": "Brute-Force Password Spray",
            "description": "20+ failed logins from a single source IP within 10 minutes.",
            "rule_type": "aggregate",
            "scope": {"event_types": ["authentication_failure"]},
            "conditions": {},
            "time_window_seconds": 600,
            "threshold": 20,
            "group_by": "src_ip",
            "priority": 95,
            "severity": "critical",
            "alert_title": "Brute-force attack from {src_ip}",
            "risk_weight": 3.0,
        },
        {
            "name": "Account Lockout Storm",
            "description": "Same username failing authentication from many distinct IPs.",
            "rule_type": "aggregate",
            "scope": {"event_types": ["authentication_failure"]},
            "conditions": {},
            "time_window_seconds": 900,
            "threshold": 15,
            "group_by": "username",
            "priority": 85,
            "severity": "high",
            "alert_title": "Account lockout storm for {username}",
            "risk_weight": 2.2,
        },
        {
            "name": "Single Account Brute-Force",
            "description": "10+ failed logins for the same username in 5 minutes.",
            "rule_type": "aggregate",
            "scope": {"event_types": ["authentication_failure"]},
            "conditions": {},
            "time_window_seconds": 300,
            "threshold": 10,
            "group_by": "username",
            "priority": 80,
            "severity": "high",
            "alert_title": "Brute-force against account {username}",
            "risk_weight": 2.0,
        },
        {
            "name": "Privilege Escalation",
            "description": "Any event indicating privilege escalation (sudo, admin group).",
            "rule_type": "single_event",
            "scope": {"event_types": ["privilege_escalation"]},
            "conditions": {},
            "priority": 85,
            "severity": "high",
            "alert_title": "Privilege escalation detected",
            "risk_weight": 2.5,
        },
        {
            "name": "Privilege Escalation by Source",
            "description": "3+ privilege escalation events from the same source IP in 10 min.",
            "rule_type": "aggregate",
            "scope": {"event_types": ["privilege_escalation"]},
            "conditions": {},
            "time_window_seconds": 600,
            "threshold": 3,
            "group_by": "src_ip",
            "priority": 88,
            "severity": "high",
            "alert_title": "Repeated privilege escalations from {src_ip}",
            "risk_weight": 2.6,
        },
        {
            "name": "Port Scan Detection",
            "description": "Traffic classified as port scanning.",
            "rule_type": "single_event",
            "scope": {"event_types": ["port_scan"]},
            "conditions": {},
            "priority": 75,
            "severity": "medium",
            "alert_title": "Port scan activity detected",
            "risk_weight": 1.6,
        },
        {
            "name": "Suspicious Process Activity",
            "description": "New/unknown process creation activity on an endpoint.",
            "rule_type": "single_event",
            "scope": {"event_types": ["process_activity"]},
            "conditions": {"process_name": {"regex": r"(powershell|rundll32|wscript|cscript|cmd\.exe|mimikatz|net\.exe)"}},
            "priority": 70,
            "severity": "medium",
            "alert_title": "Suspicious process activity",
            "risk_weight": 1.5,
        },
        {
            "name": "Impossible Login Distance",
            "description": "Flag for review — authentication event with threat-intel / suspicious source.",
            "rule_type": "single_event",
            "scope": {"event_types": ["authentication_success", "authentication_failure"]},
            "conditions": {},
            "priority": 40,
            "severity": "low",
            "alert_title": "Authentication from monitored source",
            "risk_weight": 0.8,
        },
        {
            "name": "Traffic Anomaly",
            "description": "Events classified as abnormal traffic patterns.",
            "rule_type": "single_event",
            "scope": {"event_types": ["traffic_anomaly"]},
            "conditions": {},
            "priority": 60,
            "severity": "medium",
            "alert_title": "Abnormal traffic pattern detected",
            "risk_weight": 1.4,
        },
        {
            "name": "Firewall Deny to Sensitive Port",
            "description": "Firewall denies toward sensitive service ports (22/3389/445/1433/3306).",
            "rule_type": "single_event",
            "scope": {"event_types": ["firewall_deny"]},
            "conditions": {"dst_port": {"in": [22, 3389, 445, 1433, 3306]}},
            "priority": 65,
            "severity": "medium",
            "alert_title": "Firewall denied access to sensitive port",
            "risk_weight": 1.3,
        },
        {
            "name": "Threat Intelligence Hit",
            "description": "Event source IP matches a known threat-intel indicator.",
            "rule_type": "single_event",
            "scope": {"event_types": ["authentication_failure", "network_connection", "firewall_deny"]},
            "conditions": {"labels": {"contains": "threat_intel"}},
            "priority": 90,
            "severity": "high",
            "alert_title": "Threat intelligence indicator matched",
            "risk_weight": 2.4,
        },
        {
            "name": "Unusual Authentication Time",
            "description": "Successful login outside of normal hours (flag low) — configurable review.",
            "rule_type": "single_event",
            "scope": {"event_types": ["authentication_success"]},
            "conditions": {},
            "priority": 30,
            "severity": "low",
            "alert_title": "Authentication event for review",
            "risk_weight": 0.5,
        },
    ]

    count = 0
    for r in rules:
        db.add(DetectionRule(organization_id=organization_id, **r))
        count += 1
    db.flush()
    return count
