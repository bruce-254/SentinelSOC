# SentinelSOC — Detection Rules

## Overview

Detection rules are **stored in the database** (`detection_rules` table) and are
fully configurable at runtime. Nothing is hardcoded in application logic. The
bundled rules are seeded on first boot as *configuration data*; administrators
can enable, disable, edit, prioritize, or delete them via the API or the UI.

All bundled rules detect **defensive** indicators.

## Rule anatomy

A rule is defined by:

| Field | Description |
|-------|-------------|
| `name` | Unique rule name |
| `description` | Human-readable description |
| `rule_type` | `single_event` or `aggregate` |
| `scope` | JSON limiting the events the rule considers |
| `conditions` | JSON predicate(s) the event must satisfy |
| `time_window_seconds` | Sliding window (aggregate only) |
| `threshold` | Count to cross (aggregate only) |
| `group_by` | Aggregation key: `src_ip`, `dst_ip`, `username`, `device`, `dst_port`, `source_log_type` |
| `enabled` | On/off switch |
| `priority` | 1–100 (higher = more important) |
| `severity` | `info` / `low` / `medium` / `high` / `critical` |
| `alert_title` | Alert title template (supports `{src_ip}`, `{username}`, `{dst_ip}`, `{dst_port}`) |
| `risk_weight` | Multiplier applied in risk scoring |

### Scope
```json
{ "event_types": ["authentication_failure"], "source_log_types": ["linux_auth"] }
```
Both keys are optional; empty scope matches all events.

### Conditions grammar
Conditions is a dict of `field -> predicate`, AND-ed together:

```json
{ "username": { "eq": "root" } }
{ "message": { "regex": "fail.*pass" } }
{ "dst_port": { "in": [22, 3389, 445] } }
{ "labels": { "contains": "threat_intel" } }
{ "success": { "is_false": true } }
```

Operators: `eq`, `neq`, `contains`, `in`, `regex`, `gt`, `lt`, `is_true`,
`is_false`. Shorthand `{ "field": value }` means equality.

### Aggregate example
Detect a brute-force when a source IP records ≥ 20 failed logins in 10 minutes:

```json
{
  "rule_type": "aggregate",
  "scope": { "event_types": ["authentication_failure"] },
  "conditions": {},
  "time_window_seconds": 600,
  "threshold": 20,
  "group_by": "src_ip",
  "severity": "critical"
}
```

Aggregate rules fire **once per window/group** only when the count exactly
crosses `threshold`, avoiding alert storms.

## Bundled rules

| Rule | Type | Description |
|------|------|-------------|
| Repeated Failed Logins | aggregate | ≥5 failed logins per source IP / 5 min |
| Brute-Force Password Spray | aggregate | ≥20 failed logins per source IP / 10 min |
| Account Lockout Storm | aggregate | ≥15 failures for one username / 15 min |
| Single Account Brute-Force | aggregate | ≥10 failures for one username / 5 min |
| Privilege Escalation | single | any `privilege_escalation` event |
| Privilege Escalation by Source | aggregate | ≥3 escalations per source IP / 10 min |
| Port Scan Detection | single | any `port_scan` event |
| Suspicious Process Activity | single | process activity matching PowerShell/rundll32/etc. |
| Impossible Login Distance (review) | single | auth from a monitored source (review) |
| Traffic Anomaly | single | any `traffic_anomaly` event |
| Firewall Deny to Sensitive Port | single | firewall deny toward 22/3389/445/1433/3306 |
| Threat Intelligence Hit | single | source IP matches a stored indicator |
| Unusual Authentication Time (review) | single | successful logins flagged for review |

## How detection produces alerts

For each matching event, the pipeline computes:

1. An `Alert` with a title, severity, `evidence` (rule, event fields, message),
   and the affected asset/source/user.
2. An **explainable risk score** (see `RISK` — every factor is recorded with its
   contribution and explanation in `alerts[].risk_factors`).
3. Updated entity **risk scores** (`risk_scores`) for the source IP, affected
   asset, and username.

Alerts start in `new` and are triaged by analysts through
`new → acknowledged → investigating → resolved / false_positive`.

## Managing rules

- **Admin** `POST /api/rules`, `PATCH /api/rules/{id}`,
  `POST /api/rules/{id}/enable`, `POST /api/rules/{id}/disable`,
  `DELETE /api/rules/{id}`.
- **Analyst / viewer** may read rules.

Rules are evaluated on every ingested batch, so changes take effect on the next
ingestion. To temporarily suspend a class of detections, disable the rule.
