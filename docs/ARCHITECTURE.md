# SentinelSOC — Architecture

This document describes the design of the SentinelSOC platform.

## Overview

SentinelSOC is a classic three-tier defensive SIEM:

```
 Browser (React SPA)  ── HTTP/JSON ──>  FastAPI (REST)  ──>  PostgreSQL
                         (proxied)                          (relational store)
```

```
 Input ─> Ingestion ─> Parsing ─> Normalization ─> Enrichment
        ─> Detection ─> Alert ─> Incident
```

## Components

### Frontend (`frontend/`)
A single-page React application (Vite) with a professional SOC-style dark UI.

- **Routing:** `react-router-dom`; protected routes gate on the JWT.
- **Data layer:** `src/api.js` attaches the Bearer token and normalizes errors.
- **Auth context:** `src/auth.jsx` stores/refreshes the session.
- **Pages:** Dashboard, Search, Events, Alerts (+detail), Incidents (+detail),
  Detection Rules, Risk Scoring, Assets, Reports, Audit Log, Threat Intel, Users.
- **Charts:** `recharts` (area, bar, pie) — all fed by real API aggregations.

### Backend (`backend/app/`)
A modular FastAPI application.

| Module | Responsibility |
|--------|----------------|
| `api/` | REST routers: auth, users, organizations, assets, events, rules, alerts, incidents, dashboard/risk/reports/audit/threat-intel |
| `pipeline/` | The ingestion→detection pipeline |
| `parsers.py` | One defensive parser per log source |
| `normalizer.py` | Maps parsed records into the common schema + enrichment |
| `detection.py` | Rule engine (single-event & aggregate) |
| `risk.py` | Explainable risk scoring |
| `pipeline.py` | Orchestrator: parse → normalize → store → detect → alert |
| `storage.py` | Event-storage abstraction |
| `threatintel/` | Pluggable threat-intel provider interface |
| `security.py` | Password hashing, JWT, RBAC capability matrix |
| `bootstrap.py` | First-run defaults (org, admin, seed rules) |

### Database (`app/models.py`)
All models are **organization-scoped** for multi-tenant isolation. Key tables:

- `organizations`, `users`, `assets`
- `events` — the high-volume normalized event store
- `detection_rules` — configurable rules (never hardcoded)
- `alerts` + `risk_factors` — alerts with explainable scoring
- `incidents` + `incident_notes`
- `risk_scores` — entity risk with factor explanations
- `audit_logs` — analyst/admin actions
- `threat_intel` — indicators from configured providers

## The log pipeline in detail

1. **Ingestion** — `POST /api/events/ingest` accepts a batch of `{source_log_type, raw}` records.
2. **Parsing** — the matching parser converts raw text into structured fields
   (`parsers.py`). Malformed lines raise `ParseError` and are counted as rejected
   without killing the batch.
3. **Normalization** — `normalize()` validates/coerces fields into the common schema,
   strips invalid IPs, normalizes usernames, and classifies `generic` events into
   useful `event_type`s from message content.
4. **Enrichment** — the normalizer attaches asset context and threat-intel labels.
5. **Detection** — the engine loads rules from `detection_rules`. Single-event rules
   match a condition against one event. Aggregate rules count matching events in a
   sliding window grouped by a key and fire when the count crosses `threshold`.
6. **Alert** — matched detections produce an `Alert` with evidence, a computed risk
   score, and recorded risk factors.
7. **Incident** — analysts promote alerts into incidents and drive them through the
   lifecycle. (Purely analyst-driven — incidents are never auto-created by default.)

## Event storage & scalability

High-volume events live in the `events` table. All reads and writes go through the
**`EventStore` abstraction** in `app/storage.py`. The interface (`bulk_write`,
`search`, `count_in_window`, `time_series`) is designed so that the table can later
be migrated to a search/analytics datastore (Elasticsearch, ClickHouse, OpenSearch)
by providing a new `EventStore` implementation — the API, detection, and dashboard
layers do not depend on SQL directly.

`count_in_window` and `time_series` are used by detection and dashboards; in a
scaled deployment these map naturally to search-store aggregation APIs.

## Detection rule grammar

- **Scope** — JSON `{ "event_types": [...], "source_log_types": [...] }` limits which events a rule considers.
- **Conditions** — a JSON predicate dict, AND-ed:
  - `{ "field": { "eq": value } }`, `neq`, `contains`, `in`, `regex`, `gt`, `lt`, `is_true`, `is_false`
  - shorthand `{ "field": value }` means equality.
- **Aggregate** — requires `time_window_seconds`, `threshold`, `group_by`
  (`src_ip`, `dst_ip`, `username`, `device`, `dst_port`, `source_log_type`).

## Threat intelligence

`app/threatintel/base.py` defines a `ThreatIntelProvider` with an async `fetch()`
that returns `Indicator` objects. Providers are registered in a `Registry` and
persisted to `threat_intel`. A bundled **demo provider returns an empty dataset** so
the plumbing works end-to-end without fabricating indicators. Add a real provider
(abuse.ch, AlienVault OTX, MISP, …) by implementing the same interface.

## Multi-tenancy & security boundaries

- Every query is filtered by `organization_id` derived from the authenticated JWT.
- RBAC is enforced via `require_action(...)` / `require_admin` dependencies
  (see `SECURITY.md`).
- Audit entries record the acting user, action, resource, and client IP.

## Testing strategy

The suite (`backend/tests/`) runs against an in-memory SQLite database:

- `test_parsers.py` — each log-source parser
- `test_normalizer.py` — common schema & event classification
- `test_detection.py` — rule engine evaluation
- `test_risk.py` — explainable scoring
- `test_auth.py` — login, password change, token validation
- `test_authz.py` — RBAC enforcement across roles
- `test_api.py` — rules/alerts/incidents/assets/audit/risk/threat-intel endpoints
- `test_pipeline.py` — end-to-end ingest → detect → alert
