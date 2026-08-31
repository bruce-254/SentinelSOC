# SentinelSOC — REST API

Base URL: `/api` (Swagger UI at `/api/docs`).

All endpoints except `/auth/login`, `/health` require a bearer token:
`Authorization: Bearer <jwt>`.

## Authentication

| Method | Path | Description | RBAC |
|--------|------|-------------|------|
| POST | `/auth/login` | Login → `{access_token, expires_in}` | public |
| GET | `/auth/me` | Current user | any |
| POST | `/auth/change-password` | Change own password | any |

## Organizations (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/organizations` | List organizations |
| POST | `/organizations` | Create organization |
| GET | `/organizations/{id}` | Get organization |

## Users (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/users` | List users in org |
| POST | `/users` | Create user |
| GET | `/users/{id}` | Get user |
| PATCH | `/users/{id}` | Update user (role, active, password) |

## Assets

| Method | Path | Description | RBAC |
|--------|------|-------------|------|
| GET | `/assets` | List assets | any |
| POST | `/assets` | Create asset | analyst+ |
| GET | `/assets/{id}` | Get asset | any |
| PATCH | `/assets/{id}` | Update asset | analyst+ |
| DELETE | `/assets/{id}` | Delete asset | analyst+ |

## Events

| Method | Path | Description | RBAC |
|--------|------|-------------|------|
| POST | `/events/ingest` | Ingest a batch of raw logs | analyst+ |
| GET | `/events/search` | Search normalized events | any |
| GET | `/events/meta` | Filter metadata (types, sources, severities) | any |
| GET | `/events/timeline` | Event rate timeline series | any |

### Ingest
Request:
```json
{
  "entries": [
    { "source_log_type": "linux_auth", "raw": "Jun 12 08:00:01 srv sshd[1]: Failed password for root from 203.0.113.10 port 22 ssh2" }
  ]
}
```
Supported `source_log_type` values: `linux_auth`, `windows_event`, `web_server`,
`firewall`, `application`, `csv`, `json`.

Response:
```json
{ "accepted": 1, "normalized": 1, "alerts": 2, "rejected": 0, "errors": [] }
```

### Search
Query params: `q`, `time_from`, `time_to`, `src_ip`, `dst_ip`, `username`,
`event_type`, `severity`, `source_log_type`, `page`, `page_size`.

## Detection Rules

| Method | Path | Description | RBAC |
|--------|------|-------------|------|
| GET | `/rules` | List rules | any |
| POST | `/rules` | Create rule | admin |
| GET | `/rules/{id}` | Get rule | any |
| PATCH | `/rules/{id}` | Update rule | admin |
| POST | `/rules/{id}/enable` | Enable rule | admin |
| POST | `/rules/{id}/disable` | Disable rule | admin |
| DELETE | `/rules/{id}` | Delete rule | admin |

## Alerts

| Method | Path | Description | RBAC |
|--------|------|-------------|------|
| GET | `/alerts` | List/triage queue | any |
| GET | `/alerts/{id}` | Alert detail incl. risk factors | any |
| PATCH | `/alerts/{id}` | Update status (new/acknowledged/investigating/resolved/false_positive) | analyst+ |

## Incidents

| Method | Path | Description | RBAC |
|--------|------|-------------|------|
| GET | `/incidents` | List incidents | any |
| POST | `/incidents` | Create incident | analyst+ |
| GET | `/incidents/{id}` | Incident detail + notes timeline | any |
| PATCH | `/incidents/{id}` | Update status/severity/assignee | analyst+ |
| POST | `/incidents/{id}/notes` | Add analyst note | analyst+ |

Incident statuses: `open`, `investigating`, `contained`, `resolved`, `closed`.

## Dashboard / Ops

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard?window_minutes=60` | Aggregated dashboard statistics |
| GET | `/risk` | Entity risk scores (explainable) |
| GET | `/risk/{entity_type}/{entity_id}` | Risk detail with factor explanations + related alerts |
| POST | `/reports/generate` | Generate summary report |
| GET | `/audit` | Audit log |
| GET | `/threatintel` | Stored indicators |
| GET | `/threatintel/providers` | Registered providers |
| POST | `/threatintel/sync` | Fetch & persist indicators from active providers |
| GET | `/health` | Liveness check |

## Common schema (normalized event)

| Field | Description |
|-------|-------------|
| `timestamp` | UTC event time |
| `event_type` | Normalized event type |
| `severity` | info / low / medium / high / critical |
| `src_ip` / `dst_ip` | Source / destination IP |
| `username` | Affected user |
| `source` / `destination` | Human-friendly source / destination |
| `device` | Hostname / device |
| `application` | Application / service |
| `message` | Raw or parsed message |
| `source_log_type` | Original log source |
| `success` | Boolean where applicable |
| `labels` | Enrichment labels (e.g. `threat_intel`) |
