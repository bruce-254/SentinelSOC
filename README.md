# 🛡️ SentinelSOC

**SentinelSOC** is a production-quality, defensive Security Information and Event Management (SIEM) platform built from scratch. It collects, parses, normalizes, enriches, detects on, and visualizes security events across your infrastructure.

> This is a **defensive** monitoring system only. It provides no offensive exploitation capabilities.

---

## Features

| Area | Capabilities |
|------|--------------|
| **Authentication** | Secure bcrypt password hashing, signed JWT sessions, strict auth rate limiting |
| **Organizations** | Multi-tenant scoping — every row belongs to an organization |
| **Users & RBAC** | Roles `admin` / `analyst` / `viewer` enforced at the API layer |
| **Assets** | Asset inventory with criticality used for enrichment & risk scoring |
| **Log ingestion** | Linux auth, Windows event, web server, firewall, application, CSV, and JSON logs |
| **Parsing** | A dedicated, defensive parser per log source |
| **Normalization** | Common schema: `timestamp, source, destination, username, ip, event_type, severity, device, application, message` |
| **Enrichment** | Asset matching, event-type reclassification, threat-intel labels |
| **Detection** | Database-backed rule engine (single-event and aggregate/threshold rules) |
| **Alerts** | Severities LOW / MEDIUM / HIGH / CRITICAL with rule, evidence, risk score, status |
| **Incidents** | Analyst lifecycle: OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED |
| **Risk scoring** | Explainable, weighted scoring with per-factor contributions |
| **Dashboards** | Events/min, alerts, critical alerts, top IPs, top assets, failed logins, auth trends, severity & status distributions |
| **Search** | Fast filtered event search (time, IP, username, asset, severity, event type, full text) |
| **Rule engine** | Rules stored in the database — enable / disable / edit / prioritize |
| **Threat intelligence** | Extensible provider interface; no fabricated indicators |
| **Audit** | Every analyst & admin action is recorded |
| **Reports** | Operational summary reports generated from live data |

---

## Quick start (Docker Compose)

```bash
docker compose up --build
```

- Web UI → <http://localhost:8080>
- REST API → <http://localhost:8000/api>  (Swagger at <http://localhost:8000/api/docs>)
- Default login: **`admin` / `admin12345`** (change immediately in production)

### Local development (no Docker)

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload          # http://localhost:8000

# Seed demo data (optional)
DATABASE_URL=sqlite:///./sentinel.db python -m scripts.seed_demo

# Frontend
cd frontend
npm install
npm run dev                            # http://localhost:5173 (proxies /api to :8000)
```

---

## Log pipeline

```
Input  →  Ingestion  →  Parsing  →  Normalization  →  Enrichment
      →  Detection  →  Alert  →  Incident
```

Every event flows through this pipeline in `backend/app/pipeline/`. Results are written to the database and reflected in the UI — **nothing displayed is mocked or fabricated**.

---

## Repository layout

```
backend/                 FastAPI application
  app/
    api/                 HTTP endpoints
    pipeline/            parsers, normalizer, detection engine, risk, orchestrator
    threatintel/         pluggable provider interface
    storage.py           event-storage abstraction (migratable to a search store)
  tests/                 pytest suite (parsing, normalization, detection, risk, auth, RBAC, API)
  scripts/seed_demo.py   load bundled sample logs
frontend/                React + Vite SOC-style UI (dark mode)
data/samples/            realistic sample security logs
docs/                    architecture & operations guides
ci/ci.yml                GitHub Actions workflow (move to .github/workflows/ to activate)
docker-compose.yml       PostgreSQL + API + UI
```

---

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — system design & data flow
- [SECURITY.md](docs/SECURITY.md) — security model, hardening, threat model
- [DETECTION-RULES.md](docs/DETECTION-RULES.md) — rule engine & bundled detections
- [API.md](docs/API.md) — REST API reference
- [DEPLOYMENT.md](docs/DEPLOYMENT.md) — deploying to production

---

## Testing

```bash
cd backend
pytest -v        # 70+ tests: parsing, normalization, detection, risk, auth, RBAC, API
```

---

## Tech stack

- **Backend:** Python, FastAPI, SQLAlchemy, Pydantic, JWT, bcrypt
- **Database:** PostgreSQL (SQLite for local dev / tests)
- **Frontend:** React, Vite, recharts
- **Ops:** Docker, Docker Compose, GitHub Actions

## License

Defensive security tooling for authorized security operations.
