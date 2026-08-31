# SentinelSOC — Deployment

## Requirements

- Docker & Docker Compose (recommended) — see `docker-compose.yml`
- Or: Python 3.11+ and Node 20+ for manual deployment

## 1. Docker Compose (quick start)

```bash
git clone <your-repo>
cd sentinelsoc
docker compose up --build -d
```

Services:

| Service | Image | Exposed |
|---------|-------|---------|
| `db` | postgres:16-alpine | — (internal) |
| `backend` | backend/Dockerfile | `:8000` |
| `frontend` | frontend/Dockerfile (nginx) | `:8080` |

- UI: <http://localhost:8080>
- API: <http://localhost:8000/api> · Swagger: <http://localhost:8000/api/docs>

On first boot the backend **bootstraps** the default organization, an admin
user, sample assets, and the seed detection rules.

> ⚠️ Change the default admin password and `SECRET_KEY` for any real deployment
> (see `SECURITY.md`).

## 2. Manual backend deployment

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export DATABASE_URL="postgresql+psycopg2://sentinel:password@dbhost:5432/sentinelsoc"
export SECRET_KEY="$(openssl rand -hex 32)"
export ENVIRONMENT=production

uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

## 3. Manual frontend deployment

```bash
cd frontend
npm install
npm run build        # -> frontend/dist
```
Serve `frontend/dist` with any static server and proxy `/api` to the backend.
The included `nginx.conf` and `Dockerfile` do this.

## 4. Database

PostgreSQL 16 is the supported production database. The schema is created
automatically on startup (`init_db`). For schema migrations in production,
adopt Alembic (the models are already defined in `app/models.py`).

### Event volume & scaling

High-volume events go through the **`EventStore` abstraction** (`app/storage.py`),
so the `events` table can be migrated to a search/analytics datastore
(Elasticsearch / OpenSearch / ClickHouse) by providing a new `EventStore`
implementation. The detection engine's `count_in_window` and the dashboard's
`time_series` map to search-store aggregations.

To scale the API horizontally:

1. Move rate limiting to a shared store (Redis) behind `RateLimiter`.
2. Run multiple backend workers/instances behind a load balancer.
3. Offload batch ingestion to a queue/worker calling `pipeline.process_ingest`.

## 5. Continuous integration

`.github/workflows/ci.yml` runs on every push/PR:

- Backend test suite (`pytest`)
- Frontend production build (`vite build`)
- Docker image builds for backend and frontend

## 6. Environment variables

See `backend/.env.example` for the full set. Key ones:

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Database connection string |
| `SECRET_KEY` | JWT signing key (set a strong value!) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token lifetime |
| `CORS_ORIGINS` | Allowed browser origins |
| `RATE_LIMIT_ENABLED` | Master switch for rate limiting |
| `DEFAULT_ADMIN_USER/PASS/EMAIL` | First-run bootstrap admin (only when DB empty) |
| `THREATINTEL_ENABLED` | Enable threat-intel providers |

## 7. Backups & operations

- Back up the PostgreSQL volume (`pgdata`).
- Monitor `/api/health` for liveness.
- Review the Audit Log for analyst/admin activity.
- Rotate `SECRET_KEY` and database credentials regularly.
