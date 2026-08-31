# SentinelSOC — Security

This document describes the security model of SentinelSOC and how to harden a
deployment. SentinelSOC is a **defensive** tool; it contains no offensive
capabilities.

## Authentication

- Passwords are hashed with **bcrypt** (`passlib`), never stored in plaintext
  and never logged.
- API access uses signed **JWT** bearer tokens (HS256) with a configurable
  expiry (`ACCESS_TOKEN_EXPIRE_MINUTES`, default 60).
- The login endpoint is protected by a **strict per-IP rate limiter**
  (`AUTH_RATE_LIMIT` / `AUTH_RATE_WINDOW_SECONDS`, default 10 attempts / 5 min)
  to slow credential-stuffing against the platform itself.
- Failed logins return the same generic error whether the username or password
  is wrong, so the API does not leak which accounts exist.
- Users may change their own password (`POST /api/auth/change-password`).

## Authorization (RBAC)

Roles: `viewer` (read-only) < `analyst` (triage/ingest) < `admin` (manage).

| Action | viewer | analyst | admin |
|--------|:------:|:-------:|:-----:|
| Read (events, alerts, incidents, rules, dashboard) | ✅ | ✅ | ✅ |
| Ingest events / manage assets | | ✅ | ✅ |
| Triage alerts / manage incidents / add notes | | ✅ | ✅ |
| Run reports / view audit | | ✅ | ✅ |
| Manage detection rules, users, organizations | | | ✅ |

Authorization is enforced centrally through FastAPI dependencies
(`require_action(...)`, `require_admin`) — it is not left to the client.

## Multi-tenant isolation

Every table row is scoped by `organization_id`, and every query filters on the
organization derived from the authenticated user's token. A user can never read
or modify data belonging to another organization.

## Input validation

- All request bodies are validated with **Pydantic** schemas (length, format,
  enum, regex constraints).
- IP addresses are validated with `ipaddress`; usernames are sanitized.
- Log lines are parsed defensively; malformed input is rejected without
  crashing the pipeline.

## Rate limiting

A global per-IP limiter (`API_RATE_LIMIT` / `API_RATE_WINDOW_SECONDS`) protects
authenticated APIs. The in-process limiter is suitable for a single instance;
for horizontal scaling, replace `RateLimiter` with a Redis-backed implementation
behind the same interface (`app/core/rate_limit.py`).

## Secure logging

- `app/core/logging.py` **redacts** passwords, tokens, and secrets from logs and
  truncates long values (`SECURE_LOGGING=true`).
- Secrets are never logged (password/token/secret fields are stripped).
- Audit log captures analyst/admin actions with actor, action, resource, IP.

## Secrets management

- The signing key comes from `SECRET_KEY`. **You must set a strong random value
  in production** (e.g. `openssl rand -hex 32`). The default value is for local
  development only.
- Database credentials come from environment variables / Docker secrets, never
  from committed files. `.env` is git-ignored.

## Defensive posture

- All detection rules are **defensive indicators only** (failed logins,
  brute-force patterns, privilege escalation, scanning, anomalies). There is no
  exploit, payload-generation, or attack tooling anywhere in the codebase.
- The threat-intel integration **never fabricates** indicators of compromise;
  the bundled dev provider returns an empty dataset.

## Production hardening checklist

- [ ] Set a strong `SECRET_KEY` (env / Docker secret).
- [ ] Change the default admin password immediately after first login.
- [ ] Disable the demo/`admin12345` bootstrap default by setting
      `DEFAULT_ADMIN_PASS` on first boot (bootstrap only runs when the DB is empty).
- [ ] Run behind TLS (reverse proxy terminating HTTPS).
- [ ] Restrict `CORS_ORIGINS` to the real UI origin(s).
- [ ] Use PostgreSQL with a dedicated, least-privilege DB user.
- [ ] Keep `THREATINTEL_ENABLED=false` unless a real provider is configured.
- [ ] Add network-level firewalling / IP allow-lists for the API.
- [ ] Replace the in-process rate limiter with a distributed one if scaling horizontally.
