"""Authentication and authorization primitives.

Passwords are stored as bcrypt hashes (never plaintext). API access uses
signed JSON Web Tokens. Role-based access control is enforced at the API layer
via the ``require_role`` dependency.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from .config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


def create_access_token(user_id: int, organization_id: int, role: str, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "org": organization_id,
        "role": role,
        "username": username,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError:
        return None


# --- Authorization helpers ------------------------------------------------
ROLE_PRIORITY = {"viewer": 1, "analyst": 2, "admin": 3}


def role_at_least(actual: str, required: str) -> bool:
    return ROLE_PRIORITY.get(actual, 0) >= ROLE_PRIORITY.get(required, 99)


def can(action: str, role: str) -> bool:
    """Simple RBAC capability matrix.

    - viewer: read-only
    - analyst: read + triage (update alerts/incidents, run reports, view audit)
    - admin: full management (users, rules, assets, org)
    """
    if action in {"read"}:
        return True
    if role == "viewer":
        return False
    if role == "analyst":
        allowed = {
            "update_alert", "update_incident", "create_incident", "create_note",
            "view_audit", "ingest", "run_report",
        }
        return action in allowed
    if role == "admin":
        return True
    return False
