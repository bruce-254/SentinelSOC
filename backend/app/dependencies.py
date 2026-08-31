"""FastAPI dependencies for authentication and authorization."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .core.errors import PermissionError, Unauthorized
from .database import get_db
from .models import User
from .security import can, decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise Unauthorized("Missing bearer token")
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise Unauthorized("Invalid or expired token")
    try:
        user_id = int(payload["sub"])
        org_id = int(payload["org"])
    except (KeyError, TypeError, ValueError):
        raise Unauthorized("Malformed token")
    user = db.get(User, user_id)
    if user is None or user.organization_id != org_id:
        raise Unauthorized("User not found")
    if not user.is_active:
        raise PermissionError("Account disabled")
    return user


def require_action(action: str):
    """Dependency factory enforcing RBAC by action name."""

    def _dep(user: User = Depends(get_current_user)) -> User:
        if not can(action, user.role):
            raise PermissionError(
                f"Role '{user.role}' is not allowed to perform '{action}'"
            )
        return user

    return _dep


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise PermissionError("Administrator role required")
    return user
