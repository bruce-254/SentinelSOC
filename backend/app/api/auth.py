"""Authentication endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..config import settings
from ..core.audit import record_audit
from ..core.errors import Unauthorized
from ..core.rate_limit import RateLimiter
from ..database import get_db
from ..dependencies import get_current_user
from ..models import Organization, User
from ..schemas import LoginRequest, Token, UserOut
from ..security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

# Auth endpoints get a tighter rate limit (defensive against credential
# stuffing on the login endpoint itself).
login_limiter = RateLimiter(
    max_requests=settings.auth_rate_limit,
    window_seconds=settings.auth_rate_window_seconds,
    name="auth-login",
)


@router.post("/login", response_model=Token)
async def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    if settings.rate_limit_enabled:
        allowed, retry = login_limiter.allow(request)
        if not allowed:
            raise Unauthorized(f"Too many login attempts. Retry in {retry}s.")

    user = (
        db.query(User)
        .join(Organization)
        .filter(User.username == body.username.strip())
        .first()
    )
    if user is None or not verify_password(body.password, user.password_hash):
        # log the failed attempt for audit without leaking whether the user exists
        raise Unauthorized("Invalid username or password")

    if not user.is_active:
        raise Unauthorized("Account disabled")

    token = create_access_token(
        user_id=user.id, organization_id=user.organization_id,
        role=user.role, username=user.username,
    )
    from datetime import datetime, timezone
    user.last_login_at = datetime.now(timezone.utc)
    record_audit(
        db, organization_id=user.organization_id, user_id=user.id,
        username=user.username, action="auth.login", request=request,
    )
    db.commit()
    return Token(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.post("/change-password")
def change_password(
    body: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    old = (body.get("old_password") or "").strip()
    new = (body.get("new_password") or "").strip()
    if len(new) < 8:
        raise Unauthorized("New password must be at least 8 characters")
    if not verify_password(old, user.password_hash):
        raise Unauthorized("Current password is incorrect")
    user.password_hash = hash_password(new)
    user.must_change_password = False
    record_audit(
        db, organization_id=user.organization_id, user_id=user.id,
        username=user.username, action="auth.change_password", request=request,
    )
    db.commit()
    return {"detail": "Password updated"}
