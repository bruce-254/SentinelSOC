"""User management within the current organisation (admin only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import BadRequest, NotFoundError
from ..database import get_db
from ..dependencies import get_current_user, require_admin
from ..models import User
from ..schemas import UserCreate, UserOut, UserUpdate
from ..security import hash_password

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    return (
        db.query(User).filter(User.organization_id == user.organization_id)
        .order_by(User.id).all()
    )


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    request: Request,
    actor: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if body.role not in {"admin", "analyst", "viewer"}:
        raise BadRequest("Invalid role")
    if db.query(User).filter(
        User.organization_id == actor.organization_id, User.username == body.username
    ).first():
        raise BadRequest("Username already exists")
    if db.query(User).filter(
        User.organization_id == actor.organization_id, User.email == body.email
    ).first():
        raise BadRequest("Email already in use")
    u = User(
        organization_id=actor.organization_id,
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(u)
    db.flush()
    record_audit(db, organization_id=actor.organization_id, user_id=actor.id,
                 username=actor.username, action="user.create", resource="user",
                 resource_id=u.id, details={"username": u.username, "role": u.role},
                 request=request)
    db.commit()
    return u


@router.get("/{user_id}", response_model=UserOut)
def get_user(user_id: int, actor: User = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None or u.organization_id != actor.organization_id:
        raise NotFoundError("User not found")
    return u


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    actor: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = db.get(User, user_id)
    if u is None or u.organization_id != actor.organization_id:
        raise NotFoundError("User not found")
    if u.id == actor.id and body.is_active is False:
        raise BadRequest("You cannot disable your own account")
    if body.role is not None:
        if body.role not in {"admin", "analyst", "viewer"}:
            raise BadRequest("Invalid role")
        # prevent self-demotion removing the last admin
        if u.id == actor.id and body.role != "admin":
            raise BadRequest("You cannot remove your own admin role")
        u.role = body.role
    if body.email is not None:
        u.email = body.email
    if body.is_active is not None:
        u.is_active = body.is_active
    if body.password:
        u.password_hash = hash_password(body.password)
        u.must_change_password = False
    record_audit(db, organization_id=actor.organization_id, user_id=actor.id,
                 username=actor.username, action="user.update", resource="user",
                 resource_id=u.id, details={"role": u.role, "is_active": u.is_active},
                 request=request)
    db.commit()
    return u
