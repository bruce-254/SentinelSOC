"""Organization management (admin only)."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import BadRequest, NotFoundError
from ..database import get_db
from ..dependencies import get_current_user, require_admin
from ..models import Organization, User
from ..schemas import OrganizationCreate, OrganizationOut

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.get("", response_model=list[OrganizationOut])
def list_orgs(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(Organization).order_by(Organization.id).all()


@router.post("", response_model=OrganizationOut, status_code=201)
def create_org(
    body: OrganizationCreate,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    slug = body.slug or re.sub(r"[^a-z0-9-]+", "-", body.name.lower()).strip("-") or "org"
    if db.query(Organization).filter(Organization.slug == slug).first():
        raise BadRequest(f"Organization slug '{slug}' already exists")
    org = Organization(name=body.name, slug=slug)
    db.add(org)
    db.flush()
    record_audit(db, organization_id=org.id, user_id=user.id, username=user.username,
                 action="org.create", resource="organization", resource_id=org.id,
                 details={"name": org.name}, request=request)
    db.commit()
    return org


@router.get("/{org_id}", response_model=OrganizationOut)
def get_org(org_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    org = db.get(Organization, org_id)
    if org is None:
        raise NotFoundError("Organization not found")
    return org
