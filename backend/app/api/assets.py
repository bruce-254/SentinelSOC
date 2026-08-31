"""Asset inventory (admin manages, analysts/viewers read)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import BadRequest, NotFoundError
from ..database import get_db
from ..dependencies import get_current_user, require_action
from ..models import Asset, User
from ..schemas import AssetCreate, AssetOut, AssetUpdate

router = APIRouter(prefix="/assets", tags=["assets"])

ALLOWED_CRIT = {"info", "low", "medium", "high", "critical"}


@router.get("", response_model=list[AssetOut])
def list_assets(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(Asset).filter(Asset.organization_id == user.organization_id)
        .order_by(Asset.name).all()
    )


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(
    body: AssetCreate,
    request: Request,
    user: User = Depends(require_action("ingest")),
    db: Session = Depends(get_db),
):
    body.criticality = body.criticality.lower()
    if body.criticality not in ALLOWED_CRIT:
        raise BadRequest("Invalid criticality")
    asset = Asset(organization_id=user.organization_id, **body.model_dump())
    db.add(asset)
    db.flush()
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="asset.create", resource="asset",
                 resource_id=asset.id, details={"name": asset.name, "ip": asset.ip_address},
                 request=request)
    db.commit()
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = db.get(Asset, asset_id)
    if a is None or a.organization_id != user.organization_id:
        raise NotFoundError("Asset not found")
    return a


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int,
    body: AssetUpdate,
    request: Request,
    user: User = Depends(require_action("ingest")),
    db: Session = Depends(get_db),
):
    a = db.get(Asset, asset_id)
    if a is None or a.organization_id != user.organization_id:
        raise NotFoundError("Asset not found")
    data = body.model_dump(exclude_unset=True)
    if "criticality" in data and data["criticality"] not in ALLOWED_CRIT:
        raise BadRequest("Invalid criticality")
    for k, v in data.items():
        setattr(a, k, v)
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="asset.update", resource="asset",
                 resource_id=a.id, request=request)
    db.commit()
    return a


@router.delete("/{asset_id}", status_code=204)
def delete_asset(
    asset_id: int,
    request: Request,
    user: User = Depends(require_action("ingest")),
    db: Session = Depends(get_db),
):
    a = db.get(Asset, asset_id)
    if a is None or a.organization_id != user.organization_id:
        raise NotFoundError("Asset not found")
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="asset.delete", resource="asset",
                 resource_id=a.id, request=request)
    db.delete(a)
    db.commit()
