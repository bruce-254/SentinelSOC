"""Alert management and triage."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import BadRequest, NotFoundError
from ..database import get_db
from ..dependencies import get_current_user, require_action
from ..models import Alert, RiskFactor, User
from ..schemas import AlertOut, AlertUpdate

router = APIRouter(prefix="/alerts", tags=["alerts"])

VALID_STATUS = {"new", "acknowledged", "investigating", "resolved", "false_positive"}


def _alert_out(a: Alert) -> dict:
    return AlertOut.model_validate(a).model_dump(mode="json")


@router.get("")
def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    src_ip: str | None = None,
    username: str | None = None,
    risk_min: float | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Alert).filter(Alert.organization_id == user.organization_id)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if src_ip:
        q = q.filter(Alert.src_ip == src_ip)
    if username:
        q = q.filter(Alert.username.ilike(f"%{username}%"))
    if risk_min is not None:
        q = q.filter(Alert.risk_score >= risk_min)
    total = q.count()
    items = q.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
    return {"items": [_alert_out(a) for a in items], "total": total, "limit": limit}


@router.get("/{alert_id}")
def get_alert(alert_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if a is None or a.organization_id != user.organization_id:
        raise NotFoundError("Alert not found")
    out = _alert_out(a)
    out["risk_factors"] = [
        {"factor": f.factor, "contribution": f.contribution, "explanation": f.explanation}
        for f in db.query(RiskFactor).filter(RiskFactor.alert_id == a.id).all()
    ]
    return out


@router.patch("/{alert_id}")
def update_alert(
    alert_id: int,
    body: AlertUpdate,
    request: Request,
    user: User = Depends(require_action("update_alert")),
    db: Session = Depends(get_db),
):
    a = db.get(Alert, alert_id)
    if a is None or a.organization_id != user.organization_id:
        raise NotFoundError("Alert not found")
    if body.status is not None:
        if body.status not in VALID_STATUS:
            raise BadRequest("Invalid alert status")
        a.status = body.status
        if body.status in ("resolved", "false_positive"):
            a.resolved_at = datetime.now(timezone.utc)
            a.resolved_by = user.id
    details = {"status": body.status} if body.status else None
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="alert.update", resource="alert",
                 resource_id=a.id, details=details, request=request)
    if body.note:
        record_audit(db, organization_id=user.organization_id, user_id=user.id,
                     username=user.username, action="alert.note", resource="alert",
                     resource_id=a.id, details={"note": body.note[:200]}, request=request)
    db.commit()
    return _alert_out(a)
