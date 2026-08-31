"""Detection rule management.

Rules are stored in the database and are fully configurable. Only admins may
create/edit/enable/disable rules; analysts and viewers can read them.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import BadRequest, NotFoundError
from ..database import get_db
from ..dependencies import get_current_user, require_admin
from ..models import DetectionRule, User
from ..schemas import RuleCreate, RuleOut, RuleUpdate

router = APIRouter(prefix="/rules", tags=["rules"])

VALID_SEV = {"info", "low", "medium", "high", "critical"}


@router.get("", response_model=list[RuleOut])
def list_rules(
    enabled: bool | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(DetectionRule).filter(DetectionRule.organization_id == user.organization_id)
    if enabled is not None:
        q = q.filter(DetectionRule.enabled == enabled)
    return q.order_by(DetectionRule.priority.desc(), DetectionRule.id).all()


@router.post("", response_model=RuleOut, status_code=201)
def create_rule(
    body: RuleCreate,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if body.severity not in VALID_SEV:
        raise BadRequest("Invalid severity")
    if db.query(DetectionRule).filter(
        DetectionRule.organization_id == user.organization_id,
        DetectionRule.name == body.name,
    ).first():
        raise BadRequest(f"Rule named '{body.name}' already exists")
    rule = DetectionRule(organization_id=user.organization_id, **body.model_dump())
    db.add(rule)
    db.flush()
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="rule.create", resource="rule",
                 resource_id=rule.id, details={"name": rule.name}, request=request)
    db.commit()
    return rule


@router.get("/{rule_id}", response_model=RuleOut)
def get_rule(rule_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    r = db.get(DetectionRule, rule_id)
    if r is None or r.organization_id != user.organization_id:
        raise NotFoundError("Rule not found")
    return r


@router.patch("/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: int,
    body: RuleUpdate,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    r = db.get(DetectionRule, rule_id)
    if r is None or r.organization_id != user.organization_id:
        raise NotFoundError("Rule not found")
    data = body.model_dump(exclude_unset=True)
    if "severity" in data and data["severity"] not in VALID_SEV:
        raise BadRequest("Invalid severity")
    for k, v in data.items():
        setattr(r, k, v)
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="rule.update", resource="rule",
                 resource_id=r.id, details={"name": r.name, "enabled": r.enabled},
                 request=request)
    db.commit()
    return r


@router.post("/{rule_id}/enable")
def enable_rule(rule_id: int, request: Request, user: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    return _set_enabled(db, rule_id, user, True, request)


@router.post("/{rule_id}/disable")
def disable_rule(rule_id: int, request: Request, user: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    return _set_enabled(db, rule_id, user, False, request)


def _set_enabled(db, rule_id, user, enabled: bool, request):
    r = db.get(DetectionRule, rule_id)
    if r is None or r.organization_id != user.organization_id:
        raise NotFoundError("Rule not found")
    r.enabled = enabled
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="rule.enable" if enabled else "rule.disable",
                 resource="rule", resource_id=r.id, request=request)
    db.commit()
    return RuleOut.model_validate(r).model_dump(mode="json")


@router.delete("/{rule_id}", status_code=204)
def delete_rule(rule_id: int, request: Request, user: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    r = db.get(DetectionRule, rule_id)
    if r is None or r.organization_id != user.organization_id:
        raise NotFoundError("Rule not found")
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="rule.delete", resource="rule",
                 resource_id=r.id, request=request)
    db.delete(r)
    db.commit()
