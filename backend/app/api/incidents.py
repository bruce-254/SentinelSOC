"""Incident management for analysts."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import BadRequest, NotFoundError
from ..database import get_db
from ..dependencies import get_current_user, require_action
from ..models import Alert, Incident, IncidentNote, User
from ..schemas import (
    IncidentCreate,
    IncidentNoteCreate,
    IncidentNoteOut,
    IncidentOut,
    IncidentUpdate,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])

VALID_STATUS = {"open", "investigating", "contained", "resolved", "closed"}


def _incident_out(i: Incident) -> dict:
    return IncidentOut.model_validate(i).model_dump(mode="json")


@router.get("")
def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Incident).filter(Incident.organization_id == user.organization_id)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    items = q.order_by(Incident.updated_at.desc()).all()
    return [_incident_out(i) for i in items]


@router.post("", response_model=IncidentOut, status_code=201)
def create_incident(
    body: IncidentCreate,
    request: Request,
    user: User = Depends(require_action("create_incident")),
    db: Session = Depends(get_db),
):
    if body.severity not in {"info", "low", "medium", "high", "critical"}:
        raise BadRequest("Invalid severity")
    if body.alert_ids:
        alerts = (
            db.query(Alert).filter(
                Alert.id.in_(body.alert_ids),
                Alert.organization_id == user.organization_id,
            ).all()
        )
        if len(alerts) != len(set(body.alert_ids)):
            raise BadRequest("One or more alert IDs are invalid")
    else:
        alerts = []
    incident = Incident(
        organization_id=user.organization_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        status="open",
        alert_ids=list(body.alert_ids),
        created_by=user.id,
    )
    db.add(incident)
    db.flush()
    # link alerts
    for a in alerts:
        if a.organization_id == user.organization_id:
            incident.alert_ids = sorted(set(incident.alert_ids + [a.id]))
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="incident.create", resource="incident",
                 resource_id=incident.id, details={"title": incident.title},
                 request=request)
    db.commit()
    return incident


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    i = db.get(Incident, incident_id)
    if i is None or i.organization_id != user.organization_id:
        raise NotFoundError("Incident not found")
    return i


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: int,
    body: IncidentUpdate,
    request: Request,
    user: User = Depends(require_action("update_incident")),
    db: Session = Depends(get_db),
):
    i = db.get(Incident, incident_id)
    if i is None or i.organization_id != user.organization_id:
        raise NotFoundError("Incident not found")
    data = body.model_dump(exclude_unset=True)
    if "status" in data:
        if data["status"] not in VALID_STATUS:
            raise BadRequest("Invalid incident status")
        old_status = i.status
        i.status = data["status"]
        if data["status"] in ("resolved", "closed") and i.resolved_at is None:
            i.resolved_at = datetime.now(timezone.utc)
        # record the status transition as a note
        db.add(IncidentNote(
            incident_id=i.id, user_id=user.id,
            body=f"Status changed: {old_status} -> {data['status']}",
            status_change=data["status"],
        ))
    for k, v in data.items():
        if k == "status":
            continue
        setattr(i, k, v)
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="incident.update", resource="incident",
                 resource_id=i.id, details={"status": i.status}, request=request)
    db.commit()
    return i


@router.post("/{incident_id}/notes", response_model=IncidentNoteOut)
def add_note(
    incident_id: int,
    body: IncidentNoteCreate,
    request: Request,
    user: User = Depends(require_action("create_note")),
    db: Session = Depends(get_db),
):
    i = db.get(Incident, incident_id)
    if i is None or i.organization_id != user.organization_id:
        raise NotFoundError("Incident not found")
    note = IncidentNote(incident_id=i.id, user_id=user.id, body=body.body)
    db.add(note)
    db.flush()
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="incident.note", resource="incident",
                 resource_id=i.id, request=request)
    db.commit()
    return note
