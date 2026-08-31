"""Audit logging for analyst/administrator actions."""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from ..models import AuditLog


def record_audit(
    db: Session,
    *,
    organization_id: int,
    action: str,
    user_id: int | None = None,
    username: str | None = None,
    resource: str | None = None,
    resource_id: str | int | None = None,
    details: dict | None = None,
    request: Request | None = None,
) -> AuditLog:
    ip = None
    if request is not None:
        xff = request.headers.get("x-forwarded-for")
        ip = (xff.split(",")[0].strip() if xff else None) or request.client.host
    entry = AuditLog(
        organization_id=organization_id,
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        resource_id=str(resource_id) if resource_id is not None else None,
        details=details,
        ip_address=ip,
    )
    db.add(entry)
    return entry
