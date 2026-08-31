"""Event ingestion and search."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..database import get_db
from ..dependencies import get_current_user, require_action
from ..models import User
from ..pipeline.pipeline import process_ingest
from ..schemas import EventOut, IngestBatchRequest, IngestResponse
from ..storage import get_event_store

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/ingest", response_model=IngestResponse)
def ingest(
    body: IngestBatchRequest,
    request: Request,
    user: User = Depends(require_action("ingest")),
    db: Session = Depends(get_db),
):
    entries = [e.model_dump() for e in body.entries]
    result = process_ingest(db, organization_id=user.organization_id, entries=entries)
    db.commit()
    return IngestResponse(
        accepted=result.accepted,
        normalized=result.normalized,
        alerts=result.alerts,
        rejected=result.rejected,
        errors=result.errors,
    )


@router.get("/search")
def search_events(
    q: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    username: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    source_log_type: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from datetime import datetime
    store = get_event_store(db)
    events, total = store.search(
        organization_id=user.organization_id,
        time_from=datetime.fromisoformat(time_from) if time_from else None,
        time_to=datetime.fromisoformat(time_to) if time_to else None,
        src_ip=src_ip, dst_ip=dst_ip, username=username,
        event_type=event_type, severity=severity,
        source_log_type=source_log_type, q=q, page=page, page_size=page_size,
    )
    items = [EventOut.model_validate(e).model_dump(mode="json") for e in events]
    from math import ceil
    return {
        "items": items, "total": total, "page": page,
        "page_size": page_size, "pages": ceil(total / page_size) if total else 0,
    }


@router.get("/meta")
def event_meta(user: User = Depends(get_current_user)):
    """Static metadata used to populate filter dropdowns."""
    from ..pipeline.parsers import EventTypes, KNOWN_SOURCE_TYPES, Severity
    return {
        "event_types": sorted(EventTypes.values()),
        "source_log_types": sorted(KNOWN_SOURCE_TYPES),
        "severities": sorted(Severity.values_set),
    }


@router.get("/timeline")
def event_timeline(
    since_minutes: int = Query(60, ge=5, le=60 * 24 * 30),
    event_type: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from datetime import datetime, timedelta, timezone
    store = get_event_store(db)
    since = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    series = store.time_series(
        organization_id=user.organization_id, since=since,
        bucket_seconds=60,
        event_types=[event_type] if event_type else None,
    )
    return [{"t": ts.isoformat(), "value": c} for ts, c in series]
