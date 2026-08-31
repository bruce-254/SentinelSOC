"""Dashboard statistics.

All values are computed from real data in the database — nothing is mocked or
fabricated. When a deployment moves events to a search/analytics store, these
aggregations should be backed by that store's aggregation API.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Alert, DetectionRule, Incident, NormalizedEvent, Organization
from ..storage import get_event_store


def _bucketed(store, organization_id: int, since: datetime, event_types=None, bucket=60):
    series = store.time_series(
        organization_id=organization_id, since=since,
        bucket_seconds=bucket, event_types=event_types,
    )
    # Fill gaps so the chart has a continuous axis.
    out = []
    now_bucket = since
    idx = 0
    series_map = {int(ts.timestamp()) // bucket * bucket: c for ts, c in series}
    while now_bucket <= datetime.now(timezone.utc):
        key = int(now_bucket.timestamp()) // bucket * bucket
        out.append({"t": now_bucket.isoformat(), "value": series_map.get(key, 0)})
        now_bucket = now_bucket + timedelta(seconds=bucket)
        idx += 1
        if idx > 2000:
            break
    return out


def dashboard_stats(db: Session, organization_id: int, window_minutes: int = 60) -> dict:
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=window_minutes)
    store = get_event_store(db)

    events_total = db.scalar(
        select(func.count()).select_from(NormalizedEvent)
        .where(NormalizedEvent.organization_id == organization_id)
    ) or 0

    recent_events = db.scalar(
        select(func.count()).select_from(NormalizedEvent)
        .where(NormalizedEvent.organization_id == organization_id,
               NormalizedEvent.timestamp >= since)
    ) or 0
    events_per_minute = round(recent_events / window_minutes, 2) if window_minutes else 0

    alert_counts = dict(db.execute(
        select(NormalizedEvent.event_type, func.count()).where(
            NormalizedEvent.organization_id == organization_id,
            NormalizedEvent.timestamp >= since,
        ).group_by(NormalizedEvent.event_type)
    ).all())

    failed_logins = db.scalar(
        select(func.count()).select_from(NormalizedEvent)
        .where(NormalizedEvent.organization_id == organization_id,
               NormalizedEvent.event_type == "authentication_failure",
               NormalizedEvent.timestamp >= since)
    ) or 0

    alerts_total = db.scalar(
        select(func.count()).select_from(Alert)
        .where(Alert.organization_id == organization_id)
    ) or 0
    critical_alerts = db.scalar(
        select(func.count()).select_from(Alert)
        .where(Alert.organization_id == organization_id, Alert.severity == "critical")
    ) or 0
    high_alerts = db.scalar(
        select(func.count()).select_from(Alert)
        .where(Alert.organization_id == organization_id, Alert.severity == "high")
    ) or 0

    open_incidents = db.scalar(
        select(func.count()).select_from(Incident)
        .where(Incident.organization_id == organization_id,
               Incident.status.in_(["open", "investigating", "contained"]))
    ) or 0

    active_rules = db.scalar(
        select(func.count()).select_from(DetectionRule)
        .where(DetectionRule.organization_id == organization_id,
               DetectionRule.enabled.is_(True))
    ) or 0

    # ---- distributions ----------------------------------------------------
    severity_distribution = dict(db.execute(
        select(Alert.severity, func.count())
        .where(Alert.organization_id == organization_id)
        .group_by(Alert.severity)
    ).all())
    alert_status_distribution = dict(db.execute(
        select(Alert.status, func.count())
        .where(Alert.organization_id == organization_id)
        .group_by(Alert.status)
    ).all())
    incident_status_distribution = dict(db.execute(
        select(Incident.status, func.count())
        .where(Incident.organization_id == organization_id)
        .group_by(Incident.status)
    ).all())

    # ---- top entities -----------------------------------------------------
    top_source_ips = [
        {"ip": ip, "count": c}
        for ip, c in db.execute(
            select(NormalizedEvent.src_ip, func.count())
            .where(NormalizedEvent.organization_id == organization_id,
                   NormalizedEvent.src_ip.isnot(None),
                   NormalizedEvent.timestamp >= since)
            .group_by(NormalizedEvent.src_ip)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
    ]
    top_assets = [
        {"device": d, "count": c}
        for d, c in db.execute(
            select(NormalizedEvent.device, func.count())
            .where(NormalizedEvent.organization_id == organization_id,
                   NormalizedEvent.device.isnot(None),
                   NormalizedEvent.timestamp >= since)
            .group_by(NormalizedEvent.device)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
    ]
    top_users = [
        {"username": u, "count": c}
        for u, c in db.execute(
            select(NormalizedEvent.username, func.count())
            .where(NormalizedEvent.organization_id == organization_id,
                   NormalizedEvent.username.isnot(None),
                   NormalizedEvent.timestamp >= since)
            .group_by(NormalizedEvent.username)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
    ]

    event_rate_series = _bucketed(store, organization_id, since)
    auth_trend_series = _bucketed(
        store, organization_id, since,
        event_types=["authentication_success", "authentication_failure"],
    )

    org = db.get(Organization, organization_id)
    return {
        "org": {"id": organization_id, "name": org.name if org else "?"},
        "window_minutes": window_minutes,
        "events_total": events_total,
        "events_per_minute": events_per_minute,
        "recent_events": recent_events,
        "alerts_total": alerts_total,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "failed_logins": failed_logins,
        "open_incidents": open_incidents,
        "active_rules": active_rules,
        "event_rate_series": event_rate_series,
        "auth_trend_series": auth_trend_series,
        "severity_distribution": severity_distribution,
        "alert_status_distribution": alert_status_distribution,
        "incident_status_distribution": incident_status_distribution,
        "top_source_ips": top_source_ips,
        "top_assets": top_assets,
        "top_users": top_users,
        "event_types": alert_counts,
    }
