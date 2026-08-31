"""Dashboard, risk, reports, audit and threat-intel endpoints."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ..core.audit import record_audit
from ..core.errors import BadRequest, NotFoundError
from ..database import get_db
from ..dependencies import get_current_user, require_action
from ..models import Alert, AuditLog, RiskScore, User
from ..schemas import AuditOut, ReportRequest, RiskScoreOut
from ..services.stats import dashboard_stats

router = APIRouter(tags=["ops"])


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
@router.get("/dashboard")
def get_dashboard(
    window_minutes: int = Query(60, ge=15, le=1440),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return dashboard_stats(db, user.organization_id, window_minutes)


# --------------------------------------------------------------------------
# Risk
# --------------------------------------------------------------------------
@router.get("/risk")
def list_risk_scores(
    entity_type: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(RiskScore).filter(RiskScore.organization_id == user.organization_id)
    if entity_type:
        q = q.filter(RiskScore.entity_type == entity_type)
    items = q.order_by(RiskScore.score.desc()).limit(100).all()
    return [RiskScoreOut.model_validate(x).model_dump(mode="json") for x in items]


@router.get("/risk/{entity_type}/{entity_id}")
def get_risk_detail(
    entity_type: str,
    entity_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    score = (
        db.query(RiskScore).filter(
            RiskScore.organization_id == user.organization_id,
            RiskScore.entity_type == entity_type,
            RiskScore.entity_id == entity_id,
        ).first()
    )
    if score is None:
        raise NotFoundError("No risk score for entity")
    out = RiskScoreOut.model_validate(score).model_dump(mode="json")
    # related alerts for explainability
    alerts = []
    if entity_type == "asset":
        alerts = db.query(Alert).filter(
            Alert.organization_id == user.organization_id,
            Alert.asset_id == int(entity_id),
        ).order_by(Alert.created_at.desc()).limit(20).all()
    elif entity_type == "ip":
        alerts = db.query(Alert).filter(
            Alert.organization_id == user.organization_id,
            Alert.src_ip == entity_id,
        ).order_by(Alert.created_at.desc()).limit(20).all()
    elif entity_type == "user":
        alerts = db.query(Alert).filter(
            Alert.organization_id == user.organization_id,
            Alert.username == entity_id,
        ).order_by(Alert.created_at.desc()).limit(20).all()
    from ..schemas import AlertOut
    out["alerts"] = [AlertOut.model_validate(a).model_dump(mode="json") for a in alerts]
    return out


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
@router.post("/reports/generate")
def generate_report(
    body: ReportRequest,
    request: Request,
    user: User = Depends(require_action("run_report")),
    db: Session = Depends(get_db),
):
    stats = dashboard_stats(db, user.organization_id, 60)
    # Summary report assembled from real data.
    report = {
        "report_type": body.report_type,
        "organization_id": user.organization_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "period": {
            "from": body.time_from.isoformat(),
            "to": body.time_to.isoformat(),
        },
        "summary": {
            "events_total": stats["events_total"],
            "alerts_total": stats["alerts_total"],
            "critical_alerts": stats["critical_alerts"],
            "high_alerts": stats["high_alerts"],
            "failed_logins": stats["failed_logins"],
            "open_incidents": stats["open_incidents"],
            "severity_distribution": stats["severity_distribution"],
            "incident_status_distribution": stats["incident_status_distribution"],
        },
        "top_source_ips": stats["top_source_ips"],
        "top_assets": stats["top_assets"],
    }
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="report.generate", resource="report",
                 resource_id=body.report_type, request=request)
    db.commit()
    return report


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------
@router.get("/audit", response_model=list[AuditOut])
def list_audit(
    action: str | None = None,
    limit: int = Query(200, ge=1, le=2000),
    user: User = Depends(require_action("view_audit")),
    db: Session = Depends(get_db),
):
    q = db.query(AuditLog).filter(AuditLog.organization_id == user.organization_id)
    if action:
        q = q.filter(AuditLog.action == action)
    return q.order_by(AuditLog.created_at.desc()).limit(limit).all()


# --------------------------------------------------------------------------
# Threat intelligence
# --------------------------------------------------------------------------
@router.get("/threatintel/providers")
def list_threatintel_providers(user: User = Depends(get_current_user)):
    from ..threatintel import get_providers
    return [
        {"name": p.name, "enabled": p.enabled, "requires_api_key": p.requires_api_key}
        for p in get_providers()
    ]


@router.get("/threatintel")
def list_threatintel(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from ..models import ThreatIntelIndicator
    items = db.query(ThreatIntelIndicator).filter(
        ThreatIntelIndicator.organization_id == user.organization_id
    ).order_by(ThreatIntelIndicator.created_at.desc()).limit(200).all()
    from ..schemas import ThreatIntelOut
    return [ThreatIntelOut.model_validate(x).model_dump(mode="json") for x in items]


@router.post("/threatintel/sync")
def sync_threatintel(
    request: Request,
    user: User = Depends(require_action("ingest")),
    db: Session = Depends(get_db),
):
    """Fetch indicators from all active providers and persist them.

    Providers return real data only; the bundled dev provider returns an empty
    list, so no fabricated intelligence is ever stored.
    """
    import asyncio

    from ..models import ThreatIntelIndicator
    from ..threatintel import registry

    providers = registry.active()
    if not providers:
        return {"synced": 0, "providers": [], "detail": "No threat-intel providers enabled"}

    async def _run():
        results = []
        for p in providers:
            try:
                inds = await p.fetch()
                results.append((p.name, inds))
            except Exception as e:  # defensive
                results.append((p.name, []))
        return results

    results = asyncio.run(_run())
    synced = 0
    for name, inds in results:
        for ind in inds:
            existing = db.query(ThreatIntelIndicator).filter(
                ThreatIntelIndicator.organization_id == user.organization_id,
                ThreatIntelIndicator.indicator_type == ind.indicator_type,
                ThreatIntelIndicator.value == ind.value,
                ThreatIntelIndicator.provider == ind.provider,
            ).first()
            if existing is None:
                db.add(ThreatIntelIndicator(
                    organization_id=user.organization_id,
                    indicator_type=ind.indicator_type,
                    value=ind.value,
                    provider=ind.provider,
                    confidence=ind.confidence,
                    tags=ind.tags,
                    first_seen=ind.first_seen,
                    last_seen=ind.last_seen,
                ))
                synced += 1
    record_audit(db, organization_id=user.organization_id, user_id=user.id,
                 username=user.username, action="threatintel.sync",
                 resource="threatintel", request=request)
    db.commit()
    return {"synced": synced, "providers": [p.name for p in providers]}
