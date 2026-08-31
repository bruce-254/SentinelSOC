"""The log processing pipeline.

Input -> ingestion -> parsing -> normalization -> enrichment -> detection
      -> alert -> incident.

This module is the orchestrator. It is invoked by the ingest API endpoints and
is intentionally independent of FastAPI so it can be driven from a worker/CLI.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from ..core.logging import logger
from ..models import Alert, Asset, DetectionRule, ThreatIntelIndicator
from ..storage import EventRecord, get_event_store
from .detection import (
    aggregate_group_key,
    evaluate_conditions,
    matches_scope,
    rule_matches_single,
)
from .normalizer import build_enrichment_context, normalize
from .parsers import parse_log, ParseError
from .risk import compute_alert_risk, persist_alert_risk, upsert_risk_score


class IngestResult:
    def __init__(self):
        self.accepted = 0
        self.normalized = 0
        self.rejected = 0
        self.alerts = 0
        self.errors: list[str] = []


def _load_rules(db: Session, organization_id: int) -> list[DetectionRule]:
    return (
        db.query(DetectionRule)
        .filter(DetectionRule.organization_id == organization_id)
        .all()
    )


def _load_intel(db: Session, organization_id: int) -> list[ThreatIntelIndicator]:
    return (
        db.query(ThreatIntelIndicator)
        .filter(ThreatIntelIndicator.organization_id == organization_id)
        .all()
    )


def _asset_for_event(ctx_assets: dict[str, Asset], event: EventRecord) -> Asset | None:
    if event.src_ip and event.src_ip in ctx_assets:
        return ctx_assets[event.src_ip]
    if event.dst_ip and event.dst_ip in ctx_assets:
        return ctx_assets[event.dst_ip]
    return None


def _title(template: str | None, event: EventRecord, group_value: str | None, rule_name: str) -> str:
    t = template or rule_name
    if group_value:
        t = t.replace("{src_ip}", str(group_value))
        t = t.replace("{username}", str(group_value))
        t = t.replace("{dst_ip}", str(group_value))
        t = t.replace("{dst_port}", str(group_value))
    t = t.replace("{src_ip}", event.src_ip or "unknown")
    t = t.replace("{username}", event.username or "unknown")
    t = t.replace("{dst_ip}", event.dst_ip or "unknown")
    t = t.replace("{dst_port}", str(event.dst_port) if event.dst_port else "?")
    t = t.replace("{event_type}", event.event_type)
    return t[:255]


def process_ingest(
    db: Session,
    *,
    organization_id: int,
    entries: list[dict],
) -> IngestResult:
    """entries: list of {"source_log_type": str, "raw": str}."""
    result = IngestResult()
    store = get_event_store(db)
    rules = _load_rules(db, organization_id)
    intel_rows = _load_intel(db, organization_id)
    ctx = build_enrichment_context(db, organization_id, intel_rows)
    assets_by_ip = ctx.assets_by_ip

    records: list[EventRecord] = []

    # --- parse + normalize -------------------------------------------------
    for entry in entries:
        try:
            parsed = parse_log(entry["source_log_type"], entry["raw"])
            event = normalize(
                parsed, organization_id=organization_id,
                raw=entry["raw"], ctx=ctx,
            )
            records.append(event)
            result.accepted += 1
        except ParseError as e:
            result.rejected += 1
            if len(result.errors) < 20:
                result.errors.append(f"entry: {e}")
        except Exception as e:  # defensive: never let one bad line kill the batch
            result.rejected += 1
            logger.warning("ingest error for entry: %s", e)
            if len(result.errors) < 20:
                result.errors.append(f"entry: {e}")

    if records:
        ids = store.bulk_write(records)
        result.normalized = len(ids)
    else:
        ids = []

    # --- detection ---------------------------------------------------------
    single_rules = [r for r in rules if r.rule_type == "single_event" and r.enabled]
    agg_rules = [r for r in rules if r.rule_type == "aggregate" and r.enabled]

    # matched_events: list of (rule, event, group_value|None, event_db_id|None)
    matched_events: list[tuple[DetectionRule, EventRecord, str | None, int | None]] = []
    for i, event in enumerate(records):
        for rule in single_rules:
            if rule_matches_single(event, rule):
                matched_events.append((rule, event, None, ids[i] if i < len(ids) else None))
        for rule in agg_rules:
            if not matches_scope(event, rule):
                continue
            if not evaluate_conditions(event, rule.conditions):
                continue
            key = aggregate_group_key(event, rule)
            if key is not None:
                matched_events.append((rule, event, key, ids[i] if i < len(ids) else None))

    # --- build alerts ------------------------------------------------------
    alerts: list[Alert] = []

    for rule, event, group_value, event_db_id in matched_events:
        volume = 1
        is_intel = bool("threat_intel" in (event.labels or []))
        if rule.rule_type == "aggregate":
            since = event.timestamp - timedelta(seconds=rule.time_window_seconds or 300)
            volume = store.count_in_window(
                organization_id=organization_id,
                event_type=event.event_type,
                since=since,
                group_by=rule.group_by,
                group_value=group_value,
            )

        if rule.rule_type == "aggregate" and volume != (rule.threshold or 0):
            # Fire once per window/group only when the count crosses the
            # threshold, not on every subsequent matching event.
            continue

        asset = _asset_for_event(assets_by_ip, event)
        score, factors = compute_alert_risk(
            severity=rule.severity,
            rule=rule,
            asset=asset,
            is_threat_intel=is_intel,
            volume=volume,
        )
        title = _title(rule.alert_title, event, group_value, rule.name)
        alert = Alert(
            organization_id=organization_id,
            rule_id=rule.id,
            title=title,
            severity=rule.severity,
            risk_score=score,
            status="new",
            asset_id=asset.id if asset else None,
            asset_name=asset.name if asset else None,
            source=event.src_ip or event.username,
            src_ip=event.src_ip,
            username=event.username,
            event_type=event.event_type,
            event_ids=[event_db_id] if event_db_id is not None else [],
            evidence=[
                {
                    "rule": rule.name,
                    "event_type": event.event_type,
                    "src_ip": event.src_ip,
                    "username": event.username,
                    "timestamp": event.timestamp.isoformat(),
                    "message": (event.message or "")[:400],
                    "group_value": group_value,
                    "volume": volume,
                    "device": event.device,
                    "application": event.application,
                }
            ],
        )
        db.add(alert)
        db.flush()
        persist_alert_risk(db, alert, factors)
        alerts.append(alert)
        result.alerts += 1

        # Update explainable risk scores for affected entities.
        entity_specs = _risk_entities(event, alert, asset)
        for etype, eid, label in entity_specs:
            ent_factors = factors
            upsert_risk_score(
                db, organization_id=organization_id, entity_type=etype,
                entity_id=eid, entity_label=label,
                score=score, factors=ent_factors,
            )

    db.flush()
    return result


def _risk_entities(event: EventRecord, alert: Alert, asset: Asset | None):
    specs = []
    if event.src_ip:
        specs.append(("ip", event.src_ip, event.src_ip))
    if asset:
        specs.append(("asset", str(asset.id), asset.name))
    if event.username:
        specs.append(("user", event.username, event.username))
    return specs
