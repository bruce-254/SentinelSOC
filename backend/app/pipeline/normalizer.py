"""Event normalization.

Normalizes parsed log records into the common schema and enriches them with
context (asset matching, threat-intel labels, geographic hints, process/event
classification). The output is what detection consumes.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..models import Asset
from ..storage import EventRecord
from .parsers import EventTypes, Severity, parse_timestamp


def _coerce_ip(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    if v.startswith("[") and v.endswith("]"):
        v = v[1:-1]
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        return None


def _coerce_username(v) -> str | None:
    if v is None:
        return None
    v = str(v).strip().strip("'\"")
    if not v or v in {"-", "unknown", "(none)", "anonymous"}:
        return None
    return v[:255]


def _coerce_int(v) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# Heuristic fingerprints used to (re)classify generic events.
PROCESS_HINTS = re.compile(r"(process|exec|spawn|cmd|powershell|rundll32|wscript|cscript)", re.I)
PRIV_HINTS = re.compile(r"(privilege|sudo|admin|elevat|escalat|group.*added|domain admin)", re.I)
SCAN_HINTS = re.compile(r"(port scan|syn scan|nmap|masscan|port.*sweep|scan)", re.I)
TRAFFIC_HINTS = re.compile(r"(anomal|burst|dpi|bandwidth|rate limit|flood)", re.I)
AUTH_FAIL_HINTS = re.compile(r"(failed password|invalid user|authentication failure|login failed)", re.I)
AUTH_OK_HINTS = re.compile(r"(accepted password|login success|authentication success|logged in)", re.I)


def classify_event_type(event_type: str, message: str, success: bool | None) -> str:
    et = event_type.lower()
    # Known types are accepted as-is; the special "generic" type is reclassified
    # using content heuristics so real events get useful event_types.
    if et != EventTypes.generic and et in EventTypes.values():
        return et
    msg = message or ""
    if success is False and (AUTH_FAIL_HINTS.search(msg)):
        return EventTypes.authentication_failure
    if success is True and (AUTH_OK_HINTS.search(msg)):
        return EventTypes.authentication_success
    if PRIV_HINTS.search(msg):
        return EventTypes.privilege_escalation
    if PROCESS_HINTS.search(msg):
        return EventTypes.process_activity
    if SCAN_HINTS.search(msg):
        return EventTypes.port_scan
    if TRAFFIC_HINTS.search(msg):
        return EventTypes.traffic_anomaly
    if AUTH_FAIL_HINTS.search(msg):
        return EventTypes.authentication_failure
    return EventTypes.generic


@dataclass
class EnrichmentContext:
    assets_by_ip: dict[str, Asset] = field(default_factory=dict)
    intel_ips: set[str] = field(default_factory=set)
    intel_hashes: set[str] = field(default_factory=set)


def build_enrichment_context(db, organization_id: int, intel_rows) -> EnrichmentContext:
    ctx = EnrichmentContext()
    for asset in db.query(Asset).filter(Asset.organization_id == organization_id).all():
        if asset.ip_address:
            ctx.assets_by_ip[asset.ip_address] = asset
    for row in intel_rows:
        if row.indicator_type == "ip":
            ctx.intel_ips.add(row.value)
        elif row.indicator_type == "hash":
            ctx.intel_hashes.add(row.value)
    return ctx


def normalize(parsed: dict, *, organization_id: int, raw: str, ctx: EnrichmentContext | None = None) -> EventRecord:
    """Convert a parse-result dict into a normalized ``EventRecord``."""
    ts = parsed.get("timestamp") or datetime.now(timezone.utc)
    if isinstance(ts, str):
        parsed_ts = parse_timestamp(ts)
        ts = parsed_ts or datetime.now(timezone.utc)
    if not isinstance(ts, datetime):
        ts = datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    ts = ts.astimezone(timezone.utc)

    severity = (parsed.get("severity") or "info").lower()
    if severity not in Severity.values_set:
        severity = "info"

    src_ip = _coerce_ip(parsed.get("src_ip"))
    dst_ip = _coerce_ip(parsed.get("dst_ip"))
    username = _coerce_username(parsed.get("username"))
    source = parsed.get("source") or src_ip or dst_ip or username or "unknown"
    destination = parsed.get("destination") or dst_ip or None
    application = parsed.get("application")
    device = parsed.get("device")
    message = parsed.get("message") or raw

    event_type = classify_event_type(
        parsed.get("event_type", EventTypes.generic), message, parsed.get("success")
    )
    if event_type == EventTypes.port_scan and severity == "info":
        severity = "medium"

    labels: list[str] = []
    if ctx is not None:
        if src_ip and src_ip in ctx.intel_ips:
            labels.append("threat_intel")
            if severity == "info":
                severity = "medium"
        if dst_ip and dst_ip in ctx.intel_ips:
            labels.append("threat_intel_dest")

    source_port = _coerce_int(parsed.get("source_port"))
    dst_port = _coerce_int(parsed.get("dst_port"))
    process_name = parsed.get("process_name")
    success = parsed.get("success")

    return EventRecord(
        organization_id=organization_id,
        timestamp=ts,
        event_type=event_type,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        username=username,
        source=source,
        destination=destination,
        device=device,
        application=application,
        message=message,
        source_log_type=parsed.get("source_log_type", "unknown"),
        source_port=source_port,
        dst_port=dst_port,
        success=success,
        process_name=process_name,
        geo_country=None,
        labels=labels,
        raw=raw,
    )
