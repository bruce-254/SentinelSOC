"""Pydantic request/response schemas."""
from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------
# Auth / Users
# --------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=120, pattern=r"^[a-zA-Z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="analyst")


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)


class UserOut(ORMModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    slug: str | None = Field(default=None, max_length=120)

    @field_validator("slug")
    @classmethod
    def slug_valid(cls, v):
        if v is None:
            return v
        if not re.fullmatch(r"[a-z0-9-]+", v):
            raise ValueError("slug must be lowercase alphanumeric with dashes")
        return v


class OrganizationOut(ORMModel):
    id: int
    name: str
    slug: str
    created_at: datetime


# --------------------------------------------------------------------------
# Assets
# --------------------------------------------------------------------------
class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(max_length=64)
    hostname: str | None = None
    os: str | None = None
    criticality: str = Field(default="medium")
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None

    @field_validator("criticality")
    @classmethod
    def crit_valid(cls, v):
        v = v.lower()
        if v not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("invalid criticality")
        return v


class AssetUpdate(BaseModel):
    name: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    os: str | None = None
    criticality: str | None = None
    tags: list[str] | None = None
    notes: str | None = None


class AssetOut(ORMModel):
    id: int
    name: str
    ip_address: str
    hostname: str | None
    os: str | None
    criticality: str
    tags: list
    notes: str | None
    created_at: datetime


# --------------------------------------------------------------------------
# Events / ingestion
# --------------------------------------------------------------------------
class IngestRequest(BaseModel):
    """Ingest one raw log line / record."""

    source_log_type: str = Field(min_length=1, max_length=64)
    raw: str = Field(min_length=1, max_length=200_000)


class IngestBatchRequest(BaseModel):
    entries: list[IngestRequest] = Field(max_length=5000)


class IngestResponse(BaseModel):
    accepted: int
    normalized: int
    alerts: int
    rejected: int
    errors: list[str] = Field(default_factory=list)


class EventOut(ORMModel):
    id: int
    timestamp: datetime
    event_type: str
    severity: str
    src_ip: str | None
    dst_ip: str | None
    username: str | None
    source: str | None
    destination: str | None
    device: str | None
    application: str | None
    message: str | None
    source_log_type: str
    source_port: int | None
    dst_port: int | None
    success: bool | None
    process_name: str | None
    geo_country: str | None
    labels: list


class EventSearch(BaseModel):
    q: str | None = None
    time_from: datetime | None = None
    time_to: datetime | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    asset: str | None = None
    severity: str | None = None
    event_type: str | None = None
    source_log_type: str | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)


class Page(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
    pages: int


# --------------------------------------------------------------------------
# Detection rules
# --------------------------------------------------------------------------
class RuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    rule_type: str = Field(default="single_event")
    scope: dict = Field(default_factory=dict)
    conditions: dict = Field(default_factory=dict)
    time_window_seconds: int | None = Field(default=None, gt=0, le=86400 * 7)
    threshold: int | None = Field(default=None, ge=1)
    group_by: str | None = None
    enabled: bool = True
    priority: int = Field(default=50, ge=1, le=100)
    severity: str = Field(default="medium")
    alert_title: str | None = None
    risk_weight: float = Field(default=1.0, ge=0.0, le=10.0)

    @field_validator("severity")
    @classmethod
    def sev_valid(cls, v):
        v = v.lower()
        if v not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("invalid severity")
        return v

    @model_validator(mode="after")
    def _check(self):
        if self.rule_type not in {"single_event", "aggregate"}:
            raise ValueError("rule_type must be single_event or aggregate")
        if self.rule_type == "aggregate":
            if self.time_window_seconds is None or self.threshold is None or not self.group_by:
                raise ValueError(
                    "aggregate rules require time_window_seconds, threshold and group_by"
                )
        return self


class RuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    scope: dict | None = None
    conditions: dict | None = None
    time_window_seconds: int | None = None
    threshold: int | None = None
    group_by: str | None = None
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=1, le=100)
    severity: str | None = None
    alert_title: str | None = None
    risk_weight: float | None = None


class RuleOut(ORMModel):
    id: int
    name: str
    description: str | None
    rule_type: str
    scope: dict
    conditions: dict
    time_window_seconds: int | None
    threshold: int | None
    group_by: str | None
    enabled: bool
    priority: int
    severity: str
    alert_title: str | None
    risk_weight: float
    created_at: datetime
    updated_at: datetime


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------
class AlertOut(ORMModel):
    id: int
    rule_id: int | None
    title: str
    severity: str
    risk_score: float
    status: str
    asset_name: str | None
    source: str | None
    src_ip: str | None
    username: str | None
    event_type: str | None
    evidence: list
    event_ids: list
    created_at: datetime
    updated_at: datetime


class AlertUpdate(BaseModel):
    status: str | None = None
    note: str | None = None

    @field_validator("status")
    @classmethod
    def st_valid(cls, v):
        if v is not None and v not in {
            "new", "acknowledged", "investigating", "resolved", "false_positive",
        }:
            raise ValueError("invalid status")
        return v


# --------------------------------------------------------------------------
# Incidents
# --------------------------------------------------------------------------
class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    severity: str = Field(default="medium")
    alert_ids: list[int] = Field(default_factory=list)

    @field_validator("severity")
    @classmethod
    def sev_valid(cls, v):
        v = v.lower()
        if v not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("invalid severity")
        return v


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str | None = None
    assignee_id: int | None = None

    @field_validator("status")
    @classmethod
    def st_valid(cls, v):
        if v is not None and v not in {
            "open", "investigating", "contained", "resolved", "closed",
        }:
            raise ValueError("invalid status")
        return v


class IncidentNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class IncidentNoteOut(ORMModel):
    id: int
    user_id: int | None
    body: str
    status_change: str | None
    created_at: datetime


class IncidentOut(ORMModel):
    id: int
    title: str
    description: str | None
    severity: str
    status: str
    alert_ids: list
    asset_ids: list
    assignee_id: int | None
    created_by: int | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    notes: list[IncidentNoteOut] = []


# --------------------------------------------------------------------------
# Dashboard / stats
# --------------------------------------------------------------------------
class SeriesPoint(BaseModel):
    t: str
    value: float


class DashboardStats(BaseModel):
    events_total: int
    events_per_minute: float
    alerts_total: int
    critical_alerts: int
    high_alerts: int
    failed_logins: int
    open_incidents: int
    active_rules: int
    event_rate_series: list[SeriesPoint]
    auth_trend_series: list[SeriesPoint]
    severity_distribution: dict[str, int]
    alert_status_distribution: dict[str, int]
    incident_status_distribution: dict[str, int]
    top_source_ips: list[dict]
    top_assets: list[dict]
    top_users: list[dict]
    event_types: dict[str, int]


# --------------------------------------------------------------------------
# Risk
# --------------------------------------------------------------------------
class RiskScoreOut(ORMModel):
    entity_type: str
    entity_id: str
    entity_label: str | None
    score: float
    level: str
    factors: list
    updated_at: datetime


class RiskDetail(RiskScoreOut):
    alerts: list[AlertOut] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
class ReportRequest(BaseModel):
    report_type: str = "summary"
    time_from: datetime
    time_to: datetime


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------
class AuditOut(ORMModel):
    id: int
    user_id: int | None
    username: str | None
    action: str
    resource: str | None
    resource_id: str | None
    details: dict | None
    ip_address: str | None
    created_at: datetime


# --------------------------------------------------------------------------
# Threat intelligence
# --------------------------------------------------------------------------
class ThreatIntelOut(ORMModel):
    id: int
    indicator_type: str
    value: str
    provider: str
    confidence: float
    tags: list
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime
