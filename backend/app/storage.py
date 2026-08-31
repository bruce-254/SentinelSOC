"""Event storage abstraction.

High-volume security events are written and queried through this interface so
the underlying store can later be swapped for a search/analytics datastore
(e.g. Elasticsearch or ClickHouse) without changing the API or detection
pipeline. The bundled implementation uses the SQLAlchemy ``events`` table.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .models import NormalizedEvent

# PostgreSQL can be configured with a per-statement statement timeout; this is
# a no-op for SQLite. It prevents pathological search queries.
STATEMENT_TIMEOUT = "SET statement_timeout = '30s'"


@dataclass
class EventRecord:
    organization_id: int
    timestamp: datetime
    event_type: str
    severity: str
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    source: str | None = None
    destination: str | None = None
    device: str | None = None
    application: str | None = None
    message: str | None = None
    source_log_type: str = "unknown"
    source_port: int | None = None
    dst_port: int | None = None
    success: bool | None = None
    process_name: str | None = None
    geo_country: str | None = None
    labels: list | None = None
    raw: str | None = None


class EventStoreProtocol(Protocol):
    def bulk_write(self, db: Session, records: list[EventRecord]) -> list[int]: ...


class SqlAlchemyEventStore:
    """Default store backed by the relational events table."""

    def __init__(self, db: Session):
        self.db = db

    def _apply_pg_timeout(self) -> None:
        if self.db.bind and self.db.bind.dialect.name == "postgresql":
            self.db.execute(text(STATEMENT_TIMEOUT))

    def bulk_write(self, records: list[EventRecord]) -> list[int]:
        if not records:
            return []
        rows = [NormalizedEvent(**r.__dict__) for r in records]
        self.db.add_all(rows)
        self.db.flush()
        return [r.id for r in rows]

    def search(
        self,
        *,
        organization_id: int,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        username: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        source_log_type: str | None = None,
        q: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[NormalizedEvent], int]:
        self._apply_pg_timeout()
        stmt = select(NormalizedEvent).where(
            NormalizedEvent.organization_id == organization_id
        )
        if time_from is not None:
            stmt = stmt.where(NormalizedEvent.timestamp >= time_from)
        if time_to is not None:
            stmt = stmt.where(NormalizedEvent.timestamp <= time_to)
        if src_ip:
            stmt = stmt.where(NormalizedEvent.src_ip == src_ip)
        if dst_ip:
            stmt = stmt.where(NormalizedEvent.dst_ip == dst_ip)
        if username:
            stmt = stmt.where(NormalizedEvent.username.ilike(f"%{username}%"))
        if event_type:
            stmt = stmt.where(NormalizedEvent.event_type == event_type)
        if severity:
            stmt = stmt.where(NormalizedEvent.severity == severity)
        if source_log_type:
            stmt = stmt.where(NormalizedEvent.source_log_type == source_log_type)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(
                (NormalizedEvent.message.ilike(like))
                | (NormalizedEvent.src_ip.ilike(like))
                | (NormalizedEvent.username.ilike(like))
                | (NormalizedEvent.device.ilike(like))
                | (NormalizedEvent.application.ilike(like))
            )
        total = self.db.scalar(
            select(func.count()).select_from(stmt.subquery())
        ) or 0
        stmt = stmt.order_by(NormalizedEvent.timestamp.desc()).offset(
            (page - 1) * page_size
        ).limit(page_size)
        return list(self.db.scalars(stmt)), total

    def count_in_window(
        self,
        *,
        organization_id: int,
        event_type: str,
        since: datetime,
        group_by: str | None = None,
        group_value: str | None = None,
    ) -> int:
        stmt = select(func.count()).select_from(NormalizedEvent).where(
            NormalizedEvent.organization_id == organization_id,
            NormalizedEvent.event_type == event_type,
            NormalizedEvent.timestamp >= since,
        )
        if group_by == "src_ip" and group_value:
            stmt = stmt.where(NormalizedEvent.src_ip == group_value)
        elif group_by == "username" and group_value:
            stmt = stmt.where(NormalizedEvent.username == group_value)
        elif group_by == "dst_ip" and group_value:
            stmt = stmt.where(NormalizedEvent.dst_ip == group_value)
        return self.db.scalar(stmt) or 0

    def time_series(
        self,
        *,
        organization_id: int,
        since: datetime,
        bucket_seconds: int,
        event_types: list[str] | None = None,
    ) -> list[tuple[datetime, int]]:
        """Return (bucket_start, count) series for dashboard charts."""
        self._apply_pg_timeout()
        stmt = select(
            NormalizedEvent.timestamp,
            NormalizedEvent.event_type,
        ).where(
            NormalizedEvent.organization_id == organization_id,
            NormalizedEvent.timestamp >= since,
        )
        if event_types:
            stmt = stmt.where(NormalizedEvent.event_type.in_(event_types))
        rows = self.db.execute(stmt)
        buckets: dict[int, int] = {}
        for ts, _et in rows:
            bucket = int(ts.timestamp() // bucket_seconds) * bucket_seconds
            buckets[bucket] = buckets.get(bucket, 0) + 1
        out = sorted(
            (datetime.fromtimestamp(b, tz=timezone.utc), c) for b, c in buckets.items()
        )
        return out


def get_event_store(db: Session) -> SqlAlchemyEventStore:
    return SqlAlchemyEventStore(db)
