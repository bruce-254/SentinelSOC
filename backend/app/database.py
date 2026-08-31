"""Database engine and session management.

The default database is PostgreSQL in production (docker-compose.yml) and
SQLite for local development / tests. All queries go through the SQLAlchemy
session layer; the high-volume event table is accessed via the storage
abstraction in ``app.storage`` so it can be moved to a search/analytics
datastore later without touching the API layer.
"""
from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


def _build_engine():
    kwargs: dict = {"echo": settings.db_echo, "future": True}
    if settings.is_sqlite:
        # SQLite is single-writer; use it only for dev/tests.
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in settings.database_url or settings.database_url.endswith("://"):
            # Share a single in-memory connection across the pool.
            from sqlalchemy.pool import StaticPool
            kwargs["poolclass"] = StaticPool
    else:
        kwargs["pool_size"] = settings.db_pool_size
        kwargs["max_overflow"] = settings.db_max_overflow
        kwargs["pool_pre_ping"] = True
    return create_engine(settings.database_url, **kwargs)


engine = _build_engine()

if settings.is_sqlite:
    # Enforce foreign keys on SQLite (off by default).
    @event.listens_for(engine, "connect")
    def _fk_pragma(dbapi_conn, _record):  # pragma: no cover - sqlite only
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. In production a migration tool should own the schema."""
    import app.models  # noqa: F401  ensure models are registered

    Base.metadata.create_all(bind=engine)
