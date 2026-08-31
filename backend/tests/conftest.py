"""Pytest fixtures using an isolated in-memory SQLite database."""
from __future__ import annotations

import os
import sys

import pytest

# Ensure the package is importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Use a fresh SQLite database for tests (never the real one).
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["THREATINTEL_ENABLED"] = "false"
os.environ["RATE_LIMIT_ENABLED"] = "false"

from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.database import Base, get_db  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402


from sqlalchemy.pool import StaticPool  # noqa: E402


@pytest.fixture(scope="function")
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(eng, "connect")
    def _fk(dbapi_conn, _rec):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    import app.models  # noqa: F401

    Base.metadata.create_all(eng)
    return eng


@pytest.fixture(scope="function")
def TestSessionLocal(engine):
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture
def db(engine, TestSessionLocal):
    """A session with the default org/admin/rules present (FK integrity)."""
    from app.bootstrap import bootstrap as run_bootstrap
    s = TestSessionLocal()
    try:
        run_bootstrap(s)
        s.commit()
        yield s
    finally:
        s.rollback()
        s.close()


@pytest.fixture
def client(TestSessionLocal):
    def override_get_db():
        s = TestSessionLocal()
        try:
            yield s
        finally:
            s.close()

    fastapi_app.dependency_overrides[get_db] = override_get_db
    from fastapi.testclient import TestClient

    with TestClient(fastapi_app) as c:
        yield c
    fastapi_app.dependency_overrides.clear()


@pytest.fixture
def bootstrap(TestSessionLocal):
    """Create default org + admin + rules in the test DB."""
    from app.bootstrap import bootstrap as run_bootstrap
    s = TestSessionLocal()
    try:
        run_bootstrap(s)
        s.commit()
    finally:
        s.close()
    return True


@pytest.fixture
def auth_headers(client, bootstrap):
    resp = client.post("/api/auth/login", json={
        "username": "admin", "password": "admin12345",
    })
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers(auth_headers):
    return auth_headers
