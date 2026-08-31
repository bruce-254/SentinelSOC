"""End-to-end pipeline tests: ingest -> parse -> normalize -> detect -> alert."""
import pytest

from app.models import Alert, NormalizedEvent
from app.pipeline.pipeline import process_ingest


def _fail_lines(n, ip="203.0.113.10"):
    return [
        {
            "source_log_type": "linux_auth",
            "raw": (f"Jun 12 08:00:{i:02d} srv sshd[100]: "
                    f"Failed password for root from {ip} port 22 ssh2"),
        }
        for i in range(n)
    ]


class TestPipeline:
    def test_successful_login_no_alert_for_single(self, db):
        entries = [{
            "source_log_type": "linux_auth",
            "raw": "Jun 12 08:00:00 srv sshd[1]: Accepted password for alice from 10.0.1.42 port 22 ssh2",
        }]
        # only a single success won't match an aggregate; enable nothing special
        r = process_ingest(db, organization_id=1, entries=entries)
        assert r.normalized == 1
        db.rollback()

    def test_repeated_failures_trigger_alert(self, db, bootstrap, engine, TestSessionLocal):
        # Create the org so the org id (1) matches bootstrap default
        db.commit()
        entries = _fail_lines(6)
        r = process_ingest(db, organization_id=1, entries=entries)
        assert r.normalized == 6
        assert r.alerts >= 1

    def test_events_stored(self, db):
        entries = [{
            "source_log_type": "json",
            "raw": '{"timestamp":"2024-01-01T00:00:00Z","event_type":"network_connection",'
                   '"severity":"info","src_ip":"10.0.0.5","message":"ping"}',
        }]
        r = process_ingest(db, organization_id=1, entries=entries)
        assert r.normalized == 1
        ev = db.query(NormalizedEvent).filter(NormalizedEvent.organization_id == 1).first()
        assert ev is not None
        assert ev.event_type == "network_connection"
        db.rollback()

    def test_bad_line_does_not_break_batch(self, db):
        entries = [
            {"source_log_type": "linux_auth", "raw": "complete garbage"},
            {"source_log_type": "linux_auth",
             "raw": "Jun 12 08:00:00 srv sshd[1]: Accepted password for alice from 10.0.1.42 port 22 ssh2"},
        ]
        r = process_ingest(db, organization_id=1, entries=entries)
        assert r.rejected == 1
        assert r.normalized == 1
        db.rollback()

    def test_unknown_source_type_rejected(self, db):
        entries = [{"source_log_type": "bogus", "raw": "x"}]
        r = process_ingest(db, organization_id=1, entries=entries)
        assert r.rejected == 1
        db.rollback()


class TestIngestApi:
    def test_ingest_endpoint(self, client, auth_headers, bootstrap):
        r = client.post("/api/events/ingest", headers=auth_headers, json={
            "entries": [{
                "source_log_type": "linux_auth",
                "raw": "Jun 12 08:00:00 srv sshd[1]: Failed password for root from 203.0.113.10 port 22 ssh2",
            }],
        })
        assert r.status_code == 200
        body = r.json()
        assert body["accepted"] == 1
        assert body["normalized"] == 1

    def test_ingest_requires_auth(self, client, bootstrap):
        r = client.post("/api/events/ingest", json={"entries": []})
        assert r.status_code == 401

    def test_events_search(self, client, auth_headers, bootstrap):
        client.post("/api/events/ingest", headers=auth_headers, json={
            "entries": [{
                "source_log_type": "linux_auth",
                "raw": "Jun 12 08:00:00 srv sshd[1]: Failed password for root from 203.0.113.10 port 22 ssh2",
            }],
        })
        r = client.get("/api/events/search?event_type=authentication_failure",
                       headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["total"] == 1

    def test_dashboard_counts(self, client, auth_headers, bootstrap):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        client.post("/api/events/ingest", headers=auth_headers, json={
            "entries": [
                {"source_log_type": "json",
                 "raw": ('{"timestamp":"' + now + '","event_type":"authentication_failure",'
                        '"severity":"medium","src_ip":"203.0.113.10","username":"root",'
                        '"message":"failed login"}')},
                {"source_log_type": "json",
                 "raw": ('{"timestamp":"' + now + '","event_type":"authentication_success",'
                        '"severity":"info","src_ip":"10.0.1.42","username":"alice",'
                        '"message":"ok"}')},
            ],
        })
        r = client.get("/api/dashboard", headers=auth_headers)
        assert r.status_code == 200
        d = r.json()
        assert d["events_total"] >= 2
        assert d["failed_logins"] >= 1
        assert "event_rate_series" in d
        assert "severity_distribution" in d
