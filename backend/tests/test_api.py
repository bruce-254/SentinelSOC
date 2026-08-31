"""API endpoint tests: rules, alerts, incidents, assets, audit, risk."""
from app.main import app


def _seed_alert(client, auth_headers):
    # ingest enough failures to create an alert
    entries = [{
        "source_log_type": "linux_auth",
        "raw": f"Jun 12 08:00:{i:02d} srv sshd[100]: Failed password for root from 203.0.113.10 port 22 ssh2",
    } for i in range(8)]
    client.post("/api/events/ingest", headers=auth_headers, json={"entries": entries})


class TestRules:
    def test_rules_seeded_in_db(self, client, auth_headers, bootstrap):
        r = client.get("/api/rules", headers=auth_headers)
        assert r.status_code == 200
        rules = r.json()
        assert len(rules) >= 1
        assert all("id" in x for x in rules)

    def test_admin_can_disable_rule(self, client, auth_headers, bootstrap):
        rules = client.get("/api/rules", headers=auth_headers).json()
        rid = rules[0]["id"]
        r = client.post(f"/api/rules/{rid}/disable", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["enabled"] is False
        r = client.post(f"/api/rules/{rid}/enable", headers=auth_headers)
        assert r.json()["enabled"] is True

    def test_admin_can_edit_rule(self, client, auth_headers, bootstrap):
        rules = client.get("/api/rules", headers=auth_headers).json()
        rid = rules[0]["id"]
        r = client.patch(f"/api/rules/{rid}", headers=auth_headers,
                         json={"priority": 99, "severity": "critical"})
        assert r.status_code == 200
        assert r.json()["priority"] == 99


class TestAlerts:
    def test_alerts_created_and_listed(self, client, auth_headers, bootstrap):
        _seed_alert(client, auth_headers)
        r = client.get("/api/alerts", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["total"] >= 1
        alert = r.json()["items"][0]
        for key in ("id", "title", "severity", "risk_score", "status",
                    "evidence", "created_at"):
            assert key in alert

    def test_alert_detail_has_risk_factors(self, client, auth_headers, bootstrap):
        _seed_alert(client, auth_headers)
        alert = client.get("/api/alerts", headers=auth_headers).json()["items"][0]
        r = client.get(f"/api/alerts/{alert['id']}", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["risk_factors"]
        assert r.json()["risk_factors"][0]["explanation"]

    def test_analyst_can_triage_alert(self, client, auth_headers, bootstrap):
        _create_user(client, auth_headers, "triager", "analyst")
        tok = client.post("/api/auth/login", json={
            "username": "triager", "password": "password123"}).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        _seed_alert(client, auth_headers)
        alert = client.get("/api/alerts", headers=auth_headers).json()["items"][0]
        r = client.patch(f"/api/alerts/{alert['id']}", headers=h,
                         json={"status": "investigating"})
        assert r.status_code == 200
        assert r.json()["status"] == "investigating"


class TestIncidents:
    def test_create_and_flow(self, client, auth_headers, bootstrap):
        r = client.post("/api/incidents", headers=auth_headers, json={
            "title": "Possible brute force",
            "description": "Investigating repeated failures",
            "severity": "high",
        })
        assert r.status_code == 201
        iid = r.json()["id"]

        r = client.patch(f"/api/incidents/{iid}", headers=auth_headers,
                         json={"status": "investigating"})
        assert r.json()["status"] == "investigating"

        r = client.post(f"/api/incidents/{iid}/notes", headers=auth_headers,
                        json={"body": "Confirmed scanning behavior"})
        assert r.status_code == 200

        r = client.get("/api/incidents", headers=auth_headers)
        assert any(i["id"] == iid for i in r.json())

    def test_incident_status_transitions_audited(self, client, auth_headers, bootstrap):
        r = client.post("/api/incidents", headers=auth_headers, json={"title": "t"})
        iid = r.json()["id"]
        client.patch(f"/api/incidents/{iid}", headers=auth_headers,
                     json={"status": "resolved"})
        r = client.get(f"/api/incidents/{iid}", headers=auth_headers)
        assert r.json()["status"] == "resolved"
        assert r.json()["resolved_at"] is not None


class TestAssets:
    def test_asset_crud(self, client, auth_headers, bootstrap):
        r = client.post("/api/assets", headers=auth_headers, json={
            "name": "DB Server", "ip_address": "10.0.0.20",
            "hostname": "db01", "criticality": "critical", "tags": ["db"]})
        assert r.status_code == 201
        aid = r.json()["id"]
        r = client.get("/api/assets", headers=auth_headers)
        assert any(a["id"] == aid for a in r.json())
        r = client.patch(f"/api/assets/{aid}", headers=auth_headers, json={"criticality": "high"})
        assert r.json()["criticality"] == "high"
        r = client.delete(f"/api/assets/{aid}", headers=auth_headers)
        assert r.status_code == 204


class TestAudit:
    def test_actions_audited(self, client, auth_headers, bootstrap):
        client.post("/api/incidents", headers=auth_headers, json={"title": "audit me"})
        r = client.get("/api/audit", headers=auth_headers)
        assert r.status_code == 200
        actions = [a["action"] for a in r.json()]
        assert "incident.create" in actions


class TestRiskApi:
    def test_risk_scores_populated(self, client, auth_headers, bootstrap):
        _seed_alert(client, auth_headers)
        r = client.get("/api/risk", headers=auth_headers)
        assert r.status_code == 200
        scores = r.json()
        assert any(s["score"] > 0 for s in scores)
        # explanation present
        assert scores[0]["factors"]


class TestThreatIntel:
    def test_sync_with_no_providers_enabled(self, client, auth_headers, bootstrap):
        # threatintel disabled -> no indicators, no fabrication
        r = client.post("/api/threatintel/sync", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["synced"] == 0


class TestHealth:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


def _create_user(client, admin_headers, username, role):
    return client.post("/api/users", headers=admin_headers, json={
        "username": username,
        "email": f"{username}@example.com",
        "password": "password123",
        "role": role,
    })
