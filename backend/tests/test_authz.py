"""Tests for role-based access control."""
from app.main import app


def _create_user(client, admin_headers, username, role):
    return client.post("/api/users", headers=admin_headers, json={
        "username": username,
        "email": f"{username}@example.com",
        "password": "password123",
        "role": role,
    })


def _login(client, username, password="password123"):
    return client.post("/api/auth/login", json={
        "username": username, "password": password})


class TestRbac:
    def test_viewer_cannot_create_rule(self, client, admin_headers, bootstrap):
        _create_user(client, admin_headers, "viewer1", "viewer")
        tok = _login(client, "viewer1").json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        r = client.post("/api/rules", headers=h, json={
            "name": "bad", "rule_type": "single_event", "scope": {},
            "conditions": {}, "severity": "medium"})
        assert r.status_code == 403

    def test_viewer_can_read(self, client, admin_headers, bootstrap):
        _create_user(client, admin_headers, "viewer2", "viewer")
        tok = _login(client, "viewer2").json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        r = client.get("/api/rules", headers=h)
        assert r.status_code == 200
        r = client.get("/api/dashboard", headers=h)
        assert r.status_code == 200

    def test_viewer_cannot_update_alert(self, client, admin_headers, bootstrap):
        _create_user(client, admin_headers, "viewer3", "viewer")
        tok = _login(client, "viewer3").json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        r = client.patch("/api/alerts/1", headers=h, json={"status": "resolved"})
        # viewer lacks the update_alert capability -> forbidden regardless of resource
        assert r.status_code == 403

    def test_analyst_cannot_manage_users(self, client, admin_headers, bootstrap):
        _create_user(client, admin_headers, "analyst1", "analyst")
        tok = _login(client, "analyst1").json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        r = client.post("/api/users", headers=h, json={
            "username": "x", "email": "x@example.com",
            "password": "password123", "role": "analyst"})
        assert r.status_code == 403

    def test_non_admin_cannot_list_orgs(self, client, admin_headers, bootstrap):
        _create_user(client, admin_headers, "analyst2", "analyst")
        tok = _login(client, "analyst2").json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        r = client.get("/api/organizations", headers=h)
        assert r.status_code == 403

    def test_admin_can_manage_rules(self, client, admin_headers, bootstrap):
        r = client.post("/api/rules", headers=admin_headers, json={
            "name": "Custom Rule", "rule_type": "single_event",
            "scope": {"event_types": ["authentication_failure"]},
            "conditions": {"username": {"eq": "root"}},
            "severity": "high", "priority": 70})
        assert r.status_code == 201
