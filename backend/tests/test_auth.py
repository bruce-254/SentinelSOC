"""Tests for authentication and RBAC."""
from app.database import get_db
from app.main import app


def test_login_success(client, bootstrap):
    r = client.post("/api/auth/login", json={
        "username": "admin", "password": "admin12345"})
    assert r.status_code == 200
    data = r.json()
    assert data["access_token"]
    assert data["token_type"] == "bearer"


def test_login_wrong_password(client, bootstrap):
    r = client.post("/api/auth/login", json={
        "username": "admin", "password": "wrongpass"})
    assert r.status_code == 401


def test_login_unknown_user(client, bootstrap):
    r = client.post("/api/auth/login", json={
        "username": "ghost", "password": "whatever1"})
    assert r.status_code == 401


def test_me_requires_token(client, bootstrap):
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_me_with_token(client, auth_headers, bootstrap):
    r = client.get("/api/auth/me", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["username"] == "admin"
    assert r.json()["role"] == "admin"


def test_password_change(client, auth_headers, bootstrap):
    r = client.post("/api/auth/change-password", headers=auth_headers, json={
        "old_password": "admin12345", "new_password": "newpassword123"})
    assert r.status_code == 200
    # login with new password
    r = client.post("/api/auth/login", json={
        "username": "admin", "password": "newpassword123"})
    assert r.status_code == 200


def test_invalid_token_rejected(client, bootstrap):
    r = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
    assert r.status_code == 401
