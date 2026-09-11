import json
import sqlite3
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cyberdeck_api.auth import AuthMiddleware, COOKIE, hash_password

ORIGIN = "https://security.example.com"
PASSWORD = "synthetic-test-password-only"


@pytest.fixture
def secured(tmp_path, monkeypatch):
    config = tmp_path / "users.json"
    config.write_text(json.dumps({"users": [
        {"id": "admin", "username": "superadmin", "role": "super_admin", "passwordHash": hash_password(PASSWORD)},
        {"id": "operator", "username": "operador", "role": "analyst", "passwordHash": hash_password(PASSWORD)},
    ]}))
    db = tmp_path / "sessions.sqlite"
    monkeypatch.setenv("CDE_AUTH_ENABLED", "true")
    monkeypatch.setenv("CDE_PUBLIC_ORIGIN", ORIGIN)
    monkeypatch.setenv("CDE_AUTH_USERS_FILE", str(config))
    monkeypatch.setenv("CDE_AUTH_STATE_FILE", str(db))
    app = FastAPI()
    @app.api_route("/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"])
    def protected(path: str):
        return {"protected": True}
    app.add_middleware(AuthMiddleware)
    client = TestClient(app, base_url=ORIGIN)
    yield client, db, config, app


def login(client, username="operador"):
    response = client.post("/api/auth/login", json={"username": username, "password": PASSWORD}, headers={"Origin": ORIGIN})
    assert response.status_code == 200
    return response


def test_anonymous_and_forged_browser_roles_cannot_read_data(secured):
    client, *_ = secured
    for path in ["/api/runs", "/api/reports/archive", "/reports/private.html", "/docs", "/openapi.json", "/api/auth/me"]:
        response = client.get(path, headers={"X-Role": "super_admin", "Authorization": "Bearer forged", "Cookie": "cyberdecision.session=superadmin"})
        assert response.status_code == 401
    assert client.get("/api/health").json() == {"status": "ok"}


def test_both_accounts_login_and_cookie_security(secured):
    client, *_ = secured
    for name, role in [("superadmin", "super_admin"), ("operador", "analyst")]:
        response = login(client, name)
        assert response.json()["user"]["role"] == role
        assert response.json()["user"]["passwordHash"] == ""
        cookie = response.headers["set-cookie"].lower()
        for flag in ["secure", "httponly", "samesite=strict", "path=/"]:
            assert flag in cookie
        assert client.get("/api/runs").status_code == 200


def test_operator_cannot_admin_delete_or_forge_role(secured):
    client, *_ = secured
    response = login(client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrfToken"], "X-Role": "super_admin"}
    for method, path in [("GET", "/api/licensing/overview"), ("GET", "/api/ai/config"), ("GET", "/api/auth/users"),
                         ("POST", "/api/admin/cti/knowledge/sync"), ("POST", "/api/admin/cti/knowledge/rollback"),
                         ("DELETE", "/api/reports/private.html"), ("PATCH", "/api/licensing/users/operator"),
                         ("POST", "/api/future-administration")]:
        assert client.request(method, path, headers=headers).status_code == 403
    assert client.post("/api/analysis", json={"role": "super_admin"}, headers=headers).status_code == 200
    assert client.post("/api/runs/sample/report", headers=headers).status_code == 200
    assert client.get("/reports/private.html").status_code == 200


def test_admin_allowed_csrf_required_and_logout_revokes(secured):
    client, *_ = secured
    response = login(client, "superadmin")
    token = client.cookies.get(COOKIE)
    csrf = response.json()["csrfToken"]
    assert client.post("/api/admin/change", headers={"Origin": ORIGIN}).status_code == 403
    assert client.post("/api/admin/change", headers={"Origin": "https://evil.example", "X-CSRF-Token": csrf}).status_code == 403
    assert client.post("/api/admin/change", headers={"X-CSRF-Token": csrf}).status_code == 403
    assert client.post("/api/admin/change", headers={"Origin": ORIGIN, "X-CSRF-Token": csrf}).status_code == 200
    assert client.post("/api/auth/logout", headers={"Origin": ORIGIN, "X-CSRF-Token": csrf}).status_code == 200
    assert client.get("/api/runs", headers={"Cookie": f"{COOKIE}={token}"}).status_code == 401


def test_login_origin_and_brute_force_throttle(secured):
    client, *_ = secured
    assert client.post("/api/auth/login", json={}, headers={"Origin": "https://evil.example"}).status_code == 403
    for _ in range(10):
        assert client.post("/api/auth/login", json={"username": "operador", "password": "bad"}, headers={"Origin": ORIGIN}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "operador", "password": PASSWORD}, headers={"Origin": ORIGIN}).status_code == 429


def test_expiry_restart_revocation_and_report_isolation(secured):
    client, db_path, config, app = secured
    login(client)
    for path in ["/reports/private.html", "/api/reports/private.html/download"]:
        response = client.get(path)
        assert "sandbox;" in response.headers["content-security-policy"]
        assert "allow-scripts" not in response.headers["content-security-policy"]
        assert "https:" not in response.headers["content-security-policy"]
        assert "allow-same-origin" not in response.headers["content-security-policy"]
        assert response.headers["cache-control"] == "no-store"
    # Another middleware instance reads persisted sessions, not process-local state.
    restarted = TestClient(AuthMiddleware(app), base_url=ORIGIN)
    restarted.cookies.update(client.cookies)
    assert restarted.get("/api/runs").status_code == 200
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE sessions SET touched=?", (time.time() - 1801,))
    assert client.get("/api/runs").status_code == 401
    login(client)
    payload = json.loads(config.read_text())
    payload["users"][1]["disabled"] = True
    config.write_text(json.dumps(payload))
    assert client.get("/api/runs").status_code == 401


def test_missing_configuration_fails_closed(secured):
    client, _, config, _ = secured
    login(client)
    config.unlink()
    assert client.get("/api/runs").status_code == 503
    with pytest.raises(FileNotFoundError):
        AuthMiddleware(FastAPI())


def test_real_api_routes_enforce_scope_and_administration(secured):
    from cyberdeck_api.main import app as production
    # Reuse the actual route handlers without persisting a test-mode middleware
    # stack on the global application used by local-compatibility tests.
    app = FastAPI()
    app.router.routes = production.router.routes.copy()
    app.add_middleware(AuthMiddleware)
    client = TestClient(app, base_url=ORIGIN)
    response = login(client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrfToken"]}
    assert client.get("/api/runs/status").status_code == 200
    assert client.get("/api/reports").status_code == 200
    response = client.post("/api/analysis", json={"domains": ["example.com"], "authorized_scope": False}, headers=headers)
    assert response.status_code == 403
    assert "authorized_scope" in response.json()["detail"]
    response = client.post("/api/analysis", json={"domains": ["example.com"], "authorized_scope": True, "report_display_at": "2026-01-01T00:00:00Z"}, headers=headers)
    assert response.status_code == 403
    assert "report_display_at" in response.json()["detail"]
    assert client.post("/api/admin/cti/knowledge/rollback", json={"source_ids": []}, headers=headers).status_code == 403
    response = login(client, "superadmin")
    headers["X-CSRF-Token"] = response.json()["csrfToken"]
    # Reaches the real validator, safely refusing an empty rollback operation.
    assert client.post("/api/admin/cti/knowledge/rollback", json={"source_ids": []}, headers=headers).status_code == 422


def test_password_rotation_revokes_sessions_and_generator_matches_server(secured, tmp_path, monkeypatch):
    import sys
    from scripts.vps_public_users import main
    from cyberdeck_api.auth import verify_password
    client, _, config, _ = secured
    login(client)
    payload = json.loads(config.read_text())
    payload["users"][1]["passwordHash"] = hash_password("a-new-synthetic-password")
    config.write_text(json.dumps(payload))
    assert client.get("/api/runs").status_code == 401
    target = tmp_path / "provisioned"
    monkeypatch.setattr(sys, "argv", ["vps_public_users.py", "--output-dir", str(target)])
    main()
    credentials = json.loads((target / "public-credentials.json").read_text())["users"]
    records = json.loads((target / "auth_users.json").read_text())["users"]
    for credential, record in zip(credentials, records):
        assert verify_password(credential["password"], record["passwordHash"])
    before = (target / "auth_users.json").read_bytes()
    main()
    assert before == (target / "auth_users.json").read_bytes()


def test_authenticated_actor_overrides_forged_review_and_audit_names(secured, tmp_path, monkeypatch):
    from cyberdeck_api import main as production
    from cyberdeck_api.models import DomainAnalysisRequest, RunRecord
    from cyberdeck_api.monitoring import MonitoringStore
    app = FastAPI()
    app.router.routes = production.app.router.routes.copy()
    app.add_middleware(AuthMiddleware)
    client = TestClient(app, base_url=ORIGIN)
    response = login(client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrfToken"]}
    observed = []
    record = RunRecord(id="synthetic", request=DomainAnalysisRequest(domains=["example.com"]))
    async def review_one(run_id, evidence_id, status, reviewer, reason):
        observed.append(reviewer)
        return record
    async def review_batch(run_id, reviews):
        observed.extend(review["reviewer"] for review in reviews)
        return record
    monkeypatch.setattr(production.store, "review_evidence", review_one)
    monkeypatch.setattr(production.store, "review_evidence_batch", review_batch)
    assert client.patch("/api/runs/synthetic/evidence/event", json={"status": "validated", "reviewer": "superadmin"}, headers=headers).status_code == 200
    assert client.patch("/api/runs/synthetic/evidence", json={"reviews": [{"evidence_id": "event", "status": "validated", "reviewer": "superadmin"}]}, headers=headers).status_code == 200
    assert observed == ["operador", "operador"]
    monitoring = MonitoringStore(tmp_path / "monitoring.json")
    monkeypatch.setattr(production, "monitoring_store", monitoring)
    response = client.post("/api/platform/logs", json={"id": "synthetic", "message": "Synthetic log", "user": "superadmin"}, headers=headers)
    assert response.status_code == 201
    assert response.json()["user"] == "operador"
    response = client.post("/api/support/tickets", json={"subject": "Synthetic request", "description": "Synthetic test description", "user": "superadmin"}, headers=headers)
    assert response.status_code == 201
    assert response.json()["user"] == "operador"
