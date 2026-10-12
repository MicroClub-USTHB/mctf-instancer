"""Functional tests for the extracted system router.

Mounted on a bare FastAPI app (no lifespan / DB / Redis) so the routes are
exercised in isolation — proving the extraction from main.py preserved their
behavior.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers.system import router


def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_api_root_reports_auth_mode():
    r = client().get("/api")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "auth_mode" in body


def test_health_reports_active_instance_count():
    r = client().get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "healthy"
    assert isinstance(body["active_instances"], int)
