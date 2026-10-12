"""Functional wiring tests for the extracted instances router.

Mounted on a bare app (no lifespan). In CTFd auth mode an unauthenticated
request must be rejected at the dependency, proving the router + its
get_current_user dependency moved intact (not 404/500).
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import auth
from app.models import AuthMode
from app.routers.instances import router


def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


def test_list_instances_requires_auth(monkeypatch):
    monkeypatch.setattr(auth.settings, "AUTH_MODE", AuthMode.CTFD)
    r = client().get("/instances")
    assert r.status_code == 401


def test_spawn_requires_auth(monkeypatch):
    monkeypatch.setattr(auth.settings, "AUTH_MODE", AuthMode.CTFD)
    r = client().post("/instances/spawn", json={"challenge_id": "web/echo"})
    assert r.status_code == 401


def test_extend_requires_auth(monkeypatch):
    monkeypatch.setattr(auth.settings, "AUTH_MODE", AuthMode.CTFD)
    r = client().post("/instances/abc/extend")
    assert r.status_code == 401
