"""Functional wiring tests for the extracted challenges and me routers.

Mounted on a bare app (no lifespan). In CTFd auth mode an unauthenticated
request must be rejected at the get_current_user dependency (401, not 404/500).
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import auth
from app.models import AuthMode, UserInfo
from app.routers.challenges import router as challenges_router
from app.routers.me import router as me_router


def client(user=None):
    app = FastAPI()
    app.include_router(challenges_router)
    app.include_router(me_router)
    if user is not None:
        app.dependency_overrides[auth.get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False)


def test_challenges_require_auth(monkeypatch):
    monkeypatch.setattr(auth.settings, "AUTH_MODE", AuthMode.CTFD)
    assert client().get("/challenges").status_code == 401
    assert client().get("/challenges/web-echo").status_code == 401


def test_me_requires_auth(monkeypatch):
    monkeypatch.setattr(auth.settings, "AUTH_MODE", AuthMode.CTFD)
    assert client().get("/me").status_code == 401
    assert client().get("/me/team").status_code == 401


def test_unknown_challenge_is_404():
    user = UserInfo(user_id="1", username="alice")
    assert client(user).get("/challenges/does-not-exist").status_code == 404


def test_challenge_list_shape():
    user = UserInfo(user_id="1", username="alice")
    r = client(user).get("/challenges")
    assert r.status_code == 200
    assert isinstance(r.json()["challenges"], list)
