"""Functional tests for the extracted WebSocket router.

WebSocket routes are not in the OpenAPI schema, so test_routes.py cannot see
them; these tests check that both endpoints are mounted and reject bad
credentials with close code 4001.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.routers import ws
from app.routers.ws import router


def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def closed_with(url):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client().websocket_connect(url) as conn:
            conn.receive_text()
    return exc.value.code


def test_public_ws_requires_token():
    assert closed_with("/ws") == 4001


def test_admin_ws_requires_configured_key(monkeypatch):
    monkeypatch.setattr(ws.settings, "ADMIN_KEY", None)
    assert closed_with("/ws/admin?admin_key=anything") == 4001


def test_admin_ws_rejects_wrong_key(monkeypatch):
    monkeypatch.setattr(ws.settings, "ADMIN_KEY", "right")
    assert closed_with("/ws/admin?admin_key=wrong") == 4001


def test_admin_ws_answers_ping(monkeypatch):
    monkeypatch.setattr(ws.settings, "ADMIN_KEY", "right")
    with client().websocket_connect("/ws/admin?admin_key=right") as conn:
        conn.send_text("ping")
        assert conn.receive_text() == "pong"
