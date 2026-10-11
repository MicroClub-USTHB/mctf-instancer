"""Tests for the CTFd token -> UserInfo auth flow.

CTFd calls are stubbed: a fake httpx.AsyncClient returns canned responses
keyed by URL, so we verify the derivation logic (user id, username, team id,
team name) and the rejection paths without a live CTFd.
"""
import pytest

import app.auth as auth_module
from app.auth import CTFdAuth


class FakeResp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


class FakeClient:
    """Minimal async-context-manager stand-in for httpx.AsyncClient."""

    def __init__(self, handler):
        self._handler = handler

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, **kwargs):
        return self._handler(url)


def install(monkeypatch, handler):
    monkeypatch.setattr(auth_module.httpx, "AsyncClient", lambda *a, **k: FakeClient(handler))


@pytest.mark.asyncio
async def test_valid_token_derives_user_and_team(monkeypatch):
    def handler(url):
        if url.endswith("/users/me"):
            return FakeResp(payload={"success": True, "data": {"id": 10, "name": "alice", "team_id": 5}})
        if url.endswith("/teams/5"):
            return FakeResp(payload={"success": True, "data": {"id": 5, "name": "TeamX"}})
        return FakeResp(status=404)

    install(monkeypatch, handler)
    user = await CTFdAuth().validate_token("tok")
    assert user is not None
    assert user.user_id == "10"
    assert user.username == "alice"
    assert user.team_id == "5"
    assert user.team_name == "TeamX"


@pytest.mark.asyncio
async def test_user_without_team(monkeypatch):
    def handler(url):
        if url.endswith("/users/me"):
            return FakeResp(payload={"success": True, "data": {"id": 11, "name": "solo", "team_id": None}})
        return FakeResp(status=404)

    install(monkeypatch, handler)
    user = await CTFdAuth().validate_token("tok")
    assert user is not None
    assert user.team_id is None
    assert user.team_name is None


@pytest.mark.asyncio
async def test_non_200_is_rejected(monkeypatch):
    install(monkeypatch, lambda url: FakeResp(status=401, text="unauthorized"))
    assert await CTFdAuth().validate_token("bad") is None


@pytest.mark.asyncio
async def test_success_false_is_rejected(monkeypatch):
    install(monkeypatch, lambda url: FakeResp(payload={"success": False}))
    assert await CTFdAuth().validate_token("tok") is None
