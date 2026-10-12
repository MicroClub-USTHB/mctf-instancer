"""Tests for request-identity and rate-limiting helpers.

get_client_ip is a security boundary: it must not let a client spoof its
address via X-Forwarded-For unless the direct peer is a trusted proxy.
"""
import app.request_utils as ru
from app.request_utils import (
    active_rate_limited_user_count,
    check_user_rate_limit,
    get_client_ip,
)


class FakeClient:
    def __init__(self, host):
        self.host = host


class FakeRequest:
    def __init__(self, host, headers=None):
        self.client = FakeClient(host) if host else None
        self.headers = headers or {}


def set_trusted(monkeypatch, value):
    monkeypatch.setattr(ru.settings, "TRUSTED_PROXIES", value)


def test_ignores_forwarded_header_when_no_trusted_proxy(monkeypatch):
    set_trusted(monkeypatch, "")  # nothing trusted
    req = FakeRequest("203.0.113.9", {"x-forwarded-for": "1.2.3.4"})
    assert get_client_ip(req) == "203.0.113.9"  # spoof ignored


def test_trusts_forwarded_header_from_wildcard(monkeypatch):
    set_trusted(monkeypatch, "*")
    req = FakeRequest("10.0.0.1", {"x-forwarded-for": "1.2.3.4, 5.6.7.8"})
    assert get_client_ip(req) == "1.2.3.4"  # first hop


def test_trusts_forwarded_only_from_listed_proxy(monkeypatch):
    set_trusted(monkeypatch, "10.0.0.1")
    trusted = FakeRequest("10.0.0.1", {"x-forwarded-for": "1.2.3.4"})
    assert get_client_ip(trusted) == "1.2.3.4"
    untrusted = FakeRequest("198.51.100.2", {"x-forwarded-for": "1.2.3.4"})
    assert get_client_ip(untrusted) == "198.51.100.2"  # not a trusted proxy


def test_falls_back_to_real_ip_header(monkeypatch):
    set_trusted(monkeypatch, "*")
    req = FakeRequest("10.0.0.1", {"x-real-ip": "9.9.9.9"})
    assert get_client_ip(req) == "9.9.9.9"


def test_rate_limit_allows_then_blocks(monkeypatch):
    ru._user_rate_limit.clear()
    monkeypatch.setattr(ru, "USER_RATE_LIMIT", 3)
    assert check_user_rate_limit("u1") is True
    assert check_user_rate_limit("u1") is True
    assert check_user_rate_limit("u1") is True
    assert check_user_rate_limit("u1") is False  # 4th exceeds limit of 3
    # A different user has its own budget.
    assert check_user_rate_limit("u2") is True


def test_active_rate_limited_user_count():
    ru._user_rate_limit.clear()
    check_user_rate_limit("a")
    check_user_rate_limit("b")
    assert active_rate_limited_user_count() == 2
