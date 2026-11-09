"""Functional tests for the extracted /metrics router.

The scrape reads the flag manager, forensics and event logger; they are
replaced with small stubs so the test needs no database.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers import metrics
from app.routers.metrics import router

SECRET = "test-metrics-secret"


class _Flags:
    flag_mappings = {}

    async def count_suspicious_submissions(self):
        return 0


class _Forensics:
    def get_stats(self):
        return {"auto_capture_enabled": False, "auto_capture_count": 0, "live_capture_count": 0,
                "total_size_bytes": 0}


class _Logger:
    async def get_stats(self):
        return {"event_counts": {"instance_spawn": 3}}


@pytest.fixture
def client(monkeypatch):
    async def flags():
        return _Flags()

    monkeypatch.setattr(metrics, "get_flag_manager", flags)
    monkeypatch.setattr(metrics, "get_forensics_manager", lambda: _Forensics())
    monkeypatch.setattr(metrics, "get_event_logger", lambda: _Logger())
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


def test_metrics_disabled_without_secret(client, monkeypatch):
    monkeypatch.setattr(metrics.settings, "METRICS_SECRET", None)
    assert client.get("/metrics").status_code == 503


def test_metrics_rejects_wrong_secret(client, monkeypatch):
    monkeypatch.setattr(metrics.settings, "METRICS_SECRET", SECRET)
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_metrics_scrape(client, monkeypatch):
    monkeypatch.setattr(metrics.settings, "METRICS_SECRET", SECRET)
    for headers in ({"Authorization": f"Bearer {SECRET}"}, {"X-Metrics-Secret": SECRET}):
        r = client.get("/metrics", headers=headers)
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/plain")
        body = r.text
        assert "# TYPE whaley_instances_open_total gauge" in body
        assert 'whaley_lifecycle_events_total{event="spawn_success"} 3' in body
        assert 'whaley_spawn_latency_seconds_bucket{le="+Inf"}' in body


def test_label_values_are_escaped():
    line = metrics._format_prometheus_sample("m", 1.0, {"name": 'a"b\\c\nd'})
    assert line == 'm{name="a\\"b\\\\c\\nd"} 1'
