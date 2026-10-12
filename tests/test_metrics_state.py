"""Tests for the extracted Prometheus metric state."""
import app.metrics_state as ms


def reset():
    """Zero the module-private metric state between tests."""
    ms._runtime_operation_counters.clear()
    ms._spawn_inflight_requests = 0
    ms._spawn_latency_sum_seconds = 0.0
    ms._spawn_latency_count = 0
    for b in ms.SPAWN_LATENCY_BUCKETS_SECONDS:
        ms._spawn_latency_bucket_counts[b] = 0


def test_normalize_reason_label():
    assert ms.normalize_reason_label("Port Pool Exhausted!") == "port_pool_exhausted"
    assert ms.normalize_reason_label(None) == "none"
    assert ms.normalize_reason_label("   ") == "none"
    assert ms.normalize_reason_label("!!!") == "unknown"
    assert len(ms.normalize_reason_label("x" * 200)) == 64


def test_record_runtime_operation_increments_by_normalized_key():
    reset()
    ms.record_runtime_operation("Spawn", "Success", "web/echo", "None")
    ms.record_runtime_operation("spawn", "success", "web/echo", "none")  # same normalized key
    ms.record_runtime_operation("stop", "failed", "web/echo", "access denied")
    snap = dict(ms.runtime_operations_snapshot())
    assert snap[("spawn", "success", "none", "web/echo")] == 2
    assert snap[("stop", "failed", "access_denied", "web/echo")] == 1


def test_spawn_timers_track_inflight_and_latency():
    reset()
    ms.spawn_started()
    ms.spawn_started()
    assert ms.spawn_inflight_requests() == 2
    ms.spawn_finished(0.4)
    assert ms.spawn_inflight_requests() == 1
    assert ms.spawn_latency_count() == 1
    assert abs(ms.spawn_latency_sum_seconds() - 0.4) < 1e-9
    # 0.4s falls into every bucket >= 0.5 (cumulative-style counting here).
    buckets = ms.spawn_latency_bucket_snapshot()
    assert buckets[0.25] == 0
    assert buckets[0.5] == 1
    assert buckets[60.0] == 1


def test_spawn_finished_never_goes_negative():
    reset()
    ms.spawn_finished(1.0)  # no matching started
    assert ms.spawn_inflight_requests() == 0
