"""Prometheus metric state: runtime operation counters and spawn latency.

Extracted from main.py so route modules can record metrics and the /metrics
endpoint can read snapshots through a small accessor API, instead of sharing
module-level globals. The mutable state is private to this module.
"""
import re
from collections import defaultdict

SPAWN_LATENCY_BUCKETS_SECONDS = (0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0)

_spawn_inflight_requests = 0
_spawn_latency_sum_seconds = 0.0
_spawn_latency_count = 0
_spawn_latency_bucket_counts: dict[float, int] = defaultdict(int)
_runtime_operation_counters: dict[tuple[str, str, str, str], int] = defaultdict(int)

for _bucket in SPAWN_LATENCY_BUCKETS_SECONDS:
    _spawn_latency_bucket_counts[_bucket] = 0


def normalize_reason_label(reason: str | None) -> str:
    """Normalize arbitrary reason strings into stable Prometheus label values."""
    raw_reason = (reason or "none").strip().lower()
    if not raw_reason:
        return "none"

    normalized = re.sub(r"[^a-z0-9]+", "_", raw_reason)
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    if not normalized:
        return "unknown"
    return normalized[:64]


def record_runtime_operation(
    operation: str,
    outcome: str,
    challenge_id: str | None = None,
    reason: str | None = None,
) -> None:
    """Track request outcomes for near-real-time SLO and failure dashboards."""
    key = (
        (operation or "unknown").strip().lower(),
        (outcome or "unknown").strip().lower(),
        normalize_reason_label(reason),
        str(challenge_id or "unknown"),
    )
    _runtime_operation_counters[key] += 1


def spawn_started() -> None:
    """Track an in-flight spawn request."""
    global _spawn_inflight_requests
    _spawn_inflight_requests += 1


def spawn_finished(duration_seconds: float) -> None:
    """Record spawn latency histogram and decrement in-flight counter."""
    global _spawn_inflight_requests, _spawn_latency_sum_seconds, _spawn_latency_count

    _spawn_inflight_requests = max(0, _spawn_inflight_requests - 1)
    observed = max(0.0, float(duration_seconds))
    _spawn_latency_sum_seconds += observed
    _spawn_latency_count += 1

    for bucket in SPAWN_LATENCY_BUCKETS_SECONDS:
        if observed <= bucket:
            _spawn_latency_bucket_counts[bucket] += 1


# --- read-only accessors for the /metrics endpoint ------------------------

def runtime_operations_snapshot() -> list:
    """Sorted (key, count) list of runtime operation counters."""
    return sorted(_runtime_operation_counters.items())


def spawn_latency_bucket_snapshot() -> dict:
    """Cumulative count per latency bucket, in bucket order."""
    return {b: _spawn_latency_bucket_counts.get(b, 0) for b in SPAWN_LATENCY_BUCKETS_SECONDS}


def spawn_latency_count() -> int:
    return _spawn_latency_count


def spawn_latency_sum_seconds() -> float:
    return _spawn_latency_sum_seconds


def spawn_inflight_requests() -> int:
    return _spawn_inflight_requests
