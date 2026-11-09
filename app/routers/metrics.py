"""Prometheus /metrics endpoint and its formatting helpers.

Extracted from main.py. It reads runtime state through the metrics_state and
request_utils accessors, so it has no import back to main.py.
"""
import hmac
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import PlainTextResponse

from ..config import settings
from ..flag_manager import get_flag_manager
from ..forensics import get_forensics_manager
from ..logger import get_event_logger
from ..metrics_state import SPAWN_LATENCY_BUCKETS_SECONDS
from ..metrics_state import runtime_operations_snapshot as _runtime_ops_snapshot_fn
from ..metrics_state import spawn_inflight_requests as _spawn_inflight_fn
from ..metrics_state import spawn_latency_bucket_snapshot as _spawn_bucket_snapshot_fn
from ..metrics_state import spawn_latency_count as _spawn_latency_count_fn
from ..metrics_state import spawn_latency_sum_seconds as _spawn_latency_sum_fn
from ..models import Instance
from ..request_utils import active_rate_limited_user_count
from ..runtime import docker_manager, port_manager

router = APIRouter(tags=["metrics"])


def _extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """Extract bearer token from Authorization header."""
    if not authorization_header:
        return None

    prefix = "bearer "
    if authorization_header.lower().startswith(prefix):
        token = authorization_header[len(prefix):].strip()
        return token or None

    return None


def _escape_prometheus_label_value(value: str) -> str:
    """Escape a Prometheus label value according to text exposition format."""
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


def _format_prometheus_sample(
    metric: str,
    value: float,
    labels: Optional[Dict[str, str]] = None,
) -> str:
    """Format a single Prometheus metric sample line."""
    if labels:
        label_pairs = ",".join(
            f'{key}="{_escape_prometheus_label_value(str(val))}"'
            for key, val in sorted(labels.items())
        )
        return f"{metric}{{{label_pairs}}} {value:g}"

    return f"{metric} {value:g}"


def _infer_instance_connection_labels(instance: Instance) -> Dict[str, str]:
    """Infer stable routing/connection labels for a spawned instance."""
    routing_type = str(getattr(instance, "routing_type", None) or "unknown").strip().lower()
    connection_hint = str(getattr(instance, "connection_hint", None) or "").strip().lower()
    public_url = str(getattr(instance, "public_url", None) or "").strip().lower()

    if routing_type in ("http", "https"):
        if public_url.startswith("https://") or "https://" in connection_hint:
            connection_type = "https"
        else:
            connection_type = "http"
    elif routing_type == "tcp":
        connection_type = "tcp_tls" if ("--ssl" in connection_hint or "tls" in connection_hint) else "tcp_plain"
    else:
        if public_url.startswith("https://"):
            connection_type = "https"
        elif public_url.startswith("http://"):
            connection_type = "http"
        else:
            connection_type = routing_type

    return {
        "routing_type": routing_type or "unknown",
        "connection_type": connection_type or "unknown",
    }


def verify_metrics_secret(
    authorization: Optional[str] = Header(None),
    x_metrics_secret: Optional[str] = Header(None),
) -> bool:
    """Verify secret for Prometheus metrics endpoint access."""
    configured_secret = (settings.METRICS_SECRET or "").strip()
    if not configured_secret:
        raise HTTPException(
            status_code=503,
            detail="Metrics endpoint disabled (METRICS_SECRET not configured)",
        )

    provided_secret = (
        (x_metrics_secret or "").strip()
        or (_extract_bearer_token(authorization) or "").strip()
    )

    if not provided_secret or not hmac.compare_digest(provided_secret, configured_secret):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return True


@router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics(_: bool = Depends(verify_metrics_secret)):
    """Expose Prometheus metrics focused on dynamic challenge instances."""
    now_ts = time.time()
    instances = list(docker_manager.instances.values())
    challenge_name_lookup = {
        str(challenge.id): str(challenge.name)
        for challenge in docker_manager.challenges.values()
    }

    status_counts: Dict[str, int] = defaultdict(int)
    open_instances: List[Instance] = []

    for instance in instances:
        raw_status = getattr(instance, "status", "unknown")
        status = getattr(raw_status, "value", raw_status)
        status_value = str(status).strip().lower()
        if status_value.startswith("instancestatus."):
            status_value = status_value.split(".", 1)[1]

        status_counts[status_value] += 1
        if status_value in ("running", "starting"):
            open_instances.append(instance)

    for known_status in ("running", "starting", "stopping", "stopped", "error"):
        status_counts.setdefault(known_status, 0)

    owner_counts: Dict[Tuple[str, str, str], int] = defaultdict(int)
    team_counts: Dict[Tuple[str, str], int] = defaultdict(int)
    challenge_counts: Dict[str, int] = defaultdict(int)
    expiring_within_by_challenge: Dict[str, int] = defaultdict(int)
    expiring_within_total = 0
    starting_stale_total = 0
    expiry_horizon_seconds = 300.0
    stale_starting_seconds = 120.0

    for instance in open_instances:
        is_team_owned = bool(instance.team_id)
        owner_type = "team" if is_team_owned else "user"
        owner_id = (
            instance.team_id
            if is_team_owned
            else (instance.owner_id or instance.user_id)
        )
        owner_name = (
            instance.team_name
            if is_team_owned
            else (instance.username or owner_id)
        )

        owner_key = (str(owner_id or "unknown"), str(owner_name or "unknown"), owner_type)
        owner_counts[owner_key] += 1
        challenge_counts[str(instance.challenge_id)] += 1

        if is_team_owned:
            team_key = (str(instance.team_id or "unknown"), str(instance.team_name or "unknown"))
            team_counts[team_key] += 1

        raw_status = getattr(instance, "status", "unknown")
        status = getattr(raw_status, "value", raw_status)
        status_value = str(status).strip().lower()
        if status_value.startswith("instancestatus."):
            status_value = status_value.split(".", 1)[1]

        expires_at = getattr(instance, "expires_at", None)
        created_at = getattr(instance, "created_at", None)
        seconds_until_expiry = max(0.0, (expires_at.timestamp() - now_ts)) if expires_at else 0.0
        age_seconds = max(0.0, (now_ts - created_at.timestamp())) if created_at else 0.0

        if seconds_until_expiry <= expiry_horizon_seconds:
            expiring_within_total += 1
            expiring_within_by_challenge[str(instance.challenge_id)] += 1

        if status_value == "starting" and age_seconds > stale_starting_seconds:
            starting_stale_total += 1

    owner_limits = {
        "user": max(1, int(settings.MAX_INSTANCES_PER_USER)),
        "team": max(1, int(settings.MAX_INSTANCES_PER_TEAM)),
    }

    port_pool_total = max(0, settings.PORT_RANGE_END - settings.PORT_RANGE_START + 1)
    port_pool_allocated = float(port_manager.get_allocated_count())
    port_pool_available = float(max(port_pool_total - int(port_pool_allocated), 0))
    port_pool_utilization = (port_pool_allocated / float(port_pool_total)) if port_pool_total > 0 else 0.0

    active_rate_window_users = active_rate_limited_user_count()

    flag_manager = await get_flag_manager()
    flags_by_challenge: Dict[str, int] = defaultdict(int)
    flags_by_owner: Dict[Tuple[str, str], int] = defaultdict(int)

    for mapping in flag_manager.flag_mappings.values():
        challenge_id = str(mapping.local_challenge_id or "unknown")
        flags_by_challenge[challenge_id] += 1

        if mapping.team_id:
            flags_by_owner[(str(mapping.team_id), "team")] += 1
        else:
            flags_by_owner[(str(mapping.user_id), "user")] += 1

    # Suspicious counts are fetched from DB (paginated storage, not in-memory).
    # We emit a single total metric; per-challenge breakdown is omitted
    # to avoid a full table scan on every Prometheus scrape.
    suspicious_total = await flag_manager.count_suspicious_submissions()

    forensics_stats = get_forensics_manager().get_stats()

    event_counts: Dict[str, int] = {}
    try:
        logger_stats: Dict[str, Any] = await get_event_logger().get_stats()
        raw_event_counts = logger_stats.get("event_counts", {}) if isinstance(logger_stats, dict) else {}
        event_counts = {
            str(event_type): int(count)
            for event_type, count in raw_event_counts.items()
        }
    except Exception as exc:
        print(f"[Metrics] Failed to load event logger stats: {exc}")

    runtime_operations_snapshot = _runtime_ops_snapshot_fn()
    spawn_latency_bucket_snapshot = _spawn_bucket_snapshot_fn()
    spawn_latency_count = _spawn_latency_count_fn()
    spawn_latency_sum_seconds = _spawn_latency_sum_fn()
    spawn_inflight_requests = _spawn_inflight_fn()

    lines: List[str] = [
        "# HELP whaley_instances_open_total Number of open challenge instances (running or starting).",
        "# TYPE whaley_instances_open_total gauge",
        _format_prometheus_sample("whaley_instances_open_total", float(len(open_instances))),
        "# HELP whaley_instances_status_total Number of challenge instances by status.",
        "# TYPE whaley_instances_status_total gauge",
    ]

    for status, count in sorted(status_counts.items()):
        lines.append(
            _format_prometheus_sample(
                "whaley_instances_status_total",
                float(count),
                {"status": status},
            )
        )

    lines.extend([
        "# HELP whaley_instances_by_owner Number of open instances by effective owner.",
        "# TYPE whaley_instances_by_owner gauge",
    ])
    for (owner_id, owner_name, owner_type), count in sorted(owner_counts.items()):
        lines.append(
            _format_prometheus_sample(
                "whaley_instances_by_owner",
                float(count),
                {
                    "owner_id": owner_id,
                    "owner_name": owner_name,
                    "owner_type": owner_type,
                },
            )
        )

    lines.extend([
        "# HELP whaley_owner_saturation_ratio Open instance saturation ratio per owner.",
        "# TYPE whaley_owner_saturation_ratio gauge",
    ])
    for (owner_id, owner_name, owner_type), count in sorted(owner_counts.items()):
        limit = owner_limits.get(owner_type, 1)
        lines.append(
            _format_prometheus_sample(
                "whaley_owner_saturation_ratio",
                float(count) / float(limit),
                {
                    "owner_id": owner_id,
                    "owner_name": owner_name,
                    "owner_type": owner_type,
                },
            )
        )

    lines.extend([
        "# HELP whaley_instances_by_team Number of open instances by team.",
        "# TYPE whaley_instances_by_team gauge",
    ])
    for (team_id, team_name), count in sorted(team_counts.items()):
        lines.append(
            _format_prometheus_sample(
                "whaley_instances_by_team",
                float(count),
                {
                    "team_id": team_id,
                    "team_name": team_name,
                },
            )
        )

    lines.extend([
        "# HELP whaley_team_saturation_ratio Open instance saturation ratio per team.",
        "# TYPE whaley_team_saturation_ratio gauge",
    ])
    for (team_id, team_name), count in sorted(team_counts.items()):
        lines.append(
            _format_prometheus_sample(
                "whaley_team_saturation_ratio",
                float(count) / float(owner_limits["team"]),
                {
                    "team_id": team_id,
                    "team_name": team_name,
                },
            )
        )

    lines.extend([
        "# HELP whaley_instances_by_challenge Number of open instances by challenge id.",
        "# TYPE whaley_instances_by_challenge gauge",
    ])
    for challenge_id, count in sorted(challenge_counts.items()):
        lines.append(
            _format_prometheus_sample(
                "whaley_instances_by_challenge",
                float(count),
                {
                    "challenge_id": challenge_id,
                    "challenge_name": challenge_name_lookup.get(challenge_id, challenge_id),
                },
            )
        )

    lines.extend([
        "# HELP whaley_instance_seconds_until_expiry Seconds remaining until each open instance expires.",
        "# TYPE whaley_instance_seconds_until_expiry gauge",
        "# HELP whaley_instance_age_seconds Age in seconds for each open instance.",
        "# TYPE whaley_instance_age_seconds gauge",
        "# HELP whaley_instance_info Metadata for each open instance (always 1).",
        "# TYPE whaley_instance_info gauge",
        "# HELP whaley_instance_connection_info Connection metadata for each open instance (always 1).",
        "# TYPE whaley_instance_connection_info gauge",
    ])

    for instance in sorted(open_instances, key=lambda i: i.instance_id):
        is_team_owned = bool(instance.team_id)
        owner_type = "team" if is_team_owned else "user"
        owner_id = (
            instance.team_id
            if is_team_owned
            else (instance.owner_id or instance.user_id)
        )
        owner_name = (
            instance.team_name
            if is_team_owned
            else (instance.username or owner_id)
        )

        raw_status = getattr(instance, "status", "unknown")
        status = getattr(raw_status, "value", raw_status)
        status_value = str(status).strip().lower()
        if status_value.startswith("instancestatus."):
            status_value = status_value.split(".", 1)[1]

        expires_at = getattr(instance, "expires_at", None)
        created_at = getattr(instance, "created_at", None)
        seconds_until_expiry = max(0.0, (expires_at.timestamp() - now_ts)) if expires_at else 0.0
        age_seconds = max(0.0, (now_ts - created_at.timestamp())) if created_at else 0.0

        connection_labels = _infer_instance_connection_labels(instance)
        challenge_config = docker_manager.challenges.get(str(instance.challenge_id))
        challenge_tls = getattr(challenge_config, "tls_enabled", None)
        tls_enabled_label = "unknown" if challenge_tls is None else ("true" if challenge_tls else "false")

        shared_labels = {
            "instance_id": str(instance.instance_id),
            "challenge_id": str(instance.challenge_id),
            "challenge_name": challenge_name_lookup.get(str(instance.challenge_id), str(instance.challenge_id)),
            "owner_id": str(owner_id or "unknown"),
            "owner_name": str(owner_name or "unknown"),
            "owner_type": owner_type,
            "username": str(instance.username or "unknown"),
            "spawner_username": str(instance.username or "unknown"),
            "spawner_user_id": str(instance.user_id or "unknown"),
            "team_id": str(instance.team_id or "none"),
            "team_name": str(instance.team_name or "none"),
            "tls_enabled": tls_enabled_label,
            "status": status_value,
            **connection_labels,
        }

        lines.append(
            _format_prometheus_sample(
                "whaley_instance_seconds_until_expiry",
                seconds_until_expiry,
                shared_labels,
            )
        )
        lines.append(
            _format_prometheus_sample(
                "whaley_instance_age_seconds",
                age_seconds,
                shared_labels,
            )
        )
        lines.append(_format_prometheus_sample("whaley_instance_info", 1.0, shared_labels))
        lines.append(_format_prometheus_sample("whaley_instance_connection_info", 1.0, shared_labels))

    lines.extend([
        "# HELP whaley_instances_expiring_within_total Number of open instances expiring within the configured horizon.",
        "# TYPE whaley_instances_expiring_within_total gauge",
        _format_prometheus_sample(
            "whaley_instances_expiring_within_total",
            float(expiring_within_total),
            {"horizon_seconds": str(int(expiry_horizon_seconds))},
        ),
        "# HELP whaley_instances_expiring_within_by_challenge Number of open instances expiring soon by challenge.",
        "# TYPE whaley_instances_expiring_within_by_challenge gauge",
    ])
    for challenge_id, count in sorted(expiring_within_by_challenge.items()):
        lines.append(
            _format_prometheus_sample(
                "whaley_instances_expiring_within_by_challenge",
                float(count),
                {
                    "horizon_seconds": str(int(expiry_horizon_seconds)),
                    "challenge_id": challenge_id,
                    "challenge_name": challenge_name_lookup.get(challenge_id, challenge_id),
                },
            )
        )

    lines.extend([
        "# HELP whaley_instances_starting_stale_total Number of starting instances older than the stale threshold.",
        "# TYPE whaley_instances_starting_stale_total gauge",
        _format_prometheus_sample("whaley_instances_starting_stale_total", float(starting_stale_total)),
        "# HELP whaley_challenges_loaded_total Number of challenge definitions loaded by Whaley.",
        "# TYPE whaley_challenges_loaded_total gauge",
        _format_prometheus_sample("whaley_challenges_loaded_total", float(len(docker_manager.challenges))),
        "# HELP whaley_challenges_active_total Number of active challenges available for spawn.",
        "# TYPE whaley_challenges_active_total gauge",
        _format_prometheus_sample("whaley_challenges_active_total", float(len(docker_manager.get_active_challenges()))),
        "# HELP whaley_owner_instance_limit Configured instance limit by owner type.",
        "# TYPE whaley_owner_instance_limit gauge",
        _format_prometheus_sample(
            "whaley_owner_instance_limit",
            float(settings.MAX_INSTANCES_PER_USER),
            {"owner_type": "user"},
        ),
        _format_prometheus_sample(
            "whaley_owner_instance_limit",
            float(settings.MAX_INSTANCES_PER_TEAM),
            {"owner_type": "team"},
        ),
    ])

    lines.extend([
        "# HELP whaley_port_pool_total Total ports available in configured pool.",
        "# TYPE whaley_port_pool_total gauge",
        _format_prometheus_sample("whaley_port_pool_total", float(port_pool_total)),
        "# HELP whaley_port_pool_allocated Currently allocated ports in active pool.",
        "# TYPE whaley_port_pool_allocated gauge",
        _format_prometheus_sample("whaley_port_pool_allocated", port_pool_allocated),
        "# HELP whaley_port_pool_available Currently available ports in active pool.",
        "# TYPE whaley_port_pool_available gauge",
        _format_prometheus_sample("whaley_port_pool_available", port_pool_available),
        "# HELP whaley_port_pool_utilization_ratio Current port pool utilization ratio (0-1).",
        "# TYPE whaley_port_pool_utilization_ratio gauge",
        _format_prometheus_sample("whaley_port_pool_utilization_ratio", port_pool_utilization),
        "# HELP whaley_active_rate_window_users Number of users with instance lifecycle requests in the active rate-limit window.",
        "# TYPE whaley_active_rate_window_users gauge",
        _format_prometheus_sample("whaley_active_rate_window_users", float(active_rate_window_users)),
    ])

    lines.extend([
        "# HELP whaley_flags_assigned_total Number of dynamic flags currently tracked.",
        "# TYPE whaley_flags_assigned_total gauge",
        _format_prometheus_sample("whaley_flags_assigned_total", float(len(flag_manager.flag_mappings))),
        "# HELP whaley_flags_assigned_by_challenge Number of dynamic flags by challenge.",
        "# TYPE whaley_flags_assigned_by_challenge gauge",
    ])
    for challenge_id, count in sorted(flags_by_challenge.items()):
        lines.append(
            _format_prometheus_sample(
                "whaley_flags_assigned_by_challenge",
                float(count),
                {
                    "challenge_id": challenge_id,
                    "challenge_name": challenge_name_lookup.get(challenge_id, challenge_id),
                },
            )
        )

    lines.extend([
        "# HELP whaley_flags_assigned_by_owner Number of dynamic flags by owner.",
        "# TYPE whaley_flags_assigned_by_owner gauge",
    ])
    for (owner_id, owner_type), count in sorted(flags_by_owner.items()):
        lines.append(
            _format_prometheus_sample(
                "whaley_flags_assigned_by_owner",
                float(count),
                {
                    "owner_id": owner_id,
                    "owner_type": owner_type,
                },
            )
        )

    lines.extend([
        "# HELP whaley_suspicious_submissions_total Number of suspicious submissions currently tracked.",
        "# TYPE whaley_suspicious_submissions_total gauge",
        _format_prometheus_sample("whaley_suspicious_submissions_total", float(suspicious_total)),
    ])

    lines.extend([
        "# HELP whaley_forensics_auto_capture_enabled Whether automatic forensics capture is enabled (1/0).",
        "# TYPE whaley_forensics_auto_capture_enabled gauge",
        _format_prometheus_sample(
            "whaley_forensics_auto_capture_enabled",
            1.0 if forensics_stats.get("auto_capture_enabled") else 0.0,
        ),
        "# HELP whaley_forensics_logs_total Total stored forensics logs by capture type.",
        "# TYPE whaley_forensics_logs_total gauge",
        _format_prometheus_sample(
            "whaley_forensics_logs_total",
            float(forensics_stats.get("auto_capture_count", 0)),
            {"capture_type": "auto"},
        ),
        _format_prometheus_sample(
            "whaley_forensics_logs_total",
            float(forensics_stats.get("live_capture_count", 0)),
            {"capture_type": "live"},
        ),
        "# HELP whaley_forensics_storage_bytes Total bytes consumed by forensics logs.",
        "# TYPE whaley_forensics_storage_bytes gauge",
        _format_prometheus_sample("whaley_forensics_storage_bytes", float(forensics_stats.get("total_size_bytes", 0))),
    ])

    lines.extend([
        "# HELP whaley_runtime_operations_total Runtime operation outcomes tracked since process start.",
        "# TYPE whaley_runtime_operations_total counter",
    ])
    for (operation, outcome, reason, challenge_id), count in runtime_operations_snapshot:
        lines.append(
            _format_prometheus_sample(
                "whaley_runtime_operations_total",
                float(count),
                {
                    "operation": operation,
                    "outcome": outcome,
                    "reason": reason,
                    "challenge_id": challenge_id,
                    "challenge_name": challenge_name_lookup.get(challenge_id, challenge_id),
                },
            )
        )

    lines.extend([
        "# HELP whaley_spawn_inflight Number of spawn requests currently in-flight.",
        "# TYPE whaley_spawn_inflight gauge",
        _format_prometheus_sample("whaley_spawn_inflight", float(spawn_inflight_requests)),
        "# HELP whaley_spawn_latency_seconds Histogram of spawn request latency observed by API.",
        "# TYPE whaley_spawn_latency_seconds histogram",
    ])

    for bucket in SPAWN_LATENCY_BUCKETS_SECONDS:
        lines.append(
            _format_prometheus_sample(
                "whaley_spawn_latency_seconds_bucket",
                float(spawn_latency_bucket_snapshot.get(bucket, 0)),
                {"le": f"{bucket:g}"},
            )
        )

    lines.extend([
        _format_prometheus_sample(
            "whaley_spawn_latency_seconds_bucket",
            float(spawn_latency_count),
            {"le": "+Inf"},
        ),
        _format_prometheus_sample("whaley_spawn_latency_seconds_sum", float(spawn_latency_sum_seconds)),
        _format_prometheus_sample("whaley_spawn_latency_seconds_count", float(spawn_latency_count)),
        "# HELP whaley_event_log_total Cumulative count of persisted Whaley event logs by event type.",
        "# TYPE whaley_event_log_total counter",
    ])

    for event_type, count in sorted(event_counts.items()):
        lines.append(
            _format_prometheus_sample(
                "whaley_event_log_total",
                float(count),
                {"event_type": event_type},
            )
        )

    lifecycle_event_map = {
        "spawn_success": "instance_spawn",
        "spawn_failed": "instance_spawn_failed",
        "stop": "instance_stop",
        "extend": "instance_extend",
        "expired": "instance_expired",
    }

    lines.extend([
        "# HELP whaley_lifecycle_events_total Cumulative lifecycle operations from persisted event logs.",
        "# TYPE whaley_lifecycle_events_total counter",
    ])
    for lifecycle_event, event_type in sorted(lifecycle_event_map.items()):
        lines.append(
            _format_prometheus_sample(
                "whaley_lifecycle_events_total",
                float(event_counts.get(event_type, 0)),
                {"event": lifecycle_event},
            )
        )

    payload = "\n".join(lines) + "\n"
    return PlainTextResponse(payload, media_type="text/plain; version=0.0.4; charset=utf-8")
