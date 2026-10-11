"""Pure helpers for classifying failures and sanitizing user/audit output.

Extracted from main.py: these are side-effect-free and security-relevant
(keeping backend internals out of player-facing errors, and secret values out
of audit logs), so they live here where they can be unit-tested directly.
"""


def classify_spawn_failure_reason(message: str) -> str:
    """Bucket spawn failures into low-cardinality operational reasons."""
    lowered = (message or "").lower()

    if "rate limit" in lowered:
        return "rate_limited"
    if "currently inactive" in lowered:
        return "challenge_inactive"
    if "challenge not found" in lowered:
        return "challenge_not_found"
    if "maximum instance" in lowered:
        return "instance_limit_reached"
    if "already has this challenge running" in lowered:
        return "challenge_already_running"
    if "no exposed ports" in lowered:
        return "challenge_ports_missing"
    if "no available ports" in lowered:
        return "port_pool_exhausted"
    if "failed to determine backend port" in lowered:
        return "routing_backend_port_missing"
    if "docker-compose failed" in lowered:
        return "docker_compose_failed"
    if "timeout" in lowered:
        return "timeout"
    if "failed to start instance" in lowered:
        return "instance_start_failed"

    return "unknown"


def classify_operation_failure_reason(message: str) -> str:
    """Bucket stop/extend failures for alerting-friendly metrics."""
    lowered = (message or "").lower()

    if "rate limit" in lowered:
        return "rate_limited"
    if "instance not found" in lowered:
        return "instance_not_found"
    if "doesn't own this instance" in lowered or "don't own this instance" in lowered:
        return "access_denied"
    if "challenge configuration not found" in lowered:
        return "challenge_config_missing"
    if "only running instances can be extended" in lowered:
        return "invalid_instance_state"
    if "extension is disabled" in lowered:
        return "extension_disabled"
    if "extension available in" in lowered:
        return "extension_too_early"
    if "extension limit reached" in lowered:
        return "extension_limit_reached"
    if "failed to stop instance" in lowered:
        return "instance_stop_failed"

    return "unknown"


def sanitize_user_error_message(message: str, fallback: str) -> str:
    """Prevent leaking backend/docker internals in user-visible error details."""
    lowered = (message or "").lower()
    internal_markers = (
        "docker",
        "compose",
        "traefik",
        "network",
        "traceback",
        "port is already allocated",
        "address already in use",
        "failed to start instance:",
        "failed to stop instance:",
    )
    if any(marker in lowered for marker in internal_markers):
        return fallback
    return message or fallback


SENSITIVE_SETTING_KEYS = {
    "ADMIN_KEY",
    "CTFD_API_KEY",
    "DISCORD_WEBHOOK_URL",
}
SENSITIVE_SETTING_KEYWORDS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "WEBHOOK",
)


def is_sensitive_setting_key(key: str) -> bool:
    """Classify settings keys that should never have raw values in logs."""
    normalized = (key or "").strip().upper()
    if not normalized:
        return False

    if normalized in SENSITIVE_SETTING_KEYS:
        return True

    if normalized.endswith("_KEY"):
        return True

    return any(keyword in normalized for keyword in SENSITIVE_SETTING_KEYWORDS)


def build_settings_audit_details(applied: dict[str, object]) -> dict[str, object]:
    """Build metadata-only audit details for settings updates."""
    applied_keys = sorted(applied.keys())
    sensitive_keys = [key for key in applied_keys if is_sensitive_setting_key(key)]
    return {
        "applied_keys": applied_keys,
        "applied_count": len(applied_keys),
        "sensitive_keys_redacted": sensitive_keys,
    }
