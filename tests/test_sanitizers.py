"""Tests for the extracted pure failure-classification and sanitization helpers."""
from app.sanitizers import (
    build_settings_audit_details,
    classify_operation_failure_reason,
    classify_spawn_failure_reason,
    is_sensitive_setting_key,
    sanitize_user_error_message,
)


def test_classify_spawn_reasons():
    assert classify_spawn_failure_reason("No available ports") == "port_pool_exhausted"
    assert classify_spawn_failure_reason("Challenge not found") == "challenge_not_found"
    assert classify_spawn_failure_reason("docker-compose failed: boom") == "docker_compose_failed"
    assert classify_spawn_failure_reason("") == "unknown"
    assert classify_spawn_failure_reason(None) == "unknown"


def test_classify_operation_reasons():
    assert classify_operation_failure_reason("Instance not found") == "instance_not_found"
    assert classify_operation_failure_reason("Your team doesn't own this instance") == "access_denied"
    assert classify_operation_failure_reason("You don't own this instance") == "access_denied"
    assert classify_operation_failure_reason("whatever") == "unknown"


def test_sanitize_hides_backend_internals():
    # Anything mentioning backend/infra internals collapses to the safe fallback.
    for leaky in [
        "docker: no such image",
        "traefik route conflict",
        "port is already allocated",
        "Traceback (most recent call last)",
        "network mctf_default not found",
    ]:
        assert sanitize_user_error_message(leaky, "Failed") == "Failed"


def test_sanitize_passes_through_safe_messages():
    assert sanitize_user_error_message("Too many requests", "Failed") == "Too many requests"
    # Empty/None fall back.
    assert sanitize_user_error_message("", "Failed") == "Failed"
    assert sanitize_user_error_message(None, "Failed") == "Failed"


def test_is_sensitive_setting_key():
    for key in ["ADMIN_KEY", "CTFD_API_KEY", "DISCORD_WEBHOOK_URL",
                "SOME_TOKEN", "DB_PASSWORD", "x_secret", "foo_KEY"]:
        assert is_sensitive_setting_key(key) is True, key
    for key in ["HOST", "PORT", "DEBUG", "", None]:
        assert is_sensitive_setting_key(key) is False, key


def test_build_settings_audit_details_redacts_sensitive_keys():
    details = build_settings_audit_details({"HOST": "x", "ADMIN_KEY": "secret", "PORT": 8000})
    assert details["applied_count"] == 3
    assert details["applied_keys"] == ["ADMIN_KEY", "HOST", "PORT"]  # sorted
    # Only key names are reported — never values — and sensitive ones are flagged.
    assert details["sensitive_keys_redacted"] == ["ADMIN_KEY"]
    assert "secret" not in str(details)
