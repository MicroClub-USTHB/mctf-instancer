"""Presenter helpers that build sanitized public response models.

Kept out of main.py so route modules can render responses without importing
main.py.
"""
from .models import Instance, PublicInstance


def to_public_instance(instance: Instance) -> PublicInstance:
    """Build sanitized instance payload for normal users."""
    # Expose endpoints as plain URLs only (no internal service-port keys).
    public_urls = list((instance.public_urls or {}).values())

    return PublicInstance(
        instance_id=instance.instance_id,
        challenge_id=instance.challenge_id,
        username=instance.username,
        team_name=instance.team_name,
        routing_type=instance.routing_type,
        connection_hint=instance.connection_hint,
        status=instance.status,
        created_at=instance.created_at,
        expires_at=instance.expires_at,
        public_url=instance.public_url,
        public_urls=public_urls,
    )
