"""Discord webhook notifications for Whaley lifecycle events."""
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from .config import settings


def _format_timestamp(value: Optional[datetime]) -> str:
    """Render a datetime in a human-readable UTC format."""
    if value is None:
        return "-"

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _to_iso_timestamp(value: datetime) -> str:
    """Convert datetime to ISO 8601 UTC string accepted by Discord embeds."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _stringify(value: Optional[Any], fallback: str = "-") -> str:
    """Convert value to a bounded string compatible with Discord embed field limits."""
    if value is None:
        return fallback

    rendered = str(value).strip()
    if not rendered:
        return fallback

    # Discord embed field values are limited to 1024 chars.
    if len(rendered) > 1000:
        rendered = f"{rendered[:997]}..."

    return rendered


class DiscordWebhookNotifier:
    """Dispatches lifecycle notifications to a Discord webhook endpoint."""

    def __init__(self, timeout_seconds: float = 4.0):
        self.timeout_seconds = timeout_seconds
        self.username = "Whaley"
        self._warned_disabled = False

    @property
    def webhook_url(self) -> str:
        return (settings.DISCORD_WEBHOOK_URL or "").strip()

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    @staticmethod
    def _build_field(name: str, value: Optional[Any], inline: bool = True) -> Dict[str, Any]:
        return {
            "name": name,
            "value": _stringify(value),
            "inline": inline,
        }

    async def _send_embed(
        self,
        *,
        title: str,
        color: int,
        fields: list[Dict[str, Any]],
        description: Optional[str] = None,
    ) -> bool:
        if not self.enabled:
            if not self._warned_disabled:
                print("[DiscordWebhook] Disabled: DISCORD_WEBHOOK_URL is not configured")
                self._warned_disabled = True
            return False

        self._warned_disabled = False

        embed: Dict[str, Any] = {
            "title": title,
            "color": color,
            "timestamp": _to_iso_timestamp(datetime.now(timezone.utc)),
            "fields": fields[:25],
            "footer": {"text": "Whaley lifecycle notifications"},
        }

        if description:
            embed["description"] = _stringify(description)

        payload = {
            "username": self.username,
            "embeds": [embed],
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
                response = await client.post(self.webhook_url, json=payload)

            if response.status_code >= 400:
                print(
                    "[DiscordWebhook] Failed to send notification "
                    f"(status={response.status_code}): {response.text[:200]}"
                )
                return False

            return True
        except Exception as exc:
            print(f"[DiscordWebhook] Error sending notification: {exc}")
            return False

    async def notify_instance_spawn(
        self,
        *,
        instance_id: str,
        challenge_id: str,
        created_by: str,
        created_by_id: str,
        created_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
        challenge_name: Optional[str] = None,
        team_id: Optional[str] = None,
        team_name: Optional[str] = None,
        public_url: Optional[str] = None,
        connection_hint: Optional[str] = None,
        routing_type: Optional[str] = None,
        ports: Optional[Dict[int, int]] = None,
        ip_address: Optional[str] = None,
        is_admin_test_spawn: bool = False,
    ) -> bool:
        ports_text = "-"
        if ports:
            ports_text = ", ".join(f"{internal}->{external}" for internal, external in sorted(ports.items()))

        fields = [
            self._build_field("Event", "Instance Spawned"),
            self._build_field("Instance ID", instance_id),
            self._build_field("Challenge", challenge_name or challenge_id),
            self._build_field("Created By", f"{created_by} ({created_by_id})", inline=False),
            self._build_field("Created At", _format_timestamp(created_at)),
            self._build_field("Expires At", _format_timestamp(expires_at)),
            self._build_field("Routing", routing_type or "-"),
            self._build_field("Ports", ports_text, inline=False),
            self._build_field("Public URL", public_url or "-", inline=False),
            self._build_field("Connection", connection_hint or "-", inline=False),
        ]

        if is_admin_test_spawn:
            fields.insert(0, self._build_field("Type", "Admin test spawn"))
            title = "Whaley - Test Instance Spawned"
            color = 0x3498DB  # blue
        else:
            title = "Whaley - New Instance"
            color = 0x2ECC71  # green

        if team_id or team_name:
            fields.append(self._build_field("Team", f"{team_name or '-'} ({team_id or '-'})", inline=False))
        if ip_address:
            fields.append(self._build_field("Source IP", ip_address))

        return await self._send_embed(
            title=title,
            color=color,
            fields=fields,
        )

    async def notify_instance_spawn_failed(
        self,
        *,
        challenge_id: str,
        username: str,
        user_id: str,
        reason: str,
        challenge_name: Optional[str] = None,
        team_id: Optional[str] = None,
        team_name: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> bool:
        fields = [
            self._build_field("Event", "Instance Spawn Failed"),
            self._build_field("Challenge", challenge_name or challenge_id),
            self._build_field("Requested By", f"{username} ({user_id})", inline=False),
            self._build_field("Failure Reason", reason, inline=False),
        ]

        if team_id or team_name:
            fields.append(self._build_field("Team", f"{team_name or '-'} ({team_id or '-'})", inline=False))
        if ip_address:
            fields.append(self._build_field("Source IP", ip_address))

        return await self._send_embed(
            title="Whaley - Spawn Failed",
            color=0xE74C3C,
            fields=fields,
        )

    async def notify_instance_extended(
        self,
        *,
        instance_id: str,
        challenge_id: str,
        extended_by: str,
        extended_by_id: str,
        extension_seconds: int,
        expires_at: Optional[datetime],
        challenge_name: Optional[str] = None,
        team_id: Optional[str] = None,
        team_name: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> bool:
        fields = [
            self._build_field("Event", "Instance Extended"),
            self._build_field("Instance ID", instance_id),
            self._build_field("Challenge", challenge_name or challenge_id),
            self._build_field("Extended By", f"{extended_by} ({extended_by_id})", inline=False),
            self._build_field("Extension", f"{extension_seconds}s"),
            self._build_field("New Expiry", _format_timestamp(expires_at)),
        ]

        if team_id or team_name:
            fields.append(self._build_field("Team", f"{team_name or '-'} ({team_id or '-'})", inline=False))
        if ip_address:
            fields.append(self._build_field("Source IP", ip_address))

        return await self._send_embed(
            title="Whaley - Instance Extended",
            color=0xF1C40F,
            fields=fields,
        )

    async def notify_instance_stopped(
        self,
        *,
        instance_id: str,
        challenge_id: str,
        stopped_by: str,
        reason: str,
        challenge_name: Optional[str] = None,
        stopped_by_id: Optional[str] = None,
        owner_username: Optional[str] = None,
        owner_user_id: Optional[str] = None,
        team_id: Optional[str] = None,
        team_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        message: Optional[str] = None,
    ) -> bool:
        reason_map = {
            "user_stop": "Stopped By User",
            "admin_stop": "Stopped By Admin",
            "expired": "Expired (Auto Cleanup)",
        }
        reason_text = reason_map.get(reason, reason)

        stopped_by_text = stopped_by
        if stopped_by_id:
            stopped_by_text = f"{stopped_by} ({stopped_by_id})"

        fields = [
            self._build_field("Event", "Instance Stopped"),
            self._build_field("Instance ID", instance_id),
            self._build_field("Challenge", challenge_name or challenge_id),
            self._build_field("Reason", reason_text),
            self._build_field("Stopped By", stopped_by_text, inline=False),
            self._build_field("Stopped At", _format_timestamp(datetime.now(timezone.utc))),
        ]

        if owner_username or owner_user_id:
            fields.append(
                self._build_field(
                    "Owner",
                    f"{owner_username or '-'} ({owner_user_id or '-'})",
                    inline=False,
                )
            )
        if team_id or team_name:
            fields.append(self._build_field("Team", f"{team_name or '-'} ({team_id or '-'})", inline=False))
        if ip_address:
            fields.append(self._build_field("Source IP", ip_address))
        if message:
            fields.append(self._build_field("Result", message, inline=False))

        return await self._send_embed(
            title="Whaley - Instance Stopped",
            color=0xE67E22,
            fields=fields,
        )


_discord_notifier: Optional[DiscordWebhookNotifier] = None


def get_discord_notifier() -> DiscordWebhookNotifier:
    """Get or create the global Discord webhook notifier instance."""
    global _discord_notifier
    if _discord_notifier is None:
        _discord_notifier = DiscordWebhookNotifier()
    return _discord_notifier
