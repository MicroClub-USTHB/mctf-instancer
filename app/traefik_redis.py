"""Traefik dynamic configuration via Redis KV provider."""
import json
from pathlib import Path
from typing import Any, Dict, Optional, Set

import yaml

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None

from .config import settings


class TraefikProviderError(Exception):
    """Raised for Traefik provider integration failures."""


class TraefikRedisProvider:
    """Writes dynamic Traefik router/service keys into Redis KV."""

    def __init__(self):
        self._redis = None
        self._connected = False

    @property
    def enabled(self) -> bool:
        return settings.TRAEFIK_REDIS_ENABLED

    @property
    def key_prefix(self) -> str:
        return settings.TRAEFIK_REDIS_KEY_PREFIX.strip("/")

    @property
    def redis_url(self) -> Optional[str]:
        return settings.get_traefik_redis_url()

    async def initialize(self) -> bool:
        """Connect to Redis and preload permanent Traefik keys."""
        if not self.enabled:
            print("[TraefikRedis] Disabled by configuration")
            return False

        if aioredis is None:
            raise TraefikProviderError("redis package is not available")

        if self._connected and self._redis:
            return True

        if not self.redis_url:
            raise TraefikProviderError(
                "TRAEFIK_REDIS_ENABLED is true but no Redis URL is configured"
            )

        try:
            self._redis = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_timeout=5.0,
                socket_connect_timeout=5.0,
            )
            await self._redis.ping()
            self._connected = True
            print(f"[TraefikRedis] Connected to {self.redis_url}")
            await self.bootstrap_permanent_keys()
            return True
        except Exception as exc:
            self._redis = None
            self._connected = False
            raise TraefikProviderError(f"Failed to connect to Redis: {exc}") from exc

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
        self._redis = None
        self._connected = False

    async def _ensure_ready(self) -> None:
        if not self.enabled:
            raise TraefikProviderError("Traefik Redis provider is disabled")

        if not self._connected or not self._redis:
            await self.initialize()

    def _full_key(self, relative_key: str) -> str:
        relative = relative_key.lstrip("/")
        if relative.startswith(f"{self.key_prefix}/"):
            return relative
        return f"{self.key_prefix}/{relative}"

    def _stringify(self, value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    def _flatten_nested(self, node: Any, prefix: str, out: Dict[str, str]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                key_part = str(key).strip("/")
                if not key_part:
                    continue
                child_prefix = f"{prefix}/{key_part}" if prefix else key_part
                self._flatten_nested(value, child_prefix, out)
            return

        if isinstance(node, list):
            for index, value in enumerate(node):
                child_prefix = f"{prefix}/{index}" if prefix else str(index)
                self._flatten_nested(value, child_prefix, out)
            return

        if node is None:
            return

        out[self._full_key(prefix)] = self._stringify(node)

    async def _set_keys(self, keys: Dict[str, str]) -> None:
        await self._ensure_ready()
        if not keys:
            return

        pipeline = self._redis.pipeline(transaction=False)
        for key, value in keys.items():
            pipeline.set(key, value)
        await pipeline.execute()

    async def _load_permanent_keys_from_file(self) -> Dict[str, str]:
        """Load additional permanent keys from YAML file if configured."""
        file_path = settings.TRAEFIK_PERMANENT_KEYS_FILE
        if not file_path:
            return {}

        path = Path(file_path)
        if not path.exists():
            print(f"[TraefikRedis] Permanent key file not found: {path}")
            return {}

        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except Exception as exc:
            raise TraefikProviderError(f"Failed to read permanent key file: {exc}") from exc

        if isinstance(data, dict) and isinstance(data.get("keys"), dict):
            data = data["keys"]

        flattened: Dict[str, str] = {}
        self._flatten_nested(data, "", flattened)
        return flattened

    def _load_permanent_keys_from_json(self) -> Dict[str, str]:
        """Load additional permanent keys from JSON string if configured."""
        payload = settings.TRAEFIK_PERMANENT_KEYS_JSON
        if not payload:
            return {}

        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise TraefikProviderError(f"Invalid TRAEFIK_PERMANENT_KEYS_JSON: {exc}") from exc

        flattened: Dict[str, str] = {}
        self._flatten_nested(data, "", flattened)
        return flattened

    def _build_default_permanent_keys(self) -> Dict[str, str]:
        """Build permanent keys required for baseline routing safety."""
        keys: Dict[str, str] = {
            self._full_key("tcp/routers/tcp-default/rule"): "HostSNI(`*`)",
            self._full_key("tcp/routers/tcp-default/service"): "block-all",
            self._full_key("tcp/routers/tcp-default/entrypoints/0"): settings.TRAEFIK_TCP_ENTRYPOINT,
            self._full_key("tcp/routers/tcp-default/priority"): "1",
            self._full_key("tcp/routers/tcp-default/tls"): "true",
            self._full_key("tcp/routers/tcp-default/tls/options"): settings.TRAEFIK_TCP_TLS_OPTIONS,
            self._full_key("tcp/services/block-all/loadbalancer/servers/0/address"): settings.TRAEFIK_BLOCK_ALL_ADDRESS,
        }

        if settings.CTFD_URL:
            ctfd_url = settings.CTFD_URL.rstrip("/")
            keys[self._full_key("http/middlewares/redirect-to-ctfd/redirectregex/regex")] = "^https?://[^/]+/(.*)"
            keys[self._full_key("http/middlewares/redirect-to-ctfd/redirectregex/replacement")] = f"{ctfd_url}/$1"
            keys[self._full_key("http/middlewares/redirect-to-ctfd/redirectregex/permanent")] = "true"

        if settings.TRAEFIK_DASHBOARD_USERS:
            users = [u.strip() for u in settings.TRAEFIK_DASHBOARD_USERS.split(",") if u.strip()]
            for index, user in enumerate(users):
                keys[self._full_key(f"http/middlewares/dashboard-auth/basicauth/users/{index}")] = user

        return keys

    async def bootstrap_permanent_keys(self) -> None:
        """Write permanent non-instance Traefik keys."""
        await self._ensure_ready()

        keys = self._build_default_permanent_keys()
        file_keys = await self._load_permanent_keys_from_file()
        json_keys = self._load_permanent_keys_from_json()

        keys.update(file_keys)
        keys.update(json_keys)

        await self._set_keys(keys)
        print(f"[TraefikRedis] Ensured {len(keys)} permanent key(s)")

    async def register_instance_route(
        self,
        instance_id: str,
        route_type: str,
        backend_port: int,
        dedicated_entrypoint: Optional[str] = None,
        tls_enabled: bool = True,
        tls_options: Optional[str] = None,
    ) -> str:
        """Register instance router/service keys and return public endpoint."""
        await self._ensure_ready()

        fqdn = settings.get_instance_domain(instance_id)
        route = route_type.lower().strip()
        backend_address = f"{settings.TRAEFIK_BACKEND_HOST}:{backend_port}"

        if route == "http":
            keys = {
                self._full_key(f"http/routers/{instance_id}/entrypoints/0"): settings.TRAEFIK_HTTP_ENTRYPOINT,
                self._full_key(f"http/routers/{instance_id}/rule"): f"Host(`{fqdn}`)",
                self._full_key(f"http/routers/{instance_id}/service"): instance_id,
                self._full_key(f"http/routers/{instance_id}/priority"): "100",
                self._full_key(f"http/routers/{instance_id}/tls"): "true",
                self._full_key(f"http/routers/{instance_id}/tls/options"): tls_options or settings.TRAEFIK_HTTP_TLS_OPTIONS,
                self._full_key(f"http/services/{instance_id}/loadbalancer/servers/0/url"): f"http://{backend_address}",
            }
            await self._set_keys(keys)
            return f"https://{fqdn}"

        if route == "tcp":
            keys = {
                self._full_key(f"tcp/routers/{instance_id}/entrypoints/0"): settings.TRAEFIK_TCP_ENTRYPOINT,
                self._full_key(f"tcp/routers/{instance_id}/rule"): f"HostSNI(`{fqdn}`)",
                self._full_key(f"tcp/routers/{instance_id}/service"): instance_id,
                self._full_key(f"tcp/routers/{instance_id}/priority"): "100",
                self._full_key(f"tcp/routers/{instance_id}/tls"): "true",
                self._full_key(f"tcp/routers/{instance_id}/tls/options"): tls_options or settings.TRAEFIK_TCP_TLS_OPTIONS,
                self._full_key(f"tcp/services/{instance_id}/loadbalancer/servers/0/address"): backend_address,
            }
            await self._set_keys(keys)
            return f"{fqdn}:{settings.TRAEFIK_TCP_EXTERNAL_PORT}"

        # Non-SNI protocols (for example SSH) require dedicated entrypoints.
        if not dedicated_entrypoint:
            raise TraefikProviderError(
                f"Route type '{route}' requires a dedicated Traefik entrypoint"
            )

        rule = f"HostSNI(`{fqdn}`)" if tls_enabled else "HostSNI(`*`)"
        keys = {
            self._full_key(f"tcp/routers/{instance_id}/entrypoints/0"): dedicated_entrypoint,
            self._full_key(f"tcp/routers/{instance_id}/rule"): rule,
            self._full_key(f"tcp/routers/{instance_id}/service"): instance_id,
            self._full_key(f"tcp/routers/{instance_id}/priority"): "100",
            self._full_key(f"tcp/services/{instance_id}/loadbalancer/servers/0/address"): backend_address,
        }

        if tls_enabled:
            keys[self._full_key(f"tcp/routers/{instance_id}/tls")] = "true"
            keys[self._full_key(f"tcp/routers/{instance_id}/tls/options")] = (
                tls_options or settings.TRAEFIK_TCP_TLS_OPTIONS
            )

        await self._set_keys(keys)
        return f"{fqdn} ({dedicated_entrypoint})"

    async def delete_instance_route(self, instance_id: str) -> int:
        """Delete all Traefik keys related to an instance."""
        await self._ensure_ready()

        patterns = [
            self._full_key(f"http/routers/{instance_id}*"),
            self._full_key(f"http/services/{instance_id}*"),
            self._full_key(f"tcp/routers/{instance_id}*"),
            self._full_key(f"tcp/services/{instance_id}*"),
        ]

        keys_to_delete: Set[str] = set()
        for pattern in patterns:
            async for key in self._redis.scan_iter(match=pattern):
                keys_to_delete.add(key)

        if not keys_to_delete:
            return 0

        await self._redis.delete(*sorted(keys_to_delete))
        return len(keys_to_delete)


_traefik_provider: Optional[TraefikRedisProvider] = None


def get_traefik_provider() -> TraefikRedisProvider:
    """Get singleton Traefik Redis provider."""
    global _traefik_provider
    if _traefik_provider is None:
        _traefik_provider = TraefikRedisProvider()
    return _traefik_provider


async def init_traefik_provider() -> TraefikRedisProvider:
    """Initialize Traefik Redis provider singleton."""
    provider = get_traefik_provider()
    await provider.initialize()
    return provider


async def close_traefik_provider() -> None:
    """Close Traefik Redis provider singleton."""
    global _traefik_provider
    if _traefik_provider is not None:
        await _traefik_provider.close()
        _traefik_provider = None
