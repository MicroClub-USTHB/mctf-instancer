"""Request identity and per-user rate limiting.

Extracted from main.py so route modules (app/routers/*) can share the same
rate-limit window and client-IP resolution without importing main.py.
"""
import ipaddress
import time
from collections import defaultdict

from fastapi import Request

from .config import settings

USER_RATE_LIMIT = 10  # max requests per window per user
USER_RATE_WINDOW = 60  # seconds

# user_id -> list of recent request timestamps (sliding window)
_user_rate_limit: dict[str, list] = defaultdict(list)


def get_trusted_proxies() -> set:
    """Parse trusted proxies from settings."""
    if settings.TRUSTED_PROXIES == "*":
        return {"*"}
    return {p.strip() for p in settings.TRUSTED_PROXIES.split(",") if p.strip()}


def get_client_ip(request: Request) -> str:
    """Resolve the client IP, honoring X-Forwarded-For only behind a trusted proxy.

    Prevents clients from spoofing their address: forwarded headers are trusted
    only when the direct peer is in TRUSTED_PROXIES.
    """
    direct_ip = request.client.host if request.client else "unknown"
    trusted_proxies = get_trusted_proxies()

    is_trusted = False
    if "*" in trusted_proxies:
        is_trusted = True
    elif direct_ip != "unknown":
        try:
            direct_addr = ipaddress.ip_address(direct_ip)
            for proxy in trusted_proxies:
                try:
                    if "/" in proxy:
                        if direct_addr in ipaddress.ip_network(proxy, strict=False):
                            is_trusted = True
                            break
                    else:
                        if direct_addr == ipaddress.ip_address(proxy):
                            is_trusted = True
                            break
                except ValueError:
                    continue
        except ValueError:
            pass

    if is_trusted:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

    return direct_ip


def check_user_rate_limit(user_id: str) -> bool:
    """Record a request and report whether the user is within the rate limit.

    Returns True if allowed, False if the per-window limit is exceeded.
    """
    now = time.time()
    window_start = now - USER_RATE_WINDOW

    _user_rate_limit[user_id] = [t for t in _user_rate_limit[user_id] if t > window_start]

    if len(_user_rate_limit[user_id]) >= USER_RATE_LIMIT:
        return False

    _user_rate_limit[user_id].append(now)
    return True


def active_rate_limited_user_count() -> int:
    """Number of users with at least one request in the current window.

    Read by the /metrics endpoint; kept here so the rate-limit state has a
    single owner.
    """
    window_start = time.time() - USER_RATE_WINDOW
    return sum(
        1
        for timestamps in _user_rate_limit.values()
        if any(ts > window_start for ts in timestamps)
    )
