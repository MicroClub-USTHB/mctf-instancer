"""Route-inventory safety net.

The API surface has no per-route tests yet, so this asserts that the critical
operator / admin / player routes stay registered. It protects in-progress
refactors (e.g. splitting main.py into routers) from silently dropping or
renaming an endpoint.
"""
from app import main


def registered():
    """Set of (METHOD, path) for every real HTTP route on the app."""
    out = set()
    for r in main.app.routes:
        methods = getattr(r, "methods", None)
        path = getattr(r, "path", None)
        if not path:
            continue
        if not methods:  # websocket / mount
            out.add(("WS", path))
            continue
        for m in methods:
            if m != "HEAD":
                out.add((m, path))
    return out


CRITICAL = {
    # player-facing
    ("GET", "/challenges"),
    ("POST", "/instances/spawn"),
    ("GET", "/instances"),
    ("DELETE", "/instances/{instance_id}"),
    ("POST", "/instances/{instance_id}/extend"),
    ("GET", "/me"),
    ("GET", "/health"),
    # operator / admin control plane (used by the mctf CLI)
    ("GET", "/admin/api/instances"),
    ("DELETE", "/admin/api/instances/{instance_id}"),
    ("POST", "/admin/api/instances/spawn"),
}


def test_critical_routes_registered():
    have = registered()
    missing = CRITICAL - have
    assert not missing, f"missing critical routes: {sorted(missing)}"


def test_route_surface_not_shrunk_unexpectedly():
    # A coarse tripwire: the app currently exposes a large route surface;
    # a big drop almost certainly means a refactor lost a router.
    count = len([r for r in main.app.routes if getattr(r, "path", None)])
    assert count >= 60, f"unexpectedly few routes registered: {count}"
