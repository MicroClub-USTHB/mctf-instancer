"""Route-inventory safety net.

The API surface has no per-route tests yet, so this asserts that the critical
operator / admin / player routes stay registered. It protects in-progress
refactors (e.g. splitting main.py into app/routers/*) from silently dropping
or renaming an endpoint.

Introspection goes through the OpenAPI schema rather than walking app.routes,
so it stays correct regardless of how routes are mounted (plain decorators vs
included routers, which newer Starlette wraps opaquely).
"""
from app import main


def route_pairs():
    """Set of (METHOD, path) for every documented HTTP route."""
    paths = main.app.openapi().get("paths", {})
    return {
        (method.upper(), path)
        for path, operations in paths.items()
        for method in operations
    }


CRITICAL = {
    # player-facing
    ("GET", "/challenges"),
    ("POST", "/instances/spawn"),
    ("GET", "/instances"),
    ("DELETE", "/instances/{instance_id}"),
    ("POST", "/instances/{instance_id}/extend"),
    ("GET", "/me"),
    ("GET", "/health"),
    ("GET", "/api"),
    # operator / admin control plane (used by the mctf CLI)
    ("GET", "/admin/api/instances"),
    ("DELETE", "/admin/api/instances/{instance_id}"),
    ("POST", "/admin/api/instances/spawn"),
}


def test_critical_routes_registered():
    missing = CRITICAL - route_pairs()
    assert not missing, f"missing critical routes: {sorted(missing)}"


def test_route_surface_not_shrunk_unexpectedly():
    # Coarse tripwire: a big drop almost certainly means a refactor lost a
    # router. The app currently documents ~60 method/path pairs.
    count = len(route_pairs())
    assert count >= 55, f"unexpectedly few routes registered: {count}"
