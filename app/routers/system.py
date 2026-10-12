"""System endpoints: the frontend entrypoint and health checks.

The first route group extracted from main.py into an APIRouter. It depends
only on settings and the shared runtime singletons, so it carries no coupling
back to main.py.
"""
from fastapi import APIRouter
from fastapi.responses import FileResponse

from ..config import settings
from ..runtime import STATIC_DIR, docker_manager

router = APIRouter(tags=["system"])


@router.get("/")
async def root():
    """Serve the frontend UI."""
    return FileResponse(str(STATIC_DIR / "index.html"))


@router.get("/api")
async def api_root():
    """API health check endpoint."""
    return {
        "status": "ok",
        "auth_mode": settings.AUTH_MODE,
    }


@router.get("/health")
async def health():
    """Detailed health check."""
    return {
        "status": "healthy",
        "active_instances": len(docker_manager.instances),
    }
