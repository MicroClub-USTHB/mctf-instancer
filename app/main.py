"""Main FastAPI application for the CTF Docker Instancer."""
import os
import shutil
import zipfile
import tempfile
import time
import asyncio
import tomllib
from collections import defaultdict
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, Header, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .config import settings, Settings
from .models import (
    SpawnRequest,
    Instance,
    PublicInstance,
    PublicInstanceListResponse,
    PublicSpawnResponse,
)
from .auth import init_auth, init_team_mode, is_team_mode, ctfd_auth
from .websocket import get_ws_manager
from .logger import get_event_logger, init_event_logger, EventType
from .discord_webhook import get_discord_notifier
from .flag_manager import get_flag_manager
from .forensics import get_forensics_manager
from .database.connection import init_database, close_database
from .distributed_lock import init_lock_manager, close_lock_manager
from .traefik_redis import init_traefik_provider, close_traefik_provider
from .runtime import port_manager, docker_manager, STATIC_DIR
from .request_utils import (
    get_client_ip,
    check_user_rate_limit,
    USER_RATE_LIMIT,
)
from .metrics_state import (
    record_runtime_operation as _record_runtime_operation,
    spawn_started as _spawn_started,
    spawn_finished as _spawn_finished,
)
from .routers.system import router as system_router
from .routers.instances import router as instances_router
from .routers.challenges import router as challenges_router
from .routers.me import router as me_router
from .routers.metrics import router as metrics_router
from .routers.ws import router as ws_router
from .presenters import to_public_instance as _to_public_instance
from .sanitizers import (
    build_settings_audit_details as _build_settings_audit_details,
    classify_operation_failure_reason as _classify_operation_failure_reason,
    classify_spawn_failure_reason as _classify_spawn_failure_reason,
    is_sensitive_setting_key as _is_sensitive_setting_key,
    sanitize_user_error_message as _sanitize_user_error_message,
)


# Rate limiting storage for admin endpoints
# Format: {ip: [(timestamp, count), ...]}
_admin_rate_limit: Dict[str, list] = defaultdict(list)
# Per-user rate limiting (spawn/stop/extend) lives in request_utils.

# Maximum zip file size (50MB) and entry limits
MAX_ZIP_SIZE = 50 * 1024 * 1024  # 50MB
MAX_ZIP_ENTRIES = 1000
MAX_EXTRACTED_SIZE = 200 * 1024 * 1024  # 200MB total extracted

# Background task for auto-checking submissions
_submission_check_task: Optional[asyncio.Task] = None
SUBMISSION_CHECK_INTERVAL = 60  # Check every 60 seconds (1 minute)

async def _load_settings_from_db():
    """Load persisted settings overrides from database on startup."""
    # Map of setting types for proper casting
    _SETTING_TYPES = {
        "INSTANCE_TIMEOUT": int, "MAX_INSTANCES_PER_USER": int, "MAX_INSTANCES_PER_TEAM": int,
        "CONTAINER_MAX_MEMORY": str, "CONTAINER_MAX_CPU": float, "CONTAINER_PIDS_LIMIT": int,
        "PORT_RANGE_START": int, "PORT_RANGE_END": int,
        "DYNAMIC_FLAGS_ENABLED": lambda v: str(v).lower() in ("true", "1", "yes"),
        "FLAG_PREFIX": str,
        "NETWORK_ISOLATION_ENABLED": lambda v: str(v).lower() in ("true", "1", "yes"),
        "NETWORK_ICC_DISABLED": lambda v: str(v).lower() in ("true", "1", "yes"),
        "FORENSICS_AUTO_CAPTURE": lambda v: str(v).lower() in ("true", "1", "yes"),
        "FORENSICS_RETENTION_HOURS": int,
        "PUBLIC_HOST": str,

        # Traefik Redis routing settings
        "TRAEFIK_REDIS_ENABLED": lambda v: str(v).lower() in ("true", "1", "yes"),
        "TRAEFIK_REDIS_URL": str,
        "TRAEFIK_BASE_DOMAIN": str,
        "TRAEFIK_BACKEND_HOST": str,
        "TRAEFIK_HTTP_ENTRYPOINT": str,
        "TRAEFIK_TCP_ENTRYPOINT": str,
        "TRAEFIK_TCP_EXTERNAL_PORT": int,
        "TRAEFIK_HTTP_TLS_OPTIONS": str,
        "TRAEFIK_TCP_TLS_OPTIONS": str,
        "TRAEFIK_BLOCK_ALL_ADDRESS": str,
        "TRAEFIK_DASHBOARD_USERS": str,
        "TRAEFIK_PERMANENT_KEYS_FILE": str,
        "TRAEFIK_PERMANENT_KEYS_JSON": str,
        
        # New auth settings
        "AUTH_MODE": str,
        "CTFD_URL": str,
        "CTFD_API_KEY": str,
        "DISCORD_WEBHOOK_URL": str,
    }
    try:
        from .database.connection import get_async_session
        from .database.models import WhaleySettings as WhaleySettingsModel
        from sqlalchemy import select
        
        async with get_async_session() as session:
            result = await session.execute(select(WhaleySettingsModel))
            count = 0
            for row in result.scalars().all():
                if row.key in _SETTING_TYPES:
                    try:
                        cast_fn = _SETTING_TYPES[row.key]
                        setattr(settings, row.key, cast_fn(row.value))
                        count += 1
                    except Exception as e:
                        print(f"[Settings] Warning: Failed to apply {row.key}: {e}")
        if count > 0:
            print(f"[Settings] Loaded {count} setting overrides from database")
    except Exception as e:
        print(f"[Settings] Warning: Failed to load settings from DB: {e}")


async def _auto_check_submissions():
    """Background task to automatically check submissions for cheating."""
    print(f"[AutoCheck] Starting automatic submission checker (interval: {SUBMISSION_CHECK_INTERVAL}s)")
    
    while True:
        try:
            await asyncio.sleep(SUBMISSION_CHECK_INTERVAL)
            
            flag_manager = await get_flag_manager()

            # Only run if there are flags to check
            if len(flag_manager.flag_lookup) == 0:
                continue
            
            print(f"[AutoCheck] Running automatic submission check...")
            new_suspicious = await flag_manager.check_submissions()
            
            if new_suspicious:
                print(f"[AutoCheck] Found {len(new_suspicious)} new suspicious submissions!")
                for sus in new_suspicious:
                    print(f"[AutoCheck] ⚠️ {sus.submitter_username} submitted flag of {sus.flag_owner_username}")
            else:
                print(f"[AutoCheck] No new suspicious submissions found")
                
        except asyncio.CancelledError:
            print("[AutoCheck] Submission checker stopped")
            break
        except Exception as e:
            print(f"[AutoCheck] Error during submission check: {e}")
            import traceback
            traceback.print_exc()
            # Continue running despite errors
            await asyncio.sleep(10)
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global _submission_check_task
    
    # Startup - Initialize infrastructure
    print("[Startup] Initializing database...")
    await init_database()
    
    print("[Startup] Initializing distributed lock manager...")
    await init_lock_manager(settings.REDIS_URL)
    
    print("[Startup] Initializing event logger...")
    event_logger = await init_event_logger()
    
    print("[Startup] Initializing port manager...")
    await port_manager.initialize()
    
    init_auth()
    docker_manager.load_challenges()
    await docker_manager.load_challenge_settings()
    
    # Load settings overrides from database
    await _load_settings_from_db()

    # Prune flag mappings for challenges that disable dynamic flags
    disabled_ids = docker_manager.get_disabled_flag_challenge_ids()
    if disabled_ids:
        flag_mgr = await get_flag_manager()
        removed = await flag_mgr.prune_mappings_for_disabled_challenges(disabled_ids)
        if removed > 0:
            print(f"[Startup] Pruned {removed} flag mapping(s) for challenges with disabled dynamic flags")

    print("[Startup] Initializing Traefik Redis provider...")
    await init_traefik_provider()

    print("[Startup] Cleaning stale Whaley challenge containers...")
    await docker_manager.cleanup_stale_instances_on_startup()
    
    await docker_manager.start_cleanup_task()

    # Register WebSocket lifecycle hook
    _register_ws_lifecycle_hook()
    print("[Startup] WebSocket lifecycle hook registered")

    # Initialize team mode
    team_mode_enabled = await init_team_mode()
    
    # Start auto submission checker
    _submission_check_task = asyncio.create_task(_auto_check_submissions())
    
    await event_logger.log(
        EventType.SYSTEM_START,
        f"Instancer started with {len(docker_manager.challenges)} challenges"
    )
    
    print(f"Instancer started on {settings.HOST}:{settings.PORT}")
    print(f"Auth mode: {settings.AUTH_MODE}")
    print(f"Team mode: {'enabled' if team_mode_enabled else 'disabled'} (setting: {settings.TEAM_MODE})")
    print(f"Loaded {len(docker_manager.challenges)} challenges")
    print(f"Database: {settings.DATABASE_URL or 'SQLite (default)'}")
    print(f"Redis: {settings.REDIS_URL or 'Not configured (using local locks)'}")
    print(f"Traefik Redis provider: {'enabled' if settings.TRAEFIK_REDIS_ENABLED else 'disabled'}")
    if settings.TRAEFIK_REDIS_ENABLED:
        print(f"Traefik Redis URL: {settings.get_traefik_redis_url()}")
        print(f"Instance domain suffix: {settings.TRAEFIK_BASE_DOMAIN}")
    print(
        "Discord webhook: "
        f"{'enabled (URL hidden)' if (settings.DISCORD_WEBHOOK_URL or '').strip() else 'disabled'}"
    )
    print(f"Network isolation: {'enabled' if settings.NETWORK_ISOLATION_ENABLED else 'disabled'}")
    print(f"Auto submission check: enabled (every {SUBMISSION_CHECK_INTERVAL}s)")
    
    yield
    
    # Shutdown
    event_logger = get_event_logger()
    await event_logger.log(EventType.SYSTEM_STOP, "Instancer shutting down")
    
    # Stop submission checker
    if _submission_check_task:
        _submission_check_task.cancel()
        try:
            await _submission_check_task
        except asyncio.CancelledError:
            pass
    
    await docker_manager.stop_cleanup_task()

    print("[Shutdown] Closing Traefik Redis provider...")
    await close_traefik_provider()
    
    # Close infrastructure connections
    print("[Shutdown] Closing lock manager...")
    await close_lock_manager()
    
    print("[Shutdown] Closing database...")
    await close_database()
    
    print("Instancer shut down complete.")


app = FastAPI(
    title="CTF Docker Instancer",
    description="Dedicated Docker instancer for CTF challenges",
    version="1.0.0",
    lifespan=lifespan
)

# Extracted route groups (see app/routers/).
app.include_router(system_router)
app.include_router(instances_router)
app.include_router(challenges_router)
app.include_router(me_router)
app.include_router(metrics_router)
app.include_router(ws_router)

# CORS middleware
# Note: allow_credentials=True with allow_origins=["*"] is insecure
# If you need credentials, specify explicit origins instead of "*"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # Disabled for security with wildcard origins
    allow_methods=["*"],
    allow_headers=["*"],
)


# Security headers middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # Content Security Policy - helps prevent XSS attacks
        # This is a basic policy - adjust based on your needs
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'"
        )
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Clickjacking protection
        response.headers["X-Frame-Options"] = "DENY"
        
        # XSS filter (legacy, but still useful for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# =============================================================================
# WebSocket broadcasts — the /ws routes live in app/routers/ws.py
# =============================================================================

async def _ws_lifecycle_hook(event: str, instance: "Instance", **extra: Any) -> None:
    """Forward lifecycle events to WebSocket clients."""
    from .models import Instance as InstanceModel

    wsm = get_ws_manager()
    instance_data = instance.model_dump()

    owner_ids = []
    if instance.user_id:
        owner_ids.append(instance.user_id)
    if instance.team_id:
        owner_ids.append(instance.team_id)

    if owner_ids:
        await wsm.broadcast_to_owners(owner_ids, event, instance_data)
    await wsm.broadcast_admin(event, instance_data)


def _register_ws_lifecycle_hook() -> None:
    """Register the WebSocket lifecycle hook on the DockerManager."""
    docker_manager.add_lifecycle_hook(_ws_lifecycle_hook)


async def _broadcast_challenges_updated(public: bool = False) -> None:
    """Notify WebSocket clients that the challenge list changed.

    Admin connections always receive the event. Public (user) connections
    only receive it when *public* is True — used for active/inactive toggles
    where the user-visible challenge list actually changes.
    """
    wsm = get_ws_manager()
    ts = time.time()
    await wsm.broadcast_admin("challenges_updated", {"timestamp": ts})
    if public:
        for owner_id in list(wsm._public.keys()):
            await wsm.broadcast_to_owner(owner_id, "challenges_updated", {"timestamp": ts})


@app.get("/config")
async def get_config():
    """Get public configuration for the frontend."""
    return {
        "team_mode": is_team_mode(),
        "max_instances_per_user": settings.MAX_INSTANCES_PER_USER,
        "max_instances_per_team": settings.MAX_INSTANCES_PER_TEAM,
        "instance_timeout": settings.INSTANCE_TIMEOUT,
        "auth_mode": settings.AUTH_MODE.value if hasattr(settings.AUTH_MODE, 'value') else str(settings.AUTH_MODE),
        "ctfd_url": settings.CTFD_URL or None,
    }


# ============== ADMIN ROUTES ==============

def verify_admin_key(
    request: Request,
    x_admin_key: Optional[str] = Header(None)
) -> bool:
    """Verify admin key from header with rate limiting."""
    if not settings.ADMIN_KEY:
        raise HTTPException(status_code=500, detail="Admin key not configured")
    
    # Rate limiting check
    client_ip = get_client_ip(request)
    current_time = time.time()
    window_start = current_time - 60  # 1 minute window
    
    # Clean old entries and count recent requests
    _admin_rate_limit[client_ip] = [
        ts for ts in _admin_rate_limit[client_ip] 
        if ts > window_start
    ]
    
    if len(_admin_rate_limit[client_ip]) >= settings.ADMIN_RATE_LIMIT:
        get_event_logger().log_sync(
            EventType.AUTH_FAILURE,
            f"Admin rate limit exceeded from IP {client_ip}"
        )
        raise HTTPException(
            status_code=429, 
            detail=f"Rate limit exceeded. Max {settings.ADMIN_RATE_LIMIT} requests per minute."
        )
    
    # Record this request
    _admin_rate_limit[client_ip].append(current_time)
    
    if not x_admin_key or x_admin_key != settings.ADMIN_KEY:
        get_event_logger().log_sync(
            EventType.AUTH_FAILURE,
            f"Invalid admin key attempt from IP {client_ip}"
        )
        raise HTTPException(status_code=401, detail="Invalid admin key")
    
    return True


@app.get(f"/{settings.ADMIN_PATH}")
async def admin_dashboard():
    """Serve the admin dashboard UI at the configurable ADMIN_PATH route.

    The path defaults to ``/admin`` but can be set to e.g. ``/admin-<hex>``
    via the ADMIN_PATH env var to keep the dashboard URL off the wordlists
    indexed by attackers. This is URL-obscurity only; ADMIN_KEY remains the
    real auth gate on /admin/api/*.
    """
    return FileResponse(str(STATIC_DIR / "admin.html"))


@app.get("/admin/api/stats")
async def admin_stats(_: bool = Depends(verify_admin_key)):
    """Get admin statistics."""
    logger = get_event_logger()
    stats = await logger.get_stats()
    stats["active_instances"] = len(docker_manager.instances)
    stats["challenges_loaded"] = len(docker_manager.challenges)
    stats["ports_allocated"] = port_manager.get_allocated_count()
    return stats


@app.get("/admin/api/logs")
async def admin_logs(
    limit: int = 100,
    offset: int = 0,
    event_type: Optional[str] = None,
    username: Optional[str] = None,
    _: bool = Depends(verify_admin_key)
):
    """Get event logs with pagination."""
    # Convert event_type string to enum if provided
    evt = None
    if event_type:
        try:
            evt = EventType(event_type)
        except ValueError:
            pass
    
    # Get all entries first to calculate total (for pagination)
    logger = get_event_logger()
    all_entries = await logger.get_entries(limit=10000, offset=0, event_type=evt)
    
    # Filter by username if provided
    if username:
        all_entries = [e for e in all_entries if e.username and username.lower() in e.username.lower()]
    
    # Calculate total after filtering
    total_filtered = len(all_entries)
    
    # Apply pagination
    paginated_entries = all_entries[offset:offset + limit]
    
    return {
        "logs": [e.model_dump() for e in paginated_entries],
        "total": total_filtered,
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < total_filtered
    }


@app.get("/admin/api/instances")
async def admin_instances(_: bool = Depends(verify_admin_key)):
    """Get all active instances."""
    instances = list(docker_manager.instances.values())
    return {
        "instances": [i.model_dump() for i in instances]
    }


@app.delete("/admin/api/instances/{instance_id}")
async def admin_stop_instance(
    instance_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Force stop an instance (admin)."""
    instance = docker_manager.instances.get(instance_id)
    challenge_id = instance.challenge_id if instance else "unknown"
    challenge = docker_manager.get_challenge(challenge_id) if instance else None

    success, message = await docker_manager.stop_instance(
        instance_id=instance_id,
        user_id=None,  # Admin can stop any instance
        terminate_reason="admin_stop",
    )
    
    if success:
        _record_runtime_operation("stop", "success", challenge_id, "admin_stop")
        logger = get_event_logger()
        await logger.log(
            EventType.INSTANCE_STOP,
            f"Admin force-stopped instance '{instance_id}'",
            instance_id=instance_id,
            challenge_id=challenge_id if challenge_id != "unknown" else None,
            details={"reason": "admin_stop"},
        )

        notifier = get_discord_notifier()
        await notifier.notify_instance_stopped(
            instance_id=instance_id,
            challenge_id=challenge_id,
            challenge_name=challenge.name if challenge else None,
            stopped_by="admin",
            reason="admin_stop",
            owner_username=instance.username if instance else None,
            owner_user_id=instance.user_id if instance else None,
            team_id=instance.team_id if instance else None,
            team_name=instance.team_name if instance else None,
            message=message,
        )
    else:
        _record_runtime_operation("stop", "failed", challenge_id, _classify_operation_failure_reason(message))
    
    return {"success": success, "message": message}


@app.post("/admin/api/instances/spawn")
async def admin_spawn_instance(
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Admin test-spawn: create an instance for a target user, bypassing the
    active/inactive gate. Used to smoke-test challenges before publishing.

    Body: { challenge_id: str, user_id: int }
    """
    body = await request.json()
    challenge_id = str(body.get("challenge_id", "")).strip()
    raw_user_id = body.get("user_id")

    if not challenge_id:
        raise HTTPException(status_code=400, detail="challenge_id is required")
    if raw_user_id is None:
        raise HTTPException(status_code=400, detail="user_id is required")

    try:
        target_user_id = int(raw_user_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="user_id must be an integer")

    if target_user_id < 1:
        raise HTTPException(status_code=400, detail="user_id must be positive")

    # Resolve the target user via CTFd admin API
    target_user = await ctfd_auth.resolve_user_by_id(target_user_id)
    if target_user is None:
        raise HTTPException(
            status_code=404,
            detail=f"CTFd user #{target_user_id} not found.",
        )

    target_username = target_user.username

    team_mode = is_team_mode()
    if team_mode:
        if not target_user.team_id:
            raise HTTPException(
                status_code=400,
                detail=f"Team mode is enabled but user '{target_username}' has no CTFd team. "
                       "Assign the user to a team in CTFd first.",
            )
        owner_id = target_user.team_id
        max_instances = settings.MAX_INSTANCES_PER_TEAM
    else:
        owner_id = target_user.user_id
        max_instances = settings.MAX_INSTANCES_PER_USER

    # Check owner instance limit (same as normal spawn)
    if docker_manager.get_owner_instance_count(owner_id, team_mode) >= max_instances:
        detail = (
            f"Team has reached the maximum instance limit ({max_instances})"
            if team_mode
            else f"User has reached the maximum instance limit ({max_instances})"
        )
        raise HTTPException(status_code=429, detail=detail)

    # Skip the is_active check — the whole point of this endpoint
    client_ip = get_client_ip(request)

    success, message_str, instance = await docker_manager.spawn_instance(
        challenge_id=challenge_id,
        user_id=target_user.user_id,
        username=target_user.username,
        user_info=target_user,
        team_mode=team_mode,
    )

    if not success or instance is None:
        raise HTTPException(status_code=500, detail=message_str)

    challenge = docker_manager.get_challenge(challenge_id)

    logger = get_event_logger()
    await logger.log_instance_spawn(
        user_id=target_user.user_id,
        username=target_username,
        instance_id=instance.instance_id,
        challenge_id=challenge_id,
        ports=instance.ports,
        public_url=instance.public_url or "",
        ip_address=client_ip,
        extra={"admin_test_spawn": True, "team_id": target_user.team_id, "team_name": target_user.team_name},
    )

    notifier = get_discord_notifier()
    await notifier.notify_instance_spawn(
        instance_id=instance.instance_id,
        challenge_id=challenge_id,
        challenge_name=challenge.name if challenge else None,
        created_by=target_username,
        created_by_id=target_user.user_id,
        created_at=instance.created_at,
        expires_at=instance.expires_at,
        team_id=target_user.team_id if team_mode else None,
        team_name=target_user.team_name if team_mode else None,
        public_url=instance.public_url,
        connection_hint=instance.connection_hint,
        routing_type=instance.routing_type,
        ports=instance.ports,
        ip_address=client_ip,
        is_admin_test_spawn=True,
    )

    return {
        "success": True,
        "message": f"Instance started successfully for {target_username}",
        "instance": instance.model_dump(),
    }


@app.get("/admin/api/user-ports")
async def admin_user_ports(_: bool = Depends(verify_admin_key)):
    """Get all saved user port mappings from database."""
    from .database.connection import get_async_session
    from .database.models import UserPortMapping
    from sqlalchemy import select
    
    async with get_async_session() as session:
        result = await session.execute(select(UserPortMapping))
        mappings = result.scalars().all()
    
    # Build structured response
    user_ports = {}
    flat_list = []
    
    for m in mappings:
        if m.user_id not in user_ports:
            user_ports[m.user_id] = {"_username": m.username or m.user_id}
        
        if m.challenge_id not in user_ports[m.user_id]:
            user_ports[m.user_id][m.challenge_id] = {}
        
        user_ports[m.user_id][m.challenge_id][str(m.internal_port)] = m.external_port
    
    # Create flat list
    seen_combos = set()
    for m in mappings:
        combo = (m.user_id, m.challenge_id)
        if combo not in seen_combos:
            seen_combos.add(combo)
            ports = {
                str(pm.internal_port): pm.external_port 
                for pm in mappings 
                if pm.user_id == m.user_id and pm.challenge_id == m.challenge_id
            }
            flat_list.append({
                "user_id": m.user_id,
                "username": m.username or m.user_id,
                "challenge_id": m.challenge_id,
                "ports": ports
            })
    
    return {
        "user_ports": user_ports,
        "mappings": flat_list,
        "total_users": len(user_ports),
        "total_mappings": len(flat_list)
    }


@app.get("/admin/api/port-stats")
async def admin_port_stats(_: bool = Depends(verify_admin_key)):
    """Get port usage statistics."""
    return await port_manager.get_port_stats()


@app.delete("/admin/api/user-ports")
async def admin_clear_all_user_ports(_: bool = Depends(verify_admin_key)):
    """Clear all user port mappings."""
    count = await port_manager.clear_all_user_mappings()
    return {"success": True, "message": f"Cleared {count} user mappings"}


@app.delete("/admin/api/user-ports/{user_id}")
async def admin_delete_user_ports(
    user_id: str,
    challenge_id: Optional[str] = None,
    _: bool = Depends(verify_admin_key)
):
    """Delete saved port mappings for a user (optionally for specific challenge)."""
    from .database.connection import get_async_session
    from .database.models import UserPortMapping
    from sqlalchemy import select, delete
    
    async with get_async_session() as session:
        # Check if user exists
        result = await session.execute(
            select(UserPortMapping).where(UserPortMapping.user_id == user_id)
        )
        if not result.scalars().first():
            raise HTTPException(status_code=404, detail="User not found")
        
        if challenge_id:
            # Delete specific challenge mapping
            await session.execute(
                delete(UserPortMapping).where(
                    UserPortMapping.user_id == user_id,
                    UserPortMapping.challenge_id == challenge_id
                )
            )
            await session.commit()
            return {"success": True, "message": f"Deleted ports for {user_id}/{challenge_id}"}
        else:
            # Delete all user mappings
            await session.execute(
                delete(UserPortMapping).where(UserPortMapping.user_id == user_id)
            )
            await session.commit()
            return {"success": True, "message": f"Deleted all ports for {user_id}"}


# =============================================================================
# Admin Flag Management API (Dynamic Flags / Anti-Cheat)
# =============================================================================

@app.get("/admin/api/flags")
async def admin_get_flags(_: bool = Depends(verify_admin_key)):
    """Get all flag mappings and suspicious submissions."""
    flag_mgr = await get_flag_manager()
    data = await flag_mgr.get_all_mappings()

    # Add config info
    data["dynamic_flags_enabled"] = settings.DYNAMIC_FLAGS_ENABLED
    data["ctfd_configured"] = bool(settings.CTFD_URL and settings.CTFD_API_KEY)

    return data


@app.post("/admin/api/flags/check-submissions")
async def admin_check_submissions(
    limit: int = 100,
    full_scan: bool = False,
    _: bool = Depends(verify_admin_key)
):
    """Check recent submissions for cheating (flag sharing).

    Set full_scan=true to re-check all recent submissions regardless of
    the incremental checkpoint. Default (false) only checks new submissions
    since the last check.
    """
    flag_mgr = await get_flag_manager()

    if not settings.CTFD_URL or not settings.CTFD_API_KEY:
        raise HTTPException(status_code=400, detail="CTFd not configured")

    new_suspicious = await flag_mgr.check_submissions(limit=limit, full_scan=full_scan)
    total = await flag_mgr.count_suspicious_submissions()

    return {
        "success": True,
        "new_suspicious_count": len(new_suspicious),
        "new_suspicious": [
            {
                "submission_id": s.submission_id,
                "submitter": s.submitter_username,
                "flag_owner": s.flag_owner_username,
                "challenge": s.local_challenge_id,
                "time": s.submission_time,
                "ip": s.ip_address,
            }
            for s in new_suspicious
        ],
        "total_suspicious": total,
    }


@app.delete("/admin/api/flags/suspicious")
async def admin_clear_suspicious(_: bool = Depends(verify_admin_key)):
    """Clear the suspicious submissions list."""
    flag_mgr = await get_flag_manager()
    count = flag_mgr.clear_suspicious_submissions()
    return {"success": True, "cleared": count}


@app.get("/admin/api/flags/suspicious")
async def admin_get_suspicious(
    offset: int = 0,
    limit: int = 50,
    _: bool = Depends(verify_admin_key),
):
    """Get paginated suspicious submissions (flag sharing detections)."""
    flag_mgr = await get_flag_manager()
    submissions = await flag_mgr.get_suspicious_submissions(offset=offset, limit=limit)
    total = await flag_mgr.count_suspicious_submissions()

    return {
        "suspicious": [
            {
                "submission_id": s.submission_id,
                "submitter_user_id": s.submitter_user_id,
                "submitter_username": s.submitter_username,
                "flag_owner_user_id": s.flag_owner_user_id,
                "flag_owner_username": s.flag_owner_username,
                "challenge_id": s.challenge_id,
                "local_challenge_id": s.local_challenge_id,
                "provided_flag": s.provided_flag,
                "submission_time": s.submission_time,
                "ip_address": s.ip_address,
                "submitter_team_id": s.submitter_team_id,
                "submitter_team_name": s.submitter_team_name,
                "flag_owner_team_id": s.flag_owner_team_id,
                "flag_owner_team_name": s.flag_owner_team_name,
            }
            for s in submissions
        ],
        "total": total,
    }


@app.get("/admin/api/flags/mappings")
async def admin_get_flag_mappings(_: bool = Depends(verify_admin_key)):
    """Get all flag mappings (which user has which flag for which challenge)."""
    flag_mgr = await get_flag_manager()
    
    return {
        "mappings": [
            {
                "flag_id": mapping.flag_id,
                "ctfd_challenge_id": mapping.ctfd_challenge_id,
                "local_challenge_id": mapping.local_challenge_id,
                "user_id": mapping.user_id,
                "username": mapping.username,
                "flag_content": mapping.flag_content,  # Be careful exposing this in production!
                "created_at": mapping.created_at,
                "instance_id": mapping.instance_id
            }
            for mapping in flag_mgr.flag_mappings.values()
        ],
        "challenge_mapping": flag_mgr.challenge_mapping,
        "total": len(flag_mgr.flag_mappings)
    }


@app.delete("/admin/api/flags/user/{user_id}")
async def admin_delete_user_flags(
    user_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Delete all flags for a user from CTFd."""
    flag_mgr = await get_flag_manager()
    count = await flag_mgr.cleanup_user_flags(user_id)
    return {"success": True, "deleted": count}


@app.delete("/admin/api/flags/{flag_id}")
async def admin_delete_flag(
    flag_id: int,
    _: bool = Depends(verify_admin_key)
):
    """Delete a specific flag mapping from CTFd."""
    flag_mgr = await get_flag_manager()
    
    if flag_id not in flag_mgr.flag_mappings:
        raise HTTPException(status_code=404, detail="Flag not found")
    
    # Get mapping info before deletion
    mapping = flag_mgr.flag_mappings[flag_id]

    # Try to delete from CTFd (but continue even if it fails)
    ctfd_deleted = await flag_mgr.delete_flag(flag_id)

    if ctfd_deleted:
        return {"success": True, "message": f"Deleted flag {flag_id} from CTFd and local storage"}
    else:
        return {"success": True, "message": f"Removed flag {flag_id} from local storage (CTFd deletion may have failed)"}


@app.post("/admin/api/flags/sync-challenge")
async def admin_sync_challenge(
    local_challenge_id: str,
    ctfd_challenge_id: int,
    _: bool = Depends(verify_admin_key)
):
    """Manually map a local challenge ID to CTFd challenge ID."""
    # Reject mapping if the challenge disables dynamic flags
    challenge = docker_manager.get_challenge(local_challenge_id)
    if challenge and challenge.disable_dynamic_flags:
        raise HTTPException(
            status_code=400,
            detail=f"Dynamic flags are disabled for challenge '{local_challenge_id}' (set in instance.toml). Remove disable_dynamic_flags from the challenge config to enable mapping.",
        )

    flag_mgr = await get_flag_manager()
    await flag_mgr.add_challenge_mapping(local_challenge_id, ctfd_challenge_id)
    return {
        "success": True,
        "message": f"Mapped {local_challenge_id} -> CTFd #{ctfd_challenge_id}",
    }


@app.delete("/admin/api/flags/mapping/{local_challenge_id:path}")
async def admin_delete_challenge_mapping(
    local_challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Remove a local challenge to CTFd challenge ID mapping."""
    flag_mgr = await get_flag_manager()
    removed = await flag_mgr.remove_challenge_mapping(local_challenge_id)
    if removed:
        return {
            "success": True,
            "message": f"Removed mapping for {local_challenge_id}",
        }
    raise HTTPException(status_code=404, detail="Mapping not found")


@app.get("/admin/api/ctfd/challenges")
async def admin_fetch_ctfd_challenges(
    search: Optional[str] = None,
    category: Optional[str] = None,
    _: bool = Depends(verify_admin_key)
):
    """Fetch all challenges from CTFd for sync wizard."""
    import httpx
    
    if not settings.CTFD_URL or not settings.CTFD_API_KEY:
        raise HTTPException(status_code=400, detail="CTFd not configured")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.CTFD_URL}/api/v1/challenges",
                headers={
                    "Authorization": f"Token {settings.CTFD_API_KEY}",
                    "Content-Type": "application/json"
                },
                timeout=15.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=502, 
                    detail=f"CTFd returned status {response.status_code}"
                )
            
            data = response.json()
            if not data.get("success"):
                raise HTTPException(status_code=502, detail="CTFd API error")
            
            challenges = data.get("data", [])
            
            # Extract categories
            categories = sorted(set(c.get("category", "") for c in challenges if c.get("category")))
            
            # Filter by category if specified
            if category:
                challenges = [c for c in challenges if c.get("category") == category]
            
            # Filter by search term (name)
            if search:
                search_lower = search.lower()
                challenges = [
                    c for c in challenges 
                    if search_lower in c.get("name", "").lower()
                ]
            
            # Get current mappings for comparison
            flag_mgr = await get_flag_manager()
            local_challenges = docker_manager.challenges
            
            # Build response with mapping info
            result = []
            for c in challenges:
                ctfd_id = c.get("id")
                ctfd_name = c.get("name", "")
                
                # Check if already mapped
                mapped_local_id = None
                for local_id, mapped_ctfd_id in flag_mgr.challenge_mapping.items():
                    if mapped_ctfd_id == ctfd_id:
                        mapped_local_id = local_id
                        break
                
                # Check for name match suggestions (skip challenges that disable dynamic flags)
                suggested_local = None
                name_match_score = 0
                for local_id, local_chall in local_challenges.items():
                    if local_chall.disable_dynamic_flags:
                        continue  # Can't be mapped — dynamic flags disabled per challenge
                    local_name = local_chall.name.lower()
                    ctfd_name_lower = ctfd_name.lower()

                    # Exact match
                    if local_name == ctfd_name_lower:
                        suggested_local = local_id
                        name_match_score = 100
                        break
                    # Partial match
                    elif ctfd_name_lower in local_name or local_name in ctfd_name_lower:
                        if name_match_score < 50:
                            suggested_local = local_id
                            name_match_score = 50
                
                result.append({
                    "id": ctfd_id,
                    "name": ctfd_name,
                    "category": c.get("category", ""),
                    "value": c.get("value", 0),
                    "type": c.get("type", ""),
                    "mapped_local_id": mapped_local_id,
                    "suggested_local_id": suggested_local if not mapped_local_id else None,
                    "name_match_score": name_match_score if not mapped_local_id else 0
                })
            
            # Sort by category, then name
            result.sort(key=lambda x: (x["category"], x["name"]))
            
            return {
                "success": True,
                "challenges": result,
                "categories": categories,
                "total": len(result)
            }
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Failed to connect to CTFd: {str(e)}")


@app.get("/admin/api/ctfd/users/{user_id}")
async def admin_resolve_ctfd_user(
    user_id: int,
    _: bool = Depends(verify_admin_key),
):
    """Resolve a CTFd user by ID. Used by the test-spawn confirmation dialog."""
    if not settings.CTFD_URL or not settings.CTFD_API_KEY:
        raise HTTPException(status_code=400, detail="CTFd not configured")

    user = await ctfd_auth.resolve_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail=f"CTFd user #{user_id} not found")

    return {
        "success": True,
        "user": {
            "id": int(user.user_id),
            "name": user.username,
            "team_id": user.team_id,
            "team_name": user.team_name,
        },
    }


# =============================================================================
# Instance Forensics API (Docker Log Capture)
# =============================================================================

@app.get("/admin/api/forensics/stats")
async def admin_forensics_stats(_: bool = Depends(verify_admin_key)):
    """Get forensics system statistics."""
    forensics = get_forensics_manager()
    return forensics.get_stats()


@app.post("/admin/api/forensics/toggle")
async def admin_forensics_toggle(
    enabled: bool,
    _: bool = Depends(verify_admin_key)
):
    """Enable or disable auto capture."""
    forensics = get_forensics_manager()
    forensics.set_auto_capture(enabled)
    return {
        "success": True,
        "auto_capture_enabled": forensics.auto_capture_enabled,
        "message": f"Auto capture {'enabled' if enabled else 'disabled'}"
    }


@app.get("/admin/api/forensics/logs")
async def admin_forensics_logs(
    challenge_id: Optional[str] = None,
    owner_id: Optional[str] = None,
    capture_type: Optional[str] = None,
    limit: int = 100,
    _: bool = Depends(verify_admin_key)
):
    """Get forensics logs with optional filters."""
    forensics = get_forensics_manager()
    logs = forensics.get_logs(
        challenge_id=challenge_id,
        owner_id=owner_id,
        capture_type=capture_type,
        limit=limit
    )
    
    return {
        "logs": [
            {
                "log_id": log.log_id,
                "instance_id": log.instance_id,
                "challenge_id": log.challenge_id,
                "challenge_name": log.challenge_name,
                "owner_id": log.owner_id,
                "owner_name": log.owner_name,
                "spawned_by": log.spawned_by,
                "capture_type": log.capture_type,
                "capture_time": log.capture_time,
                "terminate_reason": log.terminate_reason,
                "file_size_bytes": log.file_size_bytes,
                "compressed": log.compressed,
                "container_count": log.container_count,
                "container_names": log.container_names or [],
                "team_id": log.team_id,
                "team_name": log.team_name
            }
            for log in logs
        ],
        "total": len(logs)
    }


@app.get("/admin/api/forensics/logs/{log_id}")
async def admin_forensics_log_content(
    log_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Get content of a specific forensics log."""
    forensics = get_forensics_manager()
    success, message, content = forensics.get_log_content(log_id)
    
    if not success:
        raise HTTPException(status_code=404, detail=message)
    
    return {
        "log_id": log_id,
        "content": content
    }


@app.delete("/admin/api/forensics/logs/{log_id}")
async def admin_forensics_delete_log(
    log_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Delete a specific forensics log."""
    forensics = get_forensics_manager()
    success, message = forensics.delete_log(log_id)
    
    if not success:
        raise HTTPException(status_code=404, detail=message)
    
    return {"success": True, "message": message}


@app.delete("/admin/api/forensics/logs")
async def admin_forensics_clear_logs(_: bool = Depends(verify_admin_key)):
    """Clear all forensics logs."""
    forensics = get_forensics_manager()
    success, message = forensics.clear_all_logs()
    
    if not success:
        raise HTTPException(status_code=500, detail=message)
    
    return {"success": True, "message": message}


@app.post("/admin/api/forensics/live-capture/{instance_id}")
async def admin_forensics_live_capture(
    instance_id: str,
    _: bool = Depends(verify_admin_key)
):
    """
    Perform a live capture from a running instance.
    This is the 'self-docker logging' feature for on-demand log capture.
    """
    # Get instance info
    instance = docker_manager.instances.get(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    
    # Get challenge info
    challenge = docker_manager.get_challenge(instance.challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    # Perform live capture
    forensics = get_forensics_manager()
    success, message, log_id = await forensics.live_capture(
        instance_id=instance.instance_id,
        project_name=instance.instance_id,
        challenge_id=instance.challenge_id,
        challenge_name=challenge.name,
        owner_id=instance.owner_id or instance.user_id,
        owner_name=instance.team_name or instance.username,
        spawned_by=instance.username,
        team_id=instance.team_id,
        team_name=instance.team_name
    )
    
    if not success:
        raise HTTPException(status_code=500, detail=message)
    
    return {
        "success": True,
        "message": message,
        "log_id": log_id
    }


@app.post("/admin/api/forensics/cleanup")
async def admin_forensics_cleanup(_: bool = Depends(verify_admin_key)):
    """Manually trigger cleanup of old forensics logs."""
    forensics = get_forensics_manager()
    deleted = await forensics.cleanup_old_logs()
    return {
        "success": True,
        "deleted": deleted,
        "message": f"Cleaned up {deleted} old logs"
    }


# =============================================================================
# Monitoring API (Resource Metrics)
# =============================================================================

from .monitoring import get_monitoring_manager


@app.get("/admin/api/monitoring/system")
async def admin_monitoring_system(_: bool = Depends(verify_admin_key)):
    """Get overall system resource metrics."""
    monitoring = get_monitoring_manager()
    metrics = await monitoring.get_system_metrics()
    
    return {
        "total_containers": metrics.total_containers,
        "running_containers": metrics.running_containers,
        "total_cpu_percent": metrics.total_cpu_percent,
        "total_memory_mb": metrics.total_memory_mb,
        "host_cpu_cores": metrics.host_cpu_cores,
        "host_memory_total_mb": metrics.host_memory_total_mb,
        "host_memory_used_mb": metrics.host_memory_used_mb,
        "host_memory_percent": metrics.host_memory_percent,
        "timestamp": metrics.timestamp
    }


@app.get("/admin/api/monitoring/instances")
async def admin_monitoring_instances(_: bool = Depends(verify_admin_key)):
    """Get resource metrics for all active instances."""
    monitoring = get_monitoring_manager()
    
    # Get all active instances
    instances = list(docker_manager.instances.values())
    
    instance_metrics = []
    
    for instance in instances:
        if instance.status != "running":
            continue
        
        # Get challenge name from challenge config
        challenge = docker_manager.challenges.get(instance.challenge_id)
        challenge_name = challenge.name if challenge else instance.challenge_id
        
        # Use instance.container_ids if available, otherwise query docker compose
        container_ids = instance.container_ids
        
        if not container_ids:
            # Fallback: query docker compose using instance_id as project name
            try:
                result = await asyncio.create_subprocess_exec(
                    "docker", "compose", "-p", instance.instance_id, "ps", "-q",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(result.communicate(), timeout=10)
                container_ids = [c.strip() for c in stdout.decode().strip().split("\n") if c.strip()]
            except Exception as e:
                print(f"[Monitoring] Failed to get containers for {instance.instance_id}: {e}")
                continue
        
        if not container_ids:
            continue
        
        # Get metrics for this instance
        try:
            metrics = await monitoring.get_instance_metrics(
                instance_id=instance.instance_id,
                challenge_id=instance.challenge_id,
                challenge_name=challenge_name,
                owner_id=instance.owner_id or instance.user_id,
                owner_name=instance.team_name or instance.username,
                container_ids=container_ids
            )
            
            if metrics:
                instance_metrics.append({
                    "instance_id": metrics.instance_id,
                    "challenge_id": metrics.challenge_id,
                    "challenge_name": metrics.challenge_name,
                    "owner_id": metrics.owner_id,
                    "owner_name": metrics.owner_name,
                    "container_count": metrics.container_count,
                    "total_cpu_percent": metrics.total_cpu_percent,
                    "total_memory_mb": metrics.total_memory_mb,
                    "containers": [
                        {
                            "container_id": c.container_id,
                            "container_name": c.container_name,
                            "cpu_percent": c.cpu_percent,
                            "memory_usage_mb": c.memory_usage_mb,
                            "memory_limit_mb": c.memory_limit_mb,
                            "memory_percent": c.memory_percent,
                            "pids": c.pids
                        }
                        for c in metrics.containers
                    ],
                    "timestamp": metrics.timestamp
                })
        except Exception as e:
            print(f"[Monitoring] Failed to get metrics for instance {instance.instance_id}: {e}")
            continue
    
    return {
        "instances": instance_metrics,
        "total_instances": len(instance_metrics)
    }


# =============================================================================
# Admin Challenge Management API
# =============================================================================

ALLOWED_EXTENSIONS = {'.py', '.js', '.ts', '.html', '.css', '.yaml', '.yml', '.toml',
                      '.json', '.txt', '.md', '.sh', '.dockerfile', '.sql',
                      '.c', '.cpp', '.h', '.go', '.rs', '.php', '.rb', '.java', '.conf'}
BINARY_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', 
                     '.ttf', '.eot', '.zip', '.tar', '.gz', '.so', '.exe', '.bin'}


def is_safe_path(base_path: Path, requested_path: Path) -> bool:
    """Check if requested path is within base path (prevent path traversal)."""
    try:
        resolved = requested_path.resolve()
        base_resolved = base_path.resolve()
        # Use is_relative_to for proper path traversal prevention
        # startswith can be bypassed with paths like /challenges-evil
        return resolved.is_relative_to(base_resolved)
    except Exception:
        return False


def get_file_tree(directory: Path, base_path: Path) -> List[dict]:
    """Get directory tree structure."""
    items = []
    try:
        for item in sorted(directory.iterdir()):
            rel_path = str(item.relative_to(base_path))
            if item.is_dir():
                items.append({
                    "name": item.name,
                    "path": rel_path,
                    "type": "directory",
                    "children": get_file_tree(item, base_path)
                })
            else:
                items.append({
                    "name": item.name,
                    "path": rel_path,
                    "type": "file",
                    "size": item.stat().st_size,
                    "editable": item.suffix.lower() in ALLOWED_EXTENSIONS or item.suffix == ''
                })
    except PermissionError:
        pass
    return items


@app.get("/admin/api/challenges/list")
async def admin_list_challenges(_: bool = Depends(verify_admin_key)):
    """List all challenges with their directories."""
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenges = []
    
    if challenges_path.exists():
        for item in challenges_path.iterdir():
            if item.is_dir():
                config_file = item / "instance.toml"
                compose_yaml = item / "challenge" / "docker-compose.yaml"
                compose_yml = item / "challenge" / "docker-compose.yml"

                has_config = config_file.exists()
                has_compose = compose_yaml.exists() or compose_yml.exists()
                
                # Get challenge ID from loaded challenges (may differ from folder name)
                loaded_ids = [c.id for c in docker_manager.get_challenges()]
                is_loaded = item.name in loaded_ids
                
                # Also check if config's id is loaded (folder name might differ)
                config_id = item.name
                if has_config and not is_loaded:
                    try:
                        with open(config_file, "rb") as f:
                            cfg = tomllib.load(f)
                            if cfg and cfg.get('id'):
                                config_id = cfg.get('id')
                                if config_id in loaded_ids:
                                    is_loaded = True
                    except:
                        pass
                
                # Determine if this challenge disables dynamic flags
                disable_dynamic_flags = False
                if config_id in docker_manager.challenges:
                    disable_dynamic_flags = docker_manager.challenges[config_id].disable_dynamic_flags

                challenges.append({
                    "id": config_id,
                    "folder": item.name,
                    "path": str(item),
                    "has_config": has_config,
                    "has_compose": has_compose,
                    "loaded": is_loaded,
                    "is_active": docker_manager.is_challenge_active(config_id),
                    "disable_dynamic_flags": disable_dynamic_flags,
                })
    
    return {"challenges": challenges}


@app.post("/admin/api/challenges/upload")
async def admin_upload_challenge(
    file: UploadFile = File(...),
    _: bool = Depends(verify_admin_key)
):
    """Upload and extract a zipped challenge."""
    if not file.filename or not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only .zip files are allowed")
    
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenges_path.mkdir(parents=True, exist_ok=True)
    
    # Read and validate zip file size
    content = await file.read()
    if len(content) > MAX_ZIP_SIZE:
        raise HTTPException(
            status_code=400, 
            detail=f"Zip file too large. Maximum size is {MAX_ZIP_SIZE // (1024*1024)}MB"
        )
    
    # Create temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    
    try:
        # Validate zip file before extraction
        with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
            # Check number of entries (zip bomb protection)
            if len(zip_ref.namelist()) > MAX_ZIP_ENTRIES:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Zip contains too many files. Maximum {MAX_ZIP_ENTRIES} entries allowed"
                )
            
            # Check total uncompressed size (zip bomb protection)
            total_size = sum(info.file_size for info in zip_ref.infolist())
            if total_size > MAX_EXTRACTED_SIZE:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Extracted size too large. Maximum {MAX_EXTRACTED_SIZE // (1024*1024)}MB"
                )
            
            # Check for zip slip vulnerability (path traversal in filenames)
            for info in zip_ref.infolist():
                # Normalize and check for path traversal
                member_path = Path(info.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise HTTPException(
                        status_code=400, 
                        detail=f"Invalid path in zip: {info.filename} (potential zip slip attack)"
                    )
        
        # Extract to temp directory first
        with tempfile.TemporaryDirectory() as tmp_dir:
            with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                zip_ref.extractall(tmp_dir)
            
            # Find the root directory (handle nested zips)
            extracted_items = list(Path(tmp_dir).iterdir())
            if len(extracted_items) == 1 and extracted_items[0].is_dir():
                source_dir = extracted_items[0]
                challenge_name = source_dir.name
            else:
                # Use zip filename as challenge name
                challenge_name = file.filename.rsplit('.', 1)[0]
                source_dir = Path(tmp_dir)
            
            # Sanitize challenge name
            challenge_name = "".join(c for c in challenge_name if c.isalnum() or c in '-_').lower()
            if not challenge_name:
                challenge_name = "uploaded-challenge"
            
            target_dir = challenges_path / challenge_name
            
            # Check if exists
            if target_dir.exists():
                # Add suffix
                counter = 1
                while (challenges_path / f"{challenge_name}-{counter}").exists():
                    counter += 1
                challenge_name = f"{challenge_name}-{counter}"
                target_dir = challenges_path / challenge_name
            
            # Copy to challenges directory
            shutil.copytree(source_dir, target_dir)
        
        # Reload challenges
        docker_manager.load_challenges()

        # Prune flag mappings for uploaded challenges that disable dynamic flags
        disabled_ids = docker_manager.get_disabled_flag_challenge_ids()
        if disabled_ids:
            flag_mgr = await get_flag_manager()
            await flag_mgr.prune_mappings_for_disabled_challenges(disabled_ids)

        logger = get_event_logger()
        await logger.log(
            EventType.SYSTEM_START,
            f"Challenge uploaded: {challenge_name}",
            details={"challenge_id": challenge_name, "filename": file.filename}
        )

        await _broadcast_challenges_updated()

        return {
            "success": True,
            "message": f"Challenge '{challenge_name}' uploaded successfully",
            "challenge_id": challenge_name
        }

    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to extract: {str(e)}")
    finally:
        os.unlink(tmp_path)


@app.delete("/admin/api/challenges/{challenge_id}")
async def admin_delete_challenge(
    challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Delete a challenge directory."""
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenge_dir = challenges_path / challenge_id
    
    if not is_safe_path(challenges_path, challenge_dir):
        raise HTTPException(status_code=400, detail="Invalid challenge ID")
    
    if not challenge_dir.exists():
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    try:
        shutil.rmtree(challenge_dir)
        docker_manager.load_challenges()  # Reload

        # Clean up flag mapping for the deleted challenge
        flag_mgr = await get_flag_manager()
        await flag_mgr.remove_challenge_mapping(challenge_id)
        # Also prune any mappings for challenges that now disable dynamic flags
        disabled_ids = docker_manager.get_disabled_flag_challenge_ids()
        if disabled_ids:
            await flag_mgr.prune_mappings_for_disabled_challenges(disabled_ids)

        logger = get_event_logger()
        await logger.log(
            EventType.SYSTEM_STOP,
            f"Challenge deleted: {challenge_id}",
            details={"challenge_id": challenge_id}
        )

        await _broadcast_challenges_updated()
        return {"success": True, "message": f"Challenge '{challenge_id}' deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {str(e)}")


@app.get("/admin/api/challenges/{challenge_id}/files")
async def admin_get_challenge_files(
    challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Get file tree for a challenge."""
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenge_dir = challenges_path / challenge_id
    
    if not is_safe_path(challenges_path, challenge_dir):
        raise HTTPException(status_code=400, detail="Invalid challenge ID")
    
    if not challenge_dir.exists():
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    return {
        "challenge_id": challenge_id,
        "files": get_file_tree(challenge_dir, challenge_dir)
    }


@app.get("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
async def admin_read_file(
    challenge_id: str,
    file_path: str,
    _: bool = Depends(verify_admin_key)
):
    """Read a file from a challenge."""
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenge_dir = challenges_path / challenge_id
    target_file = challenge_dir / file_path
    
    if not is_safe_path(challenge_dir, target_file):
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    if not target_file.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    if target_file.is_dir():
        raise HTTPException(status_code=400, detail="Cannot read directory")
    
    # Check if binary
    if target_file.suffix.lower() in BINARY_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Cannot edit binary files")
    
    try:
        content = target_file.read_text(encoding='utf-8')
        return {
            "path": file_path,
            "content": content,
            "size": target_file.stat().st_size
        }
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not text/UTF-8")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read: {str(e)}")


@app.put("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
async def admin_write_file(
    challenge_id: str,
    file_path: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Write/update a file in a challenge."""
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenge_dir = challenges_path / challenge_id
    target_file = challenge_dir / file_path
    
    if not is_safe_path(challenge_dir, target_file):
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    body = await request.json()
    content = body.get("content", "")
    
    try:
        # Create parent directories if needed
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(content, encoding='utf-8')
        
        # Reload if it's a config file
        if target_file.name == 'instance.toml':
            docker_manager.load_challenges()
        
        return {
            "success": True,
            "message": f"File saved: {file_path}",
            "size": target_file.stat().st_size
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write: {str(e)}")


@app.post("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
async def admin_create_file(
    challenge_id: str,
    file_path: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Create a new file in a challenge."""
    return await admin_write_file(challenge_id, file_path, request, _)


@app.delete("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
async def admin_delete_file(
    challenge_id: str,
    file_path: str,
    _: bool = Depends(verify_admin_key)
):
    """Delete a file from a challenge."""
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenge_dir = challenges_path / challenge_id
    target_file = challenge_dir / file_path
    
    if not is_safe_path(challenge_dir, target_file):
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    if not target_file.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        if target_file.is_dir():
            shutil.rmtree(target_file)
        else:
            target_file.unlink()
        
        return {"success": True, "message": f"Deleted: {file_path}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {str(e)}")


@app.post("/admin/api/challenges/{challenge_id}/reload")
async def admin_reload_challenge(
    challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Reload challenge configuration (and clean up flag mappings for challenges that disable dynamic flags)."""
    docker_manager.load_challenges()
    await docker_manager.load_challenge_settings()

    # Prune flag mappings for challenges that now have dynamic flags disabled
    disabled_ids = docker_manager.get_disabled_flag_challenge_ids()
    if disabled_ids:
        flag_mgr = await get_flag_manager()
        removed = await flag_mgr.prune_mappings_for_disabled_challenges(disabled_ids)
        if removed > 0:
            print(f"Pruned {removed} flag mapping(s) for challenges with disabled dynamic flags")

    challenge = docker_manager.get_challenge(challenge_id)
    if challenge:
        await _broadcast_challenges_updated()
        return {
            "success": True,
            "message": f"Challenge '{challenge_id}' reloaded",
            "challenge": challenge.to_info().model_dump()
        }
    else:
        return {
            "success": False,
            "message": f"Challenge '{challenge_id}' failed to load (check instance.toml)"
        }


# =============================================================================
# Challenge Active/Inactive Toggle API
# =============================================================================

@app.post("/admin/api/challenges/{challenge_id}/toggle")
async def admin_toggle_challenge(
    challenge_id: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Toggle a challenge active/inactive status."""
    from .database.connection import get_async_session
    from .database.models import ChallengeSettings
    from sqlalchemy import select
    
    body = await request.json()
    is_active = body.get("is_active", True)
    
    async with get_async_session() as session:
        result = await session.execute(
            select(ChallengeSettings).where(ChallengeSettings.challenge_id == challenge_id)
        )
        cs = result.scalars().first()
        
        if cs:
            cs.is_active = 1 if is_active else 0
        else:
            cs = ChallengeSettings(
                challenge_id=challenge_id,
                is_active=1 if is_active else 0
            )
            session.add(cs)
        
        await session.commit()
    
    # Reload settings cache
    await docker_manager.load_challenge_settings()
    
    status = "active" if is_active else "inactive"
    logger = get_event_logger()
    await logger.log(
        EventType.SYSTEM_START,
        f"Challenge '{challenge_id}' set to {status}",
        details={"challenge_id": challenge_id, "is_active": is_active}
    )
    
    await _broadcast_challenges_updated(public=True)
    return {
        "success": True,
        "message": f"Challenge '{challenge_id}' is now {status}",
        "is_active": is_active
    }


@app.get("/admin/api/challenges/settings")
async def admin_get_challenge_settings(_: bool = Depends(verify_admin_key)):
    """Get all challenge settings (active/inactive, resource overrides)."""
    from .database.connection import get_async_session
    from .database.models import ChallengeSettings
    from sqlalchemy import select
    
    async with get_async_session() as session:
        result = await session.execute(select(ChallengeSettings))
        settings_list = result.scalars().all()
    
    settings_map = {}
    for cs in settings_list:
        settings_map[cs.challenge_id] = {
            "is_active": bool(cs.is_active),
            "max_memory": cs.max_memory,
            "max_cpu": cs.max_cpu,
        }
    
    return {"settings": settings_map}


@app.put("/admin/api/challenges/{challenge_id}/resources")
async def admin_set_challenge_resources(
    challenge_id: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Set per-challenge resource limits (overrides global defaults)."""
    from .database.connection import get_async_session
    from .database.models import ChallengeSettings
    from sqlalchemy import select
    
    body = await request.json()
    max_memory = body.get("max_memory")  # e.g., "256m", null to use global
    max_cpu = body.get("max_cpu")  # e.g., "0.5", null to use global
    
    async with get_async_session() as session:
        result = await session.execute(
            select(ChallengeSettings).where(ChallengeSettings.challenge_id == challenge_id)
        )
        cs = result.scalars().first()
        
        if cs:
            cs.max_memory = max_memory
            cs.max_cpu = max_cpu
        else:
            cs = ChallengeSettings(
                challenge_id=challenge_id,
                max_memory=max_memory,
                max_cpu=max_cpu
            )
            session.add(cs)
        
        await session.commit()
    
    await docker_manager.load_challenge_settings()
    
    return {
        "success": True,
        "message": f"Resource limits updated for '{challenge_id}'",
        "max_memory": max_memory,
        "max_cpu": max_cpu
    }


# =============================================================================
# Whaley Settings API (Global Settings via UI)
# =============================================================================

# Editable settings and their types/validation
EDITABLE_SETTINGS = {
    "INSTANCE_TIMEOUT": {"type": "int", "min": 60, "max": 86400, "label": "Instance Timeout (seconds)"},
    "MAX_INSTANCES_PER_USER": {"type": "int", "min": 1, "max": 50, "label": "Max Instances Per User"},
    "MAX_INSTANCES_PER_TEAM": {"type": "int", "min": 1, "max": 100, "label": "Max Instances Per Team"},
    "CONTAINER_MAX_MEMORY": {"type": "str", "label": "Container Max Memory (e.g., 256m, 1g)"},
    "CONTAINER_MAX_CPU": {"type": "float", "min": 0.1, "max": 16.0, "label": "Container Max CPU Cores"},
    "CONTAINER_PIDS_LIMIT": {"type": "int", "min": 16, "max": 4096, "label": "Container PID Limit"},
    "PORT_RANGE_START": {"type": "int", "min": 1024, "max": 65535, "label": "Port Range Start"},
    "PORT_RANGE_END": {"type": "int", "min": 1024, "max": 65535, "label": "Port Range End"},
    "DYNAMIC_FLAGS_ENABLED": {"type": "bool", "label": "Dynamic Flags Enabled"},
    "FLAG_PREFIX": {"type": "str", "label": "Flag Prefix"},
    "NETWORK_ISOLATION_ENABLED": {"type": "bool", "label": "Network Isolation"},
    "NETWORK_ICC_DISABLED": {"type": "bool", "label": "Disable Inter-Container Comm."},
    "FORENSICS_AUTO_CAPTURE": {"type": "bool", "label": "Forensics Auto Capture"},
    "FORENSICS_RETENTION_HOURS": {"type": "int", "min": 1, "max": 8760, "label": "Forensics Retention (hours)"},
    "PUBLIC_HOST": {"type": "str", "label": "Public Host (auto or IP/domain)"},

    # Traefik Redis routing settings
    "TRAEFIK_REDIS_ENABLED": {"type": "bool", "label": "Traefik Redis Provider Enabled"},
    "TRAEFIK_REDIS_URL": {"type": "str", "label": "Traefik Redis URL"},
    "TRAEFIK_BASE_DOMAIN": {"type": "str", "label": "Instance Base Domain"},
    "TRAEFIK_BACKEND_HOST": {"type": "str", "label": "Backend Host Reachable by Traefik"},
    "TRAEFIK_HTTP_ENTRYPOINT": {"type": "str", "label": "HTTP Entrypoint Name"},
    "TRAEFIK_TCP_ENTRYPOINT": {"type": "str", "label": "TCP Entrypoint Name"},
    "TRAEFIK_TCP_EXTERNAL_PORT": {"type": "int", "min": 1, "max": 65535, "label": "TCP Public Port"},
    "TRAEFIK_HTTP_TLS_OPTIONS": {"type": "str", "label": "HTTP TLS Options Name"},
    "TRAEFIK_TCP_TLS_OPTIONS": {"type": "str", "label": "TCP TLS Options Name"},
    "TRAEFIK_BLOCK_ALL_ADDRESS": {"type": "str", "label": "TCP Catch-all Block Address"},
    "TRAEFIK_DASHBOARD_USERS": {"type": "str", "label": "Dashboard BasicAuth Users (comma separated)"},
    "TRAEFIK_PERMANENT_KEYS_FILE": {"type": "str", "label": "Permanent Traefik Keys YAML Path"},
    "TRAEFIK_PERMANENT_KEYS_JSON": {"type": "str", "label": "Permanent Traefik Keys JSON"},
    
    # Auth and CTFd settings
    "AUTH_MODE": {"type": "select", "options": ["ctfd", "none"], "label": "Authentication Mode"},
    "CTFD_URL": {"type": "str", "label": "CTFd URL (e.g., https://ctf.example.com)"},
    "CTFD_API_KEY": {"type": "str", "label": "CTFd Admin/Access Token"},
    "DISCORD_WEBHOOK_URL": {"type": "str", "label": "Discord Webhook URL"},
}


@app.get("/admin/api/settings")
async def admin_get_settings(_: bool = Depends(verify_admin_key)):
    """Get all editable Whaley settings with current values."""
    from .database.connection import get_async_session
    from .database.models import WhaleySettings as WhaleySettingsModel
    from sqlalchemy import select
    
    # Get DB overrides
    db_overrides = {}
    try:
        async with get_async_session() as session:
            result = await session.execute(select(WhaleySettingsModel))
            for row in result.scalars().all():
                db_overrides[row.key] = row.value
    except Exception as e:
        print(f"Warning: Failed to load settings from DB: {e}")
    
    result = {}
    for key, meta in EDITABLE_SETTINGS.items():
        # Current effective value (DB override or env/default)
        current_value = getattr(settings, key, None)
        db_value = db_overrides.get(key)
        
        result[key] = {
            "value": current_value,
            "db_override": db_value,
            "has_override": db_value is not None,
            **meta
        }
    
    return {"settings": result}


@app.put("/admin/api/settings")
async def admin_update_settings(
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Update Whaley settings. Changes are persisted to database and applied immediately."""
    from .database.connection import get_async_session
    from .database.models import WhaleySettings as WhaleySettingsModel
    from sqlalchemy import select
    
    body = await request.json()
    updates = body.get("settings", {})
    
    applied = {}
    errors = {}
    
    for key, value in updates.items():
        if key not in EDITABLE_SETTINGS:
            errors[key] = "Unknown setting"
            continue
        
        meta = EDITABLE_SETTINGS[key]
        
        # Validate and cast value
        try:
            if meta["type"] == "int":
                value = int(value)
                if "min" in meta and value < meta["min"]:
                    errors[key] = f"Minimum value is {meta['min']}"
                    continue
                if "max" in meta and value > meta["max"]:
                    errors[key] = f"Maximum value is {meta['max']}"
                    continue
            elif meta["type"] == "float":
                value = float(value)
                if "min" in meta and value < meta["min"]:
                    errors[key] = f"Minimum value is {meta['min']}"
                    continue
                if "max" in meta and value > meta["max"]:
                    errors[key] = f"Maximum value is {meta['max']}"
                    continue
            elif meta["type"] == "bool":
                value = str(value).lower() in ("true", "1", "yes")
            else:
                value = str(value)
        except (ValueError, TypeError) as e:
            errors[key] = f"Invalid value: {e}"
            continue
        
        # Store in database
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(WhaleySettingsModel).where(WhaleySettingsModel.key == key)
                )
                existing = result.scalars().first()
                
                if existing:
                    existing.value = str(value)
                else:
                    session.add(WhaleySettingsModel(key=key, value=str(value)))
                
                await session.commit()
        except Exception as e:
            errors[key] = f"Database error: {e}"
            continue
        
        # Apply to running settings object
        try:
            setattr(settings, key, value)
            applied[key] = value
        except Exception as e:
            errors[key] = f"Failed to apply: {e}"
    
    # Log the change
    if applied:
        logger = get_event_logger()
        await logger.log(
            EventType.SYSTEM_START,
            f"Settings updated: {', '.join(applied.keys())}",
            details=_build_settings_audit_details(applied)
        )
    
    return {
        "success": len(errors) == 0,
        "applied": {k: str(v) for k, v in applied.items()},
        "errors": errors,
        "message": f"Applied {len(applied)} settings" + (f", {len(errors)} errors" if errors else "")
    }


@app.delete("/admin/api/settings/{key}")
async def admin_reset_setting(
    key: str,
    _: bool = Depends(verify_admin_key)
):
    """Reset a setting to its default (remove DB override)."""
    from .database.connection import get_async_session
    from .database.models import WhaleySettings as WhaleySettingsModel
    from sqlalchemy import select, delete
    
    if key not in EDITABLE_SETTINGS:
        raise HTTPException(status_code=400, detail="Unknown setting")
    
    try:
        async with get_async_session() as session:
            await session.execute(
                delete(WhaleySettingsModel).where(WhaleySettingsModel.key == key)
            )
            await session.commit()
        
        # Reset to default from Settings class
        default_settings = Settings()
        default_value = getattr(default_settings, key, None)
        if default_value is not None:
            setattr(settings, key, default_value)
        
        return {
            "success": True,
            "message": f"Setting '{key}' reset to default: {default_value}",
            "default_value": str(default_value) if default_value is not None else None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset setting: {e}")


@app.post("/admin/api/settings/load")
async def admin_reload_settings(_: bool = Depends(verify_admin_key)):
    """Reload all settings from database (apply DB overrides)."""
    from .database.connection import get_async_session
    from .database.models import WhaleySettings as WhaleySettingsModel
    from sqlalchemy import select
    
    applied = []
    try:
        async with get_async_session() as session:
            result = await session.execute(select(WhaleySettingsModel))
            for row in result.scalars().all():
                if row.key in EDITABLE_SETTINGS:
                    meta = EDITABLE_SETTINGS[row.key]
                    try:
                        if meta["type"] == "int":
                            val = int(row.value)
                        elif meta["type"] == "float":
                            val = float(row.value)
                        elif meta["type"] == "bool":
                            val = row.value.lower() in ("true", "1", "yes")
                        else:
                            val = row.value
                        setattr(settings, row.key, val)
                        applied.append(row.key)
                    except Exception as e:
                        print(f"Warning: Failed to apply setting {row.key}: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload settings: {e}")
    
    # Also reload challenge settings
    await docker_manager.load_challenge_settings()
    
    return {
        "success": True,
        "applied": applied,
        "message": f"Reloaded {len(applied)} settings from database"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
