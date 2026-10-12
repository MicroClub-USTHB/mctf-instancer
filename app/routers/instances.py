"""Per-team instance lifecycle routes: spawn / list / get / stop / extend.

Extracted from main.py. All dependencies come from neutral modules (runtime,
auth, request_utils, metrics_state, sanitizers, presenters, logger,
discord_webhook), so there is no import cycle back to main.py.
"""
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from ..auth import get_current_user, is_team_mode
from ..discord_webhook import get_discord_notifier
from ..logger import get_event_logger
from ..metrics_state import (
    record_runtime_operation as _record_runtime_operation,
)
from ..metrics_state import (
    spawn_finished as _spawn_finished,
)
from ..metrics_state import (
    spawn_started as _spawn_started,
)
from ..models import (
    PublicInstanceListResponse,
    PublicSpawnResponse,
    SpawnRequest,
    UserInfo,
)
from ..presenters import to_public_instance as _to_public_instance
from ..request_utils import USER_RATE_LIMIT, check_user_rate_limit, get_client_ip
from ..runtime import docker_manager
from ..sanitizers import (
    classify_operation_failure_reason as _classify_operation_failure_reason,
)
from ..sanitizers import (
    classify_spawn_failure_reason as _classify_spawn_failure_reason,
)
from ..sanitizers import (
    sanitize_user_error_message as _sanitize_user_error_message,
)

router = APIRouter(tags=["instances"])


@router.post("/instances/spawn", response_model=PublicSpawnResponse)
async def spawn_instance(
    request: SpawnRequest,
    req: Request,
    user: UserInfo = Depends(get_current_user)
):
    """Spawn a new challenge instance."""
    spawn_started_at = time.monotonic()
    _spawn_started()
    operation_recorded = False

    try:
        # Rate limit check
        if not check_user_rate_limit(user.user_id):
            _record_runtime_operation("spawn", "failed", request.challenge_id, "rate_limited")
            operation_recorded = True
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests. Please wait before trying again (limit: {USER_RATE_LIMIT} requests per minute)"
            )

        client_ip = get_client_ip(req)
        team_mode = is_team_mode()

        # Block spawning inactive challenges
        if not docker_manager.is_challenge_active(request.challenge_id):
            _record_runtime_operation("spawn", "failed", request.challenge_id, "challenge_inactive")
            operation_recorded = True
            raise HTTPException(status_code=403, detail="This challenge is currently inactive")

        challenge = docker_manager.get_challenge(request.challenge_id)

        success, raw_message, instance = await docker_manager.spawn_instance(
            challenge_id=request.challenge_id,
            user_id=user.user_id,
            username=user.username,
            user_info=user,
            team_mode=team_mode
        )

        # Log the event
        logger = get_event_logger()
        notifier = get_discord_notifier()
        if success and instance:
            _record_runtime_operation("spawn", "success", request.challenge_id, "none")
            operation_recorded = True

            await logger.log_instance_spawn(
                user_id=user.user_id,
                username=user.username,
                instance_id=instance.instance_id,
                challenge_id=request.challenge_id,
                ports=instance.ports,
                public_url=instance.public_url or "",
                ip_address=client_ip,
                extra={"team_id": user.team_id, "team_name": user.team_name, "team_mode": team_mode} if team_mode else None
            )

            await notifier.notify_instance_spawn(
                instance_id=instance.instance_id,
                challenge_id=request.challenge_id,
                challenge_name=challenge.name if challenge else None,
                created_by=user.username,
                created_by_id=user.user_id,
                created_at=instance.created_at,
                expires_at=instance.expires_at,
                team_id=user.team_id if team_mode else None,
                team_name=user.team_name if team_mode else None,
                public_url=instance.public_url,
                connection_hint=instance.connection_hint,
                routing_type=instance.routing_type,
                ports=instance.ports,
                ip_address=client_ip,
            )
        else:
            failure_reason = _classify_spawn_failure_reason(raw_message)
            _record_runtime_operation("spawn", "failed", request.challenge_id, failure_reason)
            operation_recorded = True

            # Extract docker error if present in message
            docker_error = None
            if "docker-compose failed:" in raw_message:
                docker_error = raw_message.split("docker-compose failed:", 1)[-1].strip()

            await logger.log_instance_spawn_failed(
                user_id=user.user_id,
                username=user.username,
                challenge_id=request.challenge_id,
                reason=raw_message,
                ip_address=client_ip,
                docker_error=docker_error,
            )

            await notifier.notify_instance_spawn_failed(
                challenge_id=request.challenge_id,
                challenge_name=challenge.name if challenge else None,
                username=user.username,
                user_id=user.user_id,
                reason=raw_message,
                team_id=user.team_id if team_mode else None,
                team_name=user.team_name if team_mode else None,
                ip_address=client_ip,
            )

        public_message = raw_message if success else _sanitize_user_error_message(
            raw_message,
            "Failed to deploy instance",
        )

        return PublicSpawnResponse(
            success=success,
            message=public_message,
            instance=_to_public_instance(instance) if instance else None
        )
    except HTTPException:
        raise
    except Exception as exc:
        if not operation_recorded:
            _record_runtime_operation(
                "spawn",
                "failed",
                request.challenge_id,
                _classify_spawn_failure_reason(str(exc)),
            )
        raise
    finally:
        _spawn_finished(time.monotonic() - spawn_started_at)


@router.get("/instances", response_model=PublicInstanceListResponse)
async def list_instances(user: UserInfo = Depends(get_current_user)):
    """List all instances for the current user/team."""
    team_mode = is_team_mode()
    
    if team_mode and user.team_id:
        # In team mode, show all team instances
        instances = docker_manager.get_owner_instances(user.team_id, team_mode=True)
    else:
        # In user mode, show only user's instances
        instances = docker_manager.get_user_instances(user.user_id)
    
    return PublicInstanceListResponse(
        instances=[_to_public_instance(instance) for instance in instances]
    )


@router.get("/instances/{instance_id}")
async def get_instance(
    instance_id: str,
    user: UserInfo = Depends(get_current_user)
):
    """Get details about a specific instance."""
    instance = docker_manager.instances.get(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    
    team_mode = is_team_mode()
    
    # Check access based on mode
    if team_mode and user.team_id:
        if instance.team_id != user.team_id:
            raise HTTPException(status_code=403, detail="Access denied")
    else:
        if instance.user_id != user.user_id:
            raise HTTPException(status_code=403, detail="Access denied")
    
    return _to_public_instance(instance)


@router.delete("/instances/{instance_id}")
async def stop_instance(
    instance_id: str,
    req: Request,
    user: UserInfo = Depends(get_current_user)
):
    """Stop and remove an instance."""
    # Rate limit check
    if not check_user_rate_limit(user.user_id):
        _record_runtime_operation("stop", "failed", "unknown", "rate_limited")
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Please wait before trying again (limit: {USER_RATE_LIMIT} requests per minute)"
        )
    
    client_ip = get_client_ip(req)
    team_mode = is_team_mode()
    
    # Get instance info before stopping for logging
    instance = docker_manager.instances.get(instance_id)
    challenge_id = instance.challenge_id if instance else "unknown"
    challenge = docker_manager.get_challenge(challenge_id) if instance else None
    
    success, message = await docker_manager.stop_instance(
        instance_id=instance_id,
        user_id=user.user_id,
        team_id=user.team_id,
        team_mode=team_mode
    )
    
    if success:
        _record_runtime_operation("stop", "success", challenge_id, "user_stop")
        logger = get_event_logger()
        await logger.log_instance_stop(
            user_id=user.user_id,
            username=user.username,
            instance_id=instance_id,
            challenge_id=challenge_id,
            ip_address=client_ip,
        )

        notifier = get_discord_notifier()
        await notifier.notify_instance_stopped(
            instance_id=instance_id,
            challenge_id=challenge_id,
            challenge_name=challenge.name if challenge else None,
            stopped_by=user.username,
            stopped_by_id=user.user_id,
            reason="user_stop",
            owner_username=instance.username if instance else user.username,
            owner_user_id=instance.user_id if instance else user.user_id,
            team_id=instance.team_id if instance else user.team_id,
            team_name=instance.team_name if instance else user.team_name,
            ip_address=client_ip,
            message=message,
        )
    
    if not success:
        _record_runtime_operation("stop", "failed", challenge_id, _classify_operation_failure_reason(message))
        raise HTTPException(
            status_code=400,
            detail=_sanitize_user_error_message(message, "Failed to stop instance")
        )
    
    return {"success": True, "message": message}


@router.post("/instances/{instance_id}/extend")
async def extend_instance(
    instance_id: str,
    req: Request,
    user: UserInfo = Depends(get_current_user)
):
    """Extend the lifetime of an instance."""
    # Rate limit check
    if not check_user_rate_limit(user.user_id):
        _record_runtime_operation("extend", "failed", "unknown", "rate_limited")
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Please wait before trying again (limit: {USER_RATE_LIMIT} requests per minute)"
        )
    
    client_ip = get_client_ip(req)
    team_mode = is_team_mode()
    instance_before = docker_manager.instances.get(instance_id)
    
    success, message, applied_extension_seconds = await docker_manager.extend_instance(
        instance_id=instance_id,
        user_id=user.user_id,
        team_id=user.team_id,
        team_mode=team_mode
    )
    
    if success:
        current_instance = docker_manager.instances.get(instance_id) or instance_before
        challenge_id = current_instance.challenge_id if current_instance else "unknown"
        _record_runtime_operation("extend", "success", challenge_id, "none")

        logger = get_event_logger()
        await logger.log_instance_extend(
            user_id=user.user_id,
            username=user.username,
            instance_id=instance_id,
            extension_seconds=applied_extension_seconds,
            ip_address=client_ip,
        )

        challenge = docker_manager.get_challenge(challenge_id) if challenge_id != "unknown" else None

        notifier = get_discord_notifier()
        await notifier.notify_instance_extended(
            instance_id=instance_id,
            challenge_id=challenge_id,
            challenge_name=challenge.name if challenge else None,
            extended_by=user.username,
            extended_by_id=user.user_id,
            extension_seconds=applied_extension_seconds,
            expires_at=current_instance.expires_at if current_instance else None,
            team_id=current_instance.team_id if current_instance else user.team_id,
            team_name=current_instance.team_name if current_instance else user.team_name,
            ip_address=client_ip,
        )
    
    if not success:
        challenge_id = instance_before.challenge_id if instance_before else "unknown"
        _record_runtime_operation("extend", "failed", challenge_id, _classify_operation_failure_reason(message))
        raise HTTPException(
            status_code=400,
            detail=_sanitize_user_error_message(message, "Failed to extend instance")
        )
    
    return {
        "success": True,
        "message": message,
        "extended_seconds": applied_extension_seconds,
    }


