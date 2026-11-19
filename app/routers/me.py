"""Current player routes: /me and /me/team.

Extracted from main.py.
"""
from typing import Optional

from fastapi import APIRouter, Depends
from fastapi.security import HTTPAuthorizationCredentials

from ..auth import ctfd_auth, get_current_user, is_team_mode, security
from ..config import settings
from ..models import PublicMeResponse, PublicUserInfo, UserInfo
from ..runtime import docker_manager

router = APIRouter(tags=["me"])


@router.get("/me", response_model=PublicMeResponse)
async def get_me(user: UserInfo = Depends(get_current_user)):
    """Get current user information."""
    team_mode = is_team_mode()
    
    if team_mode and user.team_id:
        instance_count = docker_manager.get_owner_instance_count(user.team_id, team_mode=True)
        max_instances = settings.MAX_INSTANCES_PER_TEAM
    else:
        instance_count = docker_manager.get_user_instance_count(user.user_id)
        max_instances = settings.MAX_INSTANCES_PER_USER
    
    return {
        "user": PublicUserInfo(username=user.username),
        "instances": instance_count,
        "max_instances": max_instances,
        "team_mode": team_mode
    }


@router.get("/me/team")
async def get_my_team(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    user: UserInfo = Depends(get_current_user)
):
    """Get current user's team information and members."""
    team_mode = is_team_mode()
    
    if not team_mode:
        return {
            "team_mode": False
        }
    
    if not user.team_id:
        return {
            "team_mode": True,
            "message": "You are not in a team"
        }
    
    team_name = user.team_name
    members = []
    if ctfd_auth and credentials:
        if not team_name:
            team_info = await ctfd_auth.get_team_info(int(user.team_id), credentials.credentials)
            if team_info:
                team_name = team_info.get("name")

        raw_members = await ctfd_auth.get_team_members(int(user.team_id), credentials.credentials)

        current_user_id = str(user.user_id)
        current_username = (user.username or "").strip().lower()

        for member in raw_members:
            if not isinstance(member, dict):
                continue

            member_id = str(member.get("id", "")).strip()
            member_name = str(member.get("name", "")).strip()
            if not member_name:
                continue

            is_current = (
                bool(member_id and member_id == current_user_id)
                or bool(current_username and member_name.lower() == current_username)
            )

            members.append({
                "name": member_name,
                "is_current": is_current,
            })

    current_user_id = str(user.user_id)
    current_username = (user.username or "").strip()

    if members:
        has_current = any(bool(member.get("is_current")) for member in members if isinstance(member, dict))
        if not has_current and current_username:
            current_username_lower = current_username.lower()
            for member in members:
                if not isinstance(member, dict):
                    continue
                member_name = str(member.get("name", "")).strip().lower()
                if member_name and member_name == current_username_lower:
                    member["is_current"] = True
                    has_current = True
                    break

        if not has_current and current_username:
            members.append({
                "name": current_username,
                "is_current": True,
            })
    elif current_username:
        members.append({
            "name": current_username,
            "is_current": True,
        })
    
    return {
        "team_mode": True,
        "team_name": team_name,
        "members": members,
    }
