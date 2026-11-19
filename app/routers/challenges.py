"""Public challenge listing: /challenges and /challenges/{challenge_id}.

Extracted from main.py.
"""
from fastapi import APIRouter, Depends, HTTPException

from ..auth import get_current_user
from ..models import PublicChallengeListResponse, UserInfo
from ..presenters import to_public_challenge as _to_public_challenge
from ..runtime import docker_manager

router = APIRouter(tags=["challenges"])


@router.get("/challenges", response_model=PublicChallengeListResponse)
async def list_challenges(user: UserInfo = Depends(get_current_user)):
    """List active challenges that can be spawned."""
    challenges = [
        _to_public_challenge(challenge)
        for challenge in docker_manager.get_active_challenges()
    ]
    return PublicChallengeListResponse(challenges=challenges)


@router.get("/challenges/{challenge_id}")
async def get_challenge(
    challenge_id: str,
    user: UserInfo = Depends(get_current_user)
):
    """Get details about a specific challenge."""
    challenge = docker_manager.get_challenge(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    return _to_public_challenge(challenge.to_info())
