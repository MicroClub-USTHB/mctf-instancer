"""Data models for the instancer."""
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum


def utcnow() -> datetime:
    """Get current UTC time with timezone info."""
    return datetime.now(timezone.utc)


class AuthMode(str, Enum):
    CTFD = "ctfd"
    NONE = "none"


class ChallengeType(str, Enum):
    WEB = "web"
    PWN = "pwn"
    REV = "rev"
    CRYPTO = "crypto"
    MISC = "misc"
    FORENSICS = "forensics"


class ChallengeInfo(BaseModel):
    """Information about an available challenge."""
    id: str
    name: str
    category: ChallengeType
    routing_type: str = "http"
    entrypoint: Optional[str] = None
    tls_enabled: Optional[bool] = None
    description: Optional[str] = None
    ports: List[int] = Field(default_factory=list)  # Internal ports exposed


class InstanceStatus(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class Instance(BaseModel):
    """A running challenge instance."""
    instance_id: str
    challenge_id: str
    user_id: str
    username: Optional[str] = None  # Username for display
    team_id: Optional[str] = None  # Team ID (for team mode)
    team_name: Optional[str] = None  # Team name (for team mode)
    owner_id: Optional[str] = None  # Effective owner: team_id in team mode, user_id otherwise
    routing_type: Optional[str] = None
    connection_hint: Optional[str] = None
    status: InstanceStatus = InstanceStatus.STARTING
    ports: Dict[int, int] = Field(default_factory=dict)  # internal:external port mapping
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    container_ids: List[str] = Field(default_factory=list)
    public_url: Optional[str] = None  # Primary URL (first port)
    public_urls: Dict[int, str] = Field(default_factory=dict)  # internal_port: url mapping
    network_name: Optional[str] = None  # Isolated network name for this instance
    error_message: Optional[str] = None  # Error details for failed spawns


class PublicChallengeInfo(BaseModel):
    """Sanitized challenge information exposed to normal users."""
    id: str
    name: str
    category: ChallengeType
    routing_type: str = "http"
    tls_enabled: Optional[bool] = None
    description: Optional[str] = None


class PublicInstance(BaseModel):
    """Sanitized running instance view for normal users."""
    instance_id: str
    challenge_id: str
    username: Optional[str] = None
    team_name: Optional[str] = None
    routing_type: Optional[str] = None
    connection_hint: Optional[str] = None
    status: InstanceStatus = InstanceStatus.STARTING
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    public_url: Optional[str] = None
    public_urls: List[str] = Field(default_factory=list)


class SpawnRequest(BaseModel):
    """Request to spawn a new instance."""
    challenge_id: str


class SpawnResponse(BaseModel):
    """Response after spawning an instance."""
    success: bool
    message: str
    instance: Optional[Instance] = None


class PublicSpawnResponse(BaseModel):
    """Sanitized spawn response for normal users."""
    success: bool
    message: str
    instance: Optional[PublicInstance] = None


class InstanceListResponse(BaseModel):
    """Response for listing instances."""
    instances: List[Instance]


class PublicInstanceListResponse(BaseModel):
    """Sanitized response for listing instances."""
    instances: List[PublicInstance]


class ChallengeListResponse(BaseModel):
    """Response for listing available challenges."""
    challenges: List[ChallengeInfo]


class PublicChallengeListResponse(BaseModel):
    """Sanitized response for listing challenges."""
    challenges: List[PublicChallengeInfo]


class AuthRequest(BaseModel):
    """Authentication request for CTFd mode."""
    token: str


class UserInfo(BaseModel):
    """User information from authentication."""
    user_id: str
    username: str
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    
    def get_owner_id(self, team_mode: bool) -> str:
        """Get the owner ID for instances/flags (team_id in team mode, user_id otherwise)."""
        if team_mode and self.team_id:
            return self.team_id
        return self.user_id
    
    def get_owner_name(self, team_mode: bool) -> str:
        """Get the owner name for display (team_name in team mode, username otherwise)."""
        if team_mode and self.team_name:
            return self.team_name
        return self.username


class PublicUserInfo(BaseModel):
    """Sanitized user identity for normal users."""
    username: str


class PublicMeResponse(BaseModel):
    """Sanitized /me response for normal users."""
    user: PublicUserInfo
    instances: int
    max_instances: int
    team_mode: bool
