"""Authentication handlers for CTFd and no-auth modes."""
import httpx
from typing import Optional, Tuple
from fastapi import HTTPException, Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .config import settings
from .models import UserInfo, AuthMode


security = HTTPBearer(auto_error=False)


class CTFdAuth:
    """CTFd authentication handler."""
    
    def __init__(self):
        self._ctfd_mode_cache: Optional[str] = None  # Cache for CTFd mode (users/teams)

    @property
    def ctfd_url(self) -> str:
        return (settings.CTFD_URL or "").rstrip('/')

    @property
    def api_key(self) -> str:
        return settings.CTFD_API_KEY or ""
    
    async def get_ctfd_mode(self) -> str:
        """
        Check if CTFd is in 'users' or 'teams' mode.
        Returns 'users' or 'teams'. Caches the result.
        """
        if self._ctfd_mode_cache:
            return self._ctfd_mode_cache

        if not self.ctfd_url or not self.api_key:
            return "users"
        
        try:
            async with httpx.AsyncClient() as client:
                # Try getting user_mode config from CTFd
                response = await client.get(
                    f"{self.ctfd_url}/api/v1/configs/user_mode",
                    headers={
                        "Authorization": f"Token {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        mode = data.get("data", {}).get("value", "users")
                        self._ctfd_mode_cache = mode
                        print(f"CTFd mode detected: {mode}")
                        return mode
                
                # Fallback: check if teams endpoint works
                teams_response = await client.get(
                    f"{self.ctfd_url}/api/v1/teams",
                    headers={
                        "Authorization": f"Token {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    params={"per_page": 1},
                    timeout=10.0
                )
                
                if teams_response.status_code == 200:
                    teams_data = teams_response.json()
                    if teams_data.get("success") and teams_data.get("data"):
                        self._ctfd_mode_cache = "teams"
                        print("CTFd mode detected from teams endpoint: teams")
                        return "teams"
                
        except Exception as e:
            print(f"Error detecting CTFd mode: {e}")
        
        # Default to users mode
        self._ctfd_mode_cache = "users"
        return "users"
    
    async def get_team_info(self, team_id: int, token: str) -> Optional[dict]:
        """Fetch team info from CTFd API."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.ctfd_url}/api/v1/teams/{team_id}",
                    headers={
                        "Authorization": f"Token {token}",
                        "Content-Type": "application/json"
                    },
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        return data.get("data", {})
        except Exception as e:
            print(f"Error fetching team info: {e}")
        
        return None

    @staticmethod
    def _extract_member_rows(payload) -> list:
        """Extract a member list from different CTFd payload shapes."""
        if isinstance(payload, list):
            return payload

        if not isinstance(payload, dict):
            return []

        for key in ("members", "users", "items", "results", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = CTFdAuth._extract_member_rows(value)
                if nested:
                    return nested

        return []

    @staticmethod
    def _normalize_team_members(raw_members) -> list:
        """Normalize CTFd member payloads to [{'id': ..., 'name': ...}]."""
        rows = CTFdAuth._extract_member_rows(raw_members)
        if not rows:
            return []

        normalized = []
        seen = set()

        for raw in rows:
            member_id = None
            member_name = None

            if isinstance(raw, dict):
                nested_user = {}
                for key in ("user", "member", "account"):
                    nested_value = raw.get(key)
                    if isinstance(nested_value, dict):
                        nested_user = nested_value
                        break

                candidate = nested_user or raw

                member_id = (
                    candidate.get("id")
                    or candidate.get("user_id")
                    or raw.get("id")
                    or raw.get("user_id")
                )
                member_name = (
                    candidate.get("name")
                    or candidate.get("username")
                    or candidate.get("display_name")
                    or raw.get("name")
                    or raw.get("username")
                    or raw.get("display_name")
                )
            elif isinstance(raw, str):
                member_name = raw
                member_id = raw
            elif isinstance(raw, (int, float)):
                member_id = str(int(raw))
                member_name = str(member_id)
            else:
                continue

            if member_name is None and member_id is not None:
                member_name = str(member_id)

            if member_name is None:
                continue

            member_id_str = str(member_id) if member_id is not None else str(member_name)
            member_name_str = str(member_name)

            dedupe_key = (member_id_str, member_name_str)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            normalized.append({
                "id": member_id_str,
                "name": member_name_str,
            })

        return normalized

    async def _fetch_member_payload(self, client: httpx.AsyncClient, path: str, headers: dict, params: Optional[dict] = None):
        """Fetch and decode CTFd API payload, returning data body when successful."""
        response = await client.get(
            f"{self.ctfd_url}{path}",
            headers=headers,
            params=params,
            timeout=10.0,
        )
        if response.status_code != 200:
            return None

        payload = response.json()
        if not isinstance(payload, dict):
            return None

        if not payload.get("success"):
            return None

        return payload.get("data")

    async def _resolve_member_names(self, client: httpx.AsyncClient, members: list, header_sets: list) -> list:
        """Resolve numeric member identifiers to usernames via CTFd user endpoints."""
        resolved = []
        seen = set()

        for member in members:
            if not isinstance(member, dict):
                continue

            member_id = str(member.get("id", "")).strip()
            member_name = str(member.get("name", "")).strip()
            looked_up = False

            needs_lookup = bool(member_id) and (not member_name or member_name == member_id)
            if needs_lookup:
                for headers in header_sets:
                    payload = await self._fetch_member_payload(
                        client,
                        f"/api/v1/users/{member_id}",
                        headers,
                    )
                    if not isinstance(payload, dict):
                        continue

                    fetched_name = payload.get("name") or payload.get("username")
                    if fetched_name:
                        member_name = str(fetched_name).strip()
                        looked_up = True
                        break

            if not member_name:
                continue

            # Never expose unresolved numeric IDs as names.
            if member_id and member_name == member_id and not looked_up:
                continue

            dedupe_key = member_name.lower()
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            resolved.append({
                "id": member_id,
                "name": member_name,
            })

        return resolved
    
    async def get_team_members(self, team_id: int, token: str) -> list:
        """Fetch team members from CTFd API."""
        try:
            async with httpx.AsyncClient() as client:
                user_headers = {
                    "Authorization": f"Token {token}",
                    "Content-Type": "application/json"
                }

                header_sets = [user_headers]
                if self.api_key and self.api_key != token:
                    header_sets.append({
                        "Authorization": f"Token {self.api_key}",
                        "Content-Type": "application/json"
                    })

                for headers in header_sets:
                    # Preferred endpoint for newer CTFd builds.
                    payload = await self._fetch_member_payload(
                        client,
                        f"/api/v1/teams/{team_id}/members",
                        headers,
                    )
                    members = await self._resolve_member_names(
                        client,
                        self._normalize_team_members(payload),
                        header_sets,
                    )
                    if members:
                        return members

                    # Common fallback where members may be embedded under team details.
                    payload = await self._fetch_member_payload(
                        client,
                        f"/api/v1/teams/{team_id}",
                        headers,
                    )
                    members = await self._resolve_member_names(
                        client,
                        self._normalize_team_members(payload),
                        header_sets,
                    )
                    if members:
                        return members

                    # Some CTFd builds expose current team through /teams/me.
                    payload = await self._fetch_member_payload(
                        client,
                        "/api/v1/teams/me",
                        headers,
                    )
                    members = await self._resolve_member_names(
                        client,
                        self._normalize_team_members(payload),
                        header_sets,
                    )
                    if members:
                        return members

                # Final fallback using users list (works when API key has broader permissions).
                if self.api_key:
                    admin_headers = {
                        "Authorization": f"Token {self.api_key}",
                        "Content-Type": "application/json"
                    }

                    payload = await self._fetch_member_payload(
                        client,
                        "/api/v1/users",
                        admin_headers,
                        params={"per_page": 200},
                    )

                    filtered = []
                    for item in payload if isinstance(payload, list) else []:
                        if not isinstance(item, dict):
                            continue

                        item_team_id = item.get("team_id")
                        if item_team_id is None or str(item_team_id) != str(team_id):
                            continue

                        member_id = item.get("id")
                        member_name = item.get("name") or item.get("username")
                        if member_name is None:
                            member_name = str(member_id) if member_id is not None else None

                        if member_name is None:
                            continue

                        filtered.append({
                            "id": str(member_id) if member_id is not None else str(member_name),
                            "name": str(member_name),
                        })

                    if filtered:
                        members = await self._resolve_member_names(
                            client,
                            self._normalize_team_members(filtered),
                            header_sets,
                        )
                        if members:
                            return members
        except Exception as e:
            print(f"Error fetching team members: {e}")
        
        return []
    
    async def validate_token(self, token: str) -> Optional[UserInfo]:
        """Validate a CTFd access token and get user info."""
        try:
            async with httpx.AsyncClient() as client:
                # CTFd uses "Token <access_token>" format, not "Bearer"
                headers = {
                    "Authorization": f"Token {token}",
                    "Content-Type": "application/json"
                }
                
                # Get current user info
                response = await client.get(
                    f"{self.ctfd_url}/api/v1/users/me",
                    headers=headers,
                    timeout=10.0
                )

                if response.status_code != 200:
                    print(f"CTFd auth failed: status={response.status_code}, body={response.text}")
                    return None
                
                data = response.json()
                if not data.get("success"):
                    print(f"CTFd auth failed: response={data}")
                    return None
                
                user_data = data.get("data", {})
                team_id = user_data.get("team_id")
                team_name = None
                
                # Fetch team name if user has team_id
                if team_id:
                    team_info = await self.get_team_info(team_id, token)
                    if team_info:
                        team_name = team_info.get("name")
                
                return UserInfo(
                    user_id=str(user_data.get("id")),
                    username=user_data.get("name", "unknown"),
                    team_id=str(team_id) if team_id else None,
                    team_name=team_name
                )
                
        except Exception as e:
            print(f"CTFd auth error: {e}")
            return None

    async def resolve_user_by_name(self, username: str) -> Optional[UserInfo]:
        """Look up a CTFd user by name using the admin API key.

        Used by the admin test-spawn flow to create an instance on behalf of a
        specific user without requiring that user's token.
        """
        if not self.ctfd_url or not self.api_key:
            print("resolve_user_by_name: CTFd URL or API key not configured")
            return None

        try:
            async with httpx.AsyncClient() as client:
                headers = {
                    "Authorization": f"Token {self.api_key}",
                    "Content-Type": "application/json",
                }

                response = await client.get(
                    f"{self.ctfd_url}/api/v1/users",
                    headers=headers,
                    params={"field": "name", "q": username},
                    timeout=10.0,
                )

                if response.status_code != 200:
                    print(f"resolve_user_by_name: CTFd returned {response.status_code}")
                    return None

                data = response.json()
                if not data.get("success"):
                    return None

                users = data.get("data", [])
                if not isinstance(users, list) or len(users) == 0:
                    return None

                # Pick the exact name match; fall back to first result
                target = None
                for user in users:
                    if not isinstance(user, dict):
                        continue
                    name = user.get("name", "")
                    if name.lower() == username.lower():
                        target = user
                        break
                if target is None:
                    target = users[0]

                user_id = target.get("id")
                if user_id is None:
                    return None

                team_id = target.get("team_id")
                team_name = None
                if team_id:
                    team_info = await self.get_team_info(team_id, self.api_key)
                    if team_info:
                        team_name = team_info.get("name")

                return UserInfo(
                    user_id=str(user_id),
                    username=target.get("name", username),
                    team_id=str(team_id) if team_id else None,
                    team_name=team_name,
                )

        except Exception as e:
            print(f"resolve_user_by_name error: {e}")
            return None

    async def resolve_user_by_id(self, user_id: int) -> Optional[UserInfo]:
        """Look up a CTFd user by numeric ID using the admin API key."""
        if not self.ctfd_url or not self.api_key:
            return None

        try:
            async with httpx.AsyncClient() as client:
                headers = {
                    "Authorization": f"Token {self.api_key}",
                    "Content-Type": "application/json",
                }

                response = await client.get(
                    f"{self.ctfd_url}/api/v1/users/{user_id}",
                    headers=headers,
                    timeout=10.0,
                )

                if response.status_code != 200:
                    print(f"resolve_user_by_id: CTFd returned {response.status_code}")
                    return None

                data = response.json()
                if not data.get("success"):
                    return None

                user = data.get("data", {})
                if not isinstance(user, dict) or not user.get("id"):
                    return None

                team_id = user.get("team_id")
                team_name = None
                if team_id:
                    team_info = await self.get_team_info(team_id, self.api_key)
                    if team_info:
                        team_name = team_info.get("name")

                return UserInfo(
                    user_id=str(user["id"]),
                    username=user.get("name", str(user_id)),
                    team_id=str(team_id) if team_id else None,
                    team_name=team_name,
                )

        except Exception as e:
            print(f"resolve_user_by_id error: {e}")
            return None


class NoAuth:
    """No authentication handler - uses session/IP based identification."""
    
    async def get_user(self, identifier: str) -> UserInfo:
        """Generate a user based on identifier (IP or session)."""
        return UserInfo(
            user_id=identifier,
            username=f"user_{identifier[:8]}"
        )


# Global auth instances
ctfd_auth: CTFdAuth = CTFdAuth()
no_auth = NoAuth()

# Team mode state
_team_mode_enabled: Optional[bool] = None


def init_auth():
    """Initialize authentication based on settings."""
    # CTFdAuth is now always initialized and reads from settings dynamically
    pass


async def init_team_mode() -> bool:
    """
    Initialize team mode based on settings and CTFd configuration.
    Call this at application startup.
    Returns True if team mode is enabled.
    """
    global _team_mode_enabled
    
    if settings.TEAM_MODE == "enabled":
        _team_mode_enabled = True
        return True
    elif settings.TEAM_MODE == "disabled":
        _team_mode_enabled = False
        return False
    else:  # "auto" - detect from CTFd
        if settings.AUTH_MODE == AuthMode.CTFD and ctfd_auth:
            ctfd_mode = await ctfd_auth.get_ctfd_mode()
            _team_mode_enabled = (ctfd_mode == "teams")
            return _team_mode_enabled
        else:
            # No CTFd, default to user mode
            _team_mode_enabled = False
            return False


def is_team_mode() -> bool:
    """
    Check if team mode is enabled.
    Returns False if not yet initialized.
    """
    return _team_mode_enabled or False


def get_team_mode_status() -> Optional[bool]:
    """
    Get team mode status.
    Returns None if not yet initialized.
    """
    return _team_mode_enabled


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_forwarded_for: Optional[str] = Header(None),
    x_real_ip: Optional[str] = Header(None),
) -> UserInfo:
    """Get the current authenticated user."""
    team_mode_enabled = is_team_mode()
    
    if settings.AUTH_MODE == AuthMode.NONE:
        if team_mode_enabled:
            raise HTTPException(
                status_code=403,
                detail="Team mode is enabled and requires CTFd users that belong to a team. Disable TEAM_MODE or use AUTH_MODE=ctfd."
            )

        # Use IP-based identification
        identifier = x_forwarded_for or x_real_ip or "anonymous"
        # Use first IP if multiple
        if "," in identifier:
            identifier = identifier.split(",")[0].strip()
        return await no_auth.get_user(identifier)
    
    elif settings.AUTH_MODE == AuthMode.CTFD:
        # CTFd mode requires valid authentication - no fallback to anonymous
        if not credentials:
            raise HTTPException(
                status_code=401,
                detail="Authentication required. Provide CTFd access token using 'Authorization: Bearer <token>' header.",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        if not ctfd_auth:
            raise HTTPException(
                status_code=500,
                detail="CTFd authentication not configured. Check CTFD_URL setting."
            )
        
        user = await ctfd_auth.validate_token(credentials.credentials)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired CTFd access token. Please check your token and try again.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if team_mode_enabled and not user.team_id:
            raise HTTPException(
                status_code=403,
                detail="Team mode is enabled. Only users who belong to a CTFd team can log in."
            )
        
        return user
    
    # Unknown auth mode - reject
    raise HTTPException(
        status_code=500, 
        detail=f"Unknown authentication mode: {settings.AUTH_MODE}"
    )
