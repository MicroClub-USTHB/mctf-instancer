"""Dynamic flag management for CTFd integration."""
import json
import secrets
import httpx
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .database.connection import get_async_session
from .database.models import FlagMappingModel, SuspiciousSubmissionModel, WhaleySettings
from .logger import event_logger


@dataclass
class FlagMapping:
    """Represents a flag assigned to a user/team for a challenge."""
    flag_id: int
    ctfd_challenge_id: int
    local_challenge_id: str
    user_id: str
    username: str
    flag_content: str
    created_at: str
    instance_id: Optional[str] = None
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    owner_id: Optional[str] = None


@dataclass
class SuspiciousSubmission:
    """A submission where user submitted someone else's flag."""
    id: Optional[int] = None
    submission_id: int = 0
    submitter_user_id: int = 0
    submitter_username: str = ""
    flag_owner_user_id: str = ""
    flag_owner_username: str = ""
    challenge_id: int = 0
    local_challenge_id: str = ""
    provided_flag: str = ""
    submission_time: str = ""
    ip_address: str = ""
    submitter_team_id: Optional[str] = None
    submitter_team_name: Optional[str] = None
    flag_owner_team_id: Optional[str] = None
    flag_owner_team_name: Optional[str] = None
    unique_key: Optional[str] = None


class FlagManager:
    """Manages dynamic flags for anti-cheat functionality."""

    def __init__(self):
        # In-memory indexes loaded from DB at startup (fast lookup for check_submissions).
        self.flag_mappings: Dict[int, FlagMapping] = {}
        self.user_flags: Dict[str, Dict[str, int]] = {}
        self.owner_flags: Dict[str, Dict[str, int]] = {}
        self.flag_lookup: Dict[str, int] = {}
        self.challenge_mapping: Dict[str, int] = {}

        # In-memory cache of existing suspicious unique_keys (avoids DB round-trips).
        self._suspicious_keys: set = set()

        # Highest submission_id processed for incremental checking.
        self._last_submission_id: int = 0

        self._loaded = False

    async def initialize(self) -> None:
        """Load indexes from database (call once at startup)."""
        if self._loaded:
            return

        try:
            async with get_async_session() as session:
                result = await session.execute(select(FlagMappingModel))
                rows = result.scalars().all()

                for row in rows:
                    mapping = FlagMapping(
                        flag_id=row.flag_id,
                        ctfd_challenge_id=row.ctfd_challenge_id,
                        local_challenge_id=row.local_challenge_id,
                        user_id=row.user_id,
                        username=row.username or "",
                        flag_content=row.flag_content,
                        created_at=row.created_at.isoformat() if row.created_at else "",
                        instance_id=row.instance_id,
                        team_id=row.team_id,
                        team_name=row.team_name,
                        owner_id=row.owner_id,
                    )
                    self.flag_mappings[row.flag_id] = mapping
                    self.flag_lookup[row.flag_content] = row.flag_id

                    if row.user_id:
                        self.user_flags.setdefault(row.user_id, {})[row.local_challenge_id] = row.flag_id
                    if row.owner_id:
                        self.owner_flags.setdefault(row.owner_id, {})[row.local_challenge_id] = row.flag_id

                # Load challenge mapping from whaley_settings
                result = await session.execute(
                    select(WhaleySettings).where(WhaleySettings.key == "challenge_mapping")
                )
                row = result.scalar_one_or_none()
                if row and row.value:
                    try:
                        self.challenge_mapping = json.loads(row.value)
                    except json.JSONDecodeError:
                        self.challenge_mapping = {}

                # Load suspicious unique_keys for dedup
                result = await session.execute(
                    select(SuspiciousSubmissionModel.unique_key)
                    .where(SuspiciousSubmissionModel.unique_key.isnot(None))
                )
                self._suspicious_keys = {row[0] for row in result.all() if row[0]}

                # Load last processed submission_id
                result = await session.execute(
                    select(WhaleySettings).where(WhaleySettings.key == "last_submission_id")
                )
                row = result.scalar_one_or_none()
                if row and row.value:
                    try:
                        self._last_submission_id = int(row.value)
                    except (ValueError, TypeError):
                        self._last_submission_id = 0

            print(f"Loaded {len(self.flag_mappings)} flag mappings from database, "
                  f"{len(self.challenge_mapping)} challenge mappings, "
                  f"{len(self._suspicious_keys)} suspicious keys, "
                  f"last_submission_id={self._last_submission_id}")
            self._loaded = True

        except Exception as e:
            print(f"Failed to load flag data from database: {e}")
            import traceback
            traceback.print_exc()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _suspicious_identity_key(
        user_id: Optional[str],
        team_id: Optional[str],
        fallback: Optional[str] = None,
    ) -> str:
        if team_id:
            return f"team:{team_id}"
        if not user_id:
            if fallback:
                return f"user:unknown:{fallback}"
            return "user:unknown"
        return f"user:{user_id}"

    @staticmethod
    def _build_suspicious_key(
        submitter_user_id: Optional[str],
        submitter_team_id: Optional[str],
        flag_owner_user_id: Optional[str],
        flag_owner_team_id: Optional[str],
        flag_content: str,
        submission_id: Optional[str] = None,
        submitter_fallback: Optional[str] = None,
        owner_fallback: Optional[str] = None,
    ) -> str:
        def _identity(uid, tid, fb):
            if tid:
                return f"team:{tid}"
            if not uid:
                if fb:
                    return f"user:unknown:{fb}"
                return "user:unknown"
            return f"user:{uid}"

        submitter_identity = _identity(submitter_user_id, submitter_team_id, submitter_fallback)
        owner_identity = _identity(flag_owner_user_id, flag_owner_team_id, owner_fallback)
        flag_value = (flag_content or "").strip()
        if not flag_value:
            salt = submission_id or "missing-flag"
            flag_value = f"missing-flag:{salt}"
        flag_hash = hashlib.sha256(flag_value.encode("utf-8")).hexdigest()
        unique_payload = f"{submitter_identity}|{owner_identity}|{flag_hash}"
        return hashlib.sha256(unique_payload.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Flag generation
    # ------------------------------------------------------------------

    def generate_flag(self, base_content: Optional[str] = None, prefix: str = "FLAG") -> str:
        """Generate a flag by appending 16 random hex chars to base_content, or fully random if none."""
        suffix = secrets.token_hex(8)
        if base_content is not None:
            return f"{prefix}{{{base_content}_{suffix}}}"
        return f"{prefix}{{{secrets.token_hex(16)}}}"

    # ------------------------------------------------------------------
    # Challenge mapping
    # ------------------------------------------------------------------

    async def get_ctfd_challenge_id(self, local_challenge_id: str) -> Optional[int]:
        """Get CTFd challenge ID from mapping (in-memory, loaded from DB at startup)."""
        if local_challenge_id in self.challenge_mapping:
            return self.challenge_mapping[local_challenge_id]

        for key, value in self.challenge_mapping.items():
            if key.lower() == local_challenge_id.lower():
                return value

        # Targeted DB refresh — only reload the challenge mapping, not everything.
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(WhaleySettings).where(WhaleySettings.key == "challenge_mapping")
                )
                row = result.scalar_one_or_none()
                if row and row.value:
                    fresh = json.loads(row.value)
                    self.challenge_mapping = fresh
                    if local_challenge_id in fresh:
                        return fresh[local_challenge_id]
                    for key, value in fresh.items():
                        if key.lower() == local_challenge_id.lower():
                            return value
        except Exception:
            pass

        print(f"No CTFd mapping for '{local_challenge_id}'. "
              f"Set it via Admin Panel -> Dynamic Flags -> Challenge ID Mapping")
        return None

    async def _persist_challenge_mapping(self) -> None:
        """Write the in-memory challenge_mapping to whaley_settings."""
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(WhaleySettings).where(WhaleySettings.key == "challenge_mapping")
                )
                row = result.scalar_one_or_none()
                if row:
                    row.value = json.dumps(self.challenge_mapping)
                    row.updated_at = datetime.utcnow()
                else:
                    session.add(WhaleySettings(
                        key="challenge_mapping",
                        value=json.dumps(self.challenge_mapping),
                    ))
                await session.commit()
        except Exception as e:
            print(f"Failed to persist challenge mapping: {e}")

    async def add_challenge_mapping(self, local_challenge_id: str, ctfd_challenge_id: int) -> None:
        """Add or update a local→CTFd challenge ID mapping."""
        self.challenge_mapping[local_challenge_id] = ctfd_challenge_id
        await self._persist_challenge_mapping()

    async def remove_challenge_mapping(self, local_challenge_id: str) -> bool:
        """Remove a challenge mapping. Returns True if it existed."""
        if local_challenge_id in self.challenge_mapping:
            del self.challenge_mapping[local_challenge_id]
            await self._persist_challenge_mapping()
            return True
        return False

    async def prune_mappings_for_disabled_challenges(self, disabled_ids: set) -> int:
        """Remove challenge mappings for challenges that have per-challenge dynamic flags disabled.

        Returns the number of mappings that were removed.
        """
        removed = 0
        for challenge_id in list(self.challenge_mapping.keys()):
            if challenge_id in disabled_ids:
                del self.challenge_mapping[challenge_id]
                removed += 1
        if removed > 0:
            await self._persist_challenge_mapping()
        return removed

    # ------------------------------------------------------------------
    # Flag creation (per-user / per-team)
    # ------------------------------------------------------------------

    async def _create_flag_record(
        self,
        local_challenge_id: str,
        owner_id: str,
        user_id: str,
        username: str,
        instance_id: str,
        team_id: Optional[str],
        team_name: Optional[str],
        base_flag_content: Optional[str],
    ) -> Tuple[bool, str, Optional[str]]:
        """Shared flag-creation logic for both user and team modes."""
        if not settings.CTFD_URL or not settings.CTFD_API_KEY:
            return False, "CTFd not configured", None

        existing_flag_id = self.owner_flags.get(owner_id, {}).get(local_challenge_id)
        if existing_flag_id and existing_flag_id in self.flag_mappings:
            existing = self.flag_mappings[existing_flag_id]
            return True, "Using existing flag", existing.flag_content

        ctfd_challenge_id = await self.get_ctfd_challenge_id(local_challenge_id)
        if not ctfd_challenge_id:
            return False, f"Challenge '{local_challenge_id}' not found in CTFd", None

        flag_content = self.generate_flag(base_content=base_flag_content, prefix=settings.FLAG_PREFIX)

        data_payload = (
            f"team:{team_id}|team_name:{team_name}|spawned_by:{username}|instance:{instance_id}"
            if team_id
            else f"user:{user_id}|instance:{instance_id}"
        )

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{settings.CTFD_URL}/api/v1/flags",
                    headers={
                        "Authorization": f"Token {settings.CTFD_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "challenge_id": ctfd_challenge_id,
                        "type": "static",
                        "content": flag_content,
                        "data": data_payload,
                    },
                    timeout=10.0,
                )

                if response.status_code not in (200, 201):
                    return False, f"CTFd API error: {response.status_code}", None

                data = response.json()
                if not data.get("success"):
                    return False, f"CTFd error: {data}", None

                flag_id = data["data"]["id"]

                # Persist to DB
                async with get_async_session() as session:
                    db_mapping = FlagMappingModel(
                        flag_id=flag_id,
                        ctfd_challenge_id=ctfd_challenge_id,
                        local_challenge_id=local_challenge_id,
                        user_id=user_id or owner_id,
                        username=username or owner_id,
                        flag_content=flag_content,
                        instance_id=instance_id,
                        team_id=team_id,
                        team_name=team_name,
                        owner_id=owner_id,
                        created_at=datetime.utcnow(),
                    )
                    session.add(db_mapping)
                    await session.commit()

                # Update in-memory indexes
                mapping = FlagMapping(
                    flag_id=flag_id,
                    ctfd_challenge_id=ctfd_challenge_id,
                    local_challenge_id=local_challenge_id,
                    user_id=user_id or owner_id,
                    username=username or owner_id,
                    flag_content=flag_content,
                    created_at=datetime.now(timezone.utc).isoformat(),
                    instance_id=instance_id,
                    team_id=team_id,
                    team_name=team_name,
                    owner_id=owner_id,
                )
                self.flag_mappings[flag_id] = mapping
                self.flag_lookup[flag_content] = flag_id
                self.owner_flags.setdefault(owner_id, {})[local_challenge_id] = flag_id
                if user_id:
                    self.user_flags.setdefault(user_id, {})[local_challenge_id] = flag_id

                await event_logger.log_flag_created(
                    user_id=user_id or owner_id,
                    username=username or owner_id,
                    challenge_id=local_challenge_id,
                    flag_id=flag_id,
                    instance_id=instance_id,
                    extra={"team_id": team_id, "team_name": team_name,
                           "team_mode": bool(team_id)},
                )

                label = f"team {team_name}" if team_id else f"user {username}"
                print(f"Created flag {flag_id} for {label} on challenge {local_challenge_id}")
                return True, "Flag created", flag_content

        except Exception as e:
            print(f"Error creating flag: {e}")
            return False, f"Error: {str(e)}", None

    async def create_flag_for_user(
        self,
        local_challenge_id: str,
        user_id: str,
        username: str,
        instance_id: str,
        base_flag_content: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        return await self._create_flag_record(
            local_challenge_id=local_challenge_id,
            owner_id=user_id,
            user_id=user_id,
            username=username,
            instance_id=instance_id,
            team_id=None,
            team_name=None,
            base_flag_content=base_flag_content,
        )

    async def create_flag_for_owner(
        self,
        local_challenge_id: str,
        owner_id: str,
        owner_name: str,
        instance_id: str,
        team_mode: bool = False,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        team_id: Optional[str] = None,
        team_name: Optional[str] = None,
        base_flag_content: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        if team_mode and team_id:
            return await self._create_flag_record(
                local_challenge_id=local_challenge_id,
                owner_id=owner_id,
                user_id=user_id or owner_id,
                username=username or owner_name,
                instance_id=instance_id,
                team_id=team_id,
                team_name=team_name,
                base_flag_content=base_flag_content,
            )
        return await self.create_flag_for_user(
            local_challenge_id=local_challenge_id,
            user_id=user_id or owner_id,
            username=username or owner_name,
            instance_id=instance_id,
            base_flag_content=base_flag_content,
        )

    # ------------------------------------------------------------------
    # Flag deletion
    # ------------------------------------------------------------------

    async def delete_flag(self, flag_id: int) -> bool:
        """Delete a flag from CTFd and our database."""
        if not settings.CTFD_URL or not settings.CTFD_API_KEY:
            return False

        try:
            async with httpx.AsyncClient() as client:
                response = await client.delete(
                    f"{settings.CTFD_URL}/api/v1/flags/{flag_id}",
                    headers={
                        "Authorization": f"Token {settings.CTFD_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    timeout=10.0,
                )
                if response.status_code not in (200, 204):
                    return False

            # Remove from DB
            async with get_async_session() as session:
                await session.execute(
                    delete(FlagMappingModel).where(FlagMappingModel.flag_id == flag_id)
                )
                await session.commit()

            # Remove from in-memory indexes
            if flag_id in self.flag_mappings:
                mapping = self.flag_mappings.pop(flag_id)
                self.flag_lookup.pop(mapping.flag_content, None)
                if mapping.user_id and mapping.user_id in self.user_flags:
                    self.user_flags[mapping.user_id].pop(mapping.local_challenge_id, None)
                if mapping.owner_id and mapping.owner_id in self.owner_flags:
                    self.owner_flags[mapping.owner_id].pop(mapping.local_challenge_id, None)

            return True
        except Exception as e:
            print(f"Error deleting flag {flag_id}: {e}")
            return False

    async def cleanup_user_flags(self, user_id: str) -> int:
        """Delete all flags for a user from CTFd and database."""
        count = 0
        if user_id not in self.user_flags:
            return 0

        for local_challenge_id, flag_id in list(self.user_flags[user_id].items()):
            if await self.delete_flag(flag_id):
                count += 1
            else:
                # CTFd delete failed, but clean up DB + memory anyway
                if flag_id in self.flag_mappings:
                    mapping = self.flag_mappings.pop(flag_id)
                    self.flag_lookup.pop(mapping.flag_content, None)
                try:
                    async with get_async_session() as session:
                        await session.execute(
                            delete(FlagMappingModel).where(FlagMappingModel.flag_id == flag_id)
                        )
                        await session.commit()
                except Exception:
                    pass
                count += 1

        self.user_flags.pop(user_id, None)
        return count

    # ------------------------------------------------------------------
    # Suspicious submission detection
    # ------------------------------------------------------------------

    async def check_submissions(self, limit: int = 150, full_scan: bool = False) -> List[SuspiciousSubmission]:
        """
        Check CTFd submissions for cheating (submitting someone else's flag).

        By default, only checks submissions newer than the last processed
        submission_id (incremental). Set full_scan=True to re-check all
        recent submissions regardless of checkpoint.
        """
        if not settings.CTFD_URL or not settings.CTFD_API_KEY:
            print("[check_submissions] CTFd not configured")
            return []

        print(f"[check_submissions] Checking with {len(self.flag_lookup)} flags in lookup table")

        new_suspicious: List[SuspiciousSubmission] = []

        try:
            async with httpx.AsyncClient() as client:
                # Fetch newest submissions from CTFd
                response = await client.get(
                    f"{settings.CTFD_URL}/api/v1/submissions",
                    headers={
                        "Authorization": f"Token {settings.CTFD_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    params={"per_page": 50, "page": 1},
                    timeout=15.0,
                )

                if response.status_code != 200:
                    print(f"[check_submissions] Failed to fetch submissions: {response.status_code}")
                    return []

                data = response.json()
                if not data.get("success"):
                    print("[check_submissions] API returned success=false")
                    return []

                meta = data.get("meta", {}).get("pagination", {})
                total_pages = meta.get("pages", 1)
                per_page = meta.get("per_page", 50)

                # Collect submission IDs from page 1 to find the checkpoint boundary
                page1_submissions = data.get("data", [])
                highest_id_seen = 0
                all_submissions: list = list(page1_submissions)

                for sub in page1_submissions:
                    sid = sub.get("id", 0)
                    if sid > highest_id_seen:
                        highest_id_seen = sid

                if not full_scan and self._last_submission_id > 0:
                    # Stop fetching once we go below the checkpoint
                    pass  # We'll filter after collecting

                # Fetch remaining pages that might contain new submissions
                for page_num in range(2, min(total_pages + 1, 6)):  # Up to 5 pages (250 max)
                    page_response = await client.get(
                        f"{settings.CTFD_URL}/api/v1/submissions",
                        headers={
                            "Authorization": f"Token {settings.CTFD_API_KEY}",
                            "Content-Type": "application/json",
                        },
                        params={"per_page": per_page, "page": page_num},
                        timeout=15.0,
                    )
                    if page_response.status_code == 200:
                        page_data = page_response.json()
                        if page_data.get("success"):
                            page_subs = page_data.get("data", [])
                            all_submissions.extend(page_subs)
                            for sub in page_subs:
                                sid = sub.get("id", 0)
                                if sid > highest_id_seen:
                                    highest_id_seen = sid

                # Filter to only new submissions if not doing full scan
                if not full_scan and self._last_submission_id > 0:
                    new_submissions = [s for s in all_submissions if s.get("id", 0) > self._last_submission_id]
                    print(f"[check_submissions] Incremental: "
                          f"{len(all_submissions)} fetched, "
                          f"{len(new_submissions)} new (id > {self._last_submission_id})")
                else:
                    new_submissions = all_submissions
                    print(f"[check_submissions] Full scan: {len(new_submissions)} submissions")

                # Only process up to limit truly new entries
                submissions_to_check = new_submissions[:limit]
                print(f"[check_submissions] Processing {len(submissions_to_check)} submissions")

                users_cache: dict = {}
                matched_flags = 0

                for sub in submissions_to_check:
                    provided_flag = sub.get("provided", "")
                    submitter_user_id = sub.get("user_id")
                    challenge_id = sub.get("challenge_id")
                    submission_id = sub.get("id")

                    if provided_flag not in self.flag_lookup:
                        continue

                    matched_flags += 1
                    flag_id = self.flag_lookup[provided_flag]
                    flag_mapping = self.flag_mappings.get(flag_id)
                    if not flag_mapping:
                        continue

                    flag_owner_team_id = flag_mapping.team_id
                    flag_owner_user_id = flag_mapping.user_id

                    # Extract submitter identity from submission payload
                    submitter_username = None
                    submitter_team_id = None
                    submitter_team_name = None

                    if "user" in sub and sub["user"]:
                        submitter_username = sub["user"].get("name")
                    if "team" in sub and sub["team"]:
                        submitter_team_id = sub["team"].get("id")
                        submitter_team_name = sub["team"].get("name")
                    elif sub.get("team_id"):
                        submitter_team_id = sub.get("team_id")

                    # Fallback to user API if identity data is sparse
                    if not submitter_username or (flag_owner_team_id and not submitter_team_id):
                        if submitter_user_id not in users_cache:
                            try:
                                user_resp = await client.get(
                                    f"{settings.CTFD_URL}/api/v1/users/{submitter_user_id}",
                                    headers={
                                        "Authorization": f"Token {settings.CTFD_API_KEY}",
                                        "Content-Type": "application/json",
                                    },
                                    timeout=5.0,
                                )
                                if user_resp.status_code == 200:
                                    user_data = user_resp.json()
                                    if user_data.get("success"):
                                        users_cache[submitter_user_id] = {
                                            "name": user_data["data"].get("name", str(submitter_user_id)),
                                            "team_id": user_data["data"].get("team_id"),
                                        }
                                else:
                                    users_cache[submitter_user_id] = {"name": str(submitter_user_id), "team_id": None}
                            except Exception:
                                users_cache[submitter_user_id] = {"name": str(submitter_user_id), "team_id": None}

                        cached = users_cache.get(submitter_user_id, {})
                        if not submitter_username:
                            submitter_username = cached.get("name", str(submitter_user_id))
                        if not submitter_team_id:
                            submitter_team_id = cached.get("team_id")

                    # Determine if suspicious
                    is_suspicious = False

                    if flag_owner_team_id:
                        if submitter_team_id and str(submitter_team_id) != str(flag_owner_team_id):
                            is_suspicious = True
                        elif not submitter_team_id and str(submitter_user_id) != str(flag_owner_user_id):
                            is_suspicious = True
                    else:
                        if str(submitter_user_id) != str(flag_owner_user_id):
                            is_suspicious = True

                    if not is_suspicious:
                        continue

                    # Resolve team name if missing
                    if submitter_team_id and not submitter_team_name:
                        try:
                            team_resp = await client.get(
                                f"{settings.CTFD_URL}/api/v1/teams/{submitter_team_id}",
                                headers={
                                    "Authorization": f"Token {settings.CTFD_API_KEY}",
                                    "Content-Type": "application/json",
                                },
                                timeout=5.0,
                            )
                            if team_resp.status_code == 200:
                                team_data = team_resp.json()
                                if team_data.get("success"):
                                    submitter_team_name = team_data["data"].get("name")
                        except Exception:
                            pass

                    # Build dedup key
                    unique_key = self._build_suspicious_key(
                        submitter_user_id=str(submitter_user_id),
                        submitter_team_id=str(submitter_team_id) if submitter_team_id else None,
                        flag_owner_user_id=str(flag_owner_user_id),
                        flag_owner_team_id=str(flag_owner_team_id) if flag_owner_team_id else None,
                        flag_content=flag_mapping.flag_content,
                        submission_id=str(submission_id),
                        submitter_fallback=str(submission_id) if submission_id else submitter_username,
                        owner_fallback=flag_mapping.username or None,
                    )

                    if unique_key in self._suspicious_keys:
                        continue

                    self._suspicious_keys.add(unique_key)

                    suspicious = SuspiciousSubmission(
                        submission_id=submission_id,
                        submitter_user_id=submitter_user_id,
                        submitter_username=submitter_username or str(submitter_user_id),
                        flag_owner_user_id=flag_owner_user_id,
                        flag_owner_username=flag_mapping.username or "",
                        challenge_id=challenge_id,
                        local_challenge_id=flag_mapping.local_challenge_id,
                        provided_flag=provided_flag,
                        unique_key=unique_key,
                        submission_time=sub.get("date", ""),
                        ip_address=sub.get("ip", "unknown"),
                        submitter_team_id=str(submitter_team_id) if submitter_team_id else None,
                        submitter_team_name=submitter_team_name,
                        flag_owner_team_id=flag_owner_team_id,
                        flag_owner_team_name=flag_mapping.team_name,
                    )
                    new_suspicious.append(suspicious)

                    # Persist immediately to DB
                    try:
                        async with get_async_session() as session:
                            db_sus = SuspiciousSubmissionModel(
                                submission_id=submission_id,
                                submitter_user_id=submitter_user_id,
                                submitter_username=submitter_username or str(submitter_user_id),
                                flag_owner_user_id=flag_owner_user_id or "",
                                flag_owner_username=flag_mapping.username or "",
                                challenge_id=challenge_id,
                                local_challenge_id=flag_mapping.local_challenge_id,
                                provided_flag=provided_flag,
                                submission_time=sub.get("date", ""),
                                ip_address=sub.get("ip", "unknown"),
                                submitter_team_id=str(submitter_team_id) if submitter_team_id else None,
                                submitter_team_name=submitter_team_name,
                                flag_owner_team_id=flag_owner_team_id,
                                flag_owner_team_name=flag_mapping.team_name,
                                unique_key=unique_key,
                            )
                            session.add(db_sus)
                            await session.commit()
                    except Exception as e:
                        print(f"[check_submissions] Failed to persist suspicious entry: {e}")

                    # Log to event logger
                    await event_logger.log_suspicious_submission(
                        submitter_user_id=str(submitter_user_id),
                        submitter_username=submitter_username or str(submitter_user_id),
                        flag_owner_user_id=str(flag_owner_user_id),
                        flag_owner_username=flag_mapping.username or "",
                        challenge_id=str(challenge_id),
                        local_challenge_id=flag_mapping.local_challenge_id,
                        submission_id=submission_id,
                        ip_address=sub.get("ip", "unknown"),
                    )

                # Update checkpoint
                if highest_id_seen > self._last_submission_id:
                    self._last_submission_id = highest_id_seen
                    await self._persist_last_submission_id()

                print(f"[check_submissions] Matched {matched_flags} flags, "
                      f"{len(new_suspicious)} new suspicious, "
                      f"checkpoint now at submission_id={self._last_submission_id}")
                return new_suspicious

        except Exception as e:
            print(f"[check_submissions] Error: {e}")
            import traceback
            traceback.print_exc()
            return []

    async def _persist_last_submission_id(self) -> None:
        """Store the last processed submission_id in whaley_settings."""
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(WhaleySettings).where(WhaleySettings.key == "last_submission_id")
                )
                row = result.scalar_one_or_none()
                if row:
                    row.value = str(self._last_submission_id)
                    row.updated_at = datetime.utcnow()
                else:
                    session.add(WhaleySettings(
                        key="last_submission_id",
                        value=str(self._last_submission_id),
                    ))
                await session.commit()
        except Exception as e:
            print(f"Failed to persist last_submission_id: {e}")

    # ------------------------------------------------------------------
    # Admin query methods
    # ------------------------------------------------------------------

    def get_user_flag(self, user_id: str, local_challenge_id: str) -> Optional[str]:
        """Get the flag content for a user's challenge (in-memory)."""
        flag_id = self.user_flags.get(user_id, {}).get(local_challenge_id)
        if flag_id and flag_id in self.flag_mappings:
            return self.flag_mappings[flag_id].flag_content
        return None

    async def get_all_mappings(self) -> Dict:
        """Get all flag mappings for admin view."""
        suspicious = await self.get_suspicious_submissions(offset=0, limit=500)
        return {
            "flag_mappings": [asdict(m) for m in self.flag_mappings.values()],
            "total_flags": len(self.flag_mappings),
            "total_users": len(self.user_flags),
            "suspicious_submissions": [asdict(s) for s in suspicious],
            "suspicious_total": await self.count_suspicious_submissions(),
            "challenge_mapping": self.challenge_mapping,
            "last_submission_id": self._last_submission_id,
        }

    async def get_suspicious_submissions(
        self, offset: int = 0, limit: int = 50
    ) -> List[SuspiciousSubmission]:
        """Get paginated suspicious submissions from DB."""
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(SuspiciousSubmissionModel)
                    .order_by(SuspiciousSubmissionModel.created_at.desc())
                    .offset(offset)
                    .limit(limit)
                )
                rows = result.scalars().all()
                return [
                    SuspiciousSubmission(
                        id=row.id,
                        submission_id=row.submission_id,
                        submitter_user_id=row.submitter_user_id,
                        submitter_username=row.submitter_username or "",
                        flag_owner_user_id=row.flag_owner_user_id,
                        flag_owner_username=row.flag_owner_username or "",
                        challenge_id=row.challenge_id,
                        local_challenge_id=row.local_challenge_id,
                        provided_flag=row.provided_flag or "",
                        submission_time=row.submission_time or "",
                        ip_address=row.ip_address or "",
                        submitter_team_id=row.submitter_team_id,
                        submitter_team_name=row.submitter_team_name,
                        flag_owner_team_id=row.flag_owner_team_id,
                        flag_owner_team_name=row.flag_owner_team_name,
                        unique_key=row.unique_key,
                    )
                    for row in rows
                ]
        except Exception as e:
            print(f"Failed to load suspicious submissions: {e}")
            return []

    async def count_suspicious_submissions(self) -> int:
        """Count total suspicious submissions."""
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(func.count(SuspiciousSubmissionModel.id))
                )
                return result.scalar() or 0
        except Exception:
            return 0

    async def clear_suspicious_submissions(self) -> int:
        """Clear all suspicious submissions from DB and memory."""
        try:
            async with get_async_session() as session:
                result = await session.execute(delete(SuspiciousSubmissionModel))
                count = result.rowcount
                await session.commit()
                self._suspicious_keys.clear()
                return count
        except Exception as e:
            print(f"Failed to clear suspicious submissions: {e}")
            return 0


# Global flag manager instance
_flag_manager: Optional[FlagManager] = None


async def get_flag_manager() -> FlagManager:
    """Get or create the global flag manager, initializing from DB on first call."""
    global _flag_manager
    if _flag_manager is None:
        _flag_manager = FlagManager()
        await _flag_manager.initialize()
    return _flag_manager
