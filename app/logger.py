"""Logging system for instance events with database persistence."""
import json
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc

from .database.connection import get_async_session
from .database.models import EventLog as EventLogModel


class EventType(str, Enum):
    INSTANCE_SPAWN = "instance_spawn"
    INSTANCE_SPAWN_FAILED = "instance_spawn_failed"
    INSTANCE_STOP = "instance_stop"
    INSTANCE_EXTEND = "instance_extend"
    INSTANCE_EXPIRED = "instance_expired"
    USER_LOGIN = "user_login"
    USER_LOGIN_FAILED = "user_login_failed"
    AUTH_FAILURE = "auth_failure"
    FLAG_CREATED = "flag_created"
    FLAG_DELETED = "flag_deleted"
    SUSPICIOUS_SUBMISSION = "suspicious_submission"
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"


class LogEntry(BaseModel):
    """A single log entry."""
    id: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: EventType
    user_id: Optional[str] = None
    username: Optional[str] = None
    instance_id: Optional[str] = None
    challenge_id: Optional[str] = None
    ports: Optional[Dict[int, int]] = None  # internal:external
    public_url: Optional[str] = None
    message: str
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None


class EventLogger:
    """
    Logger for instance and system events with database persistence.
    
    Replaces JSONL file storage with SQLite/PostgreSQL database.
    Supports both sync console output and async database writes.
    """
    
    def __init__(self, max_memory_entries: int = 1000):
        self.max_memory_entries = max_memory_entries
        self._memory_cache: List[LogEntry] = []
        self._counter = 0
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize logger and get current max ID from database."""
        if self._initialized:
            return
        
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(func.max(EventLogModel.id))
                )
                max_id = result.scalar()
                self._counter = max_id or 0
            self._initialized = True
            print(f"[EventLogger] Initialized with counter at {self._counter}")
        except Exception as e:
            print(f"[EventLogger] Initialization warning: {e}")
            self._initialized = True
    
    async def _save_entry_to_db(self, entry: LogEntry) -> None:
        """Save a log entry to the database."""
        try:
            async with get_async_session() as session:
                db_entry = EventLogModel(
                    id=entry.id,
                    timestamp=entry.timestamp,
                    event_type=entry.event_type.value,
                    user_id=entry.user_id,
                    username=entry.username,
                    instance_id=entry.instance_id,
                    challenge_id=entry.challenge_id,
                    ports_json=json.dumps(entry.ports) if entry.ports else None,
                    public_url=entry.public_url,
                    message=entry.message,
                    details_json=json.dumps(entry.details) if entry.details else None,
                    ip_address=entry.ip_address
                )
                session.add(db_entry)
                await session.commit()
        except Exception as e:
            print(f"[EventLogger] Failed to save log entry to database: {e}")
    
    async def log(
        self,
        event_type: EventType,
        message: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        instance_id: Optional[str] = None,
        challenge_id: Optional[str] = None,
        ports: Optional[Dict[int, int]] = None,
        public_url: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> LogEntry:
        """Add a new log entry (async version)."""
        self._counter += 1
        entry = LogEntry(
            id=self._counter,
            event_type=event_type,
            message=message,
            user_id=user_id,
            username=username,
            instance_id=instance_id,
            challenge_id=challenge_id,
            ports=ports,
            public_url=public_url,
            details=details,
            ip_address=ip_address,
        )
        
        # Add to memory cache
        self._memory_cache.append(entry)
        if len(self._memory_cache) > self.max_memory_entries:
            self._memory_cache = self._memory_cache[-self.max_memory_entries:]
        
        # Console output
        print(f"[{entry.timestamp.isoformat()}] {event_type.value}: {message}")
        
        # Save to database in background
        asyncio.create_task(self._save_entry_to_db(entry))
        
        return entry
    
    def log_sync(
        self,
        event_type: EventType,
        message: str,
        **kwargs
    ) -> None:
        """Synchronous log for places where async isn't available."""
        self._counter += 1
        timestamp = datetime.utcnow()
        print(f"[{timestamp.isoformat()}] {event_type.value}: {message}")
    
    async def log_instance_spawn(
        self,
        user_id: str,
        username: str,
        instance_id: str,
        challenge_id: str,
        ports: Dict[int, int],
        public_url: str,
        ip_address: Optional[str] = None,
        extra: Optional[Dict] = None,
    ) -> LogEntry:
        """Log an instance spawn event."""
        port_str = ", ".join([f"{k}→{v}" for k, v in ports.items()])
        details = {}
        if extra:
            details.update(extra)
        return await self.log(
            event_type=EventType.INSTANCE_SPAWN,
            message=f"User '{username}' spawned '{challenge_id}' → {public_url} (ports: {port_str})",
            user_id=user_id,
            username=username,
            instance_id=instance_id,
            challenge_id=challenge_id,
            ports=ports,
            public_url=public_url,
            ip_address=ip_address,
            details=details if details else None,
        )
    
    async def log_instance_spawn_failed(
        self,
        user_id: str,
        username: str,
        challenge_id: str,
        reason: str,
        ip_address: Optional[str] = None,
        docker_error: Optional[str] = None,
    ) -> LogEntry:
        """Log a failed instance spawn."""
        details = {"reason": reason}
        if docker_error:
            details["docker_error"] = docker_error
        return await self.log(
            event_type=EventType.INSTANCE_SPAWN_FAILED,
            message=f"User '{username}' failed to spawn '{challenge_id}': {reason}",
            user_id=user_id,
            username=username,
            challenge_id=challenge_id,
            details=details,
            ip_address=ip_address,
        )
    
    async def log_instance_stop(
        self,
        user_id: str,
        username: str,
        instance_id: str,
        challenge_id: str,
        ip_address: Optional[str] = None,
    ) -> LogEntry:
        """Log an instance stop event."""
        return await self.log(
            event_type=EventType.INSTANCE_STOP,
            message=f"User '{username}' stopped instance '{instance_id}'",
            user_id=user_id,
            username=username,
            instance_id=instance_id,
            challenge_id=challenge_id,
            ip_address=ip_address,
        )
    
    async def log_instance_extend(
        self,
        user_id: str,
        username: str,
        instance_id: str,
        extension_seconds: int,
        ip_address: Optional[str] = None,
    ) -> LogEntry:
        """Log an instance extend event."""
        return await self.log(
            event_type=EventType.INSTANCE_EXTEND,
            message=f"User '{username}' extended instance '{instance_id}' by {extension_seconds}s",
            user_id=user_id,
            username=username,
            instance_id=instance_id,
            details={"extension_seconds": extension_seconds},
            ip_address=ip_address,
        )
    
    async def log_instance_expired(
        self,
        instance_id: str,
        challenge_id: str,
        user_id: str,
    ) -> LogEntry:
        """Log an instance expiry event."""
        return await self.log(
            event_type=EventType.INSTANCE_EXPIRED,
            message=f"Instance '{instance_id}' expired and was cleaned up",
            user_id=user_id,
            instance_id=instance_id,
            challenge_id=challenge_id,
        )
    
    async def log_user_login(
        self,
        user_id: str,
        username: str,
        ip_address: Optional[str] = None,
    ) -> LogEntry:
        """Log a successful user login."""
        return await self.log(
            event_type=EventType.USER_LOGIN,
            message=f"User '{username}' logged in",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
        )
    
    async def log_user_login_failed(
        self,
        ip_address: Optional[str] = None,
        reason: str = "Invalid token",
    ) -> LogEntry:
        """Log a failed login attempt."""
        return await self.log(
            event_type=EventType.USER_LOGIN_FAILED,
            message=f"Failed login attempt: {reason}",
            ip_address=ip_address,
            details={"reason": reason},
        )
    
    async def log_flag_created(
        self,
        user_id: str,
        username: str,
        challenge_id: str,
        flag_id: int,
        instance_id: Optional[str] = None,
        extra: Optional[Dict] = None,
    ) -> LogEntry:
        """Log a dynamic flag creation event."""
        details = {"flag_id": flag_id}
        if extra:
            details.update(extra)
        return await self.log(
            event_type=EventType.FLAG_CREATED,
            message=f"Dynamic flag created for user '{username}' on '{challenge_id}'",
            user_id=user_id,
            username=username,
            challenge_id=challenge_id,
            instance_id=instance_id,
            details=details,
        )
    
    async def log_suspicious_submission(
        self,
        submitter_user_id: str,
        submitter_username: str,
        flag_owner_user_id: str,
        flag_owner_username: str,
        challenge_id: str,
        local_challenge_id: str,
        submission_id: int,
        ip_address: Optional[str] = None,
    ) -> LogEntry:
        """Log a suspicious submission (user submitted another user's flag)."""
        return await self.log(
            event_type=EventType.SUSPICIOUS_SUBMISSION,
            message=f"⚠️ SUSPICIOUS: '{submitter_username}' submitted flag belonging to '{flag_owner_username}' on '{local_challenge_id}'",
            user_id=submitter_user_id,
            username=submitter_username,
            challenge_id=local_challenge_id,
            ip_address=ip_address,
            details={
                "submission_id": submission_id,
                "flag_owner_user_id": flag_owner_user_id,
                "flag_owner_username": flag_owner_username,
                "ctfd_challenge_id": challenge_id,
            },
        )
    
    async def get_entries(
        self,
        limit: int = 100,
        offset: int = 0,
        event_type: Optional[EventType] = None,
        user_id: Optional[str] = None,
        challenge_id: Optional[str] = None,
    ) -> List[LogEntry]:
        """Get log entries with filtering from database."""
        async with get_async_session() as session:
            query = select(EventLogModel)
            
            # Apply filters
            if event_type:
                query = query.where(EventLogModel.event_type == event_type.value)
            if user_id:
                query = query.where(EventLogModel.user_id == user_id)
            if challenge_id:
                query = query.where(EventLogModel.challenge_id == challenge_id)
            
            # Order by newest first and apply pagination
            query = query.order_by(desc(EventLogModel.timestamp))
            query = query.offset(offset).limit(limit)
            
            result = await session.execute(query)
            db_entries = result.scalars().all()
            
            # Convert to LogEntry objects
            entries = []
            for db_entry in db_entries:
                try:
                    ports = json.loads(db_entry.ports_json) if db_entry.ports_json else None
                    # Convert string keys back to int for ports
                    if ports:
                        ports = {int(k): v for k, v in ports.items()}
                    
                    details = json.loads(db_entry.details_json) if db_entry.details_json else None
                    
                    entry = LogEntry(
                        id=db_entry.id,
                        timestamp=db_entry.timestamp,
                        event_type=EventType(db_entry.event_type),
                        user_id=db_entry.user_id,
                        username=db_entry.username,
                        instance_id=db_entry.instance_id,
                        challenge_id=db_entry.challenge_id,
                        ports=ports,
                        public_url=db_entry.public_url,
                        message=db_entry.message,
                        details=details,
                        ip_address=db_entry.ip_address,
                    )
                    entries.append(entry)
                except Exception as e:
                    print(f"[EventLogger] Error parsing log entry {db_entry.id}: {e}")
                    continue
            
            return entries
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get logging statistics from database."""
        async with get_async_session() as session:
            # Total entries
            total_result = await session.execute(
                select(func.count(EventLogModel.id))
            )
            total_entries = total_result.scalar() or 0
            
            # Count by event type
            event_counts = {}
            for event_type in EventType:
                count_result = await session.execute(
                    select(func.count(EventLogModel.id))
                    .where(EventLogModel.event_type == event_type.value)
                )
                event_counts[event_type.value] = count_result.scalar() or 0
            
            # Unique users
            users_result = await session.execute(
                select(func.count(func.distinct(EventLogModel.user_id)))
            )
            unique_users = users_result.scalar() or 0
            
            # Recent activity (last 24 hours)
            cutoff = datetime.utcnow() - timedelta(hours=24)
            recent_result = await session.execute(
                select(func.count(EventLogModel.id))
                .where(EventLogModel.timestamp >= cutoff)
            )
            recent_events = recent_result.scalar() or 0
            
            return {
                "total_entries": total_entries,
                "event_counts": event_counts,
                "unique_users": unique_users,
                "last_24h_events": recent_events,
            }


# Global logger instance
_event_logger: Optional[EventLogger] = None


def get_event_logger() -> EventLogger:
    """Get the global event logger instance."""
    global _event_logger
    if _event_logger is None:
        _event_logger = EventLogger()
    return _event_logger


async def init_event_logger() -> EventLogger:
    """Initialize the event logger."""
    logger = get_event_logger()
    await logger.initialize()
    return logger


# Backward compatibility alias
event_logger = get_event_logger()
