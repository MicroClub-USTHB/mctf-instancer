"""
Instance Forensics - Docker container log capture system.

Features:
- Auto Capture: Automatically dump logs when instances terminate
- Live Capture: On-demand log capture from running containers

Designed with server resource protection in mind.
"""
import asyncio
import gzip
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple

from .config import settings


def utcnow() -> datetime:
    """Get current UTC time."""
    return datetime.now(timezone.utc)


@dataclass
class ForensicsLog:
    """Represents a captured instance log."""
    log_id: str
    instance_id: str
    challenge_id: str
    challenge_name: str
    owner_id: str
    owner_name: str
    spawned_by: str  # Username who spawned
    capture_type: str  # "auto" or "live"
    capture_time: str
    terminate_reason: str  # "user_stop", "expired", "error", "live_capture"
    file_path: str
    file_size_bytes: int
    compressed: bool
    container_count: int
    # Container names captured
    container_names: Optional[List[str]] = None
    # Team info if applicable
    team_id: Optional[str] = None
    team_name: Optional[str] = None


class ForensicsManager:
    """
    Manages instance log capture with resource protection.
    
    Features:
    - Size limits per capture
    - Tail line limits
    - Automatic compression
    - Log retention/rotation
    - Async processing to avoid blocking
    """
    
    def __init__(self):
        self.log_dir = Path(settings.FORENSICS_LOG_DIR)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self._lock = Lock()
        self._logs: Dict[str, ForensicsLog] = {}  # log_id -> ForensicsLog
        self._index_file = self.log_dir / "index.json"
        
        # Runtime toggle (can be changed via admin panel)
        self._auto_capture_enabled = settings.FORENSICS_AUTO_CAPTURE
        
        # Semaphore to limit concurrent captures
        self._capture_semaphore = asyncio.Semaphore(5)
        
        self._load_index()
    
    def _load_index(self) -> None:
        """Load log index from disk."""
        try:
            if self._index_file.exists():
                with open(self._index_file, "r") as f:
                    data = json.load(f)
                    for log_id, log_data in data.items():
                        self._logs[log_id] = ForensicsLog(**log_data)
                print(f"[Forensics] Loaded {len(self._logs)} log entries from index")
        except Exception as e:
            print(f"[Forensics] Failed to load index: {e}")
            self._logs = {}
    
    def _save_index(self) -> None:
        """Save log index to disk."""
        try:
            with self._lock:
                with open(self._index_file, "w") as f:
                    data = {log_id: asdict(log) for log_id, log in self._logs.items()}
                    json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[Forensics] Failed to save index: {e}")
    
    @property
    def auto_capture_enabled(self) -> bool:
        """Check if auto capture is enabled."""
        return self._auto_capture_enabled
    
    def set_auto_capture(self, enabled: bool) -> None:
        """Enable or disable auto capture."""
        self._auto_capture_enabled = enabled
        print(f"[Forensics] Auto capture {'enabled' if enabled else 'disabled'}")
    
    def get_logs(
        self,
        challenge_id: Optional[str] = None,
        owner_id: Optional[str] = None,
        capture_type: Optional[str] = None,
        limit: int = 100
    ) -> List[ForensicsLog]:
        """Get forensics logs with optional filters."""
        logs = list(self._logs.values())
        
        if challenge_id:
            logs = [log for log in logs if log.challenge_id == challenge_id]
        if owner_id:
            logs = [log for log in logs if log.owner_id == owner_id]
        if capture_type:
            logs = [log for log in logs if log.capture_type == capture_type]
        
        # Sort by capture time (newest first)
        logs.sort(key=lambda x: x.capture_time, reverse=True)
        
        return logs[:limit]
    
    def get_log(self, log_id: str) -> Optional[ForensicsLog]:
        """Get a specific log entry."""
        return self._logs.get(log_id)
    
    def get_log_content(self, log_id: str) -> Tuple[bool, str, Optional[str]]:
        """
        Get the content of a log file.
        Returns (success, message, content).
        """
        log = self._logs.get(log_id)
        if not log:
            return False, "Log not found", None
        
        log_path = Path(log.file_path)
        if not log_path.exists():
            return False, "Log file not found on disk", None
        
        try:
            if log.compressed:
                with gzip.open(log_path, "rt", encoding="utf-8") as f:
                    content = f.read()
            else:
                with open(log_path, "r", encoding="utf-8") as f:
                    content = f.read()
            return True, "OK", content
        except Exception as e:
            return False, f"Failed to read log: {e}", None
    
    def delete_log(self, log_id: str) -> Tuple[bool, str]:
        """Delete a log entry and its file."""
        log = self._logs.get(log_id)
        if not log:
            return False, "Log not found"
        
        try:
            log_path = Path(log.file_path)
            if log_path.exists():
                log_path.unlink()
            
            with self._lock:
                del self._logs[log_id]
            
            self._save_index()
            return True, "Log deleted"
        except Exception as e:
            return False, f"Failed to delete log: {e}"
    
    async def capture_instance_logs(
        self,
        instance_id: str,
        project_name: str,
        challenge_id: str,
        challenge_name: str,
        owner_id: str,
        owner_name: str,
        spawned_by: str,
        terminate_reason: str = "user_stop",
        team_id: Optional[str] = None,
        team_name: Optional[str] = None,
        capture_type: str = "auto"
    ) -> Tuple[bool, str]:
        """
        Capture logs from an instance's containers.
        
        Args:
            instance_id: Unique instance identifier
            project_name: Docker Compose project name
            challenge_id: Challenge ID
            challenge_name: Challenge display name
            owner_id: Owner ID (user or team)
            owner_name: Owner display name
            spawned_by: Username who spawned the instance
            terminate_reason: Why the instance was terminated
            team_id: Team ID if team mode
            team_name: Team name if team mode
            capture_type: "auto" or "live"
        
        Returns:
            (success, message)
        """
        # Check if auto capture should run
        if capture_type == "auto" and not self._auto_capture_enabled:
            return False, "Auto capture is disabled"
        
        async with self._capture_semaphore:
            try:
                timestamp = utcnow().strftime("%Y%m%d_%H%M%S")
                log_id = f"{challenge_id}_{owner_id[:8]}_{timestamp}"
                
                # Determine file extension based on compression
                ext = ".log.gz" if settings.FORENSICS_COMPRESSION else ".log"
                log_file = self.log_dir / f"{log_id}{ext}"
                
                # Get container IDs for this project
                result = await asyncio.create_subprocess_exec(
                    "docker", "compose", "-p", project_name, "ps", "-q",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(result.communicate(), timeout=10)
                
                container_ids = [c.strip() for c in stdout.decode().strip().split("\n") if c.strip()]
                
                if not container_ids:
                    return False, "No containers found for instance"
                
                # Track container names
                captured_container_names: List[str] = []
                
                # Prepare log content
                log_lines = []
                log_lines.append("=" * 60)
                log_lines.append("WHALEY INSTANCE FORENSICS LOG")
                log_lines.append("=" * 60)
                log_lines.append(f"Log ID: {log_id}")
                log_lines.append(f"Instance ID: {instance_id}")
                log_lines.append(f"Challenge: {challenge_name} ({challenge_id})")
                log_lines.append(f"Owner: {owner_name} (ID: {owner_id})")
                if team_name:
                    log_lines.append(f"Team: {team_name} (ID: {team_id})")
                log_lines.append(f"Spawned by: {spawned_by}")
                log_lines.append(f"Capture Type: {capture_type}")
                log_lines.append(f"Terminate Reason: {terminate_reason}")
                log_lines.append(f"Capture Time: {utcnow().isoformat()}")
                log_lines.append(f"Containers: {len(container_ids)}")
                log_lines.append("=" * 60)
                log_lines.append("")
                
                total_size = 0
                max_size = settings.FORENSICS_MAX_SIZE_MB * 1024 * 1024
                
                for container_id in container_ids:
                    # Get container name
                    name_result = await asyncio.create_subprocess_exec(
                        "docker", "inspect", "--format", "{{.Name}}", container_id,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    name_stdout, _ = await asyncio.wait_for(name_result.communicate(), timeout=5)
                    container_name = name_stdout.decode().strip().lstrip("/")
                    captured_container_names.append(container_name)
                    
                    log_lines.append(f"\n{'─' * 50}")
                    log_lines.append(f"CONTAINER: {container_name}")
                    log_lines.append(f"ID: {container_id[:12]}")
                    log_lines.append(f"{'─' * 50}\n")
                    
                    # Get container logs with tail limit
                    log_result = await asyncio.create_subprocess_exec(
                        "docker", "logs", "--tail", str(settings.FORENSICS_TAIL_LINES),
                        "--timestamps", container_id,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    log_stdout, log_stderr = await asyncio.wait_for(
                        log_result.communicate(), timeout=30
                    )
                    
                    container_logs = log_stdout.decode(errors="replace") + log_stderr.decode(errors="replace")
                    
                    # Check size limit
                    if total_size + len(container_logs) > max_size:
                        remaining = max_size - total_size
                        if remaining > 0:
                            container_logs = container_logs[:remaining]
                            container_logs += f"\n\n[LOG TRUNCATED - Size limit {settings.FORENSICS_MAX_SIZE_MB}MB reached]"
                        else:
                            log_lines.append("[SKIPPED - Size limit reached]")
                            continue
                    
                    log_lines.append(container_logs)
                    total_size += len(container_logs)
                    
                    if total_size >= max_size:
                        log_lines.append(f"\n\n[CAPTURE STOPPED - Total size limit {settings.FORENSICS_MAX_SIZE_MB}MB reached]")
                        break
                
                log_lines.append("\n" + "=" * 60)
                log_lines.append("END OF FORENSICS LOG")
                log_lines.append("=" * 60)
                
                # Write to file
                content = "\n".join(log_lines)
                
                if settings.FORENSICS_COMPRESSION:
                    with gzip.open(log_file, "wt", encoding="utf-8", compresslevel=6) as f:
                        f.write(content)
                else:
                    with open(log_file, "w", encoding="utf-8") as f:
                        f.write(content)
                
                file_size = log_file.stat().st_size
                
                # Create log entry
                forensics_log = ForensicsLog(
                    log_id=log_id,
                    instance_id=instance_id,
                    challenge_id=challenge_id,
                    challenge_name=challenge_name,
                    owner_id=owner_id,
                    owner_name=owner_name,
                    spawned_by=spawned_by,
                    capture_type=capture_type,
                    capture_time=utcnow().isoformat(),
                    terminate_reason=terminate_reason,
                    file_path=str(log_file),
                    file_size_bytes=file_size,
                    compressed=settings.FORENSICS_COMPRESSION,
                    container_count=len(container_ids),
                    container_names=captured_container_names,
                    team_id=team_id,
                    team_name=team_name
                )
                
                with self._lock:
                    self._logs[log_id] = forensics_log
                
                self._save_index()
                
                print(f"[Forensics] Captured logs for {instance_id}: {file_size} bytes, {len(container_ids)} containers")
                return True, f"Captured {len(container_ids)} container logs ({file_size} bytes)"
                
            except asyncio.TimeoutError:
                print(f"[Forensics] Timeout capturing logs for {instance_id}")
                return False, "Capture timeout"
            except Exception as e:
                print(f"[Forensics] Error capturing logs for {instance_id}: {e}")
                return False, f"Capture failed: {e}"
    
    async def live_capture(
        self,
        instance_id: str,
        project_name: str,
        challenge_id: str,
        challenge_name: str,
        owner_id: str,
        owner_name: str,
        spawned_by: str,
        team_id: Optional[str] = None,
        team_name: Optional[str] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Perform a live capture from a running instance.
        Returns (success, message, log_id).
        """
        success, msg = await self.capture_instance_logs(
            instance_id=instance_id,
            project_name=project_name,
            challenge_id=challenge_id,
            challenge_name=challenge_name,
            owner_id=owner_id,
            owner_name=owner_name,
            spawned_by=spawned_by,
            terminate_reason="live_capture",
            team_id=team_id,
            team_name=team_name,
            capture_type="live"
        )
        
        if success:
            # Find the log_id we just created
            timestamp = utcnow().strftime("%Y%m%d_%H%M%S")
            log_id = f"{challenge_id}_{owner_id[:8]}_{timestamp}"
            return True, msg, log_id
        
        return False, msg, None
    
    async def cleanup_old_logs(self) -> int:
        """
        Delete logs older than retention period.
        Returns count of deleted logs.
        """
        try:
            cutoff = utcnow().timestamp() - (settings.FORENSICS_RETENTION_HOURS * 3600)
            deleted = 0
            
            logs_to_delete = []
            for log_id, log in self._logs.items():
                log_path = Path(log.file_path)
                if log_path.exists():
                    if log_path.stat().st_mtime < cutoff:
                        logs_to_delete.append(log_id)
                else:
                    # File doesn't exist, clean up index entry
                    logs_to_delete.append(log_id)
            
            for log_id in logs_to_delete:
                log = self._logs.get(log_id)
                if log:
                    log_path = Path(log.file_path)
                    if log_path.exists():
                        log_path.unlink()
                    with self._lock:
                        del self._logs[log_id]
                    deleted += 1
            
            if deleted > 0:
                self._save_index()
                print(f"[Forensics] Cleaned up {deleted} old logs")
            
            return deleted
        except Exception as e:
            print(f"[Forensics] Cleanup error: {e}")
            return 0
    
    def get_stats(self) -> Dict:
        """Get forensics statistics."""
        total_size = 0
        auto_count = 0
        live_count = 0
        
        for log in self._logs.values():
            total_size += log.file_size_bytes
            if log.capture_type == "auto":
                auto_count += 1
            else:
                live_count += 1
        
        return {
            "auto_capture_enabled": self._auto_capture_enabled,
            "total_logs": len(self._logs),
            "auto_capture_count": auto_count,
            "live_capture_count": live_count,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "retention_hours": settings.FORENSICS_RETENTION_HOURS,
            "max_size_per_capture_mb": settings.FORENSICS_MAX_SIZE_MB,
            "compression_enabled": settings.FORENSICS_COMPRESSION
        }
    
    def clear_all_logs(self) -> Tuple[bool, str]:
        """Delete all forensics logs. Use with caution!"""
        try:
            count = len(self._logs)
            
            for log in list(self._logs.values()):
                log_path = Path(log.file_path)
                if log_path.exists():
                    log_path.unlink()
            
            with self._lock:
                self._logs.clear()
            
            self._save_index()
            return True, f"Deleted {count} logs"
        except Exception as e:
            return False, f"Failed to clear logs: {e}"


# Singleton instance
_forensics_manager: Optional[ForensicsManager] = None


def get_forensics_manager() -> ForensicsManager:
    """Get the global ForensicsManager instance."""
    global _forensics_manager
    if _forensics_manager is None:
        _forensics_manager = ForensicsManager()
    return _forensics_manager
