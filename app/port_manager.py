"""Port management for dynamic port allocation with database persistence."""
import hashlib
import socket
from typing import Dict, Set, Optional, List

from sqlalchemy import select, delete

from .database.connection import get_async_session
from .database.models import UserPortMapping
from .distributed_lock import get_lock_manager


class PortManager:
    """
    Manages port allocation for challenge instances with database persistence.
    
    Uses distributed locking for safe concurrent access across multiple workers.
    Replaces JSON file storage with SQLite/PostgreSQL database.
    """
    
    def __init__(self, port_start: int, port_end: int):
        self.port_start = port_start
        self.port_end = port_end
        self.allocated_ports: Set[int] = set()
        self.instance_ports: Dict[str, Set[int]] = {}  # instance_id -> ports

        # Organized allocation strategy: deterministic lane-based distribution.
        self._range_size = self.port_end - self.port_start + 1
        self._lane_count = max(1, min(32, self._range_size))
        self._lane_cursors: Dict[int, int] = {lane: 0 for lane in range(self._lane_count)}

        self._lock_manager = get_lock_manager()
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize port manager and load existing allocations."""
        if self._initialized:
            return
        
        # Load currently allocated ports from active instances
        # This is done to prevent conflicts with running instances
        self._initialized = True
        print(f"[PortManager] Initialized with range {self.port_start}-{self.port_end}")
    
    def _is_port_available(self, port: int) -> bool:
        """Check if a port is available on the system."""
        if port in self.allocated_ports:
            return False
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.bind(('', port))
                return True
        except (socket.error, OSError):
            return False

    def _is_port_in_range(self, port: int) -> bool:
        """Validate that external port is inside configured range."""
        return self.port_start <= port <= self.port_end

    def _can_use_external_port(self, port: int) -> bool:
        """Hard safety check before any external port allocation."""
        if not self._is_port_in_range(port):
            return False
        return self._is_port_available(port)

    def _reserve_port(self, instance_id: str, port: int) -> None:
        """Reserve a validated external port for an instance."""
        self.allocated_ports.add(port)
        if instance_id not in self.instance_ports:
            self.instance_ports[instance_id] = set()
        self.instance_ports[instance_id].add(port)

    def _lane_capacity(self, lane_index: int) -> int:
        """Return how many ports exist in a specific allocation lane."""
        if lane_index >= self._range_size:
            return 0
        return ((self._range_size - 1 - lane_index) // self._lane_count) + 1

    def _lane_port_at(self, lane_index: int, lane_offset: int) -> int:
        """Resolve lane offset to actual external port number."""
        return self.port_start + lane_index + (lane_offset * self._lane_count)

    def _hash_to_lane(self, user_id: str, challenge_id: str, internal_port: int) -> int:
        """Deterministically map owner/challenge/port to a lane index."""
        key = f"{user_id}:{challenge_id}:{internal_port}".encode("utf-8")
        digest = hashlib.blake2b(key, digest_size=4).digest()
        return int.from_bytes(digest, "big") % self._lane_count

    def _allocate_from_lane(self, instance_id: str, lane_index: int) -> Optional[int]:
        """Allocate the next available port in a lane, advancing lane cursor."""
        capacity = self._lane_capacity(lane_index)
        if capacity <= 0:
            return None

        cursor = self._lane_cursors.get(lane_index, 0) % capacity
        for shift in range(capacity):
            lane_offset = (cursor + shift) % capacity
            candidate = self._lane_port_at(lane_index, lane_offset)
            if self._can_use_external_port(candidate):
                self._reserve_port(instance_id, candidate)
                self._lane_cursors[lane_index] = (lane_offset + 1) % capacity
                return candidate

        return None

    def _allocate_organized_port(
        self,
        instance_id: str,
        user_id: str,
        challenge_id: str,
        internal_port: int,
    ) -> Optional[int]:
        """
        Allocate in deterministic lanes (not serial and not random).

        Primary lane is stable per owner/challenge/internal-port.
        If full, walk other lanes in deterministic order.
        """
        primary_lane = self._hash_to_lane(user_id, challenge_id, internal_port)

        for step in range(self._lane_count):
            lane_index = (primary_lane + step) % self._lane_count
            allocated = self._allocate_from_lane(instance_id, lane_index)
            if allocated is not None:
                return allocated

        return None
    
    async def get_user_saved_ports(
        self, 
        user_id: str, 
        challenge_id: str
    ) -> Optional[Dict[int, int]]:
        """Get previously saved port mapping for a user+challenge combo from database."""
        async with get_async_session() as session:
            result = await session.execute(
                select(UserPortMapping)
                .where(
                    UserPortMapping.user_id == user_id,
                    UserPortMapping.challenge_id == challenge_id
                )
            )
            mappings = result.scalars().all()
            
            if not mappings:
                return None
            
            return {m.internal_port: m.external_port for m in mappings}
    
    async def save_user_ports(
        self,
        user_id: str,
        challenge_id: str,
        port_mapping: Dict[int, int],
        username: Optional[str] = None
    ) -> None:
        """Save port mapping for a user+challenge combo to database."""
        async with get_async_session() as session:
            # Delete existing mappings for this user+challenge
            await session.execute(
                delete(UserPortMapping)
                .where(
                    UserPortMapping.user_id == user_id,
                    UserPortMapping.challenge_id == challenge_id
                )
            )
            
            # Insert new mappings
            for internal_port, external_port in port_mapping.items():
                mapping = UserPortMapping(
                    user_id=user_id,
                    username=username,
                    challenge_id=challenge_id,
                    internal_port=internal_port,
                    external_port=external_port
                )
                session.add(mapping)
            
            await session.commit()
    
    def allocate_port(self, instance_id: str) -> Optional[int]:
        """
        Allocate a port using lane order (organized, deterministic, non-random).

        Used by generic callers without owner context.
        """
        for lane_index in range(self._lane_count):
            allocated = self._allocate_from_lane(instance_id, lane_index)
            if allocated is not None:
                return allocated

        return None
    
    def allocate_specific_port(self, instance_id: str, port: int) -> bool:
        """Try to allocate a specific port for an instance."""
        if self._can_use_external_port(port):
            self._reserve_port(instance_id, port)
            return True
        return False
    
    def allocate_ports(self, instance_id: str, count: int) -> List[int]:
        """Allocate multiple ports for an instance."""
        ports = []
        for _ in range(count):
            port = self.allocate_port(instance_id)
            if port is None:
                # Rollback allocated ports
                self.release_instance_ports(instance_id)
                return []
            ports.append(port)
        return ports
    
    async def allocate_ports_for_user(
        self,
        instance_id: str,
        user_id: str,
        challenge_id: str,
        internal_ports: List[int],
        username: Optional[str] = None
    ) -> Optional[Dict[int, int]]:
        """
        Allocate ports for a user, trying to reuse their saved ports.
        Uses distributed locking for safe concurrent access.
        
        Returns:
            Mapping of internal_port -> external_port, or None if failed.
        """
        lock_name = f"port:user:{user_id}:{challenge_id}"

        # Global allocator lock keeps the check-and-reserve sequence atomic
        # across users and workers, preventing duplicate external allocations.
        allocator_lock_name = "port:allocator"

        async with self._lock_manager.acquire(lock_name, timeout=30):
            async with self._lock_manager.acquire(allocator_lock_name, timeout=30):
                # Check for saved ports
                saved_mapping = await self.get_user_saved_ports(user_id, challenge_id)
                port_mapping: Dict[int, int] = {}

                if saved_mapping:
                    # Try to reuse saved ports, but reassign immediately if any are occupied.
                    all_available = True
                    seen_external_ports: Set[int] = set()

                    for internal_port in internal_ports:
                        if internal_port not in saved_mapping:
                            all_available = False
                            break

                        saved_external = saved_mapping[internal_port]
                        if saved_external in seen_external_ports:
                            all_available = False
                            break

                        if self.allocate_specific_port(instance_id, saved_external):
                            port_mapping[internal_port] = saved_external
                            seen_external_ports.add(saved_external)
                        else:
                            all_available = False
                            break

                    if all_available and len(port_mapping) == len(internal_ports):
                        # Successfully reused all saved ports
                        return port_mapping

                    # Some saved ports are missing or occupied: release and reassign.
                    self.release_instance_ports(instance_id)
                    port_mapping = {}

                # Allocate new ports with deterministic organized distribution.
                for internal_port in internal_ports:
                    external_port = self._allocate_organized_port(
                        instance_id=instance_id,
                        user_id=user_id,
                        challenge_id=challenge_id,
                        internal_port=internal_port,
                    )
                    if external_port is None:
                        self.release_instance_ports(instance_id)
                        return None
                    port_mapping[internal_port] = external_port

                # Save the new mapping to database
                await self.save_user_ports(user_id, challenge_id, port_mapping, username)

                return port_mapping
    
    def release_port(self, port: int) -> None:
        """Release a single port."""
        self.allocated_ports.discard(port)
    
    def release_instance_ports(self, instance_id: str) -> None:
        """Release all ports allocated to an instance."""
        if instance_id in self.instance_ports:
            for port in self.instance_ports[instance_id]:
                self.allocated_ports.discard(port)
            del self.instance_ports[instance_id]
    
    def get_instance_ports(self, instance_id: str) -> Set[int]:
        """Get all ports allocated to an instance."""
        return self.instance_ports.get(instance_id, set())
    
    def get_allocated_count(self) -> int:
        """Get the count of allocated ports."""
        return len(self.allocated_ports)
    
    def get_available_count(self) -> int:
        """Get the count of potentially available ports."""
        return (self.port_end - self.port_start + 1) - len(self.allocated_ports)
    
    async def clear_all_user_mappings(self) -> int:
        """Clear all persistent user port mappings. Returns count cleared."""
        async with get_async_session() as session:
            result = await session.execute(
                select(UserPortMapping)
            )
            count = len(result.scalars().all())
            
            await session.execute(delete(UserPortMapping))
            await session.commit()
            
            return count
    
    async def get_port_stats(self) -> Dict:
        """Get port usage statistics."""
        total_range = self.port_end - self.port_start + 1
        allocated = len(self.allocated_ports)
        
        # Count persistent mappings from database
        async with get_async_session() as session:
            result = await session.execute(select(UserPortMapping))
            mappings = result.scalars().all()
            
            persistent_ports = set()
            users = set()
            challenge_combos = set()
            
            for m in mappings:
                persistent_ports.add(m.external_port)
                users.add(m.user_id)
                challenge_combos.add((m.user_id, m.challenge_id))
        
        return {
            "port_range_start": self.port_start,
            "port_range_end": self.port_end,
            "total_range": total_range,
            "currently_allocated": allocated,
            "available": total_range - allocated,
            "persistent_users": len(users),
            "persistent_mappings": len(challenge_combos),
            "persistent_ports_count": len(persistent_ports),
            "usage_percent": round((allocated / total_range) * 100, 2) if total_range > 0 else 0
        }
