"""WebSocket connection manager with pub/sub broadcast for real-time updates."""

import asyncio
import json
from typing import Any, Dict, List, Optional

from fastapi import WebSocket


class ConnectionManager:
    """Manages WebSocket connections and broadcasts events to subscribers.

    Two channels:
      - Public: instance updates scoped to a user/team (authenticated via CTFd token)
      - Admin: all instance updates + stats (authenticated via admin key)
    """

    def __init__(self) -> None:
        # Public connections keyed by owner_id (user_id or team_id)
        self._public: Dict[str, List[WebSocket]] = {}
        # Admin connections
        self._admin: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect_public(self, owner_id: str, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._public.setdefault(owner_id, []).append(ws)

    async def connect_admin(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._admin.append(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            for owner_id in list(self._public):
                bucket = self._public[owner_id]
                try:
                    bucket.remove(ws)
                except ValueError:
                    pass
                if not bucket:
                    del self._public[owner_id]
            try:
                self._admin.remove(ws)
            except ValueError:
                pass

    async def _send(self, ws: WebSocket, payload: Dict[str, Any]) -> None:
        try:
            await ws.send_json(payload)
        except Exception:
            await self.disconnect(ws)

    async def broadcast_to_owner(self, owner_id: str, event: str, data: Any) -> None:
        """Send an event to all WebSocket connections for a given owner."""
        payload = {"event": event, "data": data}
        async with self._lock:
            targets = list(self._public.get(owner_id, []))
        await asyncio.gather(*(self._send(ws, payload) for ws in targets), return_exceptions=True)

    async def broadcast_to_owners(self, owner_ids: List[str], event: str, data: Any) -> None:
        """Send an event to multiple owners at once."""
        payload = {"event": event, "data": data}
        async with self._lock:
            targets = []
            for oid in owner_ids:
                targets.extend(self._public.get(oid, []))
            unique = list({id(ws): ws for ws in targets}.values())
        await asyncio.gather(*(self._send(ws, payload) for ws in unique), return_exceptions=True)

    async def broadcast_admin(self, event: str, data: Any) -> None:
        """Send an event to all admin WebSocket connections."""
        payload = {"event": event, "data": data}
        async with self._lock:
            targets = list(self._admin)
        await asyncio.gather(*(self._send(ws, payload) for ws in targets), return_exceptions=True)

    @property
    def public_count(self) -> int:
        total = 0
        for bucket in self._public.values():
            total += len(bucket)
        return total

    @property
    def admin_count(self) -> int:
        return len(self._admin)


# Module-level singleton
_manager: Optional[ConnectionManager] = None


def get_ws_manager() -> ConnectionManager:
    global _manager
    if _manager is None:
        _manager = ConnectionManager()
    return _manager
