"""WebSocket routes: /ws for players (CTFd token) and /ws/admin (admin key).

Extracted from main.py. The lifecycle hook and broadcast helpers that push events
through these connections stay in main.py; the routes only accept and hold sockets.
"""
import asyncio

from fastapi import APIRouter, Query, WebSocket

from ..auth import ctfd_auth, is_team_mode
from ..config import settings
from ..websocket import get_ws_manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws")
async def ws_public(ws: WebSocket, token: str = Query(None)):
    """Public WebSocket for real-time instance updates (authenticated via CTFd token)."""
    if not token:
        await ws.close(code=4001, reason="Missing token query parameter")
        return

    user = await ctfd_auth.validate_token(token)
    if user is None:
        await ws.close(code=4001, reason="Invalid CTFd token")
        return

    owner_id = user.team_id if is_team_mode() and user.team_id else user.user_id
    wsm = get_ws_manager()
    await wsm.connect_public(owner_id, ws)

    try:
        while True:
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=60)
                if data == "ping":
                    await ws.send_text("pong")
            except asyncio.TimeoutError:
                await ws.send_text("pong")
    except Exception:
        pass
    finally:
        await wsm.disconnect(ws)


@router.websocket("/ws/admin")
async def ws_admin(ws: WebSocket, admin_key: str = Query(None)):
    """Admin WebSocket for real-time instance and stats updates."""
    if not settings.ADMIN_KEY:
        await ws.close(code=4001, reason="Admin key not configured")
        return
    if not admin_key or admin_key != settings.ADMIN_KEY:
        await ws.close(code=4001, reason="Invalid admin key")
        return

    wsm = get_ws_manager()
    await wsm.connect_admin(ws)

    try:
        while True:
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=60)
                if data == "ping":
                    await ws.send_text("pong")
            except asyncio.TimeoutError:
                await ws.send_text("pong")
    except Exception:
        pass
    finally:
        await wsm.disconnect(ws)
