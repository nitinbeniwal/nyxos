"""
NyxOS Dashboard — WebSocket Handler

Provides real-time event broadcasting to connected dashboard clients.
Events include: command execution, new findings, AI status, scan progress, token updates.

WebSocket endpoint: ws://localhost:8080/ws/live
Message format: {"event": "event_type", "data": {...}, "timestamp": "..."}
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from loguru import logger

from nyxos.dashboard.backend.models.schemas import WebSocketEvent

router = APIRouter()


class ConnectionManager:
    """
    Manages WebSocket connections and broadcasts events to all connected clients.

    This is a singleton-style manager — import the global `manager` instance
    from this module to broadcast events from anywhere in NyxOS.

    Usage:
        from nyxos.dashboard.backend.api.websocket import manager
        await manager.broadcast("finding_new", {"title": "Open port found", ...})
    """

    def __init__(self) -> None:
        """Initialize the connection manager with an empty connection list."""
        self._active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        """Return the number of active WebSocket connections."""
        return len(self._active_connections)

    async def connect(self, websocket: WebSocket) -> None:
        """
        Accept and register a new WebSocket connection.

        Args:
            websocket: The incoming WebSocket connection to accept.
        """
        await websocket.accept()
        async with self._lock:
            self._active_connections.append(websocket)
        logger.info(
            f"WebSocket client connected. Active connections: {self.connection_count}"
        )
        # Send a welcome event
        await self.send_personal(
            websocket,
            "connected",
            {
                "message": "Connected to NyxOS Dashboard",
                "connections": self.connection_count,
            },
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """
        Remove a WebSocket connection from the active list.

        Args:
            websocket: The WebSocket connection to remove.
        """
        async with self._lock:
            if websocket in self._active_connections:
                self._active_connections.remove(websocket)
        logger.info(
            f"WebSocket client disconnected. Active connections: {self.connection_count}"
        )

    async def send_personal(
        self,
        websocket: WebSocket,
        event_type: str,
        data: Dict[str, Any],
    ) -> None:
        """
        Send a message to a specific WebSocket client.

        Args:
            websocket: Target WebSocket connection.
            event_type: The event type identifier.
            data: The event payload dictionary.
        """
        event = WebSocketEvent(
            event=event_type,
            data=data,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
        try:
            await websocket.send_text(event.model_dump_json())
        except Exception as e:
            logger.warning(f"Failed to send personal WebSocket message: {e}")
            await self.disconnect(websocket)

    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        Broadcast an event to all connected WebSocket clients.

        Disconnected or erroring clients are automatically cleaned up.

        Args:
            event_type: The event type identifier (e.g., "finding_new", "command_completed").
            data: The event payload dictionary.
        """
        if not self._active_connections:
            return

        event = WebSocketEvent(
            event=event_type,
            data=data,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
        message = event.model_dump_json()

        disconnected: List[WebSocket] = []

        async with self._lock:
            connections = list(self._active_connections)

        for connection in connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.warning(f"Failed to broadcast to client: {e}")
                disconnected.append(connection)

        # Clean up dead connections
        for ws in disconnected:
            await self.disconnect(ws)

    async def broadcast_command_started(
        self,
        command: str,
        source: str = "shell",
    ) -> None:
        """
        Broadcast that a command execution has started.

        Args:
            command: The command string being executed.
            source: Where the command originated ("shell" or "dashboard").
        """
        await self.broadcast(
            "command_started",
            {"command": command, "source": source},
        )

    async def broadcast_command_completed(
        self,
        command: str,
        success: bool,
        output: str = "",
        findings_count: int = 0,
        duration_seconds: float = 0.0,
    ) -> None:
        """
        Broadcast that a command execution has completed.

        Args:
            command: The command that was executed.
            success: Whether execution succeeded.
            output: Truncated command output (max 5000 chars for WebSocket).
            findings_count: Number of findings produced.
            duration_seconds: How long the command took.
        """
        await self.broadcast(
            "command_completed",
            {
                "command": command,
                "success": success,
                "output": output[:5000],
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
            },
        )

    async def broadcast_finding(self, finding: Dict[str, Any]) -> None:
        """
        Broadcast a newly discovered finding.

        Args:
            finding: The finding dictionary.
        """
        await self.broadcast("finding_new", finding)

    async def broadcast_ai_thinking(self, status: str = "thinking") -> None:
        """
        Broadcast AI thinking/processing status.

        Args:
            status: Current AI status ("thinking", "responding", "idle").
        """
        await self.broadcast("ai_thinking", {"status": status})

    async def broadcast_scan_progress(
        self,
        scan_id: str,
        progress: float,
        message: str = "",
    ) -> None:
        """
        Broadcast scan progress update.

        Args:
            scan_id: Unique scan identifier.
            progress: Progress percentage (0.0 to 100.0).
            message: Human-readable progress message.
        """
        await self.broadcast(
            "scan_progress",
            {
                "scan_id": scan_id,
                "progress": min(100.0, max(0.0, progress)),
                "message": message,
            },
        )

    async def broadcast_token_update(
        self,
        tokens_used: int,
        tokens_remaining: int,
        provider: str,
    ) -> None:
        """
        Broadcast token usage update.

        Args:
            tokens_used: Tokens used in the last operation.
            tokens_remaining: Remaining daily budget.
            provider: AI provider name.
        """
        await self.broadcast(
            "token_update",
            {
                "tokens_used": tokens_used,
                "tokens_remaining": tokens_remaining,
                "provider": provider,
            },
        )


# ---------------------------------------------------------------------------
# Global singleton — import this from other modules to broadcast events
# ---------------------------------------------------------------------------
manager = ConnectionManager()


# ---------------------------------------------------------------------------
# Synchronous broadcast helper for non-async code (shell, skills, etc.)
# ---------------------------------------------------------------------------
def sync_broadcast(event_type: str, data: Dict[str, Any]) -> None:
    """
    Broadcast a WebSocket event from synchronous code.

    Attempts to schedule the broadcast on the running event loop.
    If no event loop is running, the broadcast is silently skipped.

    Args:
        event_type: The event type identifier.
        data: The event payload dictionary.
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(manager.broadcast(event_type, data))
    except RuntimeError:
        # No running event loop — try to get or create one
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(manager.broadcast(event_type, data))
            else:
                # Can't broadcast without a running loop; skip silently
                pass
        except RuntimeError:
            pass


# ---------------------------------------------------------------------------
# WebSocket Route
# ---------------------------------------------------------------------------
@router.websocket("/live")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """
    Main WebSocket endpoint for real-time dashboard updates.

    Clients connect to ws://localhost:8080/ws/live and receive JSON events.
    Clients can also send messages (currently: ping/pong only).

    Event types broadcast to clients:
        - connected: Initial connection confirmation
        - command_started: A command has begun executing
        - command_completed: A command has finished
        - finding_new: A new security finding was discovered
        - ai_thinking: AI is processing a request
        - scan_progress: Scan progress update (0-100%)
        - token_update: Token budget change
        - heartbeat: Keep-alive ping
    """
    await manager.connect(websocket)
    try:
        while True:
            # Listen for incoming messages from the client
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                event = message.get("event", "")

                if event == "ping":
                    await manager.send_personal(
                        websocket,
                        "pong",
                        {"message": "alive"},
                    )
                elif event == "subscribe":
                    # Future: allow subscribing to specific event types
                    await manager.send_personal(
                        websocket,
                        "subscribed",
                        {"channels": message.get("data", {}).get("channels", ["*"])},
                    )
                else:
                    await manager.send_personal(
                        websocket,
                        "error",
                        {"message": f"Unknown event: {event}"},
                    )
            except json.JSONDecodeError:
                await manager.send_personal(
                    websocket,
                    "error",
                    {"message": "Invalid JSON"},
                )
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(websocket)
