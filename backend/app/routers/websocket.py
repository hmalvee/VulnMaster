"""
WebSocket endpoints for real-time scan progress updates and crawl activity.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import logging
from typing import Dict, List, Optional

router = APIRouter(prefix="/ws", tags=["websocket"])
logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections for real-time updates.
    Supports both scan-specific connections and general activity feeds.
    """
    
    def __init__(self):
        # Map of scan_id -> list of WebSocket connections
        self.active_connections: Dict[int, List[WebSocket]] = {}
        # Map of activity_feed_id -> list of WebSocket connections (for crawl events)
        self.activity_feeds: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, scan_id: Optional[int] = None, feed_id: Optional[str] = None):
        """
        Accept a WebSocket connection.
        
        Args:
            websocket: WebSocket connection
            scan_id: Optional scan ID for scan-specific updates
            feed_id: Optional feed ID for activity feed (e.g., "crawl")
        """
        await websocket.accept()
        
        if scan_id is not None:
            if scan_id not in self.active_connections:
                self.active_connections[scan_id] = []
            self.active_connections[scan_id].append(websocket)
            logger.info(f"WebSocket connected for scan {scan_id}")
        
        if feed_id is not None:
            if feed_id not in self.activity_feeds:
                self.activity_feeds[feed_id] = []
            self.activity_feeds[feed_id].append(websocket)
            logger.info(f"WebSocket connected for activity feed {feed_id}")
    
    def disconnect(self, websocket: WebSocket, scan_id: Optional[int] = None, feed_id: Optional[str] = None):
        """Remove a WebSocket connection."""
        if scan_id is not None and scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)
                if not self.active_connections[scan_id]:
                    del self.active_connections[scan_id]
            logger.info(f"WebSocket disconnected for scan {scan_id}")
        
        if feed_id is not None and feed_id in self.activity_feeds:
            if websocket in self.activity_feeds[feed_id]:
                self.activity_feeds[feed_id].remove(websocket)
                if not self.activity_feeds[feed_id]:
                    del self.activity_feeds[feed_id]
            logger.info(f"WebSocket disconnected for activity feed {feed_id}")
    
    async def send_progress(self, scan_id: int, message: dict):
        """
        Send progress update to all connections for a scan.
        
        Args:
            scan_id: Scan ID
            message: Message dictionary to send
        """
        if scan_id in self.active_connections:
            disconnected = []
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error sending WebSocket message: {e}")
                    disconnected.append(connection)
            
            # Remove disconnected connections
            for conn in disconnected:
                self.disconnect(conn, scan_id=scan_id)
    
    async def send_activity(self, feed_id: str, message: dict):
        """
        Send activity update to all connections in an activity feed.
        
        Args:
            feed_id: Feed ID (e.g., "crawl")
            message: Message dictionary to send
        """
        if feed_id in self.activity_feeds:
            disconnected = []
            for connection in self.activity_feeds[feed_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error sending activity message: {e}")
                    disconnected.append(connection)
            
            # Remove disconnected connections
            for conn in disconnected:
                self.disconnect(conn, feed_id=feed_id)


# Global connection manager
manager = ConnectionManager()


def create_progress_callback(scan_id: int):
    """
    Create a progress callback function for scanner service.
    
    Args:
        scan_id: Scan ID
        
    Returns:
        Async callback function
    """
    async def callback(event: str, data: dict):
        """Progress callback that sends WebSocket messages."""
        message = {
            "event": event,
            "scan_id": scan_id,
            "message": data.get("message", ""),
            "data": data,
            "timestamp": data.get("timestamp")
        }
        await manager.send_progress(scan_id, message)
    
    return callback


def create_crawl_callback(feed_id: str = "crawl"):
    """
    Create a callback function for spider service crawl progress.
    
    Args:
        feed_id: Activity feed ID (default: "crawl")
        
    Returns:
        Async callback function
    """
    async def callback(event: str, data: dict):
        """Crawl progress callback that sends WebSocket messages."""
        message = {
            "event": event,
            "message": data.get("message", ""),
            "data": data,
            "type": "crawl"  # Indicates this is a crawl event
        }
        await manager.send_activity(feed_id, message)
    
    return callback


@router.websocket("/scans/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: int):
    """
    WebSocket endpoint for real-time scan progress updates.
    
    Connect to this endpoint to receive live updates during scanning:
    - scan_started: Scan has begun
    - scan_progress: Progress update with message
    - scan_completed: Scan finished successfully
    - scan_failed: Scan encountered an error
    
    Message Format:
    {
        "event": "scan_started|scan_progress|scan_completed|scan_failed",
        "scan_id": 123,
        "message": "Human-readable message",
        "data": {
            "target_url": "...",
            "vulnerability_count": 0,
            ...
        },
        "timestamp": "2024-01-01T00:00:00Z"
    }
    """
    await manager.connect(websocket, scan_id=scan_id)
    
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "event": "connected",
            "scan_id": scan_id,
            "message": "Connected to scan progress stream"
        })
        
        # Keep connection alive and listen for messages
        while True:
            data = await websocket.receive_text()
            # Echo back (client can send ping/pong if needed)
            if data == "ping":
                await websocket.send_json({"event": "pong", "scan_id": scan_id})
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id=scan_id)
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
        manager.disconnect(websocket, scan_id=scan_id)


@router.websocket("/activity/{feed_id}")
async def websocket_activity_feed(websocket: WebSocket, feed_id: str):
    """
    WebSocket endpoint for real-time activity feeds (crawl, etc.).
    
    Connect to this endpoint to receive live activity updates:
    - crawl_started: Crawl has begun
    - crawl_progress: Currently scanning a URL
    - crawl_found: Found a new URL or form
    - crawl_completed: Crawl finished
    - crawl_failed: Crawl encountered an error
    
    Message Format:
    {
        "event": "crawl_started|crawl_progress|crawl_found|crawl_completed|crawl_failed",
        "message": "Human-readable message",
        "type": "crawl",
        "data": {
            "url": "https://example.com/admin/login",
            "depth": 2,
            "form_count": 2,
            "page_count": 10,
            "total_links": 25,
            "status_code": 200,
            ...
        }
    }
    
    Example messages:
    - {"event": "crawl_progress", "message": "Scanning: /admin/login", "type": "crawl", "data": {"url": "/admin/login", "depth": 2}}
    - {"event": "crawl_found", "message": "Found 2 form(s) at /search", "type": "crawl", "data": {"url": "/search", "form_count": 2}}
    """
    await manager.connect(websocket, feed_id=feed_id)
    
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "event": "connected",
            "feed_id": feed_id,
            "message": f"Connected to activity feed: {feed_id}"
        })
        
        # Keep connection alive and listen for messages
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"event": "pong", "feed_id": feed_id})
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, feed_id=feed_id)
    except Exception as e:
        logger.error(f"WebSocket error for feed {feed_id}: {e}")
        manager.disconnect(websocket, feed_id=feed_id)
