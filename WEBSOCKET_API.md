# WebSocket API Documentation

## Endpoints

### 1. Scan Progress: `/ws/scans/{scan_id}`

Connect to receive real-time updates for a specific scan.

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/scans/123');
```

**Events:**
- `connected`: Initial connection confirmation
- `scan_started`: Scan has begun
- `scan_progress`: Progress update during scanning
- `scan_completed`: Scan finished successfully
- `scan_failed`: Scan encountered an error
- `pong`: Response to ping message

**Message Format:**
```json
{
    "event": "scan_started|scan_progress|scan_completed|scan_failed",
    "scan_id": 123,
    "message": "Human-readable message",
    "data": {
        "target_url": "https://example.com",
        "vulnerability_count": 5,
        "message": "Additional details",
        ...
    },
    "timestamp": "2024-01-01T00:00:00Z"
}
```

**Example Messages:**

```json
// Connected
{
    "event": "connected",
    "scan_id": 123,
    "message": "Connected to scan progress stream"
}

// Scan Started
{
    "event": "scan_started",
    "scan_id": 123,
    "message": "Scan started",
    "data": {
        "scan_id": 123,
        "message": "Scan started"
    }
}

// Progress Update
{
    "event": "scan_progress",
    "scan_id": 123,
    "message": "Running SQL Injection scan...",
    "data": {
        "scan_id": 123,
        "message": "Running SQL Injection scan...",
        "target_url": "https://example.com"
    }
}

// Completed
{
    "event": "scan_completed",
    "scan_id": 123,
    "message": "Scan completed. Found 5 vulnerabilities",
    "data": {
        "scan_id": 123,
        "message": "Scan completed. Found 5 vulnerabilities",
        "vulnerability_count": 5
    }
}
```

---

### 2. Activity Feed: `/ws/activity/{feed_id}`

Connect to receive real-time activity updates (crawl, etc.).

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/activity/crawl');
```

**Feed IDs:**
- `crawl`: Website crawling/spidering activity

**Events:**
- `connected`: Initial connection confirmation
- `crawl_started`: Crawl has begun
- `crawl_progress`: Currently scanning a URL
- `crawl_found`: Found a new URL or form
- `crawl_completed`: Crawl finished
- `crawl_failed`: Crawl encountered an error
- `pong`: Response to ping message

**Message Format:**
```json
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
```

**Example Messages:**

```json
// Connected
{
    "event": "connected",
    "feed_id": "crawl",
    "message": "Connected to activity feed: crawl"
}

// Crawl Started
{
    "event": "crawl_started",
    "message": "Starting crawl of https://example.com",
    "type": "crawl",
    "data": {
        "message": "Starting crawl of https://example.com",
        "target_url": "https://example.com",
        "max_depth": 3
    }
}

// Scanning Progress
{
    "event": "crawl_progress",
    "message": "Scanning: https://example.com/admin/login",
    "type": "crawl",
    "data": {
        "message": "Scanning: https://example.com/admin/login",
        "url": "https://example.com/admin/login",
        "depth": 2,
        "status_code": null
    }
}

// Found Form
{
    "event": "crawl_found",
    "message": "Found 2 form(s) at https://example.com/search",
    "type": "crawl",
    "data": {
        "message": "Found 2 form(s) at https://example.com/search",
        "url": "https://example.com/search",
        "form_count": 2
    }
}

// Found Link
{
    "event": "crawl_found",
    "message": "Found: https://example.com/products",
    "type": "crawl",
    "data": {
        "message": "Found: https://example.com/products",
        "url": "https://example.com/products",
        "depth": 3
    }
}

// Crawl Completed
{
    "event": "crawl_completed",
    "message": "Crawl completed. Found 10 pages, 15 forms",
    "type": "crawl",
    "data": {
        "message": "Crawl completed. Found 10 pages, 15 forms",
        "page_count": 10,
        "form_count": 15,
        "total_links": 25
    }
}
```

## Frontend Implementation Example

### React Hook for WebSocket

```javascript
import { useEffect, useState } from 'react';

function useWebSocket(url) {
    const [messages, setMessages] = useState([]);
    const [connected, setConnected] = useState(false);

    useEffect(() => {
        const ws = new WebSocket(url);
        
        ws.onopen = () => {
            setConnected(true);
        };
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            setMessages(prev => [...prev, data]);
        };
        
        ws.onclose = () => {
            setConnected(false);
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
        
        // Ping every 30 seconds to keep connection alive
        const pingInterval = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send('ping');
            }
        }, 30000);
        
        return () => {
            clearInterval(pingInterval);
            ws.close();
        };
    }, [url]);
    
    return { messages, connected };
}
```

### Activity Feed Component

```javascript
function CrawlActivityFeed({ crawlId }) {
    const { messages, connected } = useWebSocket(`ws://localhost:8000/ws/activity/${crawlId}`);
    
    return (
        <div className="activity-feed">
            <div className={`status ${connected ? 'connected' : 'disconnected'}`}>
                {connected ? '🟢 Connected' : '🔴 Disconnected'}
            </div>
            <div className="log-container">
                {messages.map((msg, idx) => (
                    <div key={idx} className={`log-entry log-${msg.event}`}>
                        <span className="timestamp">{new Date().toLocaleTimeString()}</span>
                        <span className="event">{msg.event}</span>
                        <span className="message">{msg.message}</span>
                    </div>
                ))}
            </div>
        </div>
    );
}
```

### CSS for Terminal-like Log

```css
.activity-feed {
    background: #1e1e1e;
    color: #d4d4d4;
    font-family: 'Courier New', monospace;
    padding: 1rem;
    border-radius: 4px;
    height: 400px;
    overflow-y: auto;
}

.log-container {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.log-entry {
    padding: 0.25rem 0.5rem;
    border-left: 3px solid transparent;
}

.log-entry.log-crawl_started {
    border-left-color: #4ec9b0;
    color: #4ec9b0;
}

.log-entry.log-crawl_progress {
    border-left-color: #569cd6;
    color: #d4d4d4;
}

.log-entry.log-crawl_found {
    border-left-color: #ce9178;
    color: #ce9178;
}

.log-entry.log-crawl_completed {
    border-left-color: #4ec9b0;
    color: #4ec9b0;
    font-weight: bold;
}

.log-entry.log-crawl_failed {
    border-left-color: #f48771;
    color: #f48771;
}

.timestamp {
    color: #808080;
    margin-right: 0.5rem;
}

.event {
    color: #569cd6;
    margin-right: 0.5rem;
    font-weight: bold;
}

.status {
    padding: 0.5rem;
    margin-bottom: 0.5rem;
    border-radius: 4px;
}

.status.connected {
    background: #264f78;
    color: #4ec9b0;
}

.status.disconnected {
    background: #5a1d1d;
    color: #f48771;
}
```

## Message Structure Summary

All messages follow this structure:

```typescript
interface WebSocketMessage {
    event: string;           // Event type identifier
    message: string;         // Human-readable message
    data?: object;          // Additional event-specific data
    scan_id?: number;       // Present in scan-specific messages
    feed_id?: string;       // Present in activity feed messages
    type?: string;          // Present in activity feed messages (e.g., "crawl")
    timestamp?: string;     // ISO 8601 timestamp (optional)
}
```

## Best Practices

1. **Connection Management**: Implement reconnection logic for dropped connections
2. **Ping/Pong**: Send ping messages periodically to keep connection alive
3. **Message Queuing**: Queue messages if connection is temporarily unavailable
4. **Error Handling**: Handle connection errors gracefully
5. **Message Filtering**: Filter messages by event type for different UI components
6. **Performance**: Limit message history to prevent memory issues

