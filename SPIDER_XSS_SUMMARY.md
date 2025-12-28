# Spider Service & XSS Scanner Implementation Summary

## Completed Tasks

### ✅ Task 1: Async Crawler (Spider Service)
**File**: `backend/app/services/spider.py`

**Features**:
- **BFS Crawling**: Breadth-first search traversal of websites
- **Domain Scoping**: Strictly limits crawling to target domain (no external links)
- **Depth Control**: Configurable max depth (default: 3 levels)
- **Form Extraction**: Extracts all forms with:
  - Action URL (resolved to absolute)
  - HTTP method (GET/POST)
  - All input fields (name, type, required, value)
  - Source URL where form was found
- **Concurrency Control**: Uses `asyncio.Semaphore` to limit concurrent requests (default: 10)
- **Rate Limiting**: Politeness feature to avoid overwhelming target servers
- **Progress Callbacks**: Supports real-time progress updates via WebSocket

**Key Methods**:
- `crawl()`: Main async method to perform BFS crawl
- `_crawl_page()`: Crawls a single page asynchronously
- `_extract_forms()`: Extracts forms from HTML
- `_extract_links()`: Extracts links from HTML
- `get_all_forms()`: Returns all discovered forms
- `get_all_urls()`: Returns all crawled URLs

**Usage**:
```python
from app.services.spider import SpiderService
from app.routers.websocket import create_crawl_callback

# Create callback for WebSocket updates
callback = create_crawl_callback("crawl")

# Initialize spider
spider = SpiderService(
    target_url="https://example.com",
    max_depth=3,
    max_concurrent=10,
    progress_callback=callback
)

# Perform crawl
results = await spider.crawl()

# Get discovered forms
forms = spider.get_all_forms()
```

---

### ✅ Task 2: Reflected XSS Scanner Module
**File**: `backend/scanners/xss.py`

**Features**:
- **Canary Injection**: Uses unique canary string `<vM_t3st_xss>` to detect reflection
- **Context Detection**: Identifies reflection context (HTML, attribute, JavaScript, URL)
- **Safe Testing**: Uses non-executing payloads for testing
- **Educational Fixes**: Provides context-aware encoding explanations

**Detection Logic**:
1. Injects canary string into URL parameters and form inputs
2. Checks if canary is reflected unencoded in response body
3. Validates context type (HTML vs JavaScript vs Attribute)
4. Distinguishes between vulnerable (unencoded) and safe (HTML entity encoded) reflection

**Key Methods**:
- `detect()`: Main async detection method
- `_test_url_parameter()`: Tests URL parameters for XSS
- `_test_form_input()`: Tests form inputs for XSS
- `_check_reflection()`: Checks if canary is reflected and determines context
- `generate_poc()`: Generates safe CURL command with `console.log` payload
- `recommend_fix()`: Provides educational fix with context-aware encoding examples

**Safety**:
- Uses safe canary strings that don't execute
- PoC generation uses harmless `console.log` instead of `alert()`
- Educational focus on detection, not exploitation

**Educational Content**:
- **Cause**: Shows vulnerable code without encoding
- **Fix**: Demonstrates context-aware encoding (HTML, JavaScript, URL, Attribute)
- **Why**: Explains why different contexts need different encoding

---

### ✅ Task 3: Real-Time Progress (WebSockets)
**File**: `backend/app/routers/websocket.py`

**Features**:
- **ConnectionManager**: Enhanced to support both scan-specific and activity feed connections
- **Activity Feeds**: Separate WebSocket endpoint for crawl activity
- **Event Broadcasting**: Real-time event broadcasting to connected clients

**Endpoints**:

1. **`/ws/scans/{scan_id}`**: Scan progress updates
   - Events: `scan_started`, `scan_progress`, `scan_completed`, `scan_failed`

2. **`/ws/activity/{feed_id}`**: Activity feed (crawl events)
   - Events: `crawl_started`, `crawl_progress`, `crawl_found`, `crawl_completed`, `crawl_failed`

**Message Structure**:
```json
{
    "event": "crawl_progress",
    "message": "Scanning: /admin/login",
    "type": "crawl",
    "data": {
        "url": "/admin/login",
        "depth": 2,
        "status_code": 200,
        "form_count": 1
    }
}
```

**Callback Functions**:
- `create_progress_callback(scan_id)`: For scan progress
- `create_crawl_callback(feed_id)`: For crawl activity

---

## Integration Points

### Using SpiderService with ScannerService

```python
from app.services.spider import SpiderService
from app.services.scanner_service import ScannerService
from app.routers.websocket import create_crawl_callback, create_progress_callback

# 1. Crawl the site first
crawl_callback = create_crawl_callback("crawl")
spider = SpiderService(
    target_url="https://example.com",
    progress_callback=crawl_callback
)
crawl_results = await spider.crawl()

# 2. Get discovered forms and URLs
forms = spider.get_all_forms()
urls = spider.get_all_urls()

# 3. Run XSS scanner on discovered attack surfaces
xss_scanner = XSSScanner(target_url)
# (Forms and URLs can be passed to scanner for testing)
vulnerabilities = await xss_scanner.detect()
```

### WebSocket Connection Examples

**Frontend - Crawl Activity Feed**:
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/activity/crawl');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    switch(data.event) {
        case 'crawl_started':
            console.log('Crawl started:', data.data.target_url);
            break;
        case 'crawl_progress':
            console.log('Scanning:', data.data.url);
            break;
        case 'crawl_found':
            if (data.data.form_count) {
                console.log(`Found ${data.data.form_count} form(s) at ${data.data.url}`);
            } else {
                console.log('Found link:', data.data.url);
            }
            break;
        case 'crawl_completed':
            console.log('Crawl completed:', data.data);
            break;
    }
};
```

---

## File Structure

```
backend/
├── app/
│   ├── services/
│   │   ├── spider.py              # NEW: SpiderService with BFS crawler
│   │   └── scanner_service.py     # Existing scanner service
│   └── routers/
│       └── websocket.py           # UPDATED: Added activity feed support
└── scanners/
    ├── xss.py                     # NEW: XSS scanner module
    ├── sqli.py                    # Existing SQL injection scanner
    └── base.py                    # ScannerModule abstract base class
```

---

## Key Design Decisions

1. **BFS Crawling**: Ensures systematic discovery of all pages at each depth level
2. **Form Extraction**: Critical for vulnerability scanning - forms are primary attack surfaces
3. **Canary Injection**: Safe, unique strings that don't execute but clearly show reflection
4. **Context Detection**: Important for educational purposes - different contexts need different fixes
5. **Activity Feeds**: Separate WebSocket endpoint allows multiple clients to monitor crawl progress
6. **Concurrency Control**: Semaphore prevents overwhelming target servers while maintaining speed

---

## Next Steps

1. **Integrate with Scanner Service**: Update scanner service to use spider for discovery
2. **Frontend Components**: Create React components for:
   - Crawl activity feed (terminal-like log)
   - Form discovery display
   - XSS vulnerability results with context information
3. **Enhanced Detection**: Extend XSS scanner to use discovered forms from spider
4. **Additional Scanners**: Add more client-side vulnerability scanners that use spider results

---

## Documentation

- **WEBSOCKET_API.md**: Complete WebSocket API documentation with examples
- **This file**: Implementation summary

