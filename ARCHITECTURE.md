# VulnMaster Architecture Documentation

## Overview

VulnMaster follows a **Service-Repository Pattern** with async/await throughout, ensuring clean separation of concerns and non-blocking I/O operations.

## Architecture Layers

### 1. Database Layer (`app/database.py`)
- **SQLAlchemy 2.0** with async support
- Uses `aiosqlite` for async SQLite operations
- Models: `Scan`, `Vulnerability`, `Note`
- Vulnerability model includes educational fields: `attack`, `cause`, `fix`, `why`

### 2. Repository Layer (`app/repositories/`)
- **Data Access Layer** - abstracts database operations
- `ScanRepository`: Handles Scan CRUD operations
- `VulnerabilityRepository`: Handles Vulnerability operations
- All methods are async and use async SQLAlchemy sessions

### 3. Service Layer (`app/services/`)
- **Business Logic Layer** - orchestrates operations
- `ScannerService`: Manages scan lifecycle
  - Creates scans
  - Runs scans asynchronously in background
  - Handles progress callbacks for WebSocket updates
  - Manages scanner registry

### 4. Scanner Modules (`scanners/`)
- **Plugin System** with strict abstract base class
- `ScannerModule`: Abstract base class enforcing:
  - `detect()`: Async vulnerability detection
  - `generate_poc()`: Generate attack command (Red Team)
  - `recommend_fix()`: Provide secure code fix (Blue Team)
- `SQLInjectionScanner`: Async SQLi scanner using httpx
  - Heuristic detection (parameter reflection check)
  - Error-based detection
  - Boolean-based detection
  - False positive reduction (validates DB errors)

### 5. API Layer (`app/routers/`)
- **REST API** (`scans.py`): CRUD operations for scans
- **WebSocket** (`websocket.py`): Real-time scan progress updates
- All endpoints are async
- Routers are thin - delegate to service layer

### 6. Schemas (`app/schemas.py`)
- **Pydantic models** for request/response validation
- Includes new Vulnerability structure with `attack`, `cause`, `fix`, `why` fields

## Data Flow

### Scan Creation Flow
1. Client → POST `/api/scans/` → Router
2. Router → `ScannerService.create_scan()` → Repository
3. Repository → Database (create Scan record)
4. Service returns Scan object
5. Router → `BackgroundTasks.add_task()` → Start async scan
6. Background task → `ScannerService.run_scan()` → Scanner module
7. Scanner → `detect()`, `generate_poc()`, `recommend_fix()`
8. Service → Repository → Save vulnerabilities
9. WebSocket → Real-time progress updates to clients

### WebSocket Flow
1. Client → WebSocket connection to `/ws/scans/{scan_id}`
2. Scanner service → Progress callback → ConnectionManager
3. ConnectionManager → Broadcast to all connections for scan_id
4. Client receives real-time updates (started, progress, completed, failed)

## Key Design Decisions

### 1. Async Everything
- All I/O operations are async (database, HTTP requests)
- Uses `httpx` instead of `requests` for async HTTP
- SQLAlchemy async sessions with `aiosqlite`

### 2. Service-Repository Pattern
- Clean separation: Routers → Services → Repositories → Database
- Easy to test and maintain
- Repository abstracts data access

### 3. Plugin System
- Strict abstract base class enforces consistent interface
- Easy to add new scanner modules
- Each scanner must implement: detect, generate_poc, recommend_fix

### 4. Educational Focus
- Vulnerability results include:
  - **attack**: CURL command showing exploitation (Red Team)
  - **cause**: Vulnerable code snippet
  - **fix**: Secure code snippet
  - **why**: Explanation of why fix works

### 5. False Positive Reduction
- Heuristic checks (parameter reflection)
- Strict SQL error pattern matching
- Validates errors are database-related, not generic 500s

## File Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app, startup events
│   ├── database.py                # SQLAlchemy models, async setup
│   ├── schemas.py                 # Pydantic schemas
│   ├── repositories/
│   │   ├── __init__.py
│   │   ├── scan_repository.py     # Scan data access
│   │   └── vulnerability_repository.py  # Vulnerability data access
│   ├── services/
│   │   ├── __init__.py
│   │   └── scanner_service.py     # Scan orchestration logic
│   └── routers/
│       ├── __init__.py
│       ├── scans.py               # REST API endpoints
│       └── websocket.py           # WebSocket endpoints
└── scanners/
    ├── __init__.py
    ├── base.py                    # Abstract ScannerModule class
    └── sqli.py                    # SQL Injection scanner
```

## Adding New Scanner Modules

1. Create new file in `scanners/` (e.g., `xss.py`)
2. Inherit from `ScannerModule`
3. Implement required methods:
   ```python
   async def detect(self) -> List[VulnerabilityResult]
   def generate_poc(self, vulnerability) -> str
   def recommend_fix(self, vulnerability) -> Dict[str, str]
   def get_vulnerability_name(self) -> str
   ```
4. Register in `ScannerService.SCANNER_REGISTRY`
5. Add to frontend dropdown

## Dependencies

- `fastapi`: Web framework
- `uvicorn`: ASGI server
- `sqlalchemy`: ORM (async 2.0)
- `aiosqlite`: Async SQLite driver
- `httpx`: Async HTTP client
- `beautifulsoup4`: HTML parsing
- `websockets`: WebSocket support
- `pydantic`: Data validation

## State Management

Scans have the following states:
- `pending`: Created but not started
- `running`: Scan in progress
- `completed`: Scan finished successfully
- `failed`: Scan encountered an error

State transitions are managed by `ScannerService.run_scan()` and persisted via `ScanRepository.update_status()`.

