# VulnMaster Directory Structure

```
VulnMaster/
│
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI app entry point, startup events
│   │   ├── database.py                # SQLAlchemy 2.0 async models & setup
│   │   ├── schemas.py                 # Pydantic schemas for API validation
│   │   │
│   │   ├── repositories/              # Repository Layer (Data Access)
│   │   │   ├── __init__.py
│   │   │   ├── scan_repository.py     # Scan CRUD operations
│   │   │   └── vulnerability_repository.py  # Vulnerability CRUD operations
│   │   │
│   │   ├── services/                  # Service Layer (Business Logic)
│   │   │   ├── __init__.py
│   │   │   └── scanner_service.py     # Scan orchestration & state management
│   │   │
│   │   └── routers/                   # API Layer (Endpoints)
│   │       ├── __init__.py
│   │       ├── scans.py               # REST API endpoints (async)
│   │       └── websocket.py           # WebSocket endpoints for real-time updates
│   │
│   ├── scanners/                      # Scanner Modules (Plugin System)
│   │   ├── __init__.py
│   │   ├── base.py                    # Abstract ScannerModule base class
│   │   └── sqli.py                    # SQL Injection scanner (async httpx)
│   │
│   ├── requirements.txt               # Python dependencies
│   └── vulnmaster.db                  # SQLite database (auto-generated)
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   ├── index.css
│   │   └── components/
│   │       ├── ScanForm.jsx
│   │       ├── ScanList.jsx
│   │       ├── ScanDetail.jsx
│   │       └── VulnerabilityDetail.jsx
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── postcss.config.js
│
├── README.md
├── SETUP.md
├── ARCHITECTURE.md
├── DIRECTORY_STRUCTURE.md
└── .gitignore
```

## Key Files Summary

### Backend Core
- **`app/main.py`**: FastAPI application, CORS, startup events, router registration
- **`app/database.py`**: SQLAlchemy 2.0 async setup, model definitions (Scan, Vulnerability, Note)
- **`app/schemas.py`**: Pydantic models for request/response validation

### Repository Layer
- **`app/repositories/scan_repository.py`**: Scan entity database operations (async)
- **`app/repositories/vulnerability_repository.py`**: Vulnerability entity database operations (async)

### Service Layer
- **`app/services/scanner_service.py`**: Scan orchestration, state management, scanner registry, progress callbacks

### API Layer
- **`app/routers/scans.py`**: REST endpoints (POST, GET, DELETE scans) - all async
- **`app/routers/websocket.py`**: WebSocket endpoint for real-time scan progress

### Scanner Modules
- **`scanners/base.py`**: Abstract `ScannerModule` base class enforcing `detect()`, `generate_poc()`, `recommend_fix()`
- **`scanners/sqli.py`**: Async SQL Injection scanner with heuristic detection, error-based checks, false positive reduction

## Architecture Pattern

**Service-Repository Pattern** with clear separation:
- **Routers** (thin) → **Services** (business logic) → **Repositories** (data access) → **Database**

All layers use **async/await** for non-blocking I/O operations.

