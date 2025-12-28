# VulnMaster Project Structure

```
VulnMaster/
│
├── backend/                    # Python FastAPI backend
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py            # FastAPI application entry point
│   │   ├── database.py        # SQLAlchemy models and database setup
│   │   ├── schemas.py         # Pydantic schemas for API validation
│   │   └── routers/
│   │       ├── __init__.py
│   │       └── scans.py       # Scan API endpoints
│   │
│   ├── scanners/              # Modular vulnerability scanner modules
│   │   ├── __init__.py
│   │   ├── base.py            # Base scanner class (abstract)
│   │   └── sql_injection.py   # SQL Injection scanner implementation
│   │
│   └── requirements.txt       # Python dependencies
│
├── frontend/                   # React + Tailwind CSS frontend
│   ├── src/
│   │   ├── App.jsx            # Main application component
│   │   ├── main.jsx           # React entry point
│   │   ├── index.css          # Global styles + Tailwind
│   │   └── components/
│   │       ├── ScanForm.jsx           # Form to create new scans
│   │       ├── ScanList.jsx           # List of all scans
│   │       ├── ScanDetail.jsx         # Detailed view of a scan
│   │       └── VulnerabilityDetail.jsx # Detailed view of a vulnerability
│   │
│   ├── package.json           # Node.js dependencies
│   ├── vite.config.js         # Vite configuration
│   ├── tailwind.config.js     # Tailwind CSS configuration
│   └── postcss.config.js      # PostCSS configuration
│
├── README.md                   # Project overview and description
├── SETUP.md                    # Installation and setup instructions
├── PROJECT_STRUCTURE.md        # This file
└── .gitignore                  # Git ignore rules
```

## Key Components

### Backend Architecture

1. **FastAPI Application** (`app/main.py`)
   - RESTful API server
   - CORS middleware for frontend communication
   - Health check endpoint

2. **Database Layer** (`app/database.py`)
   - SQLAlchemy ORM models
   - SQLite database (vulnmaster.db)
   - Models: Scan, Vulnerability, Note

3. **API Routes** (`app/routers/scans.py`)
   - POST `/api/scans/` - Create new scan
   - GET `/api/scans/` - List all scans
   - GET `/api/scans/{id}` - Get scan details
   - GET `/api/scans/{id}/vulnerabilities` - Get vulnerabilities
   - DELETE `/api/scans/{id}` - Delete scan

4. **Scanner Framework** (`scanners/`)
   - Base class for extensibility
   - SQL Injection scanner module
   - Easy to add new vulnerability types

### Frontend Architecture

1. **Main App** (`App.jsx`)
   - State management for scans and selections
   - Layout with sidebar and main content area
   - Polling for scan updates

2. **Components**
   - **ScanForm**: Input form for creating scans
   - **ScanList**: Sidebar list of all scans with status
   - **ScanDetail**: Main view showing scan results
   - **VulnerabilityDetail**: Detailed vulnerability view with PoC and remediation

### SQL Injection Scanner Features

1. **Detection**
   - Tests URL query parameters
   - Tests HTML form inputs
   - Uses error-based SQLi payloads
   - Detects SQL error patterns in responses

2. **Proof of Concept**
   - Generates curl commands showing attack vector
   - Demonstrates how attacker would exploit the vulnerability

3. **Remediation**
   - Comprehensive guide with code examples
   - Covers parameterized queries in Python and PHP
   - Includes additional security recommendations

## Adding New Scanner Modules

To add a new vulnerability scanner:

1. Create a new file in `backend/scanners/` (e.g., `xss.py`)
2. Inherit from `BaseScanner` class
3. Implement required methods:
   - `scan()` - Perform the vulnerability scan
   - `get_vulnerability_name()` - Return vulnerability type name
4. Optionally override:
   - `generate_poc()` - Generate proof-of-concept command
   - `get_remediation_advice()` - Provide remediation guidance
5. Import and register in `backend/scanners/__init__.py`
6. Add scan type to router in `backend/app/routers/scans.py`
7. Add option to frontend dropdown in `ScanForm.jsx`

