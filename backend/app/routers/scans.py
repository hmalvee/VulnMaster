"""
API endpoints for vulnerability scanning.
Refactored to use Service-Repository pattern with async support.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import logging
import json

from ..database import get_db
from ..schemas import (
    ScanCreate, Scan as ScanSchema, ScanSummary, 
    Vulnerability as VulnerabilitySchema
)
from ..services.scanner_service import ScannerService
from ..services.llm_engine import LLMEngine
from ..repositories.vulnerability_repository import VulnerabilityRepository

router = APIRouter(prefix="/api/scans", tags=["scans"])
logger = logging.getLogger(__name__)


async def get_scanner_service(session: AsyncSession = Depends(get_db)) -> ScannerService:
    """Dependency to get scanner service instance."""
    return ScannerService(session)


@router.get("/types")
async def get_scan_types():
    """
    Get list of available scan types.
    
    Returns:
        List of available scan type names
    """
    return {
        "scan_types": list(ScannerService.SCANNER_REGISTRY.keys()),
        "descriptions": {
            "SQL Injection": "Detects SQL injection vulnerabilities using error-based and time-based techniques",
            "XSS": "Detects Cross-Site Scripting (XSS) vulnerabilities using canary injection",
            "Sensitive File Exposure": "Scans for exposed sensitive files (.env, backups, database dumps, etc.)",
            "Infrastructure": "Scans ports and analyzes HTTP headers for infrastructure vulnerabilities and CVEs",
            "Security Headers": "Detects missing or misconfigured security headers (CSP, HSTS, X-Frame-Options, etc.)",
            "CSRF": "Detects missing CSRF protection in forms performing state-changing operations"
        }
    }


@router.post("/", response_model=ScanSchema, status_code=201)
async def create_scan(
    scan: ScanCreate,
    background_tasks: BackgroundTasks,
    service: ScannerService = Depends(get_scanner_service)
):
    """
    Create a new vulnerability scan.
    
    The scan will run in the background. Use GET /api/scans/{scan_id} to check status,
    or connect to WebSocket for real-time updates.
    """
    try:
        created_scan = await service.create_scan(scan.target_url, scan.scan_type)
        
        # Start scan in background
        background_tasks.add_task(service.run_scan, created_scan.id)
        
        return created_scan
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/", response_model=List[ScanSummary])
async def list_scans(
    skip: int = 0, 
    limit: int = 100,
    service: ScannerService = Depends(get_scanner_service)
):
    """
    List all scans with summary information.
    """
    scans = await service.list_scans(skip, limit)
    result = []
    
    for scan in scans:
        from ..repositories.scan_repository import ScanRepository
        scan_repo = ScanRepository(service.session)
        vuln_count = await scan_repo.count_vulnerabilities(scan.id)
        
        result.append(ScanSummary(
            id=scan.id,
            target_url=scan.target_url,
            scan_type=scan.scan_type,
            status=scan.status,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            vulnerability_count=vuln_count
        ))
    
    return result


@router.get("/{scan_id}", response_model=ScanSchema)
async def get_scan(
    scan_id: int,
    service: ScannerService = Depends(get_scanner_service)
):
    """
    Get a specific scan with all its vulnerabilities.
    """
    scan = await service.get_scan(scan_id, include_vulnerabilities=True)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan


@router.get("/{scan_id}/vulnerabilities", response_model=List[VulnerabilitySchema])
async def get_scan_vulnerabilities(
    scan_id: int,
    service: ScannerService = Depends(get_scanner_service)
):
    """
    Get all vulnerabilities for a specific scan.
    """
    # Check if scan exists
    scan = await service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    from ..repositories.vulnerability_repository import VulnerabilityRepository
    vuln_repo = VulnerabilityRepository(service.session)
    vulnerabilities = await vuln_repo.get_by_scan_id(scan_id)
    
    return vulnerabilities


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: int,
    service: ScannerService = Depends(get_scanner_service)
):
    """
    Delete a scan and all its associated vulnerabilities.
    """
    deleted = await service.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return None


@router.post("/{scan_id}/vulnerabilities/{vulnerability_id}/remediate")
async def remediate_vulnerability(
    scan_id: int,
    vulnerability_id: int,
    session: AsyncSession = Depends(get_db)
):
    """
    Generate secure code remediation for a vulnerability using AI.
    Streams the code back via Server-Sent Events (SSE) for live updates.
    
    Args:
        scan_id: Scan ID
        vulnerability_id: Vulnerability ID to remediate
        
    Returns:
        StreamingResponse with code chunks
    """
    # Get vulnerability
    vuln_repo = VulnerabilityRepository(session)
    vulnerability = await vuln_repo.get_by_id(vulnerability_id)
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    if vulnerability.scan_id != scan_id:
        raise HTTPException(status_code=400, detail="Vulnerability does not belong to this scan")
    
    # Get LLM engine
    llm_engine = LLMEngine.get_instance()
    
    async def generate_remediation():
        """Generator function for streaming remediation code."""
        try:
            # Send initial metadata
            yield f"data: {json.dumps({'type': 'start', 'vulnerability': vulnerability.name})}\n\n"
            
            # Stream code generation
            async for chunk in llm_engine.generate_remediation_code(
                vulnerability_type=vulnerability.name,
                url=vulnerability.url or "",
                parameter=vulnerability.parameter or "",
                payload=vulnerability.payload or ""
            ):
                # Format as SSE
                yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"
            
            # Send completion signal
            yield f"data: {json.dumps({'type': 'complete'})}\n\n"
            
        except Exception as e:
            logger.error(f"Error generating remediation: {e}", exc_info=True)
            error_msg = json.dumps({'type': 'error', 'message': str(e)})
            yield f"data: {error_msg}\n\n"
    
    return StreamingResponse(
        generate_remediation(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"  # Disable buffering for nginx
        }
    )
