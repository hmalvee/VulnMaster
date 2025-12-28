"""
Scanner Service - Handles vulnerability scanning business logic.
Coordinates between scanners, repositories, and WebSocket notifications.
"""

import logging
from typing import Optional, Callable, Awaitable
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from ..repositories.scan_repository import ScanRepository
from ..repositories.vulnerability_repository import VulnerabilityRepository
from .llm_engine import LLMEngine
from scanners.sqli import SQLInjectionScanner
from scanners.xss import XSSScanner
from scanners.exposure import ExposureScanner
from scanners.infrastructure import InfrastructureScanner
from scanners.security_headers import SecurityHeadersScanner
from scanners.csrf import CSRFScanner

logger = logging.getLogger(__name__)


class ScannerService:
    """
    Service layer for vulnerability scanning operations.
    Handles scan orchestration, state management, and result persistence.
    """
    
    # Registry of available scanners
    SCANNER_REGISTRY = {
        "SQL Injection": SQLInjectionScanner,
        "XSS": XSSScanner,
        "Sensitive File Exposure": ExposureScanner,
        "Infrastructure": InfrastructureScanner,
        "Security Headers": SecurityHeadersScanner,
        "CSRF": CSRFScanner,
    }
    
    def __init__(self, session: AsyncSession):
        """
        Initialize scanner service with database session.
        
        Args:
            session: Async database session
        """
        self.session = session
        self.scan_repo = ScanRepository(session)
        self.vuln_repo = VulnerabilityRepository(session)
    
    async def create_scan(self, target_url: str, scan_type: str):
        """
        Create a new scan record.
        
        Args:
            target_url: Target URL to scan
            scan_type: Type of scan to perform
            
        Returns:
            Created Scan object
            
        Raises:
            ValueError: If scan type is not supported
        """
        if scan_type not in self.SCANNER_REGISTRY:
            raise ValueError(f"Unsupported scan type: {scan_type}")
        
        scan = await self.scan_repo.create(target_url, scan_type, status="pending")
        await self.session.commit()
        
        logger.info(f"Created scan {scan.id} for {target_url} ({scan_type})")
        return scan
    
    async def run_scan(
        self, 
        scan_id: int, 
        progress_callback: Optional[Callable[[str, dict], Awaitable[None]]] = None
    ) -> None:
        """
        Run a vulnerability scan asynchronously.
        Updates scan state and persists results.
        
        Args:
            scan_id: ID of the scan to run
            progress_callback: Optional callback for real-time progress updates
                               Signature: callback(message: str, data: dict)
        """
        try:
            # Get scan record
            scan = await self.scan_repo.get_by_id(scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return
            
            # Update status to running
            await self.scan_repo.update_status(scan_id, "running")
            await self.session.commit()
            
            if progress_callback:
                await progress_callback("scan_started", {"scan_id": scan_id, "message": "Scan started"})
            
            # Get scanner class from registry
            scanner_class = self.SCANNER_REGISTRY.get(scan.scan_type)
            if not scanner_class:
                await self.scan_repo.update_status(scan_id, "failed")
                await self.session.commit()
                logger.error(f"Unknown scan type: {scan.scan_type}")
                if progress_callback:
                    await progress_callback("scan_failed", {"scan_id": scan_id, "message": "Unknown scan type"})
                return
            
            # Initialize scanner with LLM engine for hybrid detection
            llm_engine = LLMEngine.get_instance()
            if scan.scan_type == "SQL Injection":
                scanner = scanner_class(scan.target_url, llm_engine=llm_engine)
            else:
                scanner = scanner_class(scan.target_url)
            
            if progress_callback:
                await progress_callback("scan_progress", {
                    "scan_id": scan_id,
                    "message": f"Running {scan.scan_type} scan...",
                    "target_url": scan.target_url
                })
            
            # Run detection
            vulnerabilities = await scanner.detect()
            
            if progress_callback:
                await progress_callback("scan_progress", {
                    "scan_id": scan_id,
                    "message": f"Found {len(vulnerabilities)} potential vulnerabilities, analyzing...",
                    "vulnerability_count": len(vulnerabilities)
                })
            
            # Process each vulnerability: generate PoC and fix recommendations
            processed_vulns = []
            for vuln in vulnerabilities:
                # Generate PoC (attack command)
                if not vuln.attack:
                    vuln.attack = scanner.generate_poc(vuln)
                
                # Generate fix recommendations
                if not vuln.cause or not vuln.fix or not vuln.why:
                    fix_info = scanner.recommend_fix(vuln)
                    vuln.cause = fix_info.get("cause", vuln.cause)
                    vuln.fix = fix_info.get("fix", vuln.fix)
                    vuln.why = fix_info.get("why", vuln.why)
                
                processed_vulns.append(vuln)
            
            # Save vulnerabilities to database
            if processed_vulns:
                await self.vuln_repo.create_batch(scan_id, processed_vulns)
            
            # Update scan status to completed
            await self.scan_repo.update_status(scan_id, "completed")
            await self.session.commit()
            
            logger.info(f"Scan {scan_id} completed. Found {len(processed_vulns)} vulnerabilities")
            
            if progress_callback:
                await progress_callback("scan_completed", {
                    "scan_id": scan_id,
                    "message": f"Scan completed. Found {len(processed_vulns)} vulnerabilities",
                    "vulnerability_count": len(processed_vulns)
                })
        
        except Exception as e:
            logger.error(f"Error running scan {scan_id}: {e}", exc_info=True)
            
            # Update scan status to failed
            try:
                await self.scan_repo.update_status(scan_id, "failed")
                await self.session.commit()
            except Exception as commit_error:
                logger.error(f"Error updating scan status to failed: {commit_error}")
            
            if progress_callback:
                await progress_callback("scan_failed", {
                    "scan_id": scan_id,
                    "message": f"Scan failed: {str(e)}",
                    "error": str(e)
                })
    
    async def get_scan(self, scan_id: int, include_vulnerabilities: bool = True):
        """
        Get scan by ID.
        
        Args:
            scan_id: Scan ID
            include_vulnerabilities: If True, include vulnerabilities
            
        Returns:
            Scan object or None
        """
        return await self.scan_repo.get_by_id(scan_id, include_vulnerabilities=include_vulnerabilities)
    
    async def list_scans(self, skip: int = 0, limit: int = 100):
        """
        List all scans.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records
            
        Returns:
            List of Scan objects
        """
        return await self.scan_repo.get_all(skip, limit)
    
    async def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan.
        
        Args:
            scan_id: Scan ID to delete
            
        Returns:
            True if deleted, False if not found
        """
        result = await self.scan_repo.delete(scan_id)
        if result:
            await self.session.commit()
        return result

