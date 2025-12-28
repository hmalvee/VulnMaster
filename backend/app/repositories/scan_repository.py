"""
Repository for Scan database operations.
Implements data access layer following Repository pattern.
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from typing import List, Optional
from datetime import datetime

from ..database import Scan, Vulnerability


class ScanRepository:
    """Repository for Scan entity operations."""
    
    def __init__(self, session: AsyncSession):
        """
        Initialize repository with database session.
        
        Args:
            session: Async database session
        """
        self.session = session
    
    async def create(self, target_url: str, scan_type: str, status: str = "pending") -> Scan:
        """
        Create a new scan record.
        
        Args:
            target_url: Target URL to scan
            scan_type: Type of scan (e.g., "SQL Injection")
            status: Initial status (default: "pending")
            
        Returns:
            Created Scan object
        """
        scan = Scan(
            target_url=target_url,
            scan_type=scan_type,
            status=status,
            created_at=datetime.utcnow()
        )
        self.session.add(scan)
        await self.session.flush()
        await self.session.refresh(scan)
        return scan
    
    async def get_by_id(self, scan_id: int, include_vulnerabilities: bool = False) -> Optional[Scan]:
        """
        Get scan by ID.
        
        Args:
            scan_id: Scan ID
            include_vulnerabilities: If True, eager load vulnerabilities
            
        Returns:
            Scan object or None if not found
        """
        query = select(Scan).where(Scan.id == scan_id)
        
        if include_vulnerabilities:
            query = query.options(selectinload(Scan.vulnerabilities))
        
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Scan]:
        """
        Get all scans with pagination.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of Scan objects
        """
        query = select(Scan).offset(skip).limit(limit).order_by(Scan.created_at.desc())
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def update_status(self, scan_id: int, status: str) -> Optional[Scan]:
        """
        Update scan status.
        
        Args:
            scan_id: Scan ID
            status: New status (pending, running, completed, failed)
            
        Returns:
            Updated Scan object or None if not found
        """
        scan = await self.get_by_id(scan_id)
        if not scan:
            return None
        
        scan.status = status
        if status in ["completed", "failed"]:
            scan.completed_at = datetime.utcnow()
        
        await self.session.flush()
        await self.session.refresh(scan)
        return scan
    
    async def delete(self, scan_id: int) -> bool:
        """
        Delete a scan and its associated vulnerabilities (cascade).
        
        Args:
            scan_id: Scan ID to delete
            
        Returns:
            True if deleted, False if not found
        """
        scan = await self.get_by_id(scan_id)
        if not scan:
            return False
        
        await self.session.delete(scan)
        await self.session.flush()
        return True
    
    async def count_vulnerabilities(self, scan_id: int) -> int:
        """
        Count vulnerabilities for a scan.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Number of vulnerabilities
        """
        query = select(func.count(Vulnerability.id)).where(Vulnerability.scan_id == scan_id)
        result = await self.session.execute(query)
        return result.scalar() or 0

