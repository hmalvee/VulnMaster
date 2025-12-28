"""
Pydantic schemas for request/response validation.
Updated for new Vulnerability structure with attack, cause, fix, why fields.
"""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class ScanCreate(BaseModel):
    """Schema for creating a new scan."""
    target_url: str
    scan_type: str = "SQL Injection"


class VulnerabilityBase(BaseModel):
    """Base schema for vulnerability with educational Blue Team fields."""
    name: str
    severity: str
    description: Optional[str] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    
    # Educational Blue Team fields
    attack: Optional[str] = None  # CURL command (Red Team PoC)
    cause: Optional[str] = None   # Vulnerable code snippet
    fix: Optional[str] = None     # Secure code snippet
    why: Optional[str] = None     # Explanation of why fix works
    
    # Legacy fields (for backward compatibility)
    poc_command: Optional[str] = None  # Deprecated, use 'attack'
    remediation: Optional[str] = None  # Deprecated, use 'fix' and 'why'
    evidence: Optional[str] = None


class VulnerabilityCreate(VulnerabilityBase):
    """Schema for creating a vulnerability."""
    pass


class Vulnerability(VulnerabilityBase):
    """Schema for vulnerability response."""
    id: int
    scan_id: int
    
    class Config:
        from_attributes = True


class ScanBase(BaseModel):
    """Base schema for scan."""
    target_url: str
    scan_type: str
    status: str


class Scan(ScanBase):
    """Schema for scan response."""
    id: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = []
    
    class Config:
        from_attributes = True


class ScanSummary(BaseModel):
    """Schema for scan summary (without full vulnerability details)."""
    id: int
    target_url: str
    scan_type: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    vulnerability_count: int = 0
    
    class Config:
        from_attributes = True


class NoteCreate(BaseModel):
    """Schema for creating a note."""
    content: str


class Note(BaseModel):
    """Schema for note response."""
    id: int
    vulnerability_id: int
    content: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class ScanProgressMessage(BaseModel):
    """Schema for WebSocket scan progress messages."""
    event: str  # scan_started, scan_progress, scan_completed, scan_failed
    scan_id: int
    message: str
    data: Optional[dict] = None
