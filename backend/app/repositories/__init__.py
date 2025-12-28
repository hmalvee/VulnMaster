"""Repository layer for database access."""

from .scan_repository import ScanRepository
from .vulnerability_repository import VulnerabilityRepository

__all__ = ['ScanRepository', 'VulnerabilityRepository']

