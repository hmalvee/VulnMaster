"""
Shared HTTP Client Service - Connection pooling and reuse for all scanners.

This service provides a shared HTTP client pool to improve performance
by reusing connections across requests.
"""

import logging
from typing import Optional
import httpx

logger = logging.getLogger(__name__)


class HTTPClientPool:
    """
    Shared HTTP client pool for connection reuse across scanners.
    Uses singleton pattern to ensure single pool instance.
    """
    
    _instance: Optional['HTTPClientPool'] = None
    _client: Optional[httpx.AsyncClient] = None
    
    def __init__(self):
        """Initialize HTTP client pool (singleton pattern)."""
        if HTTPClientPool._instance is not None:
            raise RuntimeError("HTTPClientPool is a singleton. Use get_instance()")
        
        # Initialize with connection pooling settings
        self._client = httpx.AsyncClient(
            timeout=10.0,
            verify=False,  # For educational/testing purposes
            follow_redirects=True,
            limits=httpx.Limits(
                max_keepalive_connections=20,  # Reuse up to 20 connections
                max_connections=100,  # Max total connections
                keepalive_expiry=30.0  # Keep connections alive for 30 seconds
            ),
            headers={
                'User-Agent': 'VulnMaster/2.0 (Educational Security Scanner)'
            }
        )
        
        HTTPClientPool._instance = self
        logger.info("HTTPClientPool initialized with connection pooling")
    
    @classmethod
    def get_instance(cls) -> 'HTTPClientPool':
        """
        Get singleton instance of HTTPClientPool.
        
        Returns:
            HTTPClientPool instance
        """
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
            cls._instance.__init__()
        return cls._instance
    
    def get_client(self) -> httpx.AsyncClient:
        """
        Get the shared HTTP client instance.
        
        Returns:
            Shared httpx.AsyncClient instance
        """
        if self._client is None:
            raise RuntimeError("HTTPClientPool not initialized")
        return self._client
    
    async def close(self):
        """Close all connections in the pool."""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("HTTPClientPool closed")


async def get_http_client() -> httpx.AsyncClient:
    """
    Get shared HTTP client instance (convenience function).
    
    Returns:
        Shared httpx.AsyncClient instance
    """
    pool = HTTPClientPool.get_instance()
    return pool.get_client()

