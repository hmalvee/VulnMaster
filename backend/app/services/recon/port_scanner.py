"""
Async Port Scanner Service

Highly concurrent port scanner using asyncio for infrastructure reconnaissance.
Scans common ports and performs banner grabbing to identify services.
"""

import asyncio
import logging
from typing import List, Optional, Tuple, Set, Dict
from dataclasses import dataclass
from socket import gethostbyname
import ipaddress

logger = logging.getLogger(__name__)


@dataclass
class PortResult:
    """Represents a scanned port result."""
    port: int
    is_open: bool
    banner: Optional[str] = None
    service: Optional[str] = None
    error: Optional[str] = None


class PortScanner:
    """
    Async port scanner with banner grabbing capabilities.
    Uses asyncio for high concurrency (100+ ports simultaneously).
    """
    
    # Top 100 common ports (prioritized by likelihood, deduplicated)
    TOP_100_PORTS = sorted(list(set([
        # Web Services
        80, 443, 8080, 8443, 8000, 8888, 3000,
        # SSH/Telnet
        22, 23,
        # Email
        25, 110, 143, 993, 995,
        # File Transfer
        21, 69,
        # Database
        3306, 5432, 1433, 1521, 27017, 6379, 5984,
        # RPC/Services
        111, 135, 139, 445,
        # Remote Access
        3389, 5900, 1723,
        # Development
        5000, 5001, 9000,
        # DNS
        53,
        # Other Services
        11211, 2049, 3690, 9092, 9200, 9300, 123, 161, 389, 636, 873,
        1194, 1527, 2375, 2376, 3128, 28015, 50000, 50030, 50060, 50070, 50075,
    ])))
    
    # Common service banners (for identification)
    SERVICE_BANNERS = {
        'ssh': ['ssh', 'openssh'],
        'ftp': ['ftp', 'filezilla', 'vsftpd'],
        'http': ['http', 'apache', 'nginx', 'iis', 'lighttpd'],
        'mysql': ['mysql'],
        'postgresql': ['postgresql', 'postgres'],
        'mongodb': ['mongodb'],
        'redis': ['redis'],
        'telnet': ['telnet'],
        'smtp': ['smtp', 'postfix', 'sendmail'],
        'imap': ['imap'],
        'pop3': ['pop3'],
        'rdp': ['rdp', 'microsoft terminal services'],
        'vnc': ['vnc'],
        'elasticsearch': ['elasticsearch'],
    }
    
    def __init__(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        max_concurrent: int = 100,
        timeout: float = 3.0,
        banner_timeout: float = 2.0
    ):
        """
        Initialize port scanner.
        
        Args:
            target: Target hostname or IP address
            ports: List of ports to scan (default: TOP_100_PORTS)
            max_concurrent: Maximum concurrent connections (default: 100)
            timeout: Connection timeout in seconds (default: 3.0)
            banner_timeout: Banner read timeout in seconds (default: 2.0)
        """
        self.target = target
        self.target_ip = None  # Will be resolved
        self.ports = ports if ports else self.TOP_100_PORTS
        # Remove duplicates and sort
        self.ports = sorted(list(set(self.ports)))
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.banner_timeout = banner_timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.results: List[PortResult] = []
    
    async def _resolve_target(self) -> str:
        """
        Resolve hostname to IP address.
        
        Returns:
            IP address string
        """
        if self.target_ip:
            return self.target_ip
        
        try:
            # Check if it's already an IP
            ipaddress.ip_address(self.target)
            self.target_ip = self.target
            return self.target_ip
        except ValueError:
            # Resolve hostname
            try:
                loop = asyncio.get_event_loop()
                self.target_ip = await loop.run_in_executor(
                    None, gethostbyname, self.target
                )
                return self.target_ip
            except Exception as e:
                logger.error(f"Error resolving {self.target}: {e}")
                raise
    
    def _identify_service(self, banner: str) -> Optional[str]:
        """
        Identify service from banner.
        
        Args:
            banner: Banner string
            
        Returns:
            Service name or None
        """
        banner_lower = banner.lower()
        for service, keywords in self.SERVICE_BANNERS.items():
            if any(keyword in banner_lower for keyword in keywords):
                return service
        return None
    
    async def _grab_banner(self, port: int) -> Optional[str]:
        """
        Attempt to grab banner from open port.
        
        Args:
            port: Port number
            
        Returns:
            Banner string or None
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, port),
                timeout=self.banner_timeout
            )
            
            try:
                # Try to read banner (first 512 bytes)
                banner_bytes = await asyncio.wait_for(
                    reader.read(512),
                    timeout=self.banner_timeout
                )
                
                if banner_bytes:
                    banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                    # Remove null bytes and control characters
                    banner = ''.join(c for c in banner if c.isprintable() or c in '\n\r\t')
                    return banner[:200]  # Limit banner length
            finally:
                writer.close()
                await writer.wait_closed()
        
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"Error grabbing banner from port {port}: {e}")
        
        return None
    
    async def _scan_port(self, port: int) -> PortResult:
        """
        Scan a single port asynchronously.
        
        Args:
            port: Port number to scan
            
        Returns:
            PortResult object
        """
        async with self.semaphore:  # Rate limiting
            result = PortResult(port=port, is_open=False)
            
            try:
                # Resolve target if needed
                if not self.target_ip:
                    await self._resolve_target()
                
                # Attempt connection
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_ip, port),
                        timeout=self.timeout
                    )
                    
                    # Port is open
                    result.is_open = True
                    
                    # Try to grab banner
                    try:
                        banner = await self._grab_banner(port)
                        if banner:
                            result.banner = banner
                            result.service = self._identify_service(banner)
                    except Exception:
                        pass  # Banner grabbing failed, but port is open
                    
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                
                except asyncio.TimeoutError:
                    result.is_open = False
                    result.error = "Connection timeout"
                
                except ConnectionRefusedError:
                    result.is_open = False
                    result.error = "Connection refused"
                
                except Exception as e:
                    result.is_open = False
                    result.error = str(e)
                    logger.debug(f"Error scanning port {port}: {e}")
            
            except Exception as e:
                result.is_open = False
                result.error = str(e)
                logger.error(f"Error in port scan for {port}: {e}")
            
            return result
    
    async def scan(self) -> List[PortResult]:
        """
        Scan all ports concurrently.
        
        Returns:
            List of PortResult objects
        """
        logger.info(f"Starting port scan on {self.target} ({len(self.ports)} ports)")
        
        try:
            # Resolve target first
            await self._resolve_target()
            logger.info(f"Resolved {self.target} to {self.target_ip}")
            
            # Scan all ports concurrently
            tasks = [self._scan_port(port) for port in self.ports]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            self.results = []
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Error in port scan task: {result}")
                    continue
                if isinstance(result, PortResult):
                    self.results.append(result)
            
            # Sort by port number
            self.results.sort(key=lambda x: x.port)
            
            open_ports = [r for r in self.results if r.is_open]
            logger.info(f"Port scan completed: {len(open_ports)} open ports found")
            
        except Exception as e:
            logger.error(f"Error during port scan: {e}", exc_info=True)
        
        return self.results
    
    def get_open_ports(self) -> List[PortResult]:
        """
        Get only open ports.
        
        Returns:
            List of PortResult objects for open ports
        """
        return [r for r in self.results if r.is_open]
    
    def get_results_summary(self) -> Dict:
        """
        Get summary of scan results.
        
        Returns:
            Dictionary with summary statistics
        """
        open_ports = self.get_open_ports()
        services = {}
        for result in open_ports:
            if result.service:
                services[result.service] = services.get(result.service, [])
                services[result.service].append(result.port)
        
        return {
            "target": self.target,
            "target_ip": self.target_ip,
            "total_ports_scanned": len(self.ports),
            "open_ports_count": len(open_ports),
            "open_ports": [r.port for r in open_ports],
            "services": services,
            "ports_with_banners": len([r for r in open_ports if r.banner])
        }

