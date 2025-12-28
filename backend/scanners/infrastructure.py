"""
Infrastructure Vulnerability Scanner Module

Combines port scanning, service fingerprinting, and CVE correlation
to identify infrastructure-level vulnerabilities.
"""

import logging
from typing import List, Optional, Dict
from urllib.parse import urlparse

import httpx

from .base import ScannerModule, VulnerabilityResult

logger = logging.getLogger(__name__)

# Lazy imports to avoid circular dependencies
PortScanner = None
ServiceAnalyzer = None

def _get_port_scanner():
    """Lazy import PortScanner."""
    global PortScanner
    if PortScanner is None:
        try:
            from app.services.recon.port_scanner import PortScanner as PS
            PortScanner = PS
        except ImportError:
            logger.warning("PortScanner not available")
    return PortScanner

def _get_service_analyzer():
    """Lazy import ServiceAnalyzer."""
    global ServiceAnalyzer
    if ServiceAnalyzer is None:
        try:
            from app.services.recon.service_analyzer import ServiceAnalyzer as SA
            ServiceAnalyzer = SA
        except ImportError:
            logger.warning("ServiceAnalyzer not available")
    return ServiceAnalyzer


class InfrastructureScanner(ScannerModule):
    """
    Infrastructure vulnerability scanner.
    
    Combines:
    - Port scanning with banner grabbing
    - Service fingerprinting from HTTP headers
    - CVE correlation based on detected versions
    """
    
    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize infrastructure scanner.
        
        Args:
            target_url: The URL to scan
            timeout: Request timeout in seconds
        """
        super().__init__(target_url)
        self.timeout = timeout
        self.client = None
        self.port_scanner = None
        self.service_analyzer = None
    
    def get_vulnerability_name(self) -> str:
        """Return the name of this vulnerability type."""
        return "Infrastructure Vulnerabilities"
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,
                follow_redirects=True,
                headers={
                    'User-Agent': 'VulnMaster/2.0 (Educational Security Scanner)'
                }
            )
        return self.client
    
    async def _close_client(self):
        """Close HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None
    
    async def detect(self) -> List[VulnerabilityResult]:
        """
        Perform infrastructure vulnerability scan.
        
        Returns:
            List of VulnerabilityResult objects found
        """
        logger.info(f"Starting infrastructure scan on {self.target_url}")
        self.vulnerabilities = []
        
        try:
            # Lazy load dependencies
            PortScannerClass = _get_port_scanner()
            ServiceAnalyzerClass = _get_service_analyzer()
            
            if not PortScannerClass or not ServiceAnalyzerClass:
                logger.error("PortScanner or ServiceAnalyzer not available")
                return []
            
            if not self.service_analyzer:
                self.service_analyzer = ServiceAnalyzerClass()
            
            parsed = urlparse(self.target_url)
            target_host = parsed.hostname or parsed.netloc
            
            if not target_host:
                logger.error(f"Could not extract hostname from {self.target_url}")
                return []
            
            # 1. Port scanning
            logger.info(f"Starting port scan on {target_host}")
            self.port_scanner = PortScannerClass(target_host)
            port_results = await self.port_scanner.scan()
            open_ports = [r for r in port_results if r.is_open]
            
            # Create vulnerabilities for open ports (especially non-standard ones)
            standard_ports = [80, 443, 22, 21, 25]
            for port_result in open_ports:
                if port_result.port not in standard_ports:
                    severity = "Low"
                    description = f"Non-standard port {port_result.port} is open"
                    
                    if port_result.service:
                        description += f" (Service: {port_result.service})"
                    
                    if port_result.banner:
                        description += f". Banner: {port_result.banner[:100]}"
                    
                    vuln = VulnerabilityResult(
                        name="Open Port",
                        severity=severity,
                        description=description,
                        url=f"{parsed.scheme}://{target_host}:{port_result.port}",
                        parameter=None,
                        payload=str(port_result.port),
                        evidence=f"Port {port_result.port} is open and accessible"
                    )
                    self.vulnerabilities.append(vuln)
            
            # 2. HTTP header analysis
            client = await self._get_client()
            try:
                response = await client.get(self.target_url)
                headers = dict(response.headers)
                
                # Analyze headers
                analysis = self.service_analyzer.analyze_headers(headers)
                
                # Create vulnerability if CVEs found
                if analysis.get('cves'):
                    cve_list = ', '.join(analysis['cves'])
                    
                    service_info = []
                    if analysis.get('web_server') and analysis.get('web_server_version'):
                        service_info.append(f"{analysis['web_server']} {analysis['web_server_version']}")
                    if analysis.get('framework') and analysis.get('framework_version'):
                        service_info.append(f"{analysis['framework']} {analysis['framework_version']}")
                    
                    service_desc = " and ".join(service_info) if service_info else "detected service"
                    
                    vuln = VulnerabilityResult(
                        name="Known CVE Vulnerability",
                        severity="High",
                        description=f"Known CVE vulnerabilities detected in {service_desc}: {cve_list}. "
                                  f"These vulnerabilities may allow attackers to exploit the system.",
                        url=self.target_url,
                        parameter=None,
                        payload=cve_list,
                        evidence=self.service_analyzer.generate_cve_report(analysis)
                    )
                    self.vulnerabilities.append(vuln)
                
                # Flag outdated versions (even without known CVEs in our DB)
                if analysis.get('web_server') and analysis.get('web_server_version'):
                    version = analysis['web_server_version']
                    # Simple check: flag if version is older than common recent versions
                    if self._is_likely_outdated(analysis['web_server'].lower(), version):
                        vuln = VulnerabilityResult(
                            name="Potentially Outdated Software",
                            severity="Medium",
                            description=f"Detected {analysis['web_server']} version {version}. "
                                      f"This version may be outdated and contain unpatched vulnerabilities. "
                                      f"Recommend updating to the latest version.",
                            url=self.target_url,
                            parameter=None,
                            payload=version,
                            evidence=f"Server header: {headers.get('Server', 'N/A')}"
                        )
                        self.vulnerabilities.append(vuln)
            
            except Exception as e:
                logger.error(f"Error analyzing HTTP headers: {e}")
            
            logger.info(f"Infrastructure scan complete. Found {len(self.vulnerabilities)} vulnerabilities")
        
        except Exception as e:
            logger.error(f"Error during infrastructure scan: {e}", exc_info=True)
        finally:
            await self._close_client()
        
        return self.vulnerabilities
    
    def _is_likely_outdated(self, service: str, version: str) -> bool:
        """
        Simple heuristic to determine if version is likely outdated.
        This is a simplified check - in production, use actual version databases.
        
        Args:
            service: Service name
            version: Version string
            
        Returns:
            True if likely outdated
        """
        # This is a simplified check - real implementation would use version databases
        # For now, just check if version matches known vulnerable versions
        if not self.service_analyzer:
            return False
        cves = self.service_analyzer._check_cves(service, version)
        return len(cves) > 0
    
    def generate_poc(self, vulnerability: VulnerabilityResult) -> str:
        """
        Generate proof-of-concept command.
        
        Args:
            vulnerability: The vulnerability to generate PoC for
            
        Returns:
            Command string
        """
        if "Port" in vulnerability.name:
            # For open ports, show connection attempt
            parsed = urlparse(vulnerability.url)
            port = vulnerability.payload
            return f"nc -zv {parsed.hostname} {port}  # Or: telnet {parsed.hostname} {port}"
        elif "CVE" in vulnerability.name:
            # For CVEs, show curl to get headers
            return f"curl -I '{vulnerability.url}' | grep -i server"
        else:
            return f"curl -I '{vulnerability.url}'"
    
    def recommend_fix(self, vulnerability: VulnerabilityResult) -> Dict[str, str]:
        """
        Provide secure fix recommendations.
        
        Args:
            vulnerability: The vulnerability to provide fix for
            
        Returns:
            Dictionary with 'cause', 'fix', and 'why' keys
        """
        if "CVE" in vulnerability.name or "Outdated" in vulnerability.name:
            return {
                "cause": '''# PROBLEM: Outdated Software with Known Vulnerabilities

# The web server or application framework is running an outdated version
# that contains known security vulnerabilities (CVEs).

# Example:
# - Server: Apache/2.4.49 (vulnerable to CVE-2021-41773 - Path Traversal)
# - Framework: PHP 7.3.0 (vulnerable to CVE-2019-11043)

# These vulnerabilities are publicly documented and exploit code is available.
# Attackers actively scan for and exploit these vulnerabilities.''',
                
                "fix": '''# SECURE FIX: Update to Latest Version

# 1. Identify Current Version
curl -I https://example.com | grep -i server
# Response: Server: Apache/2.4.49

# 2. Check Latest Version
# Visit: https://httpd.apache.org/download.cgi
# Or: apt-cache policy apache2  # (Debian/Ubuntu)

# 3. Update Software

# Ubuntu/Debian:
sudo apt update
sudo apt upgrade apache2
# OR for specific version:
sudo apt install apache2=2.4.52-1ubuntu1

# CentOS/RHEL:
sudo yum update httpd
# OR:
sudo yum install httpd-2.4.52

# Windows:
# Download latest installer from official website

# 4. Verify Update
systemctl restart apache2
curl -I https://example.com | grep -i server
# Should show: Server: Apache/2.4.52 (or newer)

# 5. Monitor for Updates
# Set up automated security updates:
sudo apt install unattended-upgrades  # (Ubuntu/Debian)
# OR use monitoring tools to alert on new CVEs''',
                
                "why": '''Keeping software updated is critical because:

1. **CVE Exploitation**: Known vulnerabilities (CVEs) have public exploit code.
   Attackers actively scan for vulnerable versions and exploit them.

2. **Patch Gap**: The longer software goes unpatched, the higher the risk of
   compromise. Most successful attacks exploit known, patchable vulnerabilities.

3. **Compliance**: Many security standards (PCI-DSS, HIPAA, SOC 2) require
   keeping software up-to-date with security patches.

4. **Defense in Depth**: While other security controls help, patching is
   the most effective defense against known vulnerabilities.

**Best Practices**:
- Implement automated patch management
- Subscribe to security advisories for used software
- Test patches in staging before production
- Have a rollback plan in case of issues
- Monitor for new CVEs affecting your stack
- Use vulnerability scanners regularly to detect outdated software'''
            }
        else:
            # Open port vulnerability
            return {
                "cause": '''# PROBLEM: Unnecessary Open Ports

# Non-standard ports are open and accessible, increasing attack surface.
# While not always a vulnerability, open ports should be:
# - Necessary for functionality
# - Properly secured
# - Monitored

# Example:
# - Port 3306 (MySQL) open to public internet
# - Port 6379 (Redis) accessible without authentication
# - Port 8080 (alternative web server) exposed''',
                
                "fix": '''# SECURE FIX: Restrict Unnecessary Ports

# 1. Identify Why Port is Open
# Determine if the port is necessary for your application

# 2. Use Firewall Rules

# Linux (iptables):
sudo iptables -A INPUT -p tcp --dport 3306 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3306 -j DROP

# Linux (ufw):
sudo ufw deny 3306
# OR allow only from specific IPs:
sudo ufw allow from 10.0.0.0/8 to any port 3306

# 3. Bind to Localhost (if service doesn't need external access)
# Edit service configuration to bind to 127.0.0.1 instead of 0.0.0.0
# Example MySQL: bind-address = 127.0.0.1

# 4. Use VPN or Private Network
# For necessary services, use VPN or private network instead of public internet

# 5. Implement Network Segmentation
# Separate services into different network segments with firewall rules''',
                
                "why": '''Minimizing open ports reduces attack surface because:

1. **Attack Surface Reduction**: Every open port is a potential entry point.
   Fewer ports = smaller attack surface.

2. **Principle of Least Privilege**: Only expose what's necessary.
   If a service doesn't need external access, don't expose it.

3. **Defense in Depth**: Even if a service is secure, hiding it provides
   an additional layer of defense.

4. **Compliance**: Security standards often require documenting and
   restricting open ports.

**Best Practices**:
- Regularly audit open ports
- Close unnecessary ports
- Use firewall rules to restrict access to necessary ports
- Bind services to localhost when external access isn't needed
- Monitor port scanning attempts
- Use port knocking for sensitive services'''
            }
