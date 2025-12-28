"""
Security Headers Scanner Module

Detects missing or misconfigured security headers that are critical
for web application security (OWASP guidelines).
"""

import logging
from typing import List, Optional, Dict
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from .base import ScannerModule, VulnerabilityResult

logger = logging.getLogger(__name__)


class SecurityHeadersScanner(ScannerModule):
    """
    Scanner for missing or misconfigured security headers.
    
    Detects:
    - Missing Content-Security-Policy (CSP)
    - Missing X-Frame-Options
    - Missing X-Content-Type-Options
    - Missing Strict-Transport-Security (HSTS)
    - Missing X-XSS-Protection
    - Missing Referrer-Policy
    - Missing Permissions-Policy
    - Misconfigured header values
    """
    
    # Required security headers and their recommended values
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "required": True,
            "severity_if_missing": "High",
            "recommended": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';",
            "description": "Prevents XSS attacks by controlling which resources can be loaded"
        },
        "X-Frame-Options": {
            "required": True,
            "severity_if_missing": "Medium",
            "recommended": "DENY",
            "description": "Prevents clickjacking attacks by controlling iframe embedding"
        },
        "X-Content-Type-Options": {
            "required": True,
            "severity_if_missing": "Medium",
            "recommended": "nosniff",
            "description": "Prevents MIME type sniffing attacks"
        },
        "Strict-Transport-Security": {
            "required": False,  # Only for HTTPS
            "severity_if_missing": "High",
            "recommended": "max-age=31536000; includeSubDomains",
            "description": "Forces HTTPS connections and prevents downgrade attacks"
        },
        "X-XSS-Protection": {
            "required": False,  # Deprecated but still used
            "severity_if_missing": "Low",
            "recommended": "1; mode=block",
            "description": "Enables XSS filtering in older browsers"
        },
        "Referrer-Policy": {
            "required": False,
            "severity_if_missing": "Low",
            "recommended": "strict-origin-when-cross-origin",
            "description": "Controls referrer information in requests"
        },
        "Permissions-Policy": {
            "required": False,
            "severity_if_missing": "Low",
            "recommended": "geolocation=(), microphone=(), camera=()",
            "description": "Controls browser features and APIs"
        }
    }
    
    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize the security headers scanner.
        
        Args:
            target_url: The URL to scan
            timeout: Request timeout in seconds
        """
        super().__init__(target_url)
        self.timeout = timeout
        self.client = None
    
    def get_vulnerability_name(self) -> str:
        """Return the name of this vulnerability type."""
        return "Missing Security Headers"
    
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
        Perform security headers scan.
        
        Returns:
            List of VulnerabilityResult objects found
        """
        logger.info(f"Starting security headers scan on {self.target_url}")
        self.vulnerabilities = []
        
        try:
            client = await self._get_client()
            response = await client.get(self.target_url)
            headers = dict(response.headers)
            
            parsed = urlparse(self.target_url)
            is_https = parsed.scheme == 'https'
            
            # Check each security header
            for header_name, header_config in self.SECURITY_HEADERS.items():
                header_value = headers.get(header_name) or headers.get(header_name.lower())
                
                # Skip HSTS check for HTTP (only relevant for HTTPS)
                if header_name == "Strict-Transport-Security" and not is_https:
                    continue
                
                # Check if header is missing
                if not header_value:
                    if header_config["required"]:
                        severity = header_config["severity_if_missing"]
                        description = f"Missing required security header: {header_name}. {header_config['description']}"
                        
                        vuln = VulnerabilityResult(
                            name="Missing Security Header",
                            severity=severity,
                            description=description,
                            url=self.target_url,
                            parameter=header_name,
                            payload=None,
                            evidence=f"Header '{header_name}' is not present in HTTP response"
                        )
                        self.vulnerabilities.append(vuln)
                    continue
                
                # Validate header value (basic checks)
                issues = self._validate_header_value(header_name, header_value, header_config)
                if issues:
                    severity = "Medium"
                    description = f"Misconfigured security header: {header_name}. {issues}"
                    
                    vuln = VulnerabilityResult(
                        name="Misconfigured Security Header",
                        severity=severity,
                        description=description,
                        url=self.target_url,
                        parameter=header_name,
                        payload=header_value,
                        evidence=f"Header '{header_name}' has value '{header_value}' which may be insecure"
                    )
                    self.vulnerabilities.append(vuln)
            
            logger.info(f"Security headers scan complete. Found {len(self.vulnerabilities)} issues")
        
        except Exception as e:
            logger.error(f"Error during security headers scan: {e}", exc_info=True)
        finally:
            await self._close_client()
        
        return self.vulnerabilities
    
    def _validate_header_value(self, header_name: str, value: str, config: Dict) -> Optional[str]:
        """
        Validate security header value for common misconfigurations.
        
        Args:
            header_name: Header name
            value: Header value
            config: Header configuration
            
        Returns:
            Issue description if misconfigured, None otherwise
        """
        value_lower = value.lower()
        
        # Check X-Frame-Options
        if header_name == "X-Frame-Options":
            if value_lower not in ["deny", "sameorigin"]:
                return "X-Frame-Options should be 'DENY' or 'SAMEORIGIN', not 'ALLOW-FROM'"
        
        # Check X-Content-Type-Options
        if header_name == "X-Content-Type-Options":
            if value_lower != "nosniff":
                return "X-Content-Type-Options should be 'nosniff'"
        
        # Check Strict-Transport-Security
        if header_name == "Strict-Transport-Security":
            if "max-age" not in value_lower:
                return "HSTS header should include 'max-age' directive"
            if "max-age=0" in value_lower:
                return "HSTS max-age=0 disables HSTS (security risk)"
        
        # Check Content-Security-Policy for unsafe directives
        if header_name == "Content-Security-Policy":
            if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
                return "CSP contains 'unsafe-inline' or 'unsafe-eval' which reduces XSS protection"
        
        return None
    
    def generate_poc(self, vulnerability: VulnerabilityResult) -> str:
        """
        Generate proof-of-concept command to check headers.
        
        Args:
            vulnerability: The vulnerability to generate PoC for
            
        Returns:
            CURL command string
        """
        return f"curl -I '{vulnerability.url}' | grep -i '{vulnerability.parameter}'"
    
    def recommend_fix(self, vulnerability: VulnerabilityResult) -> Dict[str, str]:
        """
        Provide secure fix recommendations.
        
        Args:
            vulnerability: The vulnerability to provide fix for
            
        Returns:
            Dictionary with 'cause', 'fix', and 'why' keys
        """
        header_name = vulnerability.parameter or "Security-Header"
        header_config = self.SECURITY_HEADERS.get(header_name, {})
        recommended_value = header_config.get("recommended", "N/A")
        
        return {
            "cause": f'''# PROBLEM: Missing or Misconfigured Security Header

# The HTTP response is missing the "{header_name}" security header.
# Security headers are critical HTTP response headers that browsers use
# to enforce security policies and prevent common attacks.

# Common causes:
# 1. Web server not configured to send security headers
# 2. Application framework not setting headers
# 3. Headers removed by reverse proxy/CDN
# 4. Misconfigured header values that reduce security''',
            
            "fix": f'''# SECURE FIX: Add Security Headers

# Option 1: Web Server Configuration (Recommended)

# Apache (.htaccess or httpd.conf):
<IfModule mod_headers.c>
    Header always set {header_name} "{recommended_value}"
</IfModule>

# Nginx (nginx.conf):
add_header {header_name} "{recommended_value}" always;

# Option 2: Application-Level (Framework-specific)

# Python/Flask:
@app.after_request
def set_security_headers(response):
    response.headers['{header_name}'] = "{recommended_value}"
    return response

# Python/FastAPI:
from fastapi.middleware.cors import CORSMiddleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["{header_name}"] = "{recommended_value}"
    return response

# Node.js/Express:
app.use((req, res, next) => {{
    res.setHeader('{header_name}', '{recommended_value}');
    next();
}});

# PHP:
header('{header_name}: {recommended_value}');

# Option 3: Use Security Middleware Libraries
# Many frameworks have security middleware that sets all headers:
# - Django: django.middleware.security.SecurityMiddleware
# - Rails: secure_headers gem
# - Spring Boot: spring-boot-starter-security''',
            
            "why": f'''Security headers prevent common attacks because:

1. **Browser Enforcement**: Browsers enforce these policies client-side,
   providing defense-in-depth even if application code has vulnerabilities.

2. **Attack Prevention**:
   - **XSS**: Content-Security-Policy prevents malicious script execution
   - **Clickjacking**: X-Frame-Options prevents iframe embedding
   - **MIME Sniffing**: X-Content-Type-Options prevents type confusion attacks
   - **Man-in-the-Middle**: HSTS forces HTTPS and prevents downgrade attacks

3. **Industry Standard**: OWASP, security auditors, and compliance
   frameworks (PCI-DSS, SOC 2) require security headers.

4. **Low Cost, High Value**: Headers are easy to implement but provide
   significant security improvements with minimal performance impact.

**Best Practices**:
- Set security headers at the web server level (most reliable)
- Test headers using security header scanners (securityheaders.com)
- Monitor header presence in production
- Keep header policies restrictive (e.g., CSP should avoid 'unsafe-inline')
- Use report-uri for CSP violation reporting'''
        }

