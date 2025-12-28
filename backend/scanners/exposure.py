"""
Sensitive File Exposure Scanner Module

Scans for unlinked sensitive files and directories that are publicly accessible
but not referenced in the website structure (discovered by spider).
"""

import asyncio
import logging
from typing import List, Optional, Dict
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .base import ScannerModule, VulnerabilityResult

logger = logging.getLogger(__name__)


class ExposureScanner(ScannerModule):
    """
    Scanner for sensitive file exposure vulnerabilities.
    
    Detection Strategy:
    1. Uses wordlist-based directory busting
    2. Checks for high-risk files (.env, .git, backups, etc.)
    3. Uses HEAD requests for efficiency (switches to GET if needed)
    4. Analyzes response codes and sizes to detect exposed files
    """
    
    # High-risk sensitive files and directories
    SENSITIVE_FILES = [
        # Configuration files
        '.env',
        '.env.local',
        '.env.production',
        '.env.development',
        'config.php',
        'config.inc.php',
        'configuration.php',
        'settings.php',
        'wp-config.php',
        'config.json',
        
        # Version control
        '.git/HEAD',
        '.git/config',
        '.git/refs/heads/master',
        '.svn/entries',
        '.hg/requires',
        
        # Backups
        'backup.zip',
        'backup.tar.gz',
        'backup.sql',
        'dump.sql',
        'database.sql',
        'db.sql',
        'backup.tar',
        'backup.db',
        
        # Database dumps
        'dump.sql',
        'database.sql',
        'db_backup.sql',
        'data.sql',
        
        # System files
        '.ds_store',
        '.DS_Store',
        'Thumbs.db',
        'desktop.ini',
        
        # Logs
        'error.log',
        'access.log',
        'debug.log',
        'application.log',
        
        # Documentation that might leak info
        'README.md',
        'CHANGELOG.md',
        'LICENSE',
        '.gitignore',
        '.htaccess',
        'robots.txt',  # Sometimes reveals sensitive paths
        
        # API and secrets
        'api_keys.txt',
        'secrets.json',
        'credentials.json',
        'passwords.txt',
        'keys.txt',
        
        # IDE and editor files
        '.idea/workspace.xml',
        '.vscode/settings.json',
        '.project',
        '.classpath',
    ]
    
    # File extensions that indicate sensitive content
    SENSITIVE_EXTENSIONS = ['.sql', '.bak', '.old', '.backup', '.swp', '.tmp']
    
    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize the exposure scanner.
        
        Args:
            target_url: The URL to scan
            timeout: Request timeout in seconds
        """
        super().__init__(target_url)
        self.timeout = timeout
        self.client = None
    
    def get_vulnerability_name(self) -> str:
        """Return the name of this vulnerability type."""
        return "Sensitive File Exposure"
    
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
    
    async def _check_file(self, url: str, file_path: str) -> Optional[VulnerabilityResult]:
        """
        Check if a sensitive file exists and is accessible.
        
        Args:
            url: Base URL
            file_path: File path to check
            
        Returns:
            VulnerabilityResult if file is exposed, None otherwise
        """
        try:
            file_url = urljoin(url, file_path)
            client = await self._get_client()
            
            # Try HEAD request first (more efficient)
            try:
                response = await client.head(file_url)
                
                # If HEAD returns 200 or 405 (Method Not Allowed), try GET
                if response.status_code == 405:
                    response = await client.get(file_url)
                elif response.status_code != 200:
                    return None
                else:
                    # HEAD returned 200, verify with GET for important files
                    # (some servers return 200 on HEAD but file doesn't exist)
                    if any(file_path.lower().endswith(ext) for ext in ['.env', '.sql', '.git']):
                        response = await client.get(file_url, timeout=5.0)
                
            except httpx.HTTPError:
                # HEAD not supported, try GET
                try:
                    response = await client.get(file_url, timeout=5.0)
                except Exception:
                    return None
            
            # Check if file is accessible
            if response.status_code == 200:
                content_length = response.headers.get('content-length')
                
                # Determine severity based on file type
                severity = "Medium"
                description = f"Sensitive file '{file_path}' is publicly accessible."
                
                if '.env' in file_path.lower():
                    severity = "Critical"
                    description = f"Critical: Environment file '{file_path}' is publicly accessible. " \
                                f"This file typically contains API keys, database credentials, and other secrets."
                elif file_path.endswith('.sql'):
                    severity = "Critical"
                    description = f"Critical: Database dump file '{file_path}' is publicly accessible. " \
                                f"This file may contain sensitive database contents."
                elif '.git' in file_path.lower():
                    severity = "High"
                    description = f"High: Git repository file '{file_path}' is publicly accessible. " \
                                f"This may allow attackers to access source code and commit history."
                elif any(file_path.lower().endswith(ext) for ext in ['.zip', '.tar.gz', '.tar', '.bak']):
                    severity = "High"
                    description = f"High: Backup file '{file_path}' is publicly accessible. " \
                                f"This file may contain sensitive data or source code."
                elif file_path.endswith('.log'):
                    severity = "Medium"
                    description = f"Medium: Log file '{file_path}' is publicly accessible. " \
                                f"Log files may contain sensitive information or error details."
                
                vuln = VulnerabilityResult(
                    name="Sensitive File Exposure",
                    severity=severity,
                    description=description,
                    url=file_url,
                    parameter=None,
                    payload=file_path,
                    evidence=f"File accessible at {file_url} (Status: {response.status_code}, " \
                            f"Size: {content_length or 'unknown'} bytes)"
                )
                
                return vuln
        
        except Exception as e:
            logger.debug(f"Error checking file {file_path}: {e}")
        
        return None
    
    async def detect(self) -> List[VulnerabilityResult]:
        """
        Perform sensitive file exposure scan.
        
        Returns:
            List of VulnerabilityResult objects found
        """
        logger.info(f"Starting sensitive file exposure scan on {self.target_url}")
        self.vulnerabilities = []
        
        try:
            # Check each sensitive file
            tasks = [self._check_file(self.target_url, file_path) 
                    for file_path in self.SENSITIVE_FILES]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    logger.debug(f"Error in file check task: {result}")
                    continue
                if isinstance(result, VulnerabilityResult):
                    self.vulnerabilities.append(result)
            
            logger.info(f"Sensitive file scan complete. Found {len(self.vulnerabilities)} exposed files")
        
        except Exception as e:
            logger.error(f"Error during sensitive file scan: {e}", exc_info=True)
        finally:
            await self._close_client()
        
        return self.vulnerabilities
    
    def generate_poc(self, vulnerability: VulnerabilityResult) -> str:
        """
        Generate proof-of-concept command to access exposed file.
        
        Args:
            vulnerability: The vulnerability to generate PoC for
            
        Returns:
            CURL command string
        """
        file_url = vulnerability.url
        return f"curl '{file_url}'"
    
    def recommend_fix(self, vulnerability: VulnerabilityResult) -> Dict[str, str]:
        """
        Provide secure fix recommendations.
        
        Args:
            vulnerability: The vulnerability to provide fix for
            
        Returns:
            Dictionary with 'cause', 'fix', and 'why' keys
        """
        file_path = vulnerability.payload or "sensitive_file"
        
        return {
            "cause": f'''# PROBLEM: Sensitive File Publicly Accessible

# The file "{file_path}" is accessible via HTTP without authentication.
# Common causes:
# 1. File placed in web root directory
# 2. Missing .htaccess or web server configuration
# 3. Misconfigured web server allowing directory listing
# 4. Deployment scripts copying sensitive files to public directories

# Example vulnerable scenario:
# - Developer creates .env file in project root
# - Project root is also web root
# - .env file becomes accessible at https://example.com/.env''',
            
            "fix": '''# SECURE FIXES

# 1. Move sensitive files outside web root
# BEFORE:
/var/www/html/.env          # Accessible at https://example.com/.env

# AFTER:
/var/www/.env               # Outside web root
/var/www/html/              # Web root (no sensitive files)

# 2. Configure web server to deny access

# Apache (.htaccess):
<FilesMatch "^\\.env$|^\\.git$|\\.sql$|\\.bak$">
    Require all denied
</FilesMatch>

# Nginx:
location ~ /\\.env$ {
    deny all;
    return 404;
}

location ~ /\\.git {
    deny all;
    return 404;
}

# 3. Use environment variables properly
# Instead of .env file in project, use:
# - System environment variables
# - Secure secret management (AWS Secrets Manager, HashiCorp Vault)
# - Configuration injection at runtime (not from files)

# 4. Add to .gitignore (if using version control)
.env
.env.*
*.sql
*.bak
*.backup
.git/

# 5. Regular security audits
# - Automated scanning for exposed files
# - Review file permissions
# - Monitor web server logs for access attempts''',
            
            "why": f'''Preventing sensitive file exposure is critical because:

1. **Credentials Leakage**: Files like .env contain database passwords, API keys, 
   and authentication tokens that attackers can use to compromise the system.

2. **Source Code Exposure**: .git directories allow attackers to reconstruct 
   source code, find hardcoded secrets, and understand application logic.

3. **Data Breaches**: Database dumps (.sql files) may contain personally 
   identifiable information (PII), passwords, or other sensitive data.

4. **Attack Surface Expansion**: Exposed configuration files reveal system 
   architecture, dependencies, and potential attack vectors.

**Best Practices**:
- Never store sensitive files in web-accessible directories
- Use proper web server configuration to deny access
- Implement proper secret management (environment variables, secret managers)
- Regular security scans to detect exposed files
- Monitor access logs for unauthorized file access attempts
- Use least privilege principle: files should only be accessible to processes 
  that absolutely need them'''
        }


# Fix missing import
import asyncio

