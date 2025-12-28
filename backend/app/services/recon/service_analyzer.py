"""
Service Analyzer - HTTP Header Analysis and CVE Correlation

Analyzes HTTP headers to fingerprint services, detect versions,
and correlate with known CVEs for educational purposes.
"""

import re
import logging
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class ServiceAnalyzer:
    """
    Analyzes HTTP headers and service banners to identify:
    - Operating systems
    - Web server versions
    - Application frameworks
    - Known CVEs based on version detection
    """
    
    # CVE Database (Educational - simplified local mapping)
    # Format: {service_name: {version_pattern: [CVEs]}}
    CVE_DATABASE = {
        'apache': {
            '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],  # Path Traversal
            '2.4.48': ['CVE-2021-41773'],  # Path Traversal
            '2.4.47': ['CVE-2021-41773'],  # Path Traversal
            '2.4.46': ['CVE-2021-41773'],  # Path Traversal
            '2.4.41': ['CVE-2019-0211'],   # Privilege Escalation
            '2.4.39': ['CVE-2019-0211'],   # Privilege Escalation
        },
        'nginx': {
            '1.21.0': ['CVE-2021-23017'],  # DNS resolver vulnerability
            '1.20.0': ['CVE-2021-23017'],
            '1.18.0': ['CVE-2021-23017'],
            '1.16.0': ['CVE-2019-20372'],  # DNS resolver vulnerability
        },
        'iis': {
            '10.0': ['CVE-2021-31166'],  # HTTP Protocol Stack RCE
            '7.5': ['CVE-2015-1635'],    # HTTP.sys RCE
        },
        'php': {
            '7.4.0': ['CVE-2020-7069'],  # Various vulnerabilities
            '7.3.0': ['CVE-2019-11043'], # RCE in Nginx+PHP-FPM
            '7.2.0': ['CVE-2019-11043'],
            '5.6.0': ['CVE-2019-11043'],  # Multiple CVEs
        },
        'openssh': {
            '8.0': ['CVE-2020-15778'],  # Command injection
            '7.7': ['CVE-2018-15473'],  # User enumeration
            '7.4': ['CVE-2017-15906'],  # Multiple vulnerabilities
        },
        'mysql': {
            '8.0.0': ['CVE-2021-37165'],  # Various vulnerabilities
            '5.7.0': ['CVE-2020-14559'],  # Multiple CVEs
            '5.6.0': ['CVE-2019-2737'],   # Multiple CVEs
        },
    }
    
    # Version extraction patterns
    VERSION_PATTERNS = {
        'apache': re.compile(r'Apache[\/\s]+([\d.]+)', re.IGNORECASE),
        'nginx': re.compile(r'nginx[\/\s]+([\d.]+)', re.IGNORECASE),
        'iis': re.compile(r'Microsoft-IIS[\/\s]+([\d.]+)', re.IGNORECASE),
        'php': re.compile(r'PHP[\/\s]+([\d.]+)', re.IGNORECASE),
        'openssh': re.compile(r'OpenSSH[_\-\/]([\d.]+)', re.IGNORECASE),
        'mysql': re.compile(r'mysql[\/\s]+([\d.]+)', re.IGNORECASE),
    }
    
    # OS detection patterns
    OS_PATTERNS = {
        'ubuntu': re.compile(r'Ubuntu', re.IGNORECASE),
        'debian': re.compile(r'Debian', re.IGNORECASE),
        'centos': re.compile(r'CentOS', re.IGNORECASE),
        'redhat': re.compile(r'Red[_\s]?Hat', re.IGNORECASE),
        'windows': re.compile(r'Windows', re.IGNORECASE),
        'linux': re.compile(r'Linux', re.IGNORECASE),
    }
    
    def __init__(self):
        """Initialize service analyzer."""
        pass
    
    def analyze_headers(self, headers: Dict[str, str]) -> Dict:
        """
        Analyze HTTP headers to extract service information.
        
        Args:
            headers: Dictionary of HTTP headers
            
        Returns:
            Dictionary with detected services, versions, OS, and CVEs
        """
        result = {
            'web_server': None,
            'web_server_version': None,
            'os': None,
            'framework': None,
            'framework_version': None,
            'cves': [],
            'raw_headers': {}
        }
        
        # Normalize header keys (HTTP headers are case-insensitive)
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        result['raw_headers'] = normalized_headers
        
        # Analyze Server header
        server_header = normalized_headers.get('server', '')
        if server_header:
            result.update(self._parse_server_header(server_header))
        
        # Analyze X-Powered-By header (PHP, ASP.NET, etc.)
        powered_by = normalized_headers.get('x-powered-by', '')
        if powered_by:
            framework_info = self._parse_powered_by_header(powered_by)
            if framework_info:
                result['framework'] = framework_info.get('framework')
                result['framework_version'] = framework_info.get('version')
                if framework_info.get('cves'):
                    result['cves'].extend(framework_info['cves'])
        
        # Analyze X-AspNet-Version (ASP.NET)
        aspnet_version = normalized_headers.get('x-aspnet-version', '')
        if aspnet_version:
            result['framework'] = 'ASP.NET'
            result['framework_version'] = aspnet_version
        
        # Remove duplicate CVEs
        result['cves'] = list(set(result['cves']))
        
        return result
    
    def _parse_server_header(self, server_header: str) -> Dict:
        """
        Parse Server header to extract web server and version.
        
        Args:
            server_header: Server header value
            
        Returns:
            Dictionary with web_server, web_server_version, os, and cves
        """
        result = {
            'web_server': None,
            'web_server_version': None,
            'os': None,
            'cves': []
        }
        
        server_lower = server_header.lower()
        
        # Detect web server type
        if 'apache' in server_lower:
            result['web_server'] = 'Apache'
            version = self._extract_version(server_header, 'apache')
            if version:
                result['web_server_version'] = version
                result['cves'].extend(self._check_cves('apache', version))
        
        elif 'nginx' in server_lower:
            result['web_server'] = 'Nginx'
            version = self._extract_version(server_header, 'nginx')
            if version:
                result['web_server_version'] = version
                result['cves'].extend(self._check_cves('nginx', version))
        
        elif 'microsoft-iis' in server_lower or 'iis' in server_lower:
            result['web_server'] = 'IIS'
            version = self._extract_version(server_header, 'iis')
            if version:
                result['web_server_version'] = version
                result['cves'].extend(self._check_cves('iis', version))
        
        # Detect OS from Server header
        for os_name, pattern in self.OS_PATTERNS.items():
            if pattern.search(server_header):
                result['os'] = os_name.capitalize()
                break
        
        return result
    
    def _parse_powered_by_header(self, powered_by: str) -> Optional[Dict]:
        """
        Parse X-Powered-By header to extract framework and version.
        
        Args:
            powered_by: X-Powered-By header value
            
        Returns:
            Dictionary with framework, version, and cves, or None
        """
        result = {
            'framework': None,
            'version': None,
            'cves': []
        }
        
        powered_lower = powered_by.lower()
        
        # Detect PHP
        if 'php' in powered_lower:
            result['framework'] = 'PHP'
            version = self._extract_version(powered_by, 'php')
            if version:
                result['version'] = version
                result['cves'].extend(self._check_cves('php', version))
        
        # Detect ASP.NET
        elif 'asp.net' in powered_lower:
            result['framework'] = 'ASP.NET'
            version = self._extract_version(powered_by, None)
            if version:
                result['version'] = version
        
        return result if result['framework'] else None
    
    def _extract_version(self, text: str, service: Optional[str] = None) -> Optional[str]:
        """
        Extract version number from text.
        
        Args:
            text: Text to extract version from
            service: Service name (optional, for specific patterns)
            
        Returns:
            Version string or None
        """
        if service and service in self.VERSION_PATTERNS:
            pattern = self.VERSION_PATTERNS[service]
            match = pattern.search(text)
            if match:
                return match.group(1)
        
        # Generic version pattern (major.minor.patch)
        generic_pattern = re.compile(r'([\d]+\.[\d]+(?:\.[\d]+)?)')
        match = generic_pattern.search(text)
        if match:
            return match.group(1)
        
        return None
    
    def _check_cves(self, service: str, version: str) -> List[str]:
        """
        Check for known CVEs based on service and version.
        
        Args:
            service: Service name (lowercase)
            version: Version string
            
        Returns:
            List of CVE identifiers
        """
        cves = []
        
        if service.lower() in self.CVE_DATABASE:
            service_cves = self.CVE_DATABASE[service.lower()]
            
            # Exact version match
            if version in service_cves:
                cves.extend(service_cves[version])
            
            # Check for version range matches (simplified)
            # For versions like "2.4.49", check if any vulnerable version matches
            version_parts = version.split('.')
            if len(version_parts) >= 2:
                major_minor = '.'.join(version_parts[:2])
                for vuln_version, vuln_cves in service_cves.items():
                    if vuln_version.startswith(major_minor):
                        # Compare versions (simplified - assumes newer version numbers)
                        try:
                            if self._version_compare(version, vuln_version) <= 0:
                                cves.extend(vuln_cves)
                        except Exception:
                            pass
        
        return list(set(cves))
    
    def _version_compare(self, v1: str, v2: str) -> int:
        """
        Compare two version strings.
        Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        
        Args:
            v1: Version string 1
            v2: Version string 2
            
        Returns:
            Comparison result
        """
        def normalize_version(v):
            parts = v.split('.')
            return tuple(int(p) for p in parts if p.isdigit())
        
        try:
            v1_norm = normalize_version(v1)
            v2_norm = normalize_version(v2)
            
            if v1_norm < v2_norm:
                return -1
            elif v1_norm > v2_norm:
                return 1
            else:
                return 0
        except Exception:
            return 0
    
    def analyze_banner(self, banner: str) -> Dict:
        """
        Analyze service banner (from port scanning) to extract information.
        
        Args:
            banner: Service banner string
            
        Returns:
            Dictionary with service information and CVEs
        """
        result = {
            'service': None,
            'version': None,
            'cves': []
        }
        
        banner_lower = banner.lower()
        
        # Check for SSH
        if 'ssh' in banner_lower:
            result['service'] = 'SSH'
            version = self._extract_version(banner, 'openssh')
            if version:
                result['version'] = version
                result['cves'].extend(self._check_cves('openssh', version))
        
        # Check for MySQL
        elif 'mysql' in banner_lower:
            result['service'] = 'MySQL'
            version = self._extract_version(banner, 'mysql')
            if version:
                result['version'] = version
                result['cves'].extend(self._check_cves('mysql', version))
        
        return result
    
    def generate_cve_report(self, analysis: Dict) -> str:
        """
        Generate human-readable CVE report.
        
        Args:
            analysis: Analysis result dictionary
            
        Returns:
            Formatted CVE report string
        """
        report_parts = []
        
        if analysis.get('web_server'):
            report_parts.append(f"Web Server: {analysis['web_server']}")
            if analysis.get('web_server_version'):
                report_parts.append(f"Version: {analysis['web_server_version']}")
        
        if analysis.get('framework'):
            report_parts.append(f"Framework: {analysis['framework']}")
            if analysis.get('framework_version'):
                report_parts.append(f"Version: {analysis['framework_version']}")
        
        if analysis.get('os'):
            report_parts.append(f"OS: {analysis['os']}")
        
        if analysis.get('cves'):
            report_parts.append(f"\n⚠️ Known Vulnerabilities Detected:")
            for cve in analysis['cves']:
                report_parts.append(f"  - {cve}")
            
            report_parts.append("\nRecommendation: Update to the latest version immediately.")
        else:
            report_parts.append("\n✅ No known CVEs detected in local database.")
            report_parts.append("Note: This is a simplified local database. Perform full CVE scan for comprehensive results.")
        
        return "\n".join(report_parts)

