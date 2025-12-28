"""
Cross-Site Scripting (XSS) Scanner Module - Async Implementation

This module detects Reflected XSS vulnerabilities by injecting canary strings
and checking for unencoded reflection in responses.

⚠️ EDUCATIONAL USE ONLY - For authorized testing only.
"""

import re
import logging
from typing import List, Optional, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx
from bs4 import BeautifulSoup

from .base import ScannerModule, VulnerabilityResult

logger = logging.getLogger(__name__)


class XSSScanner(ScannerModule):
    """
    Async Reflected XSS scanner using canary injection.
    
    Detection Strategy:
    1. Inject unique canary strings into URL parameters and form inputs
    2. Check if canary is reflected in response body unencoded
    3. Validate context (HTML entity encoding vs URL encoding)
    """
    
    # Canary string - unique and unlikely to appear naturally
    CANARY = "<vM_t3st_xss>"
    
    # Alternative safe canaries for different contexts
    CANARIES = [
        "<vM_t3st_xss>",
        "vM_t3st_xss",
        "'vM_t3st_xss'",
        '"vM_t3st_xss"',
    ]
    
    # Patterns to detect unencoded reflection
    REFLECTION_PATTERNS = [
        re.compile(re.escape(CANARY), re.IGNORECASE),
    ]
    
    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize the XSS scanner.
        
        Args:
            target_url: The URL to scan
            timeout: Request timeout in seconds
        """
        super().__init__(target_url)
        self.timeout = timeout
        self.client = None  # Will be initialized in async context
    
    def get_vulnerability_name(self) -> str:
        """Return the name of this vulnerability type."""
        return "Cross-Site Scripting (XSS)"
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,  # For local testing
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
    
    async def _fetch_page(self, url: str, method: str = "GET", data: Optional[dict] = None) -> Optional[httpx.Response]:
        """
        Fetch a page asynchronously.
        
        Args:
            url: URL to fetch
            method: HTTP method (GET or POST)
            data: Form data for POST requests
            
        Returns:
            Response object or None if request fails
        """
        try:
            client = await self._get_client()
            if method.upper() == "POST":
                response = await client.post(url, data=data)
            else:
                response = await client.get(url)
            return response
        except Exception as e:
            logger.debug(f"Error fetching {url}: {e}")
            return None
    
    def _check_reflection(self, response_text: str, canary: str) -> tuple[bool, Optional[str]]:
        """
        Check if canary is reflected unencoded in the response.
        
        Args:
            response_text: Response body text
            canary: The canary string that was injected
            
        Returns:
            Tuple of (is_reflected, context_type)
            context_type can be: 'html', 'attribute', 'javascript', 'url'
        """
        # Check for unencoded reflection (raw canary)
        if canary in response_text:
            # Determine context
            # Find where the canary appears
            index = response_text.find(canary)
            context_before = response_text[max(0, index - 50):index]
            context_after = response_text[index + len(canary):index + len(canary) + 50]
            
            # Check HTML context
            if '<' in context_before or '>' in context_after:
                return True, 'html'
            
            # Check attribute context
            if '="' in context_before or '"' in context_after:
                return True, 'attribute'
            
            # Check JavaScript context
            if '<script' in context_before.lower() or '</script>' in context_after.lower():
                return True, 'javascript'
            
            # Check URL context
            if '?' in context_before or '&' in context_before:
                return True, 'url'
            
            return True, 'html'  # Default to HTML
        
        # Check for HTML entity encoded (safe - not vulnerable in HTML context)
        html_encoded = canary.replace('<', '&lt;').replace('>', '&gt;')
        if html_encoded in response_text:
            return False, None
        
        return False, None
    
    async def _test_url_parameter(
        self,
        url: str,
        param_name: str,
        base_response: Optional[httpx.Response]
    ) -> List[VulnerabilityResult]:
        """
        Test a URL query parameter for XSS vulnerabilities.
        
        Args:
            url: Base URL
            param_name: Parameter name to test
            base_response: Baseline response (optional)
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Use canary
        canary = self.CANARY
        
        try:
            # Create test URL with canary
            test_params = base_params.copy()
            test_params[param_name] = [canary]
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, test_query, parsed.fragment
            ))
            
            # Send request
            test_response = await self._fetch_page(test_url)
            if not test_response:
                return vulnerabilities
            
            # Check for reflection
            is_reflected, context = self._check_reflection(test_response.text, canary)
            
            if is_reflected:
                vuln = VulnerabilityResult(
                    name="Cross-Site Scripting (XSS)",
                    severity="High",
                    description=f"Reflected XSS vulnerability detected in parameter '{param_name}'. "
                              f"The input is reflected unencoded in the response in {context} context. "
                              f"An attacker could inject malicious JavaScript code.",
                    url=test_url,
                    parameter=param_name,
                    payload=canary,
                    evidence=f"Canary string '{canary}' reflected unencoded in {context} context"
                )
                vulnerabilities.append(vuln)
                logger.warning(f"Potential XSS found in parameter '{param_name}' at {url}")
        
        except Exception as e:
            logger.debug(f"Error testing parameter {param_name}: {e}")
        
        return vulnerabilities
    
    async def _test_form_input(
        self,
        form_url: str,
        form_method: str,
        input_name: str,
        base_form_data: dict
    ) -> List[VulnerabilityResult]:
        """
        Test a form input for XSS vulnerabilities.
        
        Args:
            form_url: Form action URL
            form_method: HTTP method (GET or POST)
            input_name: Input field name
            base_form_data: Base form data
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        canary = self.CANARY
        
        try:
            test_data = base_form_data.copy()
            test_data[input_name] = canary
            
            # Submit form
            test_response = await self._fetch_page(
                form_url,
                method=form_method.upper(),
                data=test_data
            )
            
            if not test_response:
                return vulnerabilities
            
            # Check for reflection
            is_reflected, context = self._check_reflection(test_response.text, canary)
            
            if is_reflected:
                vuln = VulnerabilityResult(
                    name="Cross-Site Scripting (XSS)",
                    severity="High",
                    description=f"Reflected XSS vulnerability detected in form input '{input_name}'. "
                              f"The input is reflected unencoded in the response in {context} context. "
                              f"An attacker could inject malicious JavaScript code.",
                    url=form_url,
                    parameter=input_name,
                    payload=canary,
                    evidence=f"Canary string '{canary}' reflected unencoded in {context} context"
                )
                vulnerabilities.append(vuln)
                logger.warning(f"Potential XSS found in form input '{input_name}' at {form_url}")
        
        except Exception as e:
            logger.debug(f"Error testing form input {input_name}: {e}")
        
        return vulnerabilities
    
    async def detect(self) -> List[VulnerabilityResult]:
        """
        Perform XSS scan asynchronously.
        Note: This method expects forms and URLs to be provided via spider results.
        For now, we'll test the base URL parameters.
        
        Returns:
            List of VulnerabilityResult objects found
        """
        logger.info(f"Starting XSS scan on {self.target_url}")
        self.vulnerabilities = []
        
        try:
            # Get baseline response
            base_response = await self._fetch_page(self.target_url)
            if not base_response:
                logger.error(f"Could not fetch base URL: {self.target_url}")
                return []
            
            # Test URL parameters
            parsed = urlparse(self.target_url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            
            if query_params:
                for param_name in query_params.keys():
                    vulns = await self._test_url_parameter(
                        self.target_url, param_name, base_response
                    )
                    self.vulnerabilities.extend(vulns)
            else:
                # Test with a common parameter name if no parameters exist
                test_url = f"{self.target_url}?q=test"
                test_response = await self._fetch_page(test_url)
                if test_response:
                    vulns = await self._test_url_parameter(
                        test_url, "q", base_response
                    )
                    self.vulnerabilities.extend(vulns)
            
            # Test form inputs (if forms were discovered by spider)
            soup = BeautifulSoup(base_response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                form_url = urljoin(self.target_url, form_action) if form_action else self.target_url
                
                inputs = form.find_all(['input', 'textarea'], 
                                     type=lambda x: x and x.lower() not in ['submit', 'button', 'hidden'])
                
                if not inputs:
                    continue
                
                # Build base form data
                form_data = {}
                for input_field in inputs:
                    input_name = input_field.get('name')
                    if input_name:
                        form_data[input_name] = input_field.get('value', 'test')
                
                # Test each input
                for input_field in inputs:
                    input_name = input_field.get('name')
                    if not input_name:
                        continue
                    
                    vulns = await self._test_form_input(
                        form_url, form_method, input_name, form_data
                    )
                    self.vulnerabilities.extend(vulns)
            
            # Remove duplicates
            seen = set()
            unique_vulns = []
            for vuln in self.vulnerabilities:
                key = (vuln.url, vuln.parameter)
                if key not in seen:
                    seen.add(key)
                    unique_vulns.append(vuln)
            
            self.vulnerabilities = unique_vulns
            logger.info(f"XSS scan complete. Found {len(self.vulnerabilities)} potential vulnerabilities")
        
        except Exception as e:
            logger.error(f"Error during XSS scan: {e}", exc_info=True)
        finally:
            await self._close_client()
        
        return self.vulnerabilities
    
    def generate_poc(self, vulnerability: VulnerabilityResult) -> str:
        """
        Generate proof-of-concept attack command (CURL) for a vulnerability.
        
        Args:
            vulnerability: The vulnerability to generate PoC for
            
        Returns:
            CURL command string with harmless console.log payload
        """
        url = vulnerability.url
        parameter = vulnerability.parameter
        # Use safe, non-executing payload for educational purposes
        safe_payload = "<script>console.log('XSS')</script>"
        
        # Escape for shell
        escaped_payload = safe_payload.replace("'", "'\\''")
        
        parsed = urlparse(url)
        if parsed.query:
            # GET request - modify query parameter
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            query_params[parameter] = [safe_payload]
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            return f"curl '{test_url}'"
        else:
            # POST request (assumed)
            return f"curl -X POST '{url}' -d '{parameter}={escaped_payload}'"
    
    def recommend_fix(self, vulnerability: VulnerabilityResult) -> Dict[str, str]:
        """
        Provide secure code fix and educational explanation about context-aware encoding.
        
        Args:
            vulnerability: The vulnerability to provide fix for
            
        Returns:
            Dictionary with 'cause', 'fix', and 'why' keys
        """
        return {
            "cause": '''# VULNERABLE CODE (DON'T DO THIS!)
user_input = request.args.get('q')

# PROBLEM: User input is directly inserted into HTML without encoding
html = f"<div>Search results for: {user_input}</div>"
return html

# OR in a template:
<div>Search results for: {{ user_input }}</div>

# PROBLEM: If user_input contains <script>alert(1)</script>, it executes!''',
            
            "fix": '''# SECURE CODE - Context-Aware Encoding

from html import escape  # Python
# OR use template auto-escaping

# HTML Context (most common)
user_input = request.args.get('q')
escaped = escape(user_input)  # Converts < to &lt;, > to &gt;, etc.
html = f"<div>Search results for: {escaped}</div>"

# JavaScript Context (inside <script> tags)
# Use JSON encoding, not HTML encoding!
import json
js_value = json.dumps(user_input)  # Properly escapes for JS
html = f"<script>var search = {js_value};</script>"

# URL Context
from urllib.parse import quote
url_safe = quote(user_input)
url = f"/search?q={url_safe}"

# Attribute Context
attr_safe = escape(user_input).replace('"', '&quot;')
html = f'<input value="{attr_safe}">'

# Template Engines (RECOMMENDED)
# Most modern template engines auto-escape by default:
# - Jinja2: {{ user_input }}  (auto-escapes)
# - Django: {{ user_input }}  (auto-escapes)
# - React: {userInput}  (auto-escapes)
# - Vue: {{ userInput }}  (auto-escapes)''',
            
            "why": '''Context-Aware Encoding is crucial because different contexts require different encoding:

1. **HTML Context** (<div>{input}</div>):
   - Use HTML entity encoding: < → &lt;, > → &gt;, & → &amp;
   - Prevents <script> tags from being parsed as HTML

2. **JavaScript Context** (<script>var x = {input};</script>):
   - Use JSON encoding or JavaScript string escaping
   - HTML encoding doesn't work here! <script>var x = "&lt;script&gt;";</script> still executes
   - JSON.dumps() properly escapes quotes and special chars

3. **URL Context** (<a href="/search?q={input}">):
   - Use URL encoding: space → %20, & → %26
   - Prevents URL injection attacks

4. **Attribute Context** (<input value="{input}">):
   - Use HTML entity encoding + quote escaping
   - Prevents breaking out of attributes

**Best Practice**: Use a template engine with auto-escaping (Jinja2, Django templates, React, etc.) 
that handles context-aware encoding automatically. Only bypass escaping when you absolutely need 
to render HTML and trust the source completely (use a whitelist-based HTML sanitizer like bleach).'''
        }

