"""
Cross-Site Request Forgery (CSRF) Scanner Module

Detects missing CSRF protection in forms and state-changing operations.
"""

import logging
from typing import List, Optional, Dict
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .base import ScannerModule, VulnerabilityResult

logger = logging.getLogger(__name__)


class CSRFScanner(ScannerModule):
    """
    CSRF vulnerability scanner.
    
    Detection Strategy:
    1. Find all forms with POST/PUT/DELETE methods
    2. Check for CSRF tokens (common names: csrf_token, _token, authenticity_token, etc.)
    3. Check for SameSite cookie attributes
    4. Verify referer checks (if applicable)
    """
    
    # Common CSRF token field names
    CSRF_TOKEN_NAMES = [
        'csrf_token',
        'csrf-token',
        'csrf',
        '_token',
        'authenticity_token',
        'csrfmiddlewaretoken',
        '_csrf',
        'csrfToken',
        'X-CSRF-Token',
        'X-CSRFToken',
    ]
    
    # State-changing HTTP methods
    STATE_CHANGING_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH']
    
    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize the CSRF scanner.
        
        Args:
            target_url: The URL to scan
            timeout: Request timeout in seconds
        """
        super().__init__(target_url)
        self.timeout = timeout
        self.client = None
    
    def get_vulnerability_name(self) -> str:
        """Return the name of this vulnerability type."""
        return "Cross-Site Request Forgery (CSRF)"
    
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
    
    def _has_csrf_token(self, form) -> bool:
        """
        Check if form contains CSRF token.
        
        Args:
            form: BeautifulSoup form element
            
        Returns:
            True if CSRF token found
        """
        # Check hidden input fields for CSRF tokens
        hidden_inputs = form.find_all('input', type='hidden')
        for input_field in hidden_inputs:
            name = input_field.get('name', '').lower()
            if any(token_name.lower() in name for token_name in self.CSRF_TOKEN_NAMES):
                return True
        
        # Check meta tags (common in frameworks like Laravel)
        # This would require checking the page, not just the form
        return False
    
    def _check_samesite_cookies(self, headers: dict) -> bool:
        """
        Check if cookies have SameSite attribute.
        
        Args:
            headers: HTTP response headers
            
        Returns:
            True if SameSite cookies found
        """
        set_cookie = headers.get('Set-Cookie', '')
        if isinstance(set_cookie, list):
            set_cookie = ' '.join(set_cookie)
        
        # Check for SameSite attribute (case insensitive)
        return 'samesite' in set_cookie.lower()
    
    async def detect(self) -> List[VulnerabilityResult]:
        """
        Perform CSRF vulnerability scan.
        
        Returns:
            List of VulnerabilityResult objects found
        """
        logger.info(f"Starting CSRF scan on {self.target_url}")
        self.vulnerabilities = []
        
        try:
            client = await self._get_client()
            response = await client.get(self.target_url)
            headers = dict(response.headers)
            
            # Check for SameSite cookies (helps but doesn't prevent CSRF alone)
            has_samesite = self._check_samesite_cookies(headers)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_method = form.get('method', 'GET').upper()
                form_action = form.get('action', '')
                form_url = urljoin(self.target_url, form_action) if form_action else self.target_url
                
                # Only check state-changing operations
                if form_method not in self.STATE_CHANGING_METHODS:
                    continue
                
                # Check if form has CSRF token
                has_token = self._has_csrf_token(form)
                
                if not has_token:
                    # Found vulnerable form
                    severity = "High"
                    description = f"Form at '{form_url}' uses {form_method} method without CSRF protection. "
                    
                    if has_samesite:
                        description += "SameSite cookies are present but may not be sufficient protection."
                    else:
                        description += "No CSRF token found and no SameSite cookie protection detected."
                    
                    vuln = VulnerabilityResult(
                        name="Missing CSRF Protection",
                        severity=severity,
                        description=description,
                        url=form_url,
                        parameter=None,
                        payload=form_method,
                        evidence=f"Form uses {form_method} method without CSRF token. "
                                f"SameSite cookies: {'Present' if has_samesite else 'Not found'}"
                    )
                    self.vulnerabilities.append(vuln)
                    logger.warning(f"CSRF vulnerability detected in form at {form_url}")
            
            logger.info(f"CSRF scan complete. Found {len(self.vulnerabilities)} vulnerabilities")
        
        except Exception as e:
            logger.error(f"Error during CSRF scan: {e}", exc_info=True)
        finally:
            await self._close_client()
        
        return self.vulnerabilities
    
    def generate_poc(self, vulnerability: VulnerabilityResult) -> str:
        """
        Generate proof-of-concept HTML page demonstrating CSRF attack.
        
        Args:
            vulnerability: The vulnerability to generate PoC for
            
        Returns:
            HTML string demonstrating CSRF attack
        """
        url = vulnerability.url
        method = vulnerability.payload or "POST"
        
        return f'''<!-- CSRF Proof of Concept -->
<!-- Save this as csrf_poc.html and open in browser while logged into target site -->

<html>
<body>
<h1>CSRF Attack Demonstration</h1>
<p>If you're logged into the target site, submitting this form will perform the action without your consent.</p>

<form action="{url}" method="{method}" id="csrf-form">
    <input type="hidden" name="action" value="delete">
    <input type="hidden" name="id" value="1">
    <!-- Add other form fields as needed -->
</form>

<script>
    // Auto-submit form (demonstrates CSRF attack)
    document.getElementById('csrf-form').submit();
</script>
</body>
</html>'''
    
    def recommend_fix(self, vulnerability: VulnerabilityResult) -> Dict[str, str]:
        """
        Provide secure fix recommendations.
        
        Args:
            vulnerability: The vulnerability to provide fix for
            
        Returns:
            Dictionary with 'cause', 'fix', and 'why' keys
        """
        return {
            "cause": '''# PROBLEM: Missing CSRF Protection

# Forms that perform state-changing operations (POST, PUT, DELETE) are
# vulnerable to Cross-Site Request Forgery (CSRF) attacks if they don't
# implement CSRF protection.

# Example vulnerable form:
<form action="/delete" method="POST">
    <input name="id" value="1">
    <button>Delete</button>
</form>

# PROBLEM: An attacker can trick a logged-in user into submitting this
# form by embedding it in a malicious website or email. The browser
# automatically includes cookies, making the request appear legitimate.''',
            
            "fix": '''# SECURE FIX: Implement CSRF Protection

# Option 1: CSRF Tokens (Recommended)

# Generate token server-side and include in form:
# Server-side (Python/Flask example):
from flask import session, render_template_string
import secrets

@app.route('/form')
def show_form():
    # Generate CSRF token
    csrf_token = secrets.token_hex(16)
    session['csrf_token'] = csrf_token
    return render_template_string("""
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input name="data">
            <button>Submit</button>
        </form>
    """, csrf_token=csrf_token)

@app.route('/form', methods=['POST'])
def handle_form():
    # Validate CSRF token
    token = request.form.get('csrf_token')
    if token != session.get('csrf_token'):
        return "Invalid CSRF token", 403
    # Process form...
    session.pop('csrf_token')  # Use token once
    return "Success"

# Option 2: Framework Built-in CSRF Protection

# Django:
from django.middleware.csrf import csrf_exempt
# CSRF protection is enabled by default
# Include {% csrf_token %} in templates

# Flask with Flask-WTF:
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Then in templates:
<form method="POST">
    {{ csrf_token() }}
    <!-- form fields -->
</form>

# Laravel (PHP):
// CSRF protection enabled by default
<form method="POST">
    @csrf
    <!-- form fields -->
</form>

# Option 3: SameSite Cookie Attribute (Additional Protection)

# Set SameSite=Strict or SameSite=Lax on session cookies:
# Python/Flask:
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# Django:
SESSION_COOKIE_SAMESITE = 'Strict'

# PHP:
session_set_cookie_params([
    'samesite' => 'Strict'
]);''',
            
            "why": '''CSRF protection prevents attacks because:

1. **CSRF Tokens**: Generate a unique, unpredictable token for each form.
   The token is stored server-side (session) and included in the form.
   When the form is submitted, the server validates the token. An attacker
   cannot guess or steal the token from another domain.

2. **SameSite Cookies**: The SameSite attribute prevents cookies from being
   sent in cross-site requests. SameSite=Strict blocks all cross-site
   requests, while SameSite=Lax allows GET requests (safer for UX).

3. **Double Submit Cookie**: Set CSRF token in both cookie and form field.
   Server validates both match. Simpler but less secure than session-based.

4. **Referer Header Check**: Verify the Referer header matches the origin.
   Less reliable (can be stripped by proxies) but provides defense-in-depth.

**Best Practices**:
- Use CSRF tokens for ALL state-changing operations (POST, PUT, DELETE, PATCH)
- Tokens should be:
  - Unique per session
  - Unpredictable (use cryptographically secure random)
  - Single-use (regenerate after use)
- Combine tokens with SameSite cookies for defense-in-depth
- Validate tokens server-side on every state-changing request
- Use framework built-in CSRF protection when available (tested, maintained)'''
        }

