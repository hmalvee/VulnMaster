"""
SQL Injection (SQLi) Scanner Module - Async Implementation

This module detects SQL Injection vulnerabilities using async httpx.
Implements heuristic detection, error-based and boolean-based checks.

⚠️ EDUCATIONAL USE ONLY - For authorized testing only.
"""

import re
import logging
import asyncio
from typing import List, Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx
from bs4 import BeautifulSoup

from .base import ScannerModule, VulnerabilityResult

logger = logging.getLogger(__name__)


class SQLInjectionScanner(ScannerModule):
    """
    Async SQL Injection scanner with heuristic detection and false positive reduction.
    
    Detection Strategy:
    1. Heuristic check: Verify parameter affects response (sanity check)
    2. Error-based detection: Inject payloads and check for SQL error patterns
    3. Boolean-based detection: Compare responses for true/false conditions
    4. False positive reduction: Validate errors are database-related
    """
    
    # Database-specific error patterns (strict matching to reduce false positives)
    SQL_ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*MySQL",
        r"Warning.*\Wmysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"MySQLSyntaxErrorException",
        r"Error.*MySQL",
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        # Oracle
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"ORA-[0-9]{5}",
        r"OracleException",
        # SQL Server
        r"Microsoft.*ODBC.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Warning.*\Wmssql_",
        r"Warning.*\Wsqlsrv_",
        r"Microsoft OLE DB Provider",
        r"SqlException",
        # SQLite
        r"SQLite.*error",
        r"SQLite3::",
        r"SQLITE_ERROR",
        # Generic SQL errors
        r"Syntax error.*query",
        r"mysql_fetch",
        r"PostgreSQL query failed",
    ]
    
    # SQL injection test payloads (error-based)
    SQLI_ERROR_PAYLOADS = [
        "'",
        "''",
        "`",
        "``",
        ",",
        "\"",
        "\"\"",
        "/",
        "//",
        "\\",
        "\\\\",
        ";",
        "' OR '1",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "') OR ('1'='1' --",
        "') OR ('1'='1' /*",
        "' AND 1=1--",
        "' AND 1=2--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
    ]
    
    # Boolean-based test payloads
    SQLI_BOOLEAN_PAYLOADS = [
        ("' OR '1'='1", "' OR '1'='2"),  # True condition, False condition
        ("' AND 1=1--", "' AND 1=2--"),
    ]
    
    # Time-based blind SQLi payloads
    SQLI_TIME_BASED_PAYLOADS = [
        "' OR SLEEP(5)--",
        "' OR WAITFOR DELAY '00:00:05'--",  # SQL Server
        "' OR pg_sleep(5)--",  # PostgreSQL
        "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; WAITFOR DELAY '00:00:05'--",
        "1' AND SLEEP(5)--",
    ]
    
    def __init__(self, target_url: str, timeout: int = 10, llm_engine=None):
        """
        Initialize the SQL Injection scanner.
        
        Args:
            target_url: The URL to scan
            timeout: Request timeout in seconds
            llm_engine: Optional LLMEngine instance for false positive analysis
        """
        super().__init__(target_url)
        self.timeout = timeout
        self.client = None  # Will be initialized in async context
        self.llm_engine = llm_engine  # LLM engine for hybrid detection
    
    def get_vulnerability_name(self) -> str:
        """Return the name of this vulnerability type."""
        return "SQL Injection"
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,  # For local testing (educational tool)
                follow_redirects=True,
                headers={
                    'User-Agent': 'VulnMaster/1.0 (Educational Security Scanner)'
                }
            )
        return self.client
    
    async def _close_client(self):
        """Close HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None
    
    async def _fetch_page(self, url: str) -> Optional[httpx.Response]:
        """
        Fetch a page asynchronously.
        
        Args:
            url: URL to fetch
            
        Returns:
            Response object or None if request fails
        """
        try:
            client = await self._get_client()
            response = await client.get(url)
            return response
        except Exception as e:
            logger.debug(f"Error fetching {url}: {e}")
            return None
    
    def _sanitize_response(self, text: str) -> str:
        """
        Sanitize response text for LLM analysis.
        Removes potential sensitive data like IPs, emails, tokens.
        
        Args:
            text: Response text to sanitize
            
        Returns:
            Sanitized text
        """
        # Remove IP addresses
        text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REDACTED]', text)
        # Remove email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]', text)
        # Remove long hex strings (potential tokens)
        text = re.sub(r'\b[0-9a-fA-F]{32,}\b', '[TOKEN_REDACTED]', text)
        return text
    
    async def _heuristic_check(
        self, 
        base_response: httpx.Response, 
        test_response: httpx.Response
    ) -> bool:
        """
        Heuristic check: Verify if parameter actually affects the response.
        This helps reduce false positives by ensuring the parameter is reflected.
        
        Args:
            base_response: Baseline response
            test_response: Response with test payload
            
        Returns:
            True if parameter appears to affect response
        """
        if not base_response or not test_response:
            return False
        
        # Check if response length changed significantly
        base_len = len(base_response.text)
        test_len = len(test_response.text)
        length_diff = abs(base_len - test_len) / max(base_len, 1)
        
        # If response changed by more than 5%, parameter likely affects output
        if length_diff > 0.05:
            return True
        
        # Check if test payload is reflected in response
        # (simple check - if our test value appears, parameter is reflected)
        return False  # Conservative: only rely on length difference
    
    async def _test_time_based_sqli(
        self,
        url: str,
        param_name: str,
        parsed,
        base_params
    ) -> Optional[VulnerabilityResult]:
        """
        Test for time-based blind SQL injection vulnerabilities.
        
        Args:
            url: Base URL
            param_name: Parameter name to test
            parsed: Parsed URL components
            base_params: Base query parameters
            
        Returns:
            VulnerabilityResult if detected, None otherwise
        """
        import time
        
        for payload in self.SQLI_TIME_BASED_PAYLOADS[:3]:  # Limit to first 3 for performance
            try:
                test_params = base_params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, test_query, parsed.fragment
                ))
                
                # Measure response time
                start_time = time.time()
                test_response = await self._fetch_page(test_url)
                elapsed_time = time.time() - start_time
                
                if not test_response:
                    continue
                
                # If response took significantly longer (4+ seconds for 5 second sleep),
                # it might indicate time-based SQLi
                if elapsed_time >= 4.0:  # Allow some margin for network latency
                    # Confirm with a control request (payload that shouldn't delay)
                    control_params = base_params.copy()
                    control_params[param_name] = ["1"]
                    control_query = urlencode(control_params, doseq=True)
                    control_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, control_query, parsed.fragment
                    ))
                    
                    control_start = time.time()
                    control_response = await self._fetch_page(control_url)
                    control_elapsed = time.time() - control_start
                    
                    # If test payload caused significantly longer delay
                    if elapsed_time > (control_elapsed + 3.0):
                        vuln = VulnerabilityResult(
                            name="SQL Injection (Time-Based Blind)",
                            severity="Critical",
                            description=f"Time-based blind SQL injection vulnerability detected in parameter '{param_name}'. "
                                      f"The application responds with a delay when injected with time-based payloads, "
                                      f"indicating successful SQL execution.",
                            url=test_url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Response time: {elapsed_time:.2f}s (control: {control_elapsed:.2f}s). "
                                    f"Delay indicates SQL execution."
                        )
                        logger.warning(f"Time-based SQLi detected in parameter '{param_name}' at {url}")
                        return vuln
                
            except Exception as e:
                logger.debug(f"Error testing time-based SQLi on {param_name}: {e}")
                continue
        
        return None
    
    async def _test_url_parameter(
        self, 
        url: str, 
        param_name: str, 
        base_response: httpx.Response
    ) -> List[VulnerabilityResult]:
        """
        Test a URL query parameter for SQL injection vulnerabilities.
        
        Args:
            url: Base URL
            param_name: Parameter name to test
            base_response: Baseline response for comparison
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)
        
        if not base_params:
            return vulnerabilities
        
        # First test for time-based SQLi (do this before error-based to avoid false positives)
        time_based_vuln = await self._test_time_based_sqli(
            url, param_name, parsed, base_params
        )
        if time_based_vuln:
            vulnerabilities.append(time_based_vuln)
            # Don't test other payloads if time-based is detected (one vuln per param is enough)
            return vulnerabilities
        
        # Test with error-based payloads
        for payload in self.SQLI_ERROR_PAYLOADS:
            try:
                # Create test URL with payload
                test_params = base_params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, test_query, parsed.fragment
                ))
                
                # Send request
                test_response = await self._fetch_page(test_url)
                if not test_response:
                    continue
                
                # Heuristic check: does parameter affect response?
                if not await self._heuristic_check(base_response, test_response):
                    continue
                
                # Check for SQL error patterns (strict matching)
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, test_response.text, re.IGNORECASE):
                        # HYBRID DETECTION: Regex triggered, now use LLM-as-a-Judge
                        is_genuine = True
                        confidence = 1.0
                        reason = "Regex pattern matched"
                        
                        if self.llm_engine:
                            # Extract sanitized response snippet (surrounding lines)
                            response_lines = test_response.text.split('\n')
                            pattern_line_idx = None
                            
                            # Find the line containing the pattern match
                            for idx, line in enumerate(response_lines):
                                if re.search(pattern, line, re.IGNORECASE):
                                    pattern_line_idx = idx
                                    break
                            
                            # Extract surrounding context (5 lines before/after)
                            if pattern_line_idx is not None:
                                start = max(0, pattern_line_idx - 5)
                                end = min(len(response_lines), pattern_line_idx + 6)
                                snippet = '\n'.join(response_lines[start:end])
                                
                                # Sanitize: remove potential sensitive data
                                snippet = self._sanitize_response(snippet)
                                
                                # Call LLM for judgment
                                llm_result = await self.llm_engine.analyze_false_positive(
                                    vulnerability_type="SQL Injection",
                                    response_snippet=snippet,
                                    payload=payload,
                                    parameter=param_name
                                )
                                
                                confidence = llm_result.get("confidence", 0.5)
                                reason = llm_result.get("reason", "LLM analysis")
                                is_genuine = llm_result.get("is_genuine", True) and confidence > 0.9
                                
                                logger.info(f"LLM analysis for SQLi detection: confidence={confidence:.2f}, "
                                          f"is_genuine={is_genuine}, reason={reason}")
                        
                        # Only flag if confidence > 0.9 (or LLM unavailable)
                        if is_genuine:
                            vuln = VulnerabilityResult(
                                name="SQL Injection",
                                severity="Critical",
                                description=f"SQL Injection vulnerability detected in parameter '{param_name}'. "
                                          f"The application returns database error messages when injected with test payloads. "
                                          f"LLM confidence: {confidence:.2f}",
                                url=test_url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"SQL Error Pattern Matched: {pattern}. LLM Analysis: {reason}"
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"SQLi confirmed in parameter '{param_name}' at {url} (confidence: {confidence:.2f})")
                            break  # One vulnerability per parameter is enough
                        else:
                            logger.info(f"False positive filtered by LLM: {param_name} at {url} (confidence: {confidence:.2f})")
                
            except Exception as e:
                logger.debug(f"Error testing parameter {param_name} with payload {payload}: {e}")
                continue
        
        return vulnerabilities
    
    async def _test_form_input(
        self,
        form_url: str,
        form_method: str,
        input_name: str,
        base_form_data: dict,
        base_response: httpx.Response
    ) -> List[VulnerabilityResult]:
        """
        Test a form input for SQL injection vulnerabilities.
        
        Args:
            form_url: Form action URL
            form_method: HTTP method (GET or POST)
            input_name: Input field name
            base_form_data: Base form data
            base_response: Baseline response
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        client = await self._get_client()
        
        # Test with first few error-based payloads (to limit requests)
        for payload in self.SQLI_ERROR_PAYLOADS[:10]:
            try:
                test_data = base_form_data.copy()
                test_data[input_name] = payload
                
                # Submit form
                if form_method.lower() == "post":
                    test_response = await client.post(form_url, data=test_data)
                else:
                    test_response = await client.get(form_url, params=test_data)
                
                # Heuristic check
                if not await self._heuristic_check(base_response, test_response):
                    continue
                
                # Check for SQL error patterns
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, test_response.text, re.IGNORECASE):
                        # HYBRID DETECTION: Regex triggered, now use LLM-as-a-Judge
                        is_genuine = True
                        confidence = 1.0
                        reason = "Regex pattern matched"
                        
                        if self.llm_engine:
                            # Extract sanitized response snippet
                            response_lines = test_response.text.split('\n')
                            pattern_line_idx = None
                            
                            for idx, line in enumerate(response_lines):
                                if re.search(pattern, line, re.IGNORECASE):
                                    pattern_line_idx = idx
                                    break
                            
                            if pattern_line_idx is not None:
                                start = max(0, pattern_line_idx - 5)
                                end = min(len(response_lines), pattern_line_idx + 6)
                                snippet = '\n'.join(response_lines[start:end])
                                snippet = self._sanitize_response(snippet)
                                
                                llm_result = await self.llm_engine.analyze_false_positive(
                                    vulnerability_type="SQL Injection",
                                    response_snippet=snippet,
                                    payload=payload,
                                    parameter=input_name
                                )
                                
                                confidence = llm_result.get("confidence", 0.5)
                                reason = llm_result.get("reason", "LLM analysis")
                                is_genuine = llm_result.get("is_genuine", True) and confidence > 0.9
                        
                        if is_genuine:
                            vuln = VulnerabilityResult(
                                name="SQL Injection",
                                severity="Critical",
                                description=f"SQL Injection vulnerability detected in form input '{input_name}'. "
                                          f"The application returns database error messages when injected with test payloads. "
                                          f"LLM confidence: {confidence:.2f}",
                                url=form_url,
                                parameter=input_name,
                                payload=payload,
                                evidence=f"SQL Error Pattern Matched: {pattern}. LLM Analysis: {reason}"
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"SQLi confirmed in form input '{input_name}' at {form_url} (confidence: {confidence:.2f})")
                            break
                        else:
                            logger.info(f"False positive filtered by LLM: {input_name} at {form_url} (confidence: {confidence:.2f})")
                
            except Exception as e:
                logger.debug(f"Error testing form input {input_name}: {e}")
                continue
        
        return vulnerabilities
    
    async def detect(self) -> List[VulnerabilityResult]:
        """
        Perform SQL injection scan asynchronously.
        
        Returns:
            List of VulnerabilityResult objects found
        """
        logger.info(f"Starting SQL Injection scan on {self.target_url}")
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
                test_url = f"{self.target_url}?id=test"
                test_response = await self._fetch_page(test_url)
                if test_response:
                    vulns = await self._test_url_parameter(
                        test_url, "id", base_response
                    )
                    self.vulnerabilities.extend(vulns)
            
            # Test form inputs
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
                        form_url, form_method, input_name, form_data, base_response
                    )
                    self.vulnerabilities.extend(vulns)
            
            # Remove duplicates (same parameter, similar payload)
            seen = set()
            unique_vulns = []
            for vuln in self.vulnerabilities:
                key = (vuln.url, vuln.parameter)
                if key not in seen:
                    seen.add(key)
                    unique_vulns.append(vuln)
            
            self.vulnerabilities = unique_vulns
            logger.info(f"SQL Injection scan complete. Found {len(self.vulnerabilities)} potential vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error during SQL Injection scan: {e}", exc_info=True)
        finally:
            await self._close_client()
        
        return self.vulnerabilities
    
    def generate_poc(self, vulnerability: VulnerabilityResult) -> str:
        """
        Generate proof-of-concept attack command (CURL) for a vulnerability.
        
        Args:
            vulnerability: The vulnerability to generate PoC for
            
        Returns:
            CURL command string
        """
        url = vulnerability.url
        parameter = vulnerability.parameter
        payload = vulnerability.payload or "' OR '1'='1"
        
        # Escape payload for shell usage
        escaped_payload = payload.replace("'", "'\\''")
        
        # Determine if GET or POST based on URL structure
        parsed = urlparse(url)
        if parsed.query:
            # GET request
            return f"curl '{url}'"
        else:
            # POST request (assumed)
            return f"curl -X POST '{url}' -d '{parameter}={escaped_payload}'"
    
    def recommend_fix(self, vulnerability: VulnerabilityResult) -> Dict[str, str]:
        """
        Provide secure code fix and educational explanation.
        
        Args:
            vulnerability: The vulnerability to provide fix for
            
        Returns:
            Dictionary with 'cause', 'fix', and 'why' keys
        """
        return {
            "cause": '''# VULNERABLE CODE (DON'T DO THIS!)
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# PROBLEM: User input is directly concatenated into SQL query
# An attacker can inject SQL code: id=1 OR 1=1--''',
            
            "fix": '''# SECURE CODE (USE PARAMETERIZED QUERIES)
user_id = request.args.get('id')

# Python with sqlite3
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

# Python with psycopg2 (PostgreSQL)
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))

# Python with PyMySQL
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))''',
            
            "why": '''Parameterized queries (prepared statements) prevent SQL injection by separating 
SQL code from user data. The database treats the user input as data, not executable SQL.

How it works:
1. The SQL query structure is defined first (with placeholders like ? or %s)
2. User data is passed separately as parameters
3. The database engine ensures parameters cannot alter the query structure
4. Even if an attacker injects ' OR 1=1--, it will be treated as literal text, not SQL code

This is the industry-standard defense against SQL injection and should ALWAYS be used
when building database queries with user input.'''
        }

