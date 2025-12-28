"""
Spider Service - Website crawler for vulnerability scanning.
Implements BFS crawling with form extraction and concurrency control.
"""

import asyncio
import logging
from typing import Set, Dict, List, Optional, Callable, Awaitable
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class CrawlResult:
    """Represents a crawled page with extracted forms and links."""
    
    def __init__(self, url: str, depth: int):
        self.url = url
        self.depth = depth
        self.forms: List[Dict] = []  # List of form data dictionaries
        self.links: Set[str] = set()  # Set of discovered links
        self.status_code: Optional[int] = None
        self.content_type: Optional[str] = None
        self.error: Optional[str] = None


class SpiderService:
    """
    Spider service for crawling websites and extracting attack surfaces.
    Uses BFS traversal with concurrency control and domain scoping.
    """
    
    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        max_concurrent: int = 10,
        timeout: int = 10,
        progress_callback: Optional[Callable[[str, dict], Awaitable[None]]] = None
    ):
        """
        Initialize spider service.
        
        Args:
            target_url: Base URL to crawl
            max_depth: Maximum crawl depth (default: 3)
            max_concurrent: Maximum concurrent requests (default: 10)
            timeout: Request timeout in seconds (default: 10)
            progress_callback: Optional callback for progress updates
        """
        self.target_url = target_url
        self.base_domain = self._extract_domain(target_url)
        self.max_depth = max_depth
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.progress_callback = progress_callback
        
        # Crawl state
        self.visited: Set[str] = set()
        self.to_visit: List[tuple[str, int]] = []  # (url, depth)
        self.results: List[CrawlResult] = []
        
        # HTTP client (will be initialized in async context)
        self.client: Optional[httpx.AsyncClient] = None
    
    def _extract_domain(self, url: str) -> str:
        """
        Extract domain from URL for scope checking.
        
        Args:
            url: URL to extract domain from
            
        Returns:
            Domain string (e.g., "example.com")
        """
        parsed = urlparse(url)
        return parsed.netloc.lower()
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """
        Normalize and validate URL.
        
        Args:
            url: URL to normalize
            base_url: Base URL for resolving relative URLs
            
        Returns:
            Normalized absolute URL or None if invalid
        """
        try:
            # Remove fragment
            parsed = urlparse(url)
            normalized = urlunparse((
                parsed.scheme or urlparse(base_url).scheme,
                parsed.netloc or urlparse(base_url).netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # Remove fragment
            ))
            
            # Only HTTP/HTTPS
            if normalized.scheme not in ['http', 'https']:
                return None
            
            # Scope check: same domain
            if self._extract_domain(normalized) != self.base_domain:
                return None
            
            # Remove trailing slash for consistency (except root)
            if normalized.endswith('/') and len(normalized) > len(urlparse(normalized).scheme) + 3:
                normalized = normalized[:-1]
            
            return normalized
        except Exception as e:
            logger.debug(f"Error normalizing URL {url}: {e}")
            return None
    
    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> List[Dict]:
        """
        Extract forms from HTML page.
        
        Args:
            soup: BeautifulSoup object
            page_url: URL of the page (for resolving form actions)
            
        Returns:
            List of form dictionaries with action, method, and inputs
        """
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            # Resolve form action URL
            if form_data['action']:
                form_data['action'] = urljoin(page_url, form_data['action'])
            else:
                form_data['action'] = page_url
            
            # Extract input fields
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                input_name = inp.get('name')
                if not input_name:
                    continue
                
                input_type = inp.get('type', 'text').lower()
                # Skip submit buttons and hidden fields for discovery (but note them)
                if input_type not in ['submit', 'button', 'image']:
                    form_data['inputs'].append({
                        'name': input_name,
                        'type': input_type,
                        'required': inp.has_attr('required'),
                        'value': inp.get('value', '')
                    })
            
            if form_data['inputs']:  # Only add forms with inputs
                forms.append(form_data)
        
        return forms
    
    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> Set[str]:
        """
        Extract links from HTML page.
        
        Args:
            soup: BeautifulSoup object
            page_url: URL of the page (for resolving relative URLs)
            
        Returns:
            Set of normalized absolute URLs
        """
        links = set()
        
        # Find all <a> tags with href
        for link in soup.find_all('a', href=True):
            href = link['href']
            normalized = self._normalize_url(href, page_url)
            if normalized:
                links.add(normalized)
        
        return links
    
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
    
    async def _crawl_page(self, url: str, depth: int) -> CrawlResult:
        """
        Crawl a single page.
        
        Args:
            url: URL to crawl
            depth: Current crawl depth
            
        Returns:
            CrawlResult object
        """
        result = CrawlResult(url, depth)
        
        async with self.semaphore:  # Rate limiting
            try:
                client = await self._get_client()
                
                if self.progress_callback:
                    await self.progress_callback("crawl_progress", {
                        "message": f"Scanning: {url}",
                        "url": url,
                        "depth": depth,
                        "status_code": None  # Will be set after response
                    })
                
                response = await client.get(url)
                result.status_code = response.status_code
                result.content_type = response.headers.get('content-type', '')
                
                # Update progress with status code
                if self.progress_callback:
                    await self.progress_callback("crawl_progress", {
                        "message": f"Scanned: {url} ({response.status_code})",
                        "url": url,
                        "depth": depth,
                        "status_code": response.status_code
                    })
                
                # Only parse HTML content
                if 'text/html' in result.content_type:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract forms
                    result.forms = self._extract_forms(soup, url)
                    if result.forms and self.progress_callback:
                        await self.progress_callback("crawl_found", {
                            "message": f"Found {len(result.forms)} form(s) at {url}",
                            "url": url,
                            "form_count": len(result.forms)
                        })
                    
                    # Extract links (only if we haven't reached max depth)
                    if depth < self.max_depth:
                        result.links = self._extract_links(soup, url)
                
                logger.debug(f"Crawled {url} (depth {depth}): {len(result.forms)} forms, {len(result.links)} links")
                
            except httpx.HTTPError as e:
                result.error = f"HTTP error: {str(e)}"
                logger.debug(f"HTTP error crawling {url}: {e}")
            except Exception as e:
                result.error = f"Error: {str(e)}"
                logger.error(f"Error crawling {url}: {e}")
        
        return result
    
    async def crawl(self) -> List[CrawlResult]:
        """
        Perform BFS crawl of the target website.
        
        Returns:
            List of CrawlResult objects
        """
        # Initialize with target URL
        self.to_visit.append((self.target_url, 0))
        self.visited.add(self.target_url)
        
        if self.progress_callback:
            await self.progress_callback("crawl_started", {
                "message": f"Starting crawl of {self.target_url}",
                "target_url": self.target_url,
                "max_depth": self.max_depth
            })
        
        try:
            while self.to_visit:
                # Get all URLs at current depth level for concurrent crawling
                current_level: List[tuple[str, int]] = []
                current_depth = self.to_visit[0][1]
                
                # Collect all URLs at the same depth
                while self.to_visit and self.to_visit[0][1] == current_depth:
                    current_level.append(self.to_visit.pop(0))
                
                # Crawl all pages at this level concurrently
                tasks = [self._crawl_page(url, depth) for url, depth in current_level]
                level_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for res in level_results:
                    if isinstance(res, Exception):
                        logger.error(f"Error in crawl task: {res}")
                        continue
                    
                    if isinstance(res, CrawlResult):
                        self.results.append(res)
                        
                        # Add discovered links to queue (if depth allows)
                        if res.depth < self.max_depth:
                            for link in res.links:
                                if link not in self.visited:
                                    self.visited.add(link)
                                    self.to_visit.append((link, res.depth + 1))
                                    
                                    if self.progress_callback:
                                        await self.progress_callback("crawl_found", {
                                            "message": f"Found: {link}",
                                            "url": link,
                                            "depth": res.depth + 1
                                        })
            
            if self.progress_callback:
                await self.progress_callback("crawl_completed", {
                    "message": f"Crawl completed. Found {len(self.results)} pages, {sum(len(r.forms) for r in self.results)} forms",
                    "page_count": len(self.results),
                    "form_count": sum(len(r.forms) for r in self.results),
                    "total_links": len(self.visited)
                })
            
            logger.info(f"Crawl completed: {len(self.results)} pages, {sum(len(r.forms) for r in self.results)} forms")
            
        except Exception as e:
            logger.error(f"Error during crawl: {e}", exc_info=True)
            if self.progress_callback:
                await self.progress_callback("crawl_failed", {
                    "message": f"Crawl failed: {str(e)}",
                    "error": str(e)
                })
        finally:
            await self._close_client()
        
        return self.results
    
    def get_all_forms(self) -> List[Dict]:
        """
        Get all forms discovered during crawl.
        
        Returns:
            List of all form dictionaries from all crawled pages
        """
        all_forms = []
        for result in self.results:
            for form in result.forms:
                # Add source URL to form data
                form_with_source = form.copy()
                form_with_source['source_url'] = result.url
                all_forms.append(form_with_source)
        return all_forms
    
    def get_all_urls(self) -> List[str]:
        """
        Get all URLs discovered during crawl.
        
        Returns:
            List of all crawled URLs
        """
        return [result.url for result in self.results]

