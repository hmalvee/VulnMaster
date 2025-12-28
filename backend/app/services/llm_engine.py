"""
LLM Engine Service - Unified Anthropic Claude integration for VulnMaster.

Provides:
- False positive analysis (LLM-as-a-Judge)
- Automated code remediation generation
- Token management and rate limiting
- Dependency injection for client reuse
"""

import os
import json
import logging
import asyncio
from typing import Optional, Dict, Any, AsyncGenerator
from datetime import datetime, timedelta
from collections import deque

from anthropic import AsyncAnthropic
from anthropic.types import MessageParam

from ..prompts import (
    ANALYSIS_SYSTEM_PROMPT,
    ANALYSIS_USER_PROMPT_TEMPLATE,
    REMEDIATION_SYSTEM_PROMPT,
    REMEDIATION_USER_PROMPT_TEMPLATE
)

logger = logging.getLogger(__name__)

# Model configuration
CLAUDE_MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 4096
MAX_INPUT_TOKENS = 100000  # Truncate if input exceeds this

# Rate limiting configuration
MAX_REQUESTS_PER_MINUTE = 10
RATE_LIMIT_WINDOW = 60  # seconds


class TokenEstimator:
    """Simple token estimator (rough approximation: 1 token ≈ 4 characters)."""
    
    @staticmethod
    def estimate_tokens(text: str) -> int:
        """
        Estimate token count for text.
        Rough approximation: 1 token ≈ 4 characters for English text.
        
        Args:
            text: Input text
            
        Returns:
            Estimated token count
        """
        return len(text) // 4
    
    @staticmethod
    def truncate_to_tokens(text: str, max_tokens: int) -> str:
        """
        Truncate text to fit within token limit.
        
        Args:
            text: Input text
            max_tokens: Maximum token count
            
        Returns:
            Truncated text
        """
        estimated = TokenEstimator.estimate_tokens(text)
        if estimated <= max_tokens:
            return text
        
        # Truncate to approximately max_tokens
        max_chars = max_tokens * 4
        truncated = text[:max_chars]
        logger.warning(f"Truncated text from {len(text)} chars to {len(truncated)} chars "
                      f"({estimated} → ~{max_tokens} tokens)")
        return truncated


class RateLimiter:
    """Simple in-memory rate limiter using sliding window."""
    
    def __init__(self, max_requests: int = MAX_REQUESTS_PER_MINUTE, window_seconds: int = RATE_LIMIT_WINDOW):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_times: deque = deque()
        self.lock = asyncio.Lock()
    
    async def acquire(self) -> bool:
        """
        Try to acquire a request slot.
        
        Returns:
            True if request allowed, False if rate limited
        """
        async with self.lock:
            now = datetime.now()
            
            # Remove requests outside the window
            while self.request_times and (now - self.request_times[0]).total_seconds() > self.window_seconds:
                self.request_times.popleft()
            
            # Check if we're at the limit
            if len(self.request_times) >= self.max_requests:
                logger.warning(f"Rate limit exceeded: {len(self.request_times)}/{self.max_requests} requests in window")
                return False
            
            # Allow request
            self.request_times.append(now)
            return True
    
    async def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded."""
        if not await self.acquire():
            # Calculate wait time
            oldest = self.request_times[0]
            wait_seconds = self.window_seconds - (datetime.now() - oldest).total_seconds() + 1
            if wait_seconds > 0:
                logger.info(f"Rate limited. Waiting {wait_seconds:.1f} seconds...")
                await asyncio.sleep(wait_seconds)
                await self.acquire()  # Try again after waiting


class LLMEngine:
    """
    Unified LLM Engine for VulnMaster.
    
    Provides:
    - False positive analysis (LLM-as-a-Judge)
    - Automated code remediation
    - Token management
    - Rate limiting
    """
    
    _instance: Optional['LLMEngine'] = None
    _client: Optional[AsyncAnthropic] = None
    
    def __init__(self):
        """Initialize LLM Engine (singleton pattern)."""
        if LLMEngine._instance is not None:
            raise RuntimeError("LLMEngine is a singleton. Use LLMEngine.get_instance()")
        
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning("ANTHROPIC_API_KEY not set. LLM features will be disabled.")
            self.client = None
            self.enabled = False
        else:
            self.client = AsyncAnthropic(api_key=api_key)
            self.enabled = True
            logger.info("LLM Engine initialized with Anthropic API")
        
        self.rate_limiter = RateLimiter()
        self.token_estimator = TokenEstimator()
    
    @classmethod
    def get_instance(cls) -> 'LLMEngine':
        """
        Get singleton instance of LLMEngine.
        
        Returns:
            LLMEngine instance
        """
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
            cls._instance.__init__()
        return cls._instance
    
    def _truncate_input(self, text: str, max_tokens: int = MAX_INPUT_TOKENS) -> str:
        """
        Truncate input text to fit within token limits.
        
        Args:
            text: Input text
            max_tokens: Maximum token count
            
        Returns:
            Truncated text
        """
        return self.token_estimator.truncate_to_tokens(text, max_tokens)
    
    async def analyze_false_positive(
        self,
        vulnerability_type: str,
        response_snippet: str,
        payload: str,
        parameter: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Use LLM-as-a-Judge to analyze if a regex detection is a false positive.
        
        Args:
            vulnerability_type: Type of vulnerability (e.g., "SQL Injection")
            response_snippet: Sanitized HTTP response snippet
            payload: Test payload that triggered detection
            parameter: Parameter name (optional)
            
        Returns:
            Dictionary with keys: confidence (float), reason (str), is_genuine (bool)
            Falls back to {"confidence": 0.5, "reason": "LLM unavailable", "is_genuine": True}
            if LLM is disabled or fails
        """
        if not self.enabled or not self.client:
            logger.debug("LLM disabled, defaulting to regex-only detection")
            return {
                "confidence": 0.5,
                "reason": "LLM unavailable - using regex-only detection",
                "is_genuine": True  # Don't filter out if LLM unavailable
            }
        
        try:
            # Rate limiting
            await self.rate_limiter.wait_if_needed()
            
            # Truncate response snippet if too large
            truncated_snippet = self._truncate_input(response_snippet, max_tokens=5000)
            
            # Build prompt
            user_prompt = ANALYSIS_USER_PROMPT_TEMPLATE.format(
                vulnerability_type=vulnerability_type,
                payload=payload,
                parameter=parameter or "N/A",
                response_snippet=truncated_snippet
            )
            
            # Call Claude
            message: MessageParam = {
                "role": "user",
                "content": user_prompt
            }
            
            response = await self.client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=MAX_TOKENS,
                system=ANALYSIS_SYSTEM_PROMPT,
                messages=[message],
                temperature=0.1  # Low temperature for consistent judgment
            )
            
            # Parse JSON response
            content = response.content[0].text.strip()
            
            # Extract JSON (handle markdown code blocks)
            if "```json" in content:
                json_start = content.find("```json") + 7
                json_end = content.find("```", json_start)
                content = content[json_start:json_end].strip()
            elif "```" in content:
                json_start = content.find("```") + 3
                json_end = content.find("```", json_start)
                content = content[json_start:json_end].strip()
            
            result = json.loads(content)
            
            logger.info(f"LLM analysis: confidence={result.get('confidence', 0)}, "
                       f"is_genuine={result.get('is_genuine', False)}")
            
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON response: {e}")
            return {
                "confidence": 0.5,
                "reason": "Failed to parse LLM response",
                "is_genuine": True  # Default to allowing detection
            }
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}", exc_info=True)
            return {
                "confidence": 0.5,
                "reason": f"LLM error: {str(e)}",
                "is_genuine": True  # Fallback: allow detection
            }
    
    async def generate_remediation_code(
        self,
        vulnerability_type: str,
        url: str,
        parameter: str,
        payload: str
    ) -> AsyncGenerator[str, None]:
        """
        Generate secure code remediation using LLM.
        Streams response back for live updates.
        
        Args:
            vulnerability_type: Type of vulnerability
            url: Vulnerable URL
            parameter: Vulnerable parameter name
            payload: Test payload
            
        Yields:
            Code chunks as they're generated
        """
        if not self.enabled or not self.client:
            # Fallback to static recommendation
            yield "# LLM unavailable. Using static recommendation.\n\n"
            yield "from sqlalchemy.ext.asyncio import AsyncSession\n"
            yield "from sqlalchemy import select\n\n"
            yield "async def secure_query(session: AsyncSession, param: str):\n"
            yield "    result = await session.execute(\n"
            yield "        select(Model).where(Model.field == param)\n"
            yield "    )\n"
            yield "    return result.scalar_one_or_none()\n"
            return
        
        try:
            # Rate limiting
            await self.rate_limiter.wait_if_needed()
            
            # Build prompt
            user_prompt = REMEDIATION_USER_PROMPT_TEMPLATE.format(
                vulnerability_type=vulnerability_type,
                url=url,
                parameter=parameter,
                payload=payload
            )
            
            message: MessageParam = {
                "role": "user",
                "content": user_prompt
            }
            
            # Stream response
            async with self.client.messages.stream(
                model=CLAUDE_MODEL,
                max_tokens=MAX_TOKENS,
                system=REMEDIATION_SYSTEM_PROMPT,
                messages=[message],
                temperature=0.2  # Low temperature for code generation
            ) as stream:
                async for text_block in stream.text_stream:
                    yield text_block
                    
        except Exception as e:
            logger.error(f"LLM remediation generation failed: {e}", exc_info=True)
            yield f"# Error generating remediation: {str(e)}\n"
            yield "# Falling back to static recommendation.\n\n"
            yield "from sqlalchemy.ext.asyncio import AsyncSession\n"
            yield "from sqlalchemy import select\n\n"
            yield "# Use parameterized queries or SQLAlchemy ORM\n"

