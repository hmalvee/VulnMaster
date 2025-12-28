"""
Strict abstract base class for vulnerability scanner modules.
All scanner modules MUST implement detect(), generate_poc(), and recommend_fix().
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class VulnerabilityResult:
    """
    Standardized vulnerability result structure for educational purposes.
    Includes Red Team (attack) and Blue Team (fix) information.
    """
    name: str
    severity: str  # 'Critical', 'High', 'Medium', 'Low'
    description: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    
    # Educational Blue Team fields
    attack: Optional[str] = None  # CURL command showing how to exploit (Red Team)
    cause: Optional[str] = None   # Vulnerable code snippet
    fix: Optional[str] = None     # Secure code snippet (parameterized queries)
    why: Optional[str] = None     # Explanation of why the fix works
    
    # Evidence and metadata
    evidence: Optional[str] = None


class ScannerModule(ABC):
    """
    Strict abstract base class for all vulnerability scanner modules.
    
    This enforces a consistent interface:
    - detect(): Performs the vulnerability detection
    - generate_poc(): Creates proof-of-concept attack command
    - recommend_fix(): Provides secure code fix and explanation
    
    All methods must be implemented by child classes.
    """
    
    def __init__(self, target_url: str):
        """
        Initialize the scanner with a target URL.
        
        Args:
            target_url: The URL to scan for vulnerabilities
        """
        self.target_url = target_url
        self.vulnerabilities: List[VulnerabilityResult] = []
    
    @abstractmethod
    async def detect(self) -> List[VulnerabilityResult]:
        """
        Perform the vulnerability detection scan.
        This is the main detection logic that must be implemented.
        
        Returns:
            List of VulnerabilityResult objects found
        """
        pass
    
    @abstractmethod
    def generate_poc(self, vulnerability: VulnerabilityResult) -> str:
        """
        Generate a proof-of-concept attack command (CURL) for a vulnerability.
        This demonstrates the Red Team attack vector.
        
        Args:
            vulnerability: The vulnerability to generate PoC for
            
        Returns:
            String containing the attack command (e.g., curl command)
        """
        pass
    
    @abstractmethod
    def recommend_fix(self, vulnerability: VulnerabilityResult) -> Dict[str, str]:
        """
        Provide secure code fix and educational explanation.
        This demonstrates the Blue Team remediation.
        
        Args:
            vulnerability: The vulnerability to provide fix for
            
        Returns:
            Dictionary with keys: 'cause', 'fix', 'why'
            - cause: Vulnerable code snippet
            - fix: Secure code snippet
            - why: Explanation of why the fix works
        """
        pass
    
    @abstractmethod
    def get_vulnerability_name(self) -> str:
        """
        Return the name of this vulnerability type.
        
        Returns:
            String name of the vulnerability (e.g., "SQL Injection")
        """
        pass
