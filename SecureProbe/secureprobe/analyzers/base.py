"""
Base analyzer class defining the interface for all security analyzers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

import structlog

from secureprobe.models import AnalyzerType, Finding

if TYPE_CHECKING:
    from secureprobe.models import ScanConfig


class BaseAnalyzer(ABC):
    """
    Abstract base class for security analyzers.

    Provides common infrastructure including logging, configuration access,
    and the standard analyze interface.
    """

    analyzer_type: AnalyzerType

    def __init__(self, config: "ScanConfig") -> None:
        """
        Initialize analyzer with scan configuration.

        Args:
            config: Scan configuration
        """
        self.config = config
        self.logger = structlog.get_logger(analyzer=self.analyzer_type.value)

    @abstractmethod
    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Analyze page data for vulnerabilities.

        Args:
            url: Current page URL
            page_data: Dictionary containing:
                - html: Page HTML content
                - headers: Response headers (dict)
                - cookies: Cookie list
                - forms: Extracted form data
                - scripts: JavaScript sources
                - network_log: Network request log

        Returns:
            List of discovered findings
        """
        pass

    def _create_finding(
        self,
        severity: str,
        title: str,
        description: str,
        cwe_id: str,
        cwe_name: str,
        url: str,
        evidence: str = "",
        remediation: str = "",
        cvss_score: float = 0.0,
        references: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """
        Create a Finding with analyzer context.

        Args:
            severity: Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
            title: Finding title
            description: Detailed description
            cwe_id: CWE identifier (e.g., "CWE-79")
            cwe_name: CWE vulnerability name
            url: Affected URL
            evidence: Supporting evidence
            remediation: Remediation guidance
            cvss_score: CVSS base score
            references: Reference URLs
            metadata: Additional metadata

        Returns:
            Configured Finding instance
        """
        from secureprobe.models import Severity

        return Finding(
            analyzer=self.analyzer_type,
            severity=Severity(severity),
            title=title,
            description=description,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            url=url,
            evidence=evidence,
            remediation=remediation,
            cvss_score=cvss_score,
            references=references or [],
            metadata=metadata or {},
        )
