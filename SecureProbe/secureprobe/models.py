"""
Pydantic models for SecureProbe vulnerability scanner.

Defines all data structures including findings, scan results,
severity levels, and configuration with CVSS-aligned severities.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(StrEnum):
    """CVSS-aligned severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def cvss_range(self) -> tuple[float, float]:
        """Return CVSS score range for this severity."""
        match self:
            case Severity.CRITICAL:
                return (9.0, 10.0)
            case Severity.HIGH:
                return (7.0, 8.9)
            case Severity.MEDIUM:
                return (4.0, 6.9)
            case Severity.LOW:
                return (0.1, 3.9)
            case Severity.INFO:
                return (0.0, 0.0)


class AnalyzerType(StrEnum):
    """Types of security analyzers."""

    HEADER = "header"
    COOKIE = "cookie"
    FORM = "form"
    TLS = "tls"
    INFO_LEAK = "info_leak"
    ENDPOINT = "endpoint"
    SESSION_SECURITY = "session_security"
    INPUT_VALIDATION = "input_validation"
    ACCESS_CONTROL = "access_control"
    CRYPTO_ANALYSIS = "crypto_analysis"
    API_SECURITY = "api_security"
    CHAOS_ATTACKS = "chaos_attacks"
    APT_ATTACKS = "apt_attacks"
    JS_LIBRARY_CVE = "js_library_cve"
    NOVEL_ATTACKS = "novel_attacks"
    BLOODY_MARY = "bloody_mary"
    MEMORY_ASSAULT = "memory_assault"
    CHAOS_TEEN = "chaos_teen"
    CREDENTIAL_SPRAY = "credential_spray"
    DEEP_SNIFF = "deep_sniff"


class ScanMode(StrEnum):
    """Scan mode determining test aggressiveness."""

    PASSIVE = "passive"  # Observation only, no test payloads
    ACTIVE = "active"  # With test payloads for authorized testing


class Finding(BaseModel):
    """Security finding with CWE reference and remediation guidance."""

    id: str = Field(default="", description="Unique finding identifier")
    analyzer: AnalyzerType = Field(description="Analyzer that discovered this finding")
    severity: Severity = Field(description="CVSS-aligned severity level")
    title: str = Field(min_length=1, description="Brief finding title")
    description: str = Field(min_length=1, description="Detailed description")
    cwe_id: str = Field(pattern=r"^CWE-\d+$", description="CWE identifier")
    cwe_name: str = Field(min_length=1, description="CWE vulnerability name")
    evidence: str = Field(default="", description="Evidence supporting the finding")
    url: str = Field(default="", description="Affected URL (first occurrence)")
    affected_urls: list[str] = Field(default_factory=list, description="All URLs where this finding was detected")
    remediation: str = Field(default="", description="Remediation guidance")
    cvss_score: float = Field(ge=0.0, le=10.0, default=0.0, description="CVSS base score")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Finding discovery timestamp",
    )

    @model_validator(mode="after")
    def generate_id(self) -> "Finding":
        """Generate unique ID based on finding content."""
        if not self.id:
            content = f"{self.analyzer}:{self.cwe_id}:{self.title}:{self.url}:{self.evidence}"
            self.id = hashlib.sha256(content.encode()).hexdigest()[:16]
        return self

    def __hash__(self) -> int:
        """Hash based on dedupe key for set operations."""
        return hash(self.dedupe_key)

    def __eq__(self, other: object) -> bool:
        """Equality based on dedupe key."""
        if not isinstance(other, Finding):
            return NotImplemented
        return self.dedupe_key == other.dedupe_key

    @property
    def dedupe_key(self) -> str:
        """Key for cross-URL deduplication (ignores URL to group same findings)."""
        return f"{self.analyzer}:{self.cwe_id}:{self.title}:{self.evidence[:100]}"


class ScanConfig(BaseModel):
    """Scan configuration with validation."""

    target_url: str = Field(min_length=1, description="Target URL to scan")
    max_depth: int = Field(default=1, ge=1, le=10, description="Maximum crawl depth")
    rate_limit: float = Field(default=2.0, gt=0.0, le=100.0, description="Requests per second")
    timeout: int = Field(default=30, ge=5, le=300, description="Request timeout in seconds")
    user_agent: str = Field(
        default="SecureProbe/1.0 Security Scanner",
        description="User agent string",
    )
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    authorization_token: str | None = Field(
        default=None,
        description="Authorization token for authenticated scans",
    )
    proxy_urls: list[str] = Field(default_factory=list, description="Proxy URLs for rotation")
    enabled_analyzers: set[AnalyzerType] = Field(
        default_factory=lambda: set(AnalyzerType),
        description="Enabled analyzer types",
    )
    exclude_patterns: list[str] = Field(
        default_factory=list,
        description="URL patterns to exclude from scanning",
    )
    custom_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Custom headers to include in requests",
    )
    scan_mode: ScanMode = Field(
        default=ScanMode.PASSIVE,
        description="Scan mode: passive (observation) or active (test payloads)",
    )
    browser_contexts: int = Field(
        default=1,
        ge=1,
        le=10,
        description="Number of browser contexts for isolation testing",
    )

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Ensure URL has valid scheme."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("Target URL must start with http:// or https://")
        return v.rstrip("/")

    @field_validator("proxy_urls")
    @classmethod
    def validate_proxies(cls, v: list[str]) -> list[str]:
        """Validate proxy URL formats."""
        for proxy in v:
            if not proxy.startswith(("http://", "https://", "socks5://")):
                raise ValueError(f"Invalid proxy URL: {proxy}")
        return v


class ScanResult(BaseModel):
    """Complete scan result with statistics and findings."""

    target_url: str = Field(description="Scanned target URL")
    scan_id: str = Field(default="", description="Unique scan identifier")
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Scan start timestamp",
    )
    completed_at: datetime | None = Field(default=None, description="Scan completion timestamp")
    duration_seconds: float = Field(default=0.0, description="Scan duration in seconds")
    findings: list[Finding] = Field(default_factory=list, description="Discovered findings")
    urls_scanned: int = Field(default=0, description="Number of URLs scanned")
    errors: list[str] = Field(default_factory=list, description="Errors encountered during scan")
    authorization_verified: bool = Field(
        default=False,
        description="Whether authorization was verified",
    )

    @model_validator(mode="after")
    def generate_scan_id(self) -> "ScanResult":
        """Generate unique scan ID."""
        if not self.scan_id:
            content = f"{self.target_url}:{self.started_at.isoformat()}"
            self.scan_id = hashlib.sha256(content.encode()).hexdigest()[:12]
        return self

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        """Group findings by severity."""
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for finding in self.findings:
            result[finding.severity].append(finding)
        return result

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Count findings by severity."""
        return {s: len(f) for s, f in self.findings_by_severity.items()}

    def add_finding(self, finding: Finding) -> bool:
        """Add finding with cross-URL deduplication. Returns True if new finding added."""
        for existing in self.findings:
            if existing.dedupe_key == finding.dedupe_key:
                # Same finding type - add URL to affected_urls list
                if finding.url and finding.url not in existing.affected_urls:
                    existing.affected_urls.append(finding.url)
                return False
        # New unique finding - initialize affected_urls with current url
        if finding.url and finding.url not in finding.affected_urls:
            finding.affected_urls.append(finding.url)
        self.findings.append(finding)
        return True

    def finalize(self) -> None:
        """Mark scan as complete and calculate duration."""
        self.completed_at = datetime.now(timezone.utc)
        self.duration_seconds = (self.completed_at - self.started_at).total_seconds()


class ProxyConfig(BaseModel):
    """Proxy configuration for rotation."""

    url: str = Field(description="Proxy URL")
    username: str | None = Field(default=None, description="Proxy username")
    password: str | None = Field(default=None, description="Proxy password")
    weight: int = Field(default=1, ge=1, description="Selection weight for rotation")
    last_used: datetime | None = Field(default=None, description="Last usage timestamp")
    failure_count: int = Field(default=0, ge=0, description="Consecutive failure count")
    max_failures: int = Field(default=3, ge=1, description="Max failures before skip")

    @property
    def is_available(self) -> bool:
        """Check if proxy is available for use."""
        return self.failure_count < self.max_failures
