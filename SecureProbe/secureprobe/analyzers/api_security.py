"""
API Security Analyzer.

Analyzes API security including rate limiting, error handling,
versioning, content-type enforcement, and CORS configuration.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity


class APISecurityAnalyzer(BaseAnalyzer):
    """
    Analyzer for API security vulnerabilities.

    Checks for:
    - Rate limiting effectiveness (CWE-770)
    - Verbose error messages (CWE-209)
    - API versioning security (CWE-693)
    - Content-type enforcement (CWE-436)
    - CORS configuration (CWE-346)
    """

    analyzer_type = AnalyzerType.API_SECURITY

    # Rate limit header patterns
    RATE_LIMIT_HEADERS = [
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-rate-limit-limit",
        "x-rate-limit-remaining",
        "x-rate-limit-reset",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "retry-after",
    ]

    # Error patterns that indicate verbose error messages
    VERBOSE_ERROR_PATTERNS = [
        (r"stack\s*trace", "Stack trace exposed"),
        (r"Traceback.*\n.*File", "Python traceback exposed"),
        (r"at\s+[\w.]+\([\w.]+:\d+\)", "Java/JS stack trace exposed"),
        (r"Exception\s+in\s+thread", "Java exception exposed"),
        (r"Fatal\s+error.*line\s+\d+", "PHP fatal error exposed"),
        (r"SQLSTATE\[\w+\]", "SQL error state exposed"),
        (r"ORA-\d{5}", "Oracle error code exposed"),
        (r"MySQL.*error", "MySQL error exposed"),
        (r"PostgreSQL.*error", "PostgreSQL error exposed"),
        (r"Microsoft.*SQL.*Server", "MSSQL error exposed"),
        (r"Syntax\s+error.*line\s+\d+", "Syntax error details exposed"),
        (r"undefined\s+(variable|index|offset)", "PHP undefined variable exposed"),
        (r"Notice:\s+Undefined", "PHP notice exposed"),
        (r"Warning:\s+\w+\(\)", "PHP warning exposed"),
        (r'"file":\s*"[^"]+\.\w+".*"line":\s*\d+', "Debug info in JSON exposed"),
        (r"\"debug\":\s*true", "Debug mode enabled"),
        (r"internal\s+server\s+error.*details", "Internal error details exposed"),
    ]

    # API versioning patterns
    API_VERSION_PATTERNS = [
        r"/api/v(\d+)",
        r"/v(\d+)/",
        r"\?version=(\d+)",
        r"api-version=(\d+)",
        r"X-API-Version:\s*(\d+)",
    ]

    # Deprecated API version indicators
    DEPRECATED_API_INDICATORS = [
        "deprecated",
        "legacy",
        "old",
        "sunset",
        "end-of-life",
        "eol",
        "v1",  # Often first version is deprecated
    ]

    # Security headers expected for API responses
    API_SECURITY_HEADERS = {
        "x-content-type-options": ("nosniff", Severity.MEDIUM),
        "x-frame-options": (["deny", "sameorigin"], Severity.LOW),
        "cache-control": ("no-store", Severity.MEDIUM),
    }

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze API security configuration."""
        findings: list[Finding] = []
        headers = page_data.get("headers", {})
        html_content = page_data.get("html", "")
        network_log = page_data.get("network_log", [])
        scan_mode = page_data.get("scan_mode", "passive")

        # Detect if this appears to be an API endpoint
        is_api = self._is_api_endpoint(url, headers, html_content)

        if is_api:
            # Core API security checks
            findings.extend(self._analyze_rate_limiting(url, headers))
            findings.extend(self._analyze_content_type(url, headers))
            findings.extend(self._analyze_cors(url, headers))
            findings.extend(self._analyze_api_security_headers(url, headers))
            findings.extend(self._analyze_api_versioning(url, network_log))

        # Error message analysis applies to all pages
        findings.extend(self._analyze_error_messages(url, html_content, headers))

        # Active mode analysis
        if scan_mode == "active":
            findings.extend(self._analyze_method_security(url, headers))

        return findings

    def _is_api_endpoint(
        self,
        url: str,
        headers: dict[str, str],
        content: str,
    ) -> bool:
        """Determine if URL appears to be an API endpoint."""
        # URL patterns
        api_url_patterns = [
            r"/api/",
            r"/v\d+/",
            r"/rest/",
            r"/graphql",
            r"/rpc/",
            r"\.json$",
            r"\.xml$",
        ]

        for pattern in api_url_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True

        # Content-Type check
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        content_type = normalized_headers.get("content-type", "")

        if any(
            ct in content_type.lower()
            for ct in ["application/json", "application/xml", "application/graphql"]
        ):
            return True

        # Content looks like JSON/XML
        content_stripped = content.strip()
        if content_stripped.startswith("{") or content_stripped.startswith("["):
            return True
        if content_stripped.startswith("<?xml") or content_stripped.startswith("<"):
            if "<!DOCTYPE html" not in content_stripped[:100]:
                return True

        return False

    def _analyze_rate_limiting(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Analyze rate limiting headers."""
        findings: list[Finding] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        rate_limit_present = False
        rate_limit_info: dict[str, str] = {}

        for header in self.RATE_LIMIT_HEADERS:
            if header in normalized_headers:
                rate_limit_present = True
                rate_limit_info[header] = normalized_headers[header]

        if not rate_limit_present:
            findings.append(
                self._create_finding(
                    severity=Severity.INFO,
                    title="No Rate Limiting Headers Detected",
                    description=(
                        "API response does not include rate limiting headers. "
                        "Note: Rate limiting may be implemented at the infrastructure level "
                        "(API gateway, load balancer, CDN, WAF) without exposing headers.\n\n"
                        "This finding is informational - verify rate limiting implementation "
                        "through other means if headers are intentionally not exposed."
                    ),
                    cwe_id="CWE-770",
                    cwe_name="Allocation of Resources Without Limits or Throttling",
                    url=url,
                    evidence="No X-RateLimit-* or similar headers present",
                    remediation=(
                        "If rate limiting is not implemented elsewhere, consider adding it with headers: "
                        "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset. "
                        "Rate limiting can be implemented at: application level, API gateway, "
                        "load balancer, or CDN/WAF layer."
                    ),
                    cvss_score=0.0,
                    metadata={"confidence": "low", "note": "may be implemented at infrastructure level"},
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                    ],
                )
            )
        else:
            # Check if rate limit values are reasonable
            limit_str = rate_limit_info.get(
                "x-ratelimit-limit", rate_limit_info.get("ratelimit-limit", "")
            )
            try:
                limit = int(limit_str)
                if limit > 10000:  # Very high limit
                    findings.append(
                        self._create_finding(
                            severity=Severity.LOW,
                            title="High API Rate Limit Detected",
                            description=(
                                f"API rate limit is set to {limit} requests. "
                                "Very high rate limits may not provide effective protection "
                                "against abuse or denial of service."
                            ),
                            cwe_id="CWE-770",
                            cwe_name="Allocation of Resources Without Limits or Throttling",
                            url=url,
                            evidence=f"X-RateLimit-Limit: {limit}",
                            remediation=(
                                "Review rate limit values for appropriateness. "
                                "Consider lower limits for sensitive endpoints."
                            ),
                            cvss_score=3.1,
                            metadata={"rate_limit": limit},
                        )
                    )
            except ValueError:
                pass

        return findings

    def _analyze_content_type(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Analyze Content-Type header enforcement."""
        findings: list[Finding] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        content_type = normalized_headers.get("content-type", "")

        if not content_type:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="API Response Missing Content-Type",
                    description=(
                        "API response does not include Content-Type header. "
                        "Missing Content-Type can lead to content-sniffing attacks "
                        "and unexpected parsing behavior."
                    ),
                    cwe_id="CWE-436",
                    cwe_name="Interpretation Conflict",
                    url=url,
                    evidence="Content-Type header not present",
                    remediation=(
                        "Always set explicit Content-Type header. "
                        "For JSON APIs: Content-Type: application/json; charset=utf-8"
                    ),
                    cvss_score=4.3,
                )
            )

        # Check for generic text/html on API endpoint
        if "text/html" in content_type.lower() and self._is_api_endpoint(url, headers, ""):
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="API Returns text/html Content-Type",
                    description=(
                        "API endpoint returns Content-Type: text/html instead of "
                        "application-specific type like application/json. "
                        "This could enable XSS if response is rendered as HTML."
                    ),
                    cwe_id="CWE-436",
                    cwe_name="Interpretation Conflict",
                    url=url,
                    evidence=f"Content-Type: {content_type}",
                    remediation="Use application/json or appropriate Content-Type for API responses.",
                    cvss_score=3.1,
                )
            )

        return findings

    def _analyze_cors(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Analyze CORS configuration for API security."""
        findings: list[Finding] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        acao = normalized_headers.get("access-control-allow-origin", "")
        acac = normalized_headers.get("access-control-allow-credentials", "")
        acam = normalized_headers.get("access-control-allow-methods", "")
        acah = normalized_headers.get("access-control-allow-headers", "")

        # Wildcard origin with credentials
        if acao == "*" and acac.lower() == "true":
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="CORS: Wildcard Origin with Credentials",
                    description=(
                        "API allows requests from any origin (*) with credentials. "
                        "This is actually blocked by browsers, indicating misconfiguration."
                    ),
                    cwe_id="CWE-346",
                    cwe_name="Origin Validation Error",
                    url=url,
                    evidence=f"ACAO: {acao}; ACAC: {acac}",
                    remediation=(
                        "Use specific origin values when credentials are required. "
                        "Implement dynamic origin validation against allowlist."
                    ),
                    cvss_score=8.1,
                )
            )
        elif acao == "*":
            findings.append(
                self._create_finding(
                    severity=Severity.INFO,
                    title="CORS: Wildcard Origin Allowed",
                    description=(
                        "API allows cross-origin requests from any origin. "
                        "Verify this is intentional for public APIs."
                    ),
                    cwe_id="CWE-346",
                    cwe_name="Origin Validation Error",
                    url=url,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Restrict origins if this is not a public API.",
                    cvss_score=0.0,
                )
            )

        # Overly permissive methods
        if acam:
            dangerous_methods = ["DELETE", "PUT", "PATCH"]
            allowed_methods = [m.strip().upper() for m in acam.split(",")]

            exposed_dangerous = [m for m in dangerous_methods if m in allowed_methods]
            if exposed_dangerous:
                findings.append(
                    self._create_finding(
                        severity=Severity.LOW,
                        title=f"CORS: Dangerous Methods Allowed: {', '.join(exposed_dangerous)}",
                        description=(
                            f"CORS configuration allows potentially dangerous HTTP methods: "
                            f"{', '.join(exposed_dangerous)}. Ensure these are intentional."
                        ),
                        cwe_id="CWE-346",
                        cwe_name="Origin Validation Error",
                        url=url,
                        evidence=f"Access-Control-Allow-Methods: {acam}",
                        remediation="Only expose necessary HTTP methods via CORS.",
                        cvss_score=3.1,
                        metadata={"dangerous_methods": exposed_dangerous},
                    )
                )

        # Overly permissive headers
        if acah:
            if "*" in acah:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="CORS: Wildcard Headers Allowed",
                        description=(
                            "CORS allows any request header (*). "
                            "This could expose the API to unexpected headers from malicious origins."
                        ),
                        cwe_id="CWE-346",
                        cwe_name="Origin Validation Error",
                        url=url,
                        evidence=f"Access-Control-Allow-Headers: {acah}",
                        remediation="Specify explicit allowed headers instead of wildcard.",
                        cvss_score=4.3,
                    )
                )

        return findings

    def _analyze_error_messages(
        self,
        url: str,
        content: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Analyze response for verbose error messages."""
        findings: list[Finding] = []

        for pattern, description in self.VERBOSE_ERROR_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Verbose Error Message: {description}",
                        description=(
                            f"Response contains verbose error information: {description}. "
                            "Detailed error messages help attackers understand application "
                            "internals and identify vulnerabilities."
                        ),
                        cwe_id="CWE-209",
                        cwe_name="Generation of Error Message Containing Sensitive Information",
                        url=url,
                        evidence=f"Pattern: {description}",
                        remediation=(
                            "Implement generic error messages for users. "
                            "Log detailed errors server-side only. "
                            "Disable debug mode in production."
                        ),
                        cvss_score=5.3,
                        references=[
                            "https://cwe.mitre.org/data/definitions/209.html",
                        ],
                    )
                )
                break  # Report only first match to avoid duplicates

        return findings

    def _analyze_api_security_headers(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Check for API-specific security headers."""
        findings: list[Finding] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        for header, (expected_value, severity) in self.API_SECURITY_HEADERS.items():
            actual_value = normalized_headers.get(header, "")

            if not actual_value:
                findings.append(
                    self._create_finding(
                        severity=severity,
                        title=f"API Missing Security Header: {header}",
                        description=(
                            f"API response is missing the {header} security header. "
                            f"Expected value: {expected_value if isinstance(expected_value, str) else expected_value[0]}"
                        ),
                        cwe_id="CWE-693",
                        cwe_name="Protection Mechanism Failure",
                        url=url,
                        evidence=f"{header} header not present",
                        remediation=f"Add header: {header}: {expected_value if isinstance(expected_value, str) else expected_value[0]}",
                        cvss_score=4.3 if severity == Severity.MEDIUM else 2.1,
                    )
                )
            elif isinstance(expected_value, list):
                if actual_value.lower() not in [v.lower() for v in expected_value]:
                    findings.append(
                        self._create_finding(
                            severity=severity,
                            title=f"API Security Header Misconfigured: {header}",
                            description=(
                                f"Header {header} has value '{actual_value}', "
                                f"expected one of: {expected_value}"
                            ),
                            cwe_id="CWE-693",
                            cwe_name="Protection Mechanism Failure",
                            url=url,
                            evidence=f"{header}: {actual_value}",
                            remediation=f"Set {header} to: {expected_value[0]}",
                            cvss_score=3.1,
                        )
                    )
            elif expected_value.lower() not in actual_value.lower():
                findings.append(
                    self._create_finding(
                        severity=severity,
                        title=f"API Security Header Misconfigured: {header}",
                        description=(
                            f"Header {header} is set to '{actual_value}', "
                            f"but should include '{expected_value}'"
                        ),
                        cwe_id="CWE-693",
                        cwe_name="Protection Mechanism Failure",
                        url=url,
                        evidence=f"{header}: {actual_value}",
                        remediation=f"Include '{expected_value}' in {header}",
                        cvss_score=3.1,
                    )
                )

        return findings

    def _analyze_api_versioning(
        self,
        url: str,
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """Analyze API versioning practices."""
        findings: list[Finding] = []
        detected_versions: set[str] = set()

        # Check current URL
        for pattern in self.API_VERSION_PATTERNS:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                detected_versions.add(match.group(1))

        # Check network log
        for entry in network_log:
            entry_url = entry.get("url", "")
            for pattern in self.API_VERSION_PATTERNS:
                match = re.search(pattern, entry_url, re.IGNORECASE)
                if match:
                    detected_versions.add(match.group(1))

        if detected_versions:
            # Only flag version issues when multiple versions are detected
            # Removed single v1 warning - using v1 alone is not a security issue
            # Many stable, well-maintained APIs remain at v1 indefinitely

            # Multiple versions in use could indicate version confusion
            if len(detected_versions) > 1:
                findings.append(
                    self._create_finding(
                        severity=Severity.LOW,
                        title="Multiple API Versions Detected",
                        description=(
                            f"Found references to multiple API versions: {', '.join(sorted(detected_versions))}. "
                            "Multiple versions may have different security levels and could "
                            "allow version downgrade attacks."
                        ),
                        cwe_id="CWE-693",
                        cwe_name="Protection Mechanism Failure",
                        url=url,
                        evidence=f"Versions: {', '.join(sorted(detected_versions))}",
                        remediation=(
                            "Standardize on the latest secure API version. "
                            "Deprecate and remove older versions when possible."
                        ),
                        cvss_score=2.1,
                        metadata={"versions": list(detected_versions)},
                    )
                )

        return findings

    def _analyze_method_security(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Analyze HTTP method handling (active mode)."""
        findings: list[Finding] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        # Check for Allow header which indicates supported methods
        allow = normalized_headers.get("allow", "")

        if allow:
            methods = [m.strip().upper() for m in allow.split(",")]
            dangerous = ["TRACE", "TRACK", "DEBUG"]

            exposed = [m for m in dangerous if m in methods]
            if exposed:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Dangerous HTTP Methods Enabled: {', '.join(exposed)}",
                        description=(
                            f"Server supports dangerous HTTP methods: {', '.join(exposed)}. "
                            "TRACE/TRACK can enable Cross-Site Tracing attacks. "
                            "DEBUG may expose sensitive information."
                        ),
                        cwe_id="CWE-749",
                        cwe_name="Exposed Dangerous Method or Function",
                        url=url,
                        evidence=f"Allow: {allow}",
                        remediation="Disable TRACE, TRACK, and DEBUG HTTP methods on the server.",
                        cvss_score=5.3,
                        metadata={"dangerous_methods": exposed},
                    )
                )

        return findings
