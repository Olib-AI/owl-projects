"""
Endpoint and Technology Analyzer.

Analyzes JavaScript sources for endpoint discovery and performs
technology fingerprinting to identify frameworks and libraries.
"""

from __future__ import annotations

import re
from typing import Any

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity
from secureprobe.utils import TECHNOLOGY_SIGNATURES


def _is_path_segment_match(endpoint: str, keyword: str) -> bool:
    """
    Check if keyword appears as a standalone path segment, not a substring.

    Examples:
        /api/auth/login -> "auth" matches, "uth" does not
        /docs/authentication-guide -> "auth" does NOT match (it's part of "authentication")
        /user/profile -> "user" matches
        /superuser/settings -> "user" does NOT match (it's part of "superuser")
    """
    # Normalize the endpoint path
    path_lower = endpoint.lower()
    keyword_lower = keyword.lower()

    # Split path into segments by common delimiters
    # Handle: /path/segments, path-segments, path_segments, path.segments
    segments = re.split(r"[/\-_.]", path_lower)

    # Check for exact segment match
    return keyword_lower in segments


def _extract_path_segments(endpoint: str) -> list[str]:
    """Extract individual path segments from an endpoint URL."""
    # Remove query string and fragment
    path = endpoint.split("?")[0].split("#")[0]
    # Split by path delimiters and filter empty segments
    return [seg for seg in re.split(r"[/\-_.]", path.lower()) if seg]


class EndpointAnalyzer(BaseAnalyzer):
    """
    Analyzer for endpoint discovery and technology fingerprinting.

    Checks for:
    - API endpoints in JavaScript
    - Hidden/undocumented endpoints
    - Technology stack identification
    - Outdated library versions
    - Source map exposure
    """

    analyzer_type = AnalyzerType.ENDPOINT

    ENDPOINT_PATTERNS = [
        r'["\'](?:https?://[^"\']+)?(/api/[^"\']*)["\']',
        r'["\'](?:https?://[^"\']+)?(/v[0-9]+/[^"\']*)["\']',
        r'["\'](?:https?://[^"\']+)?(/graphql)["\']',
        r'["\'](?:https?://[^"\']+)?(/rest/[^"\']*)["\']',
        r'["\'](?:https?://[^"\']+)?(/admin[^"\']*)["\']',
        r'["\'](?:https?://[^"\']+)?(/internal[^"\']*)["\']',
        r'["\'](?:https?://[^"\']+)?(/debug[^"\']*)["\']',
        r'["\'](?:https?://[^"\']+)?(/test[^"\']*)["\']',
        r'["\'](?:https?://[^"\']+)?(/dev[^"\']*)["\']',
        r'["\'](?:https?://[^"\']+)?(/staging[^"\']*)["\']',
        r'["\'](?:https?://[^"\']+)?(/backup[^"\']*)["\']',
        r'["\'](?:https?://[^"\']+)?(/config[^"\']*)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\$\.(ajax|get|post)\s*\(\s*["\']([^"\']+)["\']',
        r'XMLHttpRequest.*\.open\s*\([^,]+,\s*["\']([^"\']+)["\']',
        r'new\s+Request\s*\(\s*["\']([^"\']+)["\']',
    ]

    # High-confidence sensitive endpoints (always flag if found as path segment)
    SENSITIVE_ENDPOINTS_HIGH = frozenset({
        "admin", "oauth", "token", "api-key", "apikey",
        "secret", "private", "internal", "debug",
        "backup", "config", "settings",
    })

    # Medium-confidence endpoints (flag if found as standalone segment, not in docs/guides)
    SENSITIVE_ENDPOINTS_MEDIUM = frozenset({
        "login", "auth", "password", "reset", "signup", "register",
        "account", "profile", "export", "import", "management",
    })

    # Low-confidence endpoints (only flag if multiple indicators present)
    # Removed overly common terms: "user", "users", "file", "files", "document",
    # "documents", "upload", "download", "test", "dev", "staging", "hidden"
    SENSITIVE_ENDPOINTS_LOW = frozenset({
        "credentials", "session", "key", "keys", "tokens",
    })

    # Path segments that indicate documentation/non-sensitive context
    DOCUMENTATION_INDICATORS = frozenset({
        "docs", "documentation", "guide", "guides", "tutorial",
        "tutorials", "help", "faq", "about", "blog", "articles",
        "examples", "samples", "demo", "learn", "reference",
    })

    VULNERABLE_LIBRARY_PATTERNS: dict[str, dict[str, str]] = {
        "jquery": {
            "pattern": r"jquery[/\-._]?([\d.]+)",
            "vulnerable_before": "3.5.0",
            "cve": "CVE-2020-11022",
        },
        "angular": {
            "pattern": r"angular[/\-._]?([\d.]+)",
            "vulnerable_before": "1.6.0",
            "cve": "Multiple XSS vulnerabilities",
        },
        "bootstrap": {
            "pattern": r"bootstrap[/\-._]?([\d.]+)",
            "vulnerable_before": "4.3.1",
            "cve": "CVE-2019-8331",
        },
        "lodash": {
            "pattern": r"lodash[/\-._]?([\d.]+)",
            "vulnerable_before": "4.17.21",
            "cve": "CVE-2021-23337",
        },
        "moment": {
            "pattern": r"moment[/\-._]?([\d.]+)",
            "vulnerable_before": "2.29.2",
            "cve": "CVE-2022-24785",
        },
    }

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze endpoints and technology stack."""
        findings: list[Finding] = []
        html = page_data.get("html", "")
        scripts = page_data.get("scripts", [])
        headers = page_data.get("headers", {})

        all_content = html
        if scripts:
            for script in scripts:
                if isinstance(script, str):
                    all_content += "\n" + script

        findings.extend(self._discover_endpoints(url, all_content))
        findings.extend(self._fingerprint_technologies(url, all_content, headers))
        findings.extend(self._check_source_maps(url, html, scripts))
        findings.extend(self._check_vulnerable_libraries(url, all_content))

        return findings

    def _is_in_documentation_context(self, endpoint: str) -> bool:
        """Check if endpoint appears to be in a documentation/guide context."""
        segments = _extract_path_segments(endpoint)
        return bool(self.DOCUMENTATION_INDICATORS & set(segments))

    def _classify_endpoint_sensitivity(
        self, endpoint: str
    ) -> tuple[str | None, str | None]:
        """
        Classify endpoint sensitivity using path segment matching.

        Returns:
            Tuple of (confidence_level, matched_keyword) or (None, None) if not sensitive.
            confidence_level is one of: "high", "medium", "low"
        """
        # Skip documentation/guide contexts for medium/low sensitivity
        in_docs = self._is_in_documentation_context(endpoint)

        # Check high-confidence keywords (always flag)
        for keyword in self.SENSITIVE_ENDPOINTS_HIGH:
            if _is_path_segment_match(endpoint, keyword):
                return ("high", keyword)

        # Skip medium/low checks if in documentation context
        if in_docs:
            return (None, None)

        # Check medium-confidence keywords
        for keyword in self.SENSITIVE_ENDPOINTS_MEDIUM:
            if _is_path_segment_match(endpoint, keyword):
                return ("medium", keyword)

        # Check low-confidence keywords
        for keyword in self.SENSITIVE_ENDPOINTS_LOW:
            if _is_path_segment_match(endpoint, keyword):
                return ("low", keyword)

        return (None, None)

    def _discover_endpoints(
        self,
        url: str,
        content: str,
    ) -> list[Finding]:
        """Discover API endpoints from JavaScript with context-aware sensitivity detection."""
        findings: list[Finding] = []
        discovered_endpoints: set[str] = set()

        for pattern in self.ENDPOINT_PATTERNS:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    endpoint = match if isinstance(match, str) else match[-1] if match else ""
                    if endpoint:
                        endpoint = endpoint.strip()
                        if not endpoint.startswith(("http://", "https://", "/")):
                            endpoint = "/" + endpoint
                        discovered_endpoints.add(endpoint)
            except re.error:
                continue

        # Classify endpoints by sensitivity level
        high_sensitive: list[tuple[str, str]] = []
        medium_sensitive: list[tuple[str, str]] = []
        low_sensitive: list[tuple[str, str]] = []

        for endpoint in discovered_endpoints:
            level, keyword = self._classify_endpoint_sensitivity(endpoint)
            if level == "high":
                high_sensitive.append((endpoint, keyword or ""))
            elif level == "medium":
                medium_sensitive.append((endpoint, keyword or ""))
            elif level == "low":
                low_sensitive.append((endpoint, keyword or ""))

        # Report high-sensitivity endpoints at MEDIUM severity
        if high_sensitive:
            endpoints_list = [ep for ep, _ in high_sensitive]
            keywords_found = sorted({kw for _, kw in high_sensitive})
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Sensitive Endpoints Discovered in JavaScript",
                    description=(
                        f"Found {len(high_sensitive)} sensitive API endpoint(s) "
                        f"in JavaScript code containing: {', '.join(keywords_found)}. "
                        "These may expose administrative, authentication, or internal functionality."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence=f"Endpoints: {', '.join(endpoints_list[:5])}{'...' if len(endpoints_list) > 5 else ''}",
                    remediation=(
                        "Review exposed endpoints for proper authorization. "
                        "Remove references to internal/admin endpoints from client-side code."
                    ),
                    cvss_score=5.3,
                    metadata={
                        "confidence": "high",
                        "endpoint_count": len(discovered_endpoints),
                        "sensitive_count": len(high_sensitive),
                        "endpoints": endpoints_list[:20],
                        "keywords_matched": keywords_found,
                    },
                )
            )

        # Report medium-sensitivity endpoints at LOW severity
        if medium_sensitive:
            endpoints_list = [ep for ep, _ in medium_sensitive]
            keywords_found = sorted({kw for _, kw in medium_sensitive})
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Potentially Sensitive Endpoints Discovered",
                    description=(
                        f"Found {len(medium_sensitive)} potentially sensitive endpoint(s) "
                        f"containing: {', '.join(keywords_found)}. "
                        "These may warrant review for proper access controls."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence=f"Endpoints: {', '.join(endpoints_list[:5])}{'...' if len(endpoints_list) > 5 else ''}",
                    remediation=(
                        "Verify these endpoints have appropriate access controls. "
                        "Consider whether they should be exposed in client-side code."
                    ),
                    cvss_score=3.1,
                    metadata={
                        "confidence": "medium",
                        "sensitive_count": len(medium_sensitive),
                        "endpoints": endpoints_list[:20],
                        "keywords_matched": keywords_found,
                    },
                )
            )

        # Only report low-sensitivity endpoints if there are multiple indicators
        # or combined with high/medium findings (informational only)
        if low_sensitive and len(low_sensitive) >= 3:
            endpoints_list = [ep for ep, _ in low_sensitive]
            findings.append(
                self._create_finding(
                    severity=Severity.INFO,
                    title="Credential-Related Endpoints Found",
                    description=(
                        f"Found {len(low_sensitive)} endpoint(s) that may be related to "
                        "credentials or session management. Review for appropriate security."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence=f"Endpoints: {', '.join(endpoints_list[:5])}",
                    remediation="Review endpoints for secure credential handling.",
                    cvss_score=0.0,
                    metadata={
                        "confidence": "low",
                        "endpoints": endpoints_list[:10],
                    },
                )
            )

        if len(discovered_endpoints) > 50:
            findings.append(
                self._create_finding(
                    severity=Severity.INFO,
                    title="Large Number of API Endpoints Discovered",
                    description=(
                        f"Found {len(discovered_endpoints)} API endpoints in JavaScript. "
                        "Consider reviewing for unnecessary exposure."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence=f"Total endpoints discovered: {len(discovered_endpoints)}",
                    remediation="Review API surface area and minimize exposed endpoints.",
                    cvss_score=0.0,
                    metadata={"endpoint_count": len(discovered_endpoints)},
                )
            )

        return findings

    def _fingerprint_technologies(
        self,
        url: str,
        content: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Identify technologies used by the application."""
        findings: list[Finding] = []
        detected_tech: list[str] = []

        content_lower = content.lower()
        header_str = str(headers).lower()
        all_content = content_lower + header_str

        for tech, patterns in TECHNOLOGY_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, all_content, re.IGNORECASE):
                    detected_tech.append(tech)
                    break

        if detected_tech:
            findings.append(
                self._create_finding(
                    severity=Severity.INFO,
                    title="Technology Stack Fingerprinted",
                    description=(
                        f"Detected technologies: {', '.join(detected_tech)}. "
                        "This information could help attackers target known vulnerabilities."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence=f"Technologies: {', '.join(detected_tech)}",
                    remediation=(
                        "While technology fingerprinting cannot be fully prevented, "
                        "ensure all components are kept up to date."
                    ),
                    cvss_score=0.0,
                    metadata={"technologies": detected_tech},
                )
            )

        return findings

    def _check_source_maps(
        self,
        url: str,
        html: str,
        scripts: list[Any],
    ) -> list[Finding]:
        """Check for exposed source maps."""
        findings: list[Finding] = []

        source_map_patterns = [
            r"//# sourceMappingURL=([^\s]+)",
            r"/\*# sourceMappingURL=([^\s*]+)",
            r"X-SourceMap:\s*(\S+)",
        ]

        all_content = html
        if scripts:
            for script in scripts:
                if isinstance(script, str):
                    all_content += "\n" + script

        source_maps_found: list[str] = []
        for pattern in source_map_patterns:
            matches = re.findall(pattern, all_content, re.IGNORECASE)
            source_maps_found.extend(matches)

        if source_maps_found:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Source Maps Exposed",
                    description=(
                        "JavaScript source maps were found. These may expose original "
                        "source code, making it easier to understand application logic."
                    ),
                    cwe_id="CWE-540",
                    cwe_name="Inclusion of Sensitive Information in Source Code",
                    url=url,
                    evidence=f"Source maps: {', '.join(source_maps_found[:3])}",
                    remediation=(
                        "Remove source maps from production or restrict access. "
                        "Configure build tools to not generate source maps for production."
                    ),
                    cvss_score=3.1,
                    metadata={"source_maps": source_maps_found[:10]},
                )
            )

        return findings

    def _check_vulnerable_libraries(
        self,
        url: str,
        content: str,
    ) -> list[Finding]:
        """Check for known vulnerable library versions."""
        findings: list[Finding] = []

        for lib_name, lib_info in self.VULNERABLE_LIBRARY_PATTERNS.items():
            pattern = lib_info["pattern"]
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    version = matches[0]
                    if self._is_version_vulnerable(version, lib_info["vulnerable_before"]):
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title=f"Potentially Vulnerable {lib_name.title()} Version",
                                description=(
                                    f"Detected {lib_name} version {version}. "
                                    f"Versions before {lib_info['vulnerable_before']} may be vulnerable. "
                                    f"Known issue: {lib_info['cve']}"
                                ),
                                cwe_id="CWE-1104",
                                cwe_name="Use of Unmaintained Third Party Components",
                                url=url,
                                evidence=f"{lib_name} version {version}",
                                remediation=f"Update {lib_name} to the latest version.",
                                cvss_score=5.3,
                                metadata={
                                    "library": lib_name,
                                    "detected_version": version,
                                    "vulnerable_before": lib_info["vulnerable_before"],
                                    "cve": lib_info["cve"],
                                },
                            )
                        )
            except re.error:
                continue

        return findings

    def _is_version_vulnerable(self, detected: str, vulnerable_before: str) -> bool:
        """Compare versions to determine if detected version is vulnerable."""
        try:
            detected_parts = [int(x) for x in detected.split(".")[:3]]
            threshold_parts = [int(x) for x in vulnerable_before.split(".")[:3]]

            while len(detected_parts) < 3:
                detected_parts.append(0)
            while len(threshold_parts) < 3:
                threshold_parts.append(0)

            return detected_parts < threshold_parts
        except ValueError:
            return False
