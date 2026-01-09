"""
Access Control Analyzer.

Analyzes authorization mechanisms, privilege boundaries,
and access control implementations for authorized security testing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity


@dataclass(frozen=True, slots=True)
class IDORConfidence:
    """Confidence assessment for IDOR detection."""

    level: str  # "high", "medium", "low"
    score: float  # 0.0 to 1.0
    indicators: tuple[str, ...]

    @property
    def severity(self) -> Severity:
        """Map confidence level to appropriate severity."""
        match self.level:
            case "high":
                return Severity.MEDIUM
            case "medium":
                return Severity.LOW
            case _:
                return Severity.INFO


class AccessControlAnalyzer(BaseAnalyzer):
    """
    Analyzer for access control vulnerabilities.

    Checks for:
    - Horizontal privilege boundaries (CWE-639)
    - Vertical access controls (CWE-269)
    - Direct object reference handling (CWE-639)
    - Path traversal defenses (CWE-22)
    - Authorization header handling (CWE-287)
    """

    analyzer_type = AnalyzerType.ACCESS_CONTROL

    # High-confidence IDOR patterns (user-specific resources)
    IDOR_HIGH_CONFIDENCE_PATTERNS = [
        r"/users?/(\d+)",
        r"/accounts?/(\d+)",
        r"/profiles?/(\d+)",
        r"\?user_id=(\d+)",
        r"\?account_id=(\d+)",
    ]

    # Medium-confidence IDOR patterns (potentially sensitive resources)
    IDOR_MEDIUM_CONFIDENCE_PATTERNS = [
        r"/orders?/(\d+)",
        r"/invoices?/(\d+)",
        r"/messages?/(\d+)",
        r"/documents?/(\d+)",
        r"\?order_id=(\d+)",
        r"\?doc_id=(\d+)",
    ]

    # Low-confidence patterns (generic numeric IDs, require additional context)
    IDOR_LOW_CONFIDENCE_PATTERNS = [
        r"/files?/(\d+)",
        r"/records?/(\d+)",
        r"\?id=(\d+)",
        r"\?file_id=(\d+)",
        r"\?record_id=(\d+)",
        r"/api/v\d+/\w+/([a-f0-9-]{36})",  # UUID patterns
        r"/api/v\d+/\w+/(\d+)",
    ]

    # Keywords indicating user-specific data (boost confidence)
    IDOR_SENSITIVE_KEYWORDS = frozenset({
        "user", "account", "profile", "personal", "private",
        "my", "me", "self", "owner", "member", "customer",
    })

    # High-confidence admin patterns (definitive admin paths)
    ADMIN_HIGH_CONFIDENCE_PATTERNS = [
        r"^/admin(?:/|$)",
        r"^/administrator(?:/|$)",
        r"^/_admin(?:/|$)",
        r"^/wp-admin(?:/|$)",
        r"^/phpmyadmin(?:/|$)",
        r"^/cpanel(?:/|$)",
        r"^/webadmin(?:/|$)",
        r"^/superuser(?:/|$)",
    ]

    # Medium-confidence admin patterns (require additional indicators)
    ADMIN_MEDIUM_CONFIDENCE_PATTERNS = [
        r"^/management(?:/|$)",
        r"^/backend(?:/|$)",
        r"^/internal(?:/|$)",
        r"^/manager(?:/|$)",
        r"^/root(?:/|$)",
        r"^/control(?:/|$)",
    ]

    # Admin indicator keywords (used to boost confidence for ambiguous paths)
    ADMIN_INDICATOR_KEYWORDS = frozenset({
        "admin", "manage", "config", "settings", "users",
        "roles", "permissions", "system", "console",
    })

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e/",
        r"%2e%2e\\",
        r"\.\.%2f",
        r"\.\.%5c",
        r"%252e%252e/",
        r"..%c0%af",
        r"..%c1%9c",
    ]

    # Sensitive file patterns
    SENSITIVE_FILE_PATTERNS = [
        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/hosts",
        r"web\.config",
        r"\.htaccess",
        r"\.env",
        r"config\.php",
        r"settings\.py",
        r"database\.yml",
        r"wp-config\.php",
        r"\.git/config",
        r"\.svn/entries",
    ]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze access control mechanisms."""
        findings: list[Finding] = []
        html_content = page_data.get("html", "")
        headers = page_data.get("headers", {})
        network_log = page_data.get("network_log", [])
        forms = page_data.get("forms", [])
        scan_mode = page_data.get("scan_mode", "passive")

        # Passive analysis
        findings.extend(self._analyze_idor_patterns(url, html_content, network_log))
        findings.extend(self._analyze_admin_exposure(url, html_content, network_log))
        findings.extend(self._analyze_authorization_headers(url, headers))
        findings.extend(self._analyze_access_control_headers(url, headers))
        findings.extend(self._analyze_hidden_fields(url, forms))

        # Active mode analysis
        if scan_mode == "active":
            findings.extend(self._analyze_path_traversal_patterns(url, html_content))
            findings.extend(self._analyze_sensitive_file_exposure(url, html_content, network_log))

        return findings

    def _assess_idor_confidence(
        self,
        target_url: str,
        all_idor_urls: set[str],
        html_content: str,
    ) -> IDORConfidence:
        """
        Assess confidence level for IDOR detection based on multiple indicators.

        Confidence is determined by:
        - Pattern tier (high/medium/low confidence patterns matched)
        - Presence of user-specific keywords in URL or content
        - Number of unique IDOR-prone URLs found
        - Whether sequential IDs suggest enumeration vulnerability
        """
        indicators: list[str] = []
        base_score = 0.0

        # Check which tier of patterns matched
        high_confidence_matches = 0
        medium_confidence_matches = 0
        low_confidence_matches = 0

        for idor_url in all_idor_urls:
            for pattern in self.IDOR_HIGH_CONFIDENCE_PATTERNS:
                if re.search(pattern, idor_url, re.IGNORECASE):
                    high_confidence_matches += 1
                    break
            else:
                for pattern in self.IDOR_MEDIUM_CONFIDENCE_PATTERNS:
                    if re.search(pattern, idor_url, re.IGNORECASE):
                        medium_confidence_matches += 1
                        break
                else:
                    for pattern in self.IDOR_LOW_CONFIDENCE_PATTERNS:
                        if re.search(pattern, idor_url, re.IGNORECASE):
                            low_confidence_matches += 1
                            break

        if high_confidence_matches > 0:
            base_score += 0.4
            indicators.append(f"user-specific endpoints ({high_confidence_matches})")

        if medium_confidence_matches > 0:
            base_score += 0.2
            indicators.append(f"sensitive resource endpoints ({medium_confidence_matches})")

        if low_confidence_matches > 0:
            base_score += 0.1
            indicators.append(f"generic ID endpoints ({low_confidence_matches})")

        # Check for user-specific keywords in URLs
        url_text = " ".join(all_idor_urls).lower()
        keyword_matches = [kw for kw in self.IDOR_SENSITIVE_KEYWORDS if kw in url_text]
        if keyword_matches:
            base_score += 0.2
            indicators.append(f"user-data keywords: {', '.join(keyword_matches[:3])}")

        # Check for user-specific content indicators in HTML
        user_data_patterns = [
            r"email[\"']?\s*:\s*[\"'][^\"']+@",
            r"user(?:name|_name)[\"']?\s*:\s*[\"']",
            r"profile",
            r"account",
            r"personal",
        ]
        content_indicators = sum(
            1 for p in user_data_patterns
            if re.search(p, html_content, re.IGNORECASE)
        )
        if content_indicators >= 2:
            base_score += 0.15
            indicators.append("response contains user-specific data patterns")

        # Multiple unique IDOR URLs increase confidence
        if len(all_idor_urls) >= 3:
            base_score += 0.1
            indicators.append(f"multiple endpoints affected ({len(all_idor_urls)})")

        # Determine confidence level
        if base_score >= 0.5:
            level = "high"
        elif base_score >= 0.3:
            level = "medium"
        else:
            level = "low"

        return IDORConfidence(
            level=level,
            score=min(base_score, 1.0),
            indicators=tuple(indicators),
        )

    def _analyze_idor_patterns(
        self,
        url: str,
        html_content: str,
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """Detect potential Insecure Direct Object Reference patterns with confidence scoring."""
        findings: list[Finding] = []
        idor_urls: set[str] = set()

        # Combine all pattern tiers for initial detection
        all_patterns = (
            self.IDOR_HIGH_CONFIDENCE_PATTERNS
            + self.IDOR_MEDIUM_CONFIDENCE_PATTERNS
            + self.IDOR_LOW_CONFIDENCE_PATTERNS
        )

        # Check current URL
        for pattern in all_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                idor_urls.add(url)
                break

        # Check network log URLs
        for entry in network_log:
            entry_url = entry.get("url", "")
            for pattern in all_patterns:
                if re.search(pattern, entry_url, re.IGNORECASE):
                    idor_urls.add(entry_url)
                    break

        # Check links in HTML
        href_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
        links = re.findall(href_pattern, html_content, re.IGNORECASE)

        for link in links:
            for pattern in all_patterns:
                if re.search(pattern, link, re.IGNORECASE):
                    idor_urls.add(link)
                    break

        if not idor_urls:
            return findings

        # Assess confidence based on multiple indicators
        confidence = self._assess_idor_confidence(url, idor_urls, html_content)

        # Only report if we have at least 2 indicators for low-confidence patterns
        # or any high/medium confidence pattern matches
        has_high_medium_match = any(
            re.search(p, u, re.IGNORECASE)
            for u in idor_urls
            for p in (self.IDOR_HIGH_CONFIDENCE_PATTERNS + self.IDOR_MEDIUM_CONFIDENCE_PATTERNS)
        )

        if not has_high_medium_match and len(confidence.indicators) < 2:
            # Not enough evidence for low-confidence patterns
            return findings

        # Count sequential IDs for evidence
        sequential_ids: list[str] = []
        for idor_url in idor_urls:
            id_match = re.search(r"/(\d{1,10})(?:[/?]|$)", idor_url)
            if id_match:
                sequential_ids.append(idor_url)

        # Build description based on confidence
        confidence_desc = {
            "high": "High confidence: ",
            "medium": "Medium confidence: ",
            "low": "Low confidence (informational): ",
        }

        cvss_scores = {"high": 6.5, "medium": 4.0, "low": 0.0}

        indicators_text = "; ".join(confidence.indicators) if confidence.indicators else "pattern match only"

        findings.append(
            self._create_finding(
                severity=confidence.severity,
                title="Potential IDOR Vulnerability: Sequential IDs",
                description=(
                    f"{confidence_desc[confidence.level]}"
                    f"Found {len(idor_urls)} URL(s) using numeric identifiers. "
                    f"Indicators: {indicators_text}. "
                    "Sequential IDs may allow unauthorized access "
                    "to other users' resources if proper authorization checks are missing."
                ),
                cwe_id="CWE-639",
                cwe_name="Authorization Bypass Through User-Controlled Key",
                url=url,
                evidence=f"URLs with IDs: {', '.join(list(idor_urls)[:3])}",
                remediation=(
                    "Use UUIDs or other non-guessable identifiers for resources. "
                    "Implement proper authorization checks on every request. "
                    "Verify user ownership/access rights before returning resources."
                ),
                cvss_score=cvss_scores[confidence.level],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                    "https://cwe.mitre.org/data/definitions/639.html",
                ],
                metadata={
                    "idor_urls": list(idor_urls)[:10],
                    "sequential_count": len(sequential_ids),
                    "confidence_level": confidence.level,
                    "confidence_score": confidence.score,
                    "confidence_indicators": list(confidence.indicators),
                },
            )
        )

        return findings

    def _extract_path(self, url_or_path: str) -> str:
        """Extract path component from URL or path string."""
        if url_or_path.startswith(("http://", "https://")):
            parsed = urlparse(url_or_path)
            return parsed.path
        return url_or_path

    def _has_admin_indicators(self, path: str, html_content: str = "") -> bool:
        """Check if path or content has additional admin indicators."""
        path_lower = path.lower()
        content_lower = html_content.lower() if html_content else ""

        # Check for admin keywords in the path segments
        path_segments = path_lower.split("/")
        for keyword in self.ADMIN_INDICATOR_KEYWORDS:
            if keyword in path_segments:
                return True

        # Check content for admin-related elements
        admin_content_patterns = [
            r"<title>[^<]*admin[^<]*</title>",
            r"admin.*panel",
            r"admin.*dashboard",
            r"manage.*users",
            r"system.*settings",
        ]
        for pattern in admin_content_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True

        return False

    def _analyze_admin_exposure(
        self,
        url: str,
        html_content: str,
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """Detect exposed administrative paths and functionality with confidence scoring."""
        findings: list[Finding] = []
        high_confidence_paths: set[str] = set()
        medium_confidence_paths: set[str] = set()

        def check_and_categorize(target_url: str) -> None:
            """Categorize URL by admin pattern confidence."""
            path = self._extract_path(target_url)

            # Check high-confidence patterns first
            for pattern in self.ADMIN_HIGH_CONFIDENCE_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    high_confidence_paths.add(target_url[:100])
                    return

            # Check medium-confidence patterns (require additional indicators)
            for pattern in self.ADMIN_MEDIUM_CONFIDENCE_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    # Only add if we have additional admin indicators
                    if self._has_admin_indicators(path, html_content):
                        medium_confidence_paths.add(target_url[:100])
                    return

        # Check current URL
        check_and_categorize(url)

        # Check links in HTML
        href_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
        links = re.findall(href_pattern, html_content, re.IGNORECASE)
        for link in links:
            check_and_categorize(link)

        # Check network log
        for entry in network_log:
            entry_url = entry.get("url", "")
            if entry_url:
                check_and_categorize(entry_url)

        # Report high-confidence findings as MEDIUM severity
        if high_confidence_paths:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Administrative Paths Discovered",
                    description=(
                        f"Found {len(high_confidence_paths)} administrative path(s) referenced. "
                        "Exposed admin paths should be protected with strong authentication "
                        "and restricted to authorized personnel only."
                    ),
                    cwe_id="CWE-269",
                    cwe_name="Improper Privilege Management",
                    url=url,
                    evidence=f"Admin paths: {', '.join(list(high_confidence_paths)[:5])}",
                    remediation=(
                        "Restrict administrative paths using: "
                        "1) IP whitelisting, "
                        "2) VPN-only access, "
                        "3) Multi-factor authentication, "
                        "4) Strong role-based access controls. "
                        "Consider using non-standard admin URLs."
                    ),
                    cvss_score=5.3,
                    metadata={
                        "admin_paths": list(high_confidence_paths)[:10],
                        "confidence": "high",
                    },
                )
            )

        # Report medium-confidence findings as LOW severity (with indicators)
        if medium_confidence_paths:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Potential Administrative Paths Discovered",
                    description=(
                        f"Found {len(medium_confidence_paths)} potential administrative path(s). "
                        "These paths contain management-related keywords and additional admin indicators. "
                        "Verify access controls are properly configured."
                    ),
                    cwe_id="CWE-269",
                    cwe_name="Improper Privilege Management",
                    url=url,
                    evidence=f"Potential admin paths: {', '.join(list(medium_confidence_paths)[:5])}",
                    remediation=(
                        "Review these paths to determine if they require administrative access controls. "
                        "If administrative, apply appropriate restrictions."
                    ),
                    cvss_score=3.1,
                    metadata={
                        "admin_paths": list(medium_confidence_paths)[:10],
                        "confidence": "medium",
                    },
                )
            )

        return findings

    def _analyze_authorization_headers(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Analyze authorization-related headers."""
        findings: list[Finding] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        # Check for WWW-Authenticate header (indicates authentication is being used)
        www_auth = normalized_headers.get("www-authenticate", "")
        if www_auth and "basic" in www_auth.lower():
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Basic Authentication in Use",
                    description=(
                        "Server uses HTTP Basic Authentication. "
                        "Basic auth transmits credentials base64-encoded (not encrypted) "
                        "and is vulnerable to credential theft without HTTPS."
                    ),
                    cwe_id="CWE-287",
                    cwe_name="Improper Authentication",
                    url=url,
                    evidence=f"WWW-Authenticate: {www_auth}",
                    remediation=(
                        "Use token-based authentication (OAuth2, JWT) instead of Basic auth. "
                        "If Basic auth is required, ensure HTTPS is enforced. "
                        "Consider implementing API keys or session tokens."
                    ),
                    cvss_score=5.3,
                )
            )

        return findings

    def _analyze_access_control_headers(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Analyze CORS and access control headers."""
        findings: list[Finding] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        # CORS analysis
        acao = normalized_headers.get("access-control-allow-origin", "")
        acac = normalized_headers.get("access-control-allow-credentials", "")

        if acao == "*":
            if acac.lower() == "true":
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title="Dangerous CORS Configuration: Wildcard with Credentials",
                        description=(
                            "CORS is configured with Access-Control-Allow-Origin: * and "
                            "Access-Control-Allow-Credentials: true. This configuration "
                            "is actually blocked by browsers, but indicates misconfiguration."
                        ),
                        cwe_id="CWE-346",
                        cwe_name="Origin Validation Error",
                        url=url,
                        evidence=f"ACAO: {acao}; ACAC: {acac}",
                        remediation=(
                            "Use specific origin values instead of wildcards when credentials are needed. "
                            "Implement dynamic origin validation against an allowlist."
                        ),
                        cvss_score=8.1,
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                        ],
                    )
                )
            else:
                findings.append(
                    self._create_finding(
                        severity=Severity.LOW,
                        title="CORS Allows Any Origin",
                        description=(
                            "CORS is configured with Access-Control-Allow-Origin: *. "
                            "Any website can make requests to this endpoint. "
                            "Ensure this is intentional for public APIs only."
                        ),
                        cwe_id="CWE-346",
                        cwe_name="Origin Validation Error",
                        url=url,
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation=(
                            "Restrict CORS to specific trusted origins if this is not a public API. "
                            "Implement origin allowlist validation."
                        ),
                        cvss_score=3.1,
                    )
                )

        # Check for reflected origin (potential vulnerability)
        if acao and acao not in ["*", "null"]:
            # If origin is dynamically reflected, could be vulnerable
            parsed = urlparse(url)
            if acao != f"{parsed.scheme}://{parsed.netloc}":
                findings.append(
                    self._create_finding(
                        severity=Severity.INFO,
                        title="CORS Origin Policy Detected",
                        description=(
                            f"CORS allows requests from: {acao}. "
                            "Verify this origin is intentionally trusted."
                        ),
                        cwe_id="CWE-346",
                        cwe_name="Origin Validation Error",
                        url=url,
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation="Regularly audit CORS allowed origins.",
                        cvss_score=0.0,
                    )
                )

        return findings

    def _analyze_hidden_fields(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """Analyze hidden form fields for privilege-related data."""
        findings: list[Finding] = []

        privilege_patterns = [
            r"role",
            r"admin",
            r"privilege",
            r"permission",
            r"access",
            r"level",
            r"is_?admin",
            r"user_?type",
            r"account_?type",
            r"group",
            r"rights",
        ]

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", "") or form.get("action", "unknown")
            inputs = form.get("inputs", [])

            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue

                input_type = input_field.get("type", "").lower()
                name = input_field.get("name", "").lower()

                if input_type == "hidden":
                    for pattern in privilege_patterns:
                        if re.search(pattern, name, re.IGNORECASE):
                            findings.append(
                                self._create_finding(
                                    severity=Severity.MEDIUM,
                                    title=f"Privilege-Related Hidden Field: {name}",
                                    description=(
                                        f"Form contains hidden field '{name}' that appears related to "
                                        "user privileges or access control. Hidden fields can be "
                                        "modified by attackers and should not be trusted for authorization."
                                    ),
                                    cwe_id="CWE-269",
                                    cwe_name="Improper Privilege Management",
                                    url=url,
                                    evidence=f"Form: {form_id}; Hidden field: {name}",
                                    remediation=(
                                        "Never rely on client-side hidden fields for access control. "
                                        "Verify all privilege/role assignments server-side using "
                                        "authenticated session data."
                                    ),
                                    cvss_score=5.3,
                                    metadata={
                                        "form_id": form_id,
                                        "field_name": name,
                                    },
                                )
                            )
                            break

        return findings

    def _analyze_path_traversal_patterns(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """Detect path traversal patterns in content (active mode)."""
        findings: list[Finding] = []

        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE) or re.search(
                pattern, html_content, re.IGNORECASE
            ):
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title="Path Traversal Pattern Detected",
                        description=(
                            f"Detected path traversal pattern '{pattern}' in URL or response. "
                            "This could indicate a path traversal vulnerability allowing "
                            "access to files outside the intended directory."
                        ),
                        cwe_id="CWE-22",
                        cwe_name="Improper Limitation of a Pathname to a Restricted Directory",
                        url=url,
                        evidence=f"Pattern: {pattern}",
                        remediation=(
                            "Validate and sanitize all file path inputs. "
                            "Use allowlists for permitted files/directories. "
                            "Resolve paths canonically and verify they remain within allowed directories. "
                            "Consider using chroot or containerization."
                        ),
                        cvss_score=7.5,
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://cwe.mitre.org/data/definitions/22.html",
                        ],
                    )
                )
                break

        return findings

    def _analyze_sensitive_file_exposure(
        self,
        url: str,
        html_content: str,
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """Detect references to sensitive files (active mode)."""
        findings: list[Finding] = []
        sensitive_refs: set[str] = set()

        all_content = html_content + url
        for entry in network_log:
            all_content += entry.get("url", "")

        for pattern in self.SENSITIVE_FILE_PATTERNS:
            matches = re.findall(pattern, all_content, re.IGNORECASE)
            sensitive_refs.update(matches)

        if sensitive_refs:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="Sensitive File References Detected",
                    description=(
                        f"Found references to {len(sensitive_refs)} potentially sensitive file(s). "
                        "These files may contain configuration, credentials, or system information."
                    ),
                    cwe_id="CWE-538",
                    cwe_name="Insertion of Sensitive Information into Externally-Accessible File or Directory",
                    url=url,
                    evidence=f"Files: {', '.join(list(sensitive_refs)[:5])}",
                    remediation=(
                        "Ensure sensitive files are not accessible via web server. "
                        "Configure proper file permissions and web server access rules. "
                        "Move sensitive files outside the web root."
                    ),
                    cvss_score=7.5,
                    metadata={"sensitive_files": list(sensitive_refs)},
                )
            )

        return findings
