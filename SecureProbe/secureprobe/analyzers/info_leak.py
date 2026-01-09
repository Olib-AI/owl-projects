"""
Information Leakage Analyzer.

Detects exposed secrets, debug information, stack traces,
and other sensitive data in page content.
"""

from __future__ import annotations

import re
from typing import Any

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity
from secureprobe.utils import (
    COMMON_SECRET_PATTERNS,
    DEBUG_PATTERNS,
    truncate_string,
    is_high_entropy,
    is_generic_secret_false_positive,
)


class InfoLeakAnalyzer(BaseAnalyzer):
    """
    Analyzer for information leakage.

    Detects:
    - AWS keys, JWT tokens, GitHub tokens
    - API keys and database connection strings
    - Debug mode indicators
    - Stack traces and error messages
    - Internal paths and system information
    - Source code comments with sensitive info
    """

    analyzer_type = AnalyzerType.INFO_LEAK

    SEVERITY_MAP: dict[str, Severity] = {
        "aws_access_key": Severity.CRITICAL,
        "aws_secret_key": Severity.CRITICAL,
        "private_key": Severity.CRITICAL,
        "ssh_private_key": Severity.CRITICAL,
        "github_token": Severity.CRITICAL,
        "github_oauth": Severity.CRITICAL,
        "jwt_token": Severity.HIGH,
        "stripe_secret": Severity.CRITICAL,
        "stripe_publishable": Severity.MEDIUM,
        "slack_token": Severity.HIGH,
        "slack_webhook": Severity.HIGH,
        "google_api_key": Severity.HIGH,
        "firebase_key": Severity.HIGH,
        "twilio_sid": Severity.HIGH,
        "twilio_token": Severity.HIGH,
        "sendgrid_key": Severity.HIGH,
        "npm_token": Severity.HIGH,
        "pypi_token": Severity.HIGH,
        "postgres_uri": Severity.CRITICAL,
        "mysql_uri": Severity.CRITICAL,
        "mongodb_uri": Severity.CRITICAL,
        "redis_uri": Severity.HIGH,
        "heroku_api": Severity.HIGH,
        "generic_api_key": Severity.MEDIUM,
        "generic_secret": Severity.MEDIUM,
        "bearer_token": Severity.HIGH,
        "basic_auth": Severity.HIGH,
    }

    CWE_MAP: dict[str, tuple[str, str]] = {
        "aws_access_key": ("CWE-798", "Use of Hard-coded Credentials"),
        "aws_secret_key": ("CWE-798", "Use of Hard-coded Credentials"),
        "private_key": ("CWE-321", "Use of Hard-coded Cryptographic Key"),
        "ssh_private_key": ("CWE-321", "Use of Hard-coded Cryptographic Key"),
        "github_token": ("CWE-798", "Use of Hard-coded Credentials"),
        "jwt_token": ("CWE-200", "Exposure of Sensitive Information"),
        "postgres_uri": ("CWE-798", "Use of Hard-coded Credentials"),
        "mysql_uri": ("CWE-798", "Use of Hard-coded Credentials"),
        "mongodb_uri": ("CWE-798", "Use of Hard-coded Credentials"),
        "default": ("CWE-200", "Exposure of Sensitive Information"),
    }

    # Internal path patterns - only match actual filesystem paths, not common URL segments
    INTERNAL_PATH_PATTERNS = [
        r"/home/[a-zA-Z0-9_-]+/",
        r"/Users/[a-zA-Z0-9_-]+/",
        r"C:\\Users\\[a-zA-Z0-9_-]+\\",
        r"/var/www/[a-zA-Z0-9_-]+",
        r"/var/log/[a-zA-Z0-9_-]+",
        r"/opt/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+",
        r"/srv/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+",
        r"/etc/[a-zA-Z0-9_-]+/",
        r"/usr/local/[a-zA-Z0-9_-]+/",
        # Removed /app/ and /src/ as they are too common in URLs
    ]

    COMMENT_SECRET_PATTERNS = [
        r"<!--[^>]*(?:password|secret|key|token|api[_-]?key)[^>]*-->",
        r"/\*[^*]*(?:password|secret|key|token|api[_-]?key)[^*]*\*/",
        r"//[^\n]*(?:password|secret|key|token|api[_-]?key)[^\n]*",
    ]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze page for information leakage."""
        findings: list[Finding] = []
        html = page_data.get("html", "")
        scripts = page_data.get("scripts", [])

        if html:
            findings.extend(self._check_secrets(url, html))
            findings.extend(self._check_debug_info(url, html))
            findings.extend(self._check_internal_paths(url, html))
            findings.extend(self._check_comments(url, html))

        if scripts:
            for script in scripts:
                if isinstance(script, str):
                    findings.extend(self._check_secrets(url, script, source="JavaScript"))
                    findings.extend(self._check_debug_info(url, script, source="JavaScript"))

        network_log = page_data.get("network_log", [])
        if network_log:
            findings.extend(self._check_network_leaks(url, network_log))

        return findings

    def _check_secrets(
        self,
        url: str,
        content: str,
        source: str = "HTML",
    ) -> list[Finding]:
        """Check content for exposed secrets."""
        findings: list[Finding] = []

        # Determine if content is likely a JavaScript bundle (lower confidence for matches)
        is_js_bundle = source == "JavaScript" or self._is_javascript_bundle(content)

        for secret_type, pattern in COMMON_SECRET_PATTERNS.items():
            try:
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                if matches:
                    for match_obj in matches[:3]:
                        # Extract the captured group if present, otherwise full match
                        if match_obj.groups():
                            match_str = next((g for g in match_obj.groups() if g), "")
                        else:
                            match_str = match_obj.group(0)

                        if not match_str:
                            continue

                        # Get context around the match for validation
                        start = max(0, match_obj.start() - 100)
                        end = min(len(content), match_obj.end() + 100)
                        context = content[start:end]

                        # Apply entropy check for generic patterns
                        if secret_type in ["generic_api_key", "generic_secret"]:
                            if not is_high_entropy(match_str):
                                continue

                        # Apply false positive check for generic_secret
                        if secret_type == "generic_secret":
                            if is_generic_secret_false_positive(context, match_str):
                                continue

                        # Check if this looks like a config example rather than a real secret
                        if self._is_config_example(context, match_str):
                            continue

                        severity = self.SEVERITY_MAP.get(secret_type, Severity.MEDIUM)

                        # Reduce severity for JS bundle matches (higher false positive rate)
                        if is_js_bundle and severity in [Severity.CRITICAL, Severity.HIGH]:
                            severity = Severity.MEDIUM

                        cwe_id, cwe_name = self.CWE_MAP.get(
                            secret_type,
                            self.CWE_MAP["default"]
                        )

                        masked = self._mask_secret(match_str)

                        findings.append(
                            self._create_finding(
                                severity=severity,
                                title=f"Exposed {self._format_secret_type(secret_type)}",
                                description=(
                                    f"A {self._format_secret_type(secret_type)} was found "
                                    f"in {source} content. This credential may be compromised."
                                ),
                                cwe_id=cwe_id,
                                cwe_name=cwe_name,
                                url=url,
                                evidence=f"Found in {source}: {masked}",
                                remediation=(
                                    f"1. Immediately rotate/revoke the exposed {self._format_secret_type(secret_type)}. "
                                    "2. Remove the credential from source code. "
                                    "3. Use environment variables or secret management."
                                ),
                                cvss_score=self._get_cvss_score(severity),
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_an_error_message",
                                ],
                                metadata={
                                    "secret_type": secret_type,
                                    "source": source,
                                    "confidence": "medium" if is_js_bundle else "high",
                                },
                            )
                        )
            except re.error:
                continue

        return findings

    def _is_javascript_bundle(self, content: str) -> bool:
        """
        Detect if content is likely a minified JavaScript bundle.

        Args:
            content: Content to analyze

        Returns:
            True if content appears to be a JS bundle
        """
        # Check for common bundle indicators
        bundle_indicators = [
            "webpackJsonp",
            "__webpack_require__",
            "!function(e,t)",
            "!function(t,e)",
            'use strict";!function',
            "sourceMappingURL=",
            ".chunk.js",
            ".bundle.js",
        ]
        content_start = content[:5000]
        return any(indicator in content_start for indicator in bundle_indicators)

    def _is_config_example(self, context: str, match: str) -> bool:
        """
        Check if a secret match appears to be a configuration example.

        Args:
            context: Surrounding text context
            match: The matched secret value

        Returns:
            True if likely a config example, False otherwise
        """
        context_lower = context.lower()

        # Common example/placeholder indicators
        example_indicators = [
            "your_",
            "your-",
            "<your",
            "replace_",
            "replace-",
            "xxx",
            "yyy",
            "zzz",
            "change_me",
            "changeme",
            "insert_",
            "put_your",
            "enter_your",
            "placeholder",
            "example_",
            "sample_",
            "my_secret",
            "my_password",
            "my_api_key",
        ]

        for indicator in example_indicators:
            if indicator in match.lower() or indicator in context_lower:
                return True

        # Check for repetitive patterns suggesting placeholder (e.g., "xxxxxxxxxxxx")
        if len(set(match.lower())) <= 3 and len(match) > 8:
            return True

        return False

    def _check_debug_info(
        self,
        url: str,
        content: str,
        source: str = "HTML",
    ) -> list[Finding]:
        """Check for debug mode indicators and stack traces."""
        findings: list[Finding] = []

        for pattern in DEBUG_PATTERNS:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    match_str = matches[0] if matches else pattern

                    if "Traceback" in pattern or "Exception" in pattern or "error" in pattern.lower():
                        severity = Severity.MEDIUM
                        title = "Stack Trace or Error Message Exposed"
                        description = (
                            "A stack trace or detailed error message was found in the page. "
                            "This may reveal internal application structure and aid attackers."
                        )
                    elif "DEBUG" in pattern.upper():
                        severity = Severity.HIGH
                        title = "Debug Mode Enabled"
                        description = (
                            "Debug mode appears to be enabled in production. "
                            "This may expose sensitive information and development features."
                        )
                    else:
                        severity = Severity.LOW
                        title = "Development Artifact Found"
                        description = "Development-related content was found in the page."

                    findings.append(
                        self._create_finding(
                            severity=severity,
                            title=title,
                            description=description,
                            cwe_id="CWE-209",
                            cwe_name="Generation of Error Message Containing Sensitive Information",
                            url=url,
                            evidence=truncate_string(match_str, 150),
                            remediation=(
                                "Disable debug mode in production. "
                                "Configure error handling to show generic messages to users."
                            ),
                            cvss_score=self._get_cvss_score(severity),
                        )
                    )
                    break
            except re.error:
                continue

        return findings

    def _check_internal_paths(
        self,
        url: str,
        content: str,
    ) -> list[Finding]:
        """Check for exposed internal file paths."""
        findings: list[Finding] = []

        for pattern in self.INTERNAL_PATH_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append(
                    self._create_finding(
                        severity=Severity.LOW,
                        title="Internal Path Disclosure",
                        description=(
                            "Internal file system paths were found in the page. "
                            "This reveals server configuration information."
                        ),
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information",
                        url=url,
                        evidence=f"Path found: {matches[0]}",
                        remediation="Remove internal paths from error messages and responses.",
                        cvss_score=2.1,
                    )
                )
                break

        return findings

    def _check_comments(
        self,
        url: str,
        content: str,
    ) -> list[Finding]:
        """Check HTML/JS comments for sensitive information."""
        findings: list[Finding] = []

        for pattern in self.COMMENT_SECRET_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="Sensitive Information in Comments",
                        description=(
                            "Comments containing potentially sensitive keywords were found. "
                            "This may expose credentials, secrets, or internal information."
                        ),
                        cwe_id="CWE-615",
                        cwe_name="Inclusion of Sensitive Information in Source Code Comments",
                        url=url,
                        evidence=truncate_string(matches[0], 100),
                        remediation="Remove comments containing sensitive information from production code.",
                        cvss_score=4.3,
                    )
                )
                break

        return findings

    def _check_network_leaks(
        self,
        url: str,
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """Check network requests for information leakage."""
        findings: list[Finding] = []

        sensitive_params = [
            "password", "passwd", "pwd", "secret", "token", "api_key",
            "apikey", "key", "auth", "credential", "ssn", "credit",
        ]

        for entry in network_log[:50]:
            request_url = entry.get("url", "")

            for param in sensitive_params:
                if f"{param}=" in request_url.lower():
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title="Sensitive Data in URL Parameter",
                            description=(
                                f"Sensitive parameter '{param}' found in URL. "
                                "This data may be logged and exposed in browser history."
                            ),
                            cwe_id="CWE-598",
                            cwe_name="Use of GET Request Method With Sensitive Query Strings",
                            url=url,
                            evidence=f"Parameter '{param}' in: {truncate_string(request_url, 100)}",
                            remediation="Use POST requests for sensitive data. Never include secrets in URLs.",
                            cvss_score=6.5,
                        )
                    )
                    break

        return findings

    def _mask_secret(self, secret: str) -> str:
        """Mask a secret value for safe display."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _format_secret_type(self, secret_type: str) -> str:
        """Format secret type for display."""
        return secret_type.replace("_", " ").title()

    def _get_cvss_score(self, severity: Severity) -> float:
        """Get representative CVSS score for severity."""
        match severity:
            case Severity.CRITICAL:
                return 9.0
            case Severity.HIGH:
                return 7.5
            case Severity.MEDIUM:
                return 5.3
            case Severity.LOW:
                return 3.1
            case Severity.INFO:
                return 0.0
