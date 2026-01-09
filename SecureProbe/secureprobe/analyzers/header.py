"""
HTTP Security Header Analyzer.

Analyzes response headers for security misconfigurations including
CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and more.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity


class HeaderAnalyzer(BaseAnalyzer):
    """
    Analyzer for HTTP security headers.

    Checks for missing or misconfigured security headers including:
    - Content-Security-Policy (CSP)
    - Strict-Transport-Security (HSTS)
    - X-Frame-Options
    - X-Content-Type-Options
    - Referrer-Policy
    - Permissions-Policy
    - X-XSS-Protection (deprecated but still checked)
    """

    analyzer_type = AnalyzerType.HEADER

    HSTS_MIN_AGE = 31536000

    CSP_UNSAFE_DIRECTIVES = [
        "unsafe-inline",
        "unsafe-eval",
        "data:",
        "*",
    ]

    CSP_REQUIRED_DIRECTIVES = [
        "default-src",
        "script-src",
        "style-src",
        "object-src",
        "base-uri",
        "form-action",
    ]

    # URL path segments that indicate sensitive endpoints (must be actual path segments)
    SENSITIVE_PATH_SEGMENTS = frozenset({
        "login", "signin", "sign-in", "auth", "authenticate", "oauth",
        "account", "profile", "dashboard", "admin", "user", "users",
        "password", "reset-password", "forgot-password", "change-password",
        "settings", "preferences", "billing", "payment", "checkout",
        "api/auth", "api/user", "api/account", "api/admin",
    })

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze HTTP response headers for security issues."""
        findings: list[Finding] = []
        headers = page_data.get("headers", {})

        if not headers:
            self.logger.warning("no_headers_found", url=url)
            return findings

        normalized_headers = {k.lower(): v for k, v in headers.items()}

        findings.extend(self._check_csp(url, normalized_headers, page_data))
        findings.extend(self._check_hsts(url, normalized_headers))
        findings.extend(self._check_x_frame_options(url, normalized_headers))
        findings.extend(self._check_x_content_type_options(url, normalized_headers))
        findings.extend(self._check_referrer_policy(url, normalized_headers))
        findings.extend(self._check_permissions_policy(url, normalized_headers))
        findings.extend(self._check_cache_control(url, normalized_headers))
        findings.extend(self._check_server_header(url, normalized_headers))
        findings.extend(self._check_x_powered_by(url, normalized_headers))

        return findings

    def _check_csp(
        self,
        url: str,
        headers: dict[str, str],
        page_data: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Check Content-Security-Policy header."""
        findings: list[Finding] = []
        csp = headers.get("content-security-policy", "")

        if not csp:
            # Assess context to determine appropriate severity
            severity, cvss, notes = self._assess_csp_severity(url, headers, page_data)

            description = (
                "The Content-Security-Policy (CSP) header is not set. "
                "CSP helps mitigate Cross-Site Scripting (XSS) and data injection attacks "
                "by specifying which content sources are allowed."
            )
            if notes:
                description += f" Note: {notes}"

            findings.append(
                self._create_finding(
                    severity=severity,
                    title="Missing Content-Security-Policy Header",
                    description=description,
                    cwe_id="CWE-693",
                    cwe_name="Protection Mechanism Failure",
                    url=url,
                    evidence="Content-Security-Policy header not present in response",
                    remediation=(
                        "Implement a strict Content-Security-Policy. Start with: "
                        "default-src 'self'; script-src 'self'; style-src 'self'; "
                        "object-src 'none'; base-uri 'self'; form-action 'self';"
                    ),
                    cvss_score=cvss,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                        "https://cwe.mitre.org/data/definitions/693.html",
                    ],
                )
            )
            return findings

        for unsafe in self.CSP_UNSAFE_DIRECTIVES:
            if unsafe in csp.lower():
                severity = Severity.HIGH if unsafe in ["unsafe-eval", "*"] else Severity.MEDIUM
                findings.append(
                    self._create_finding(
                        severity=severity,
                        title=f"CSP Contains Unsafe Directive: {unsafe}",
                        description=(
                            f"The Content-Security-Policy contains '{unsafe}' which "
                            f"weakens XSS protection. "
                            f"{'unsafe-eval allows dynamic code execution.' if unsafe == 'unsafe-eval' else ''}"
                            f"{'unsafe-inline allows inline scripts.' if unsafe == 'unsafe-inline' else ''}"
                            f"{'Wildcard * allows any source.' if unsafe == '*' else ''}"
                        ),
                        cwe_id="CWE-693",
                        cwe_name="Protection Mechanism Failure",
                        url=url,
                        evidence=f"CSP header contains: {unsafe}",
                        remediation=(
                            f"Remove '{unsafe}' from CSP and use nonce or hash-based "
                            "approaches for inline scripts and styles."
                        ),
                        cvss_score=6.1 if unsafe == "unsafe-eval" else 5.3,
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                        ],
                    )
                )

        for directive in self.CSP_REQUIRED_DIRECTIVES:
            if directive not in csp.lower():
                findings.append(
                    self._create_finding(
                        severity=Severity.LOW,
                        title=f"CSP Missing Recommended Directive: {directive}",
                        description=(
                            f"The CSP is missing the '{directive}' directive. "
                            "This may leave some attack vectors unprotected."
                        ),
                        cwe_id="CWE-693",
                        cwe_name="Protection Mechanism Failure",
                        url=url,
                        evidence=f"CSP missing: {directive}",
                        remediation=f"Add '{directive}' directive to Content-Security-Policy.",
                        cvss_score=3.1,
                    )
                )

        return findings

    def _check_hsts(self, url: str, headers: dict[str, str]) -> list[Finding]:
        """Check Strict-Transport-Security header."""
        findings: list[Finding] = []

        if not url.startswith("https://"):
            return findings

        hsts = headers.get("strict-transport-security", "")

        if not hsts:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="Missing Strict-Transport-Security Header",
                    description=(
                        "HSTS header is not set. Without HSTS, browsers may connect "
                        "over HTTP first, allowing downgrade attacks and man-in-the-middle attacks."
                    ),
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    url=url,
                    evidence="Strict-Transport-Security header not present",
                    remediation=(
                        "Add HSTS header with minimum 1 year max-age: "
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    ),
                    cvss_score=7.4,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                        "https://hstspreload.org/",
                    ],
                )
            )
            return findings

        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < self.HSTS_MIN_AGE:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="HSTS max-age Too Short",
                        description=(
                            f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). "
                            f"Minimum recommended is {self.HSTS_MIN_AGE} seconds (1 year) "
                            "to prevent downgrade attacks during the gap period."
                        ),
                        cwe_id="CWE-319",
                        cwe_name="Cleartext Transmission of Sensitive Information",
                        url=url,
                        evidence=f"HSTS max-age={max_age}",
                        remediation=f"Increase max-age to at least {self.HSTS_MIN_AGE} seconds.",
                        cvss_score=5.3,
                    )
                )

        if "includesubdomains" not in hsts.lower():
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="HSTS Missing includeSubDomains",
                    description=(
                        "HSTS header does not include 'includeSubDomains' directive. "
                        "Subdomains may be vulnerable to downgrade attacks."
                    ),
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    url=url,
                    evidence=f"HSTS header: {hsts}",
                    remediation="Add 'includeSubDomains' to HSTS header.",
                    cvss_score=3.7,
                )
            )

        return findings

    def _check_x_frame_options(self, url: str, headers: dict[str, str]) -> list[Finding]:
        """Check X-Frame-Options header."""
        findings: list[Finding] = []
        xfo = headers.get("x-frame-options", "")

        if not xfo:
            csp = headers.get("content-security-policy", "")
            if "frame-ancestors" not in csp.lower():
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="Missing Clickjacking Protection",
                        description=(
                            "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                            "The page may be vulnerable to clickjacking attacks."
                        ),
                        cwe_id="CWE-1021",
                        cwe_name="Improper Restriction of Rendered UI Layers or Frames",
                        url=url,
                        evidence="No X-Frame-Options or CSP frame-ancestors",
                        remediation=(
                            "Set X-Frame-Options: DENY or SAMEORIGIN, or use "
                            "CSP frame-ancestors directive."
                        ),
                        cvss_score=4.3,
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                        ],
                    )
                )
        elif xfo.upper() not in ["DENY", "SAMEORIGIN"]:
            if not xfo.upper().startswith("ALLOW-FROM"):
                findings.append(
                    self._create_finding(
                        severity=Severity.LOW,
                        title="Invalid X-Frame-Options Value",
                        description=f"X-Frame-Options has invalid value: {xfo}",
                        cwe_id="CWE-1021",
                        cwe_name="Improper Restriction of Rendered UI Layers or Frames",
                        url=url,
                        evidence=f"X-Frame-Options: {xfo}",
                        remediation="Use DENY or SAMEORIGIN for X-Frame-Options.",
                        cvss_score=3.1,
                    )
                )

        return findings

    def _check_x_content_type_options(self, url: str, headers: dict[str, str]) -> list[Finding]:
        """Check X-Content-Type-Options header."""
        findings: list[Finding] = []
        xcto = headers.get("x-content-type-options", "")

        if xcto.lower() != "nosniff":
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM if not xcto else Severity.LOW,
                    title="Missing or Invalid X-Content-Type-Options",
                    description=(
                        "X-Content-Type-Options is not set to 'nosniff'. "
                        "Browsers may MIME-sniff responses, potentially executing "
                        "malicious content as different types."
                    ),
                    cwe_id="CWE-693",
                    cwe_name="Protection Mechanism Failure",
                    url=url,
                    evidence=f"X-Content-Type-Options: {xcto or 'not set'}",
                    remediation="Set X-Content-Type-Options: nosniff",
                    cvss_score=4.3 if not xcto else 3.1,
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                    ],
                )
            )

        return findings

    def _check_referrer_policy(self, url: str, headers: dict[str, str]) -> list[Finding]:
        """Check Referrer-Policy header."""
        findings: list[Finding] = []
        rp = headers.get("referrer-policy", "")

        if not rp:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Missing Referrer-Policy Header",
                    description=(
                        "Referrer-Policy is not set. URLs may leak to third parties "
                        "through the Referer header, potentially exposing sensitive data."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence="Referrer-Policy header not present",
                    remediation=(
                        "Set Referrer-Policy to a secure value like "
                        "'strict-origin-when-cross-origin' or 'no-referrer'."
                    ),
                    cvss_score=3.1,
                )
            )
        elif rp.lower() == "unsafe-url":
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Insecure Referrer-Policy: unsafe-url",
                    description=(
                        "Referrer-Policy is set to 'unsafe-url' which sends the full URL "
                        "including path and query string to all origins."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence="Referrer-Policy: unsafe-url",
                    remediation="Use a more restrictive policy like 'strict-origin-when-cross-origin'.",
                    cvss_score=4.3,
                )
            )

        return findings

    def _check_permissions_policy(self, url: str, headers: dict[str, str]) -> list[Finding]:
        """Check Permissions-Policy (formerly Feature-Policy) header."""
        findings: list[Finding] = []
        pp = headers.get("permissions-policy", headers.get("feature-policy", ""))

        if not pp:
            findings.append(
                self._create_finding(
                    severity=Severity.INFO,
                    title="Missing Permissions-Policy Header",
                    description=(
                        "Permissions-Policy is not set. Consider restricting browser features "
                        "like camera, microphone, and geolocation to prevent unauthorized access."
                    ),
                    cwe_id="CWE-693",
                    cwe_name="Protection Mechanism Failure",
                    url=url,
                    evidence="Permissions-Policy header not present",
                    remediation=(
                        "Add Permissions-Policy header to restrict sensitive features: "
                        "Permissions-Policy: camera=(), microphone=(), geolocation=()"
                    ),
                    cvss_score=0.0,
                )
            )

        return findings

    def _check_cache_control(self, url: str, headers: dict[str, str]) -> list[Finding]:
        """Check Cache-Control header for sensitive pages."""
        findings: list[Finding] = []
        cc = headers.get("cache-control", "")

        # Use path segment matching to avoid false positives like /docs/login-guide
        is_sensitive = self._is_sensitive_endpoint(url)

        # Also check content-type - only flag HTML/JSON responses for sensitive endpoints
        content_type = headers.get("content-type", "").lower()
        is_cacheable_response = (
            "text/html" in content_type
            or "application/json" in content_type
            or "application/xml" in content_type
            or not content_type  # Unknown content type - be cautious
        )

        if is_sensitive and is_cacheable_response and "no-store" not in cc.lower():
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Sensitive Page Missing Cache-Control: no-store",
                    description=(
                        "A potentially sensitive page does not have 'no-store' in Cache-Control. "
                        "Sensitive data may be cached by browsers or proxies."
                    ),
                    cwe_id="CWE-525",
                    cwe_name="Use of Web Browser Cache Containing Sensitive Information",
                    url=url,
                    evidence=f"Cache-Control: {cc or 'not set'}",
                    remediation="Set Cache-Control: no-store, no-cache, must-revalidate",
                    cvss_score=4.3,
                )
            )

        return findings

    def _is_sensitive_endpoint(self, url: str) -> bool:
        """
        Determine if URL represents a sensitive endpoint using path segment matching.

        This avoids false positives where sensitive keywords appear in non-sensitive contexts,
        e.g., /docs/login-guide should NOT match, but /login should.
        """
        parsed = urllib.parse.urlparse(url.lower())
        path = parsed.path.strip("/")

        # Split path into segments
        segments = [seg for seg in path.split("/") if seg]

        # Check if any segment matches a sensitive path segment
        for segment in segments:
            if segment in self.SENSITIVE_PATH_SEGMENTS:
                return True

        # Check for compound sensitive paths (e.g., api/auth)
        for i in range(len(segments) - 1):
            compound = f"{segments[i]}/{segments[i + 1]}"
            if compound in self.SENSITIVE_PATH_SEGMENTS:
                return True

        return False

    def _assess_csp_severity(
        self,
        url: str,
        headers: dict[str, str],
        page_data: dict[str, Any] | None = None,
    ) -> tuple[Severity, float, str]:
        """
        Assess appropriate severity for missing CSP based on page context.

        Returns (severity, cvss_score, notes).
        """
        content_type = headers.get("content-type", "").lower()

        # Non-HTML responses have lower XSS risk
        if content_type and "text/html" not in content_type:
            return (
                Severity.INFO,
                0.0,
                "Non-HTML response type reduces XSS risk.",
            )

        # Check page content for indicators of XSS risk
        if page_data:
            html_content = page_data.get("html", "")
            forms = page_data.get("forms", [])
            scripts = page_data.get("scripts", [])

            # Low risk indicators: static page with no scripts/forms/user input
            has_inline_scripts = bool(re.search(r"<script[^>]*>", html_content, re.IGNORECASE))
            has_forms = bool(forms) if isinstance(forms, list) else bool(re.search(r"<form", html_content, re.IGNORECASE))
            has_external_scripts = bool(scripts)

            # Check for user input reflection indicators
            has_user_input = bool(re.search(
                r"(?:search|query|q|keyword|term|input|user)=",
                url,
                re.IGNORECASE,
            ))

            if not has_inline_scripts and not has_forms and not has_external_scripts and not has_user_input:
                return (
                    Severity.INFO,
                    2.0,
                    "Static page with no inline scripts or forms has lower XSS risk. "
                    "Consider implementing CSP as defense-in-depth.",
                )

            # Check for alternative protections
            x_xss_protection = headers.get("x-xss-protection", "")
            has_xss_filter = "1" in x_xss_protection and "mode=block" in x_xss_protection.lower()

            if has_xss_filter and not has_inline_scripts:
                return (
                    Severity.MEDIUM,
                    5.0,
                    "X-XSS-Protection provides partial mitigation but is deprecated. "
                    "CSP provides more comprehensive protection.",
                )

        # Default: dynamic page with potential XSS vectors - HIGH severity
        return (Severity.HIGH, 7.1, "")

    def _check_server_header(self, url: str, headers: dict[str, str]) -> list[Finding]:
        """Check for version disclosure in Server header."""
        findings: list[Finding] = []
        server = headers.get("server", "")

        if server:
            version_pattern = r"[\d]+\.[\d]+(?:\.[\d]+)?"
            if re.search(version_pattern, server):
                findings.append(
                    self._create_finding(
                        severity=Severity.LOW,
                        title="Server Version Disclosure",
                        description=(
                            f"The Server header discloses version information: {server}. "
                            "This helps attackers identify known vulnerabilities."
                        ),
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information",
                        url=url,
                        evidence=f"Server: {server}",
                        remediation="Configure web server to hide version information.",
                        cvss_score=2.1,
                    )
                )

        return findings

    def _check_x_powered_by(self, url: str, headers: dict[str, str]) -> list[Finding]:
        """Check for X-Powered-By header disclosure."""
        findings: list[Finding] = []
        xpb = headers.get("x-powered-by", "")

        if xpb:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Technology Disclosure via X-Powered-By",
                    description=(
                        f"The X-Powered-By header reveals: {xpb}. "
                        "This information aids attackers in crafting targeted exploits."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence=f"X-Powered-By: {xpb}",
                    remediation="Remove X-Powered-By header in web server configuration.",
                    cvss_score=2.1,
                )
            )

        return findings
