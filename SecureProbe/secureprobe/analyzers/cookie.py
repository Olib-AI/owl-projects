"""
Cookie Security Analyzer.

Analyzes cookies for security attributes including Secure, HttpOnly,
SameSite, and entropy analysis for session tokens.
"""

from __future__ import annotations

import re
from typing import Any

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity
from secureprobe.utils import calculate_entropy, parse_cookie_header


class CookieAnalyzer(BaseAnalyzer):
    """
    Analyzer for cookie security attributes.

    Checks for:
    - Missing Secure flag on HTTPS sites
    - Missing HttpOnly flag on sensitive cookies
    - SameSite attribute configuration
    - Session token entropy (minimum 4.0 bits/char)
    - Cookie prefixes (__Secure-, __Host-)
    - Excessive cookie scope
    """

    analyzer_type = AnalyzerType.COOKIE

    MIN_ENTROPY = 4.0

    # High-confidence session cookie patterns (exact matches or well-known identifiers)
    HIGH_CONFIDENCE_SESSION_PATTERNS = [
        r"^phpsessid$",
        r"^jsessionid$",
        r"^asp\.net_sessionid$",
        r"^aspsessionid",
        r"^connect\.sid$",
        r"^session$",
        r"^sessionid$",
        r"^session[_-]?id$",
        r"^session[_-]?token$",
        r"^auth[_-]?token$",
        r"^access[_-]?token$",
        r"^refresh[_-]?token$",
        r"^bearer[_-]?token$",
        r"^jwt$",
        r"^id[_-]?token$",
    ]

    # Lower-confidence patterns that suggest session-related cookies
    SESSION_COOKIE_PATTERNS = [
        r"\bsess\b",
        r"\bsession\b",
        r"\bsid\b",
        r"[_-]token$",
        r"^token[_-]",
        r"\bauth\b",
        r"\bjwt\b",
        r"\baccess[_-]?token\b",
        r"\brefresh[_-]?token\b",
        r"\bcsrf\b",
        r"\bxsrf\b",
        r"[_-]session$",
        r"^session[_-]",
    ]

    SENSITIVE_COOKIE_PATTERNS = [
        r"\bsess\b",
        r"\bsession\b",
        r"\bsid\b",
        r"[_-]token$",
        r"^token[_-]",
        r"\bauth\b",
        r"\bjwt\b",
        r"\bremember\b",
        r"\bcredential\b",
        r"\bsecret\b",
        r"\bpassword\b",
        r"\badmin[_-]?(?:token|key|auth)\b",
        r"\bapi[_-]?(?:token|key|auth|secret)\b",
        r"\baccess[_-]?token\b",
        r"\brefresh[_-]?token\b",
    ]

    # Cookies that should be excluded from security analysis (analytics, tracking, etc.)
    ANALYTICS_TRACKING_PATTERNS = [
        r"^_ga$",
        r"^_gid$",
        r"^_gat",
        r"^_gcl_",
        r"^_fbp$",
        r"^_fbc$",
        r"^amplitude_",
        r"^_vis_opt_",
        r"^_vwo_",
        r"^optimizely",
        r"^_hjid$",
        r"^_hjSession",
        r"^intercom",
        r"^hubspot",
        r"^_pk_",
        r"^mp_",
        r"^mixpanel",
        r"^__utm",
        r"^_clck$",
        r"^_clsk$",
        r"^ajs_",
        r"^segment_",
    ]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze cookies for security issues."""
        findings: list[Finding] = []
        cookies = page_data.get("cookies", [])
        headers = page_data.get("headers", {})
        is_https = url.startswith("https://")

        if not cookies and not headers:
            return findings

        if isinstance(cookies, list) and cookies:
            for cookie in cookies:
                if isinstance(cookie, dict):
                    findings.extend(self._analyze_cookie(url, cookie, is_https))

        set_cookie_headers = []
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                if isinstance(value, list):
                    set_cookie_headers.extend(value)
                else:
                    set_cookie_headers.append(value)

        for header in set_cookie_headers:
            parsed = parse_cookie_header(header)
            if parsed.get("name"):
                findings.extend(self._analyze_cookie(url, parsed, is_https))

        return findings

    def _analyze_cookie(
        self,
        url: str,
        cookie: dict[str, Any],
        is_https: bool,
    ) -> list[Finding]:
        """Analyze individual cookie for security issues."""
        findings: list[Finding] = []

        name = cookie.get("name", "")
        value = cookie.get("value", "")
        secure = cookie.get("secure", False)
        httponly = cookie.get("httponly", cookie.get("http_only", False))
        samesite = cookie.get("samesite", cookie.get("same_site", "")).lower()
        domain = cookie.get("domain", "")
        path = cookie.get("path", "/")

        if not name:
            return findings

        # Skip analytics and tracking cookies - they are not security-sensitive
        if self._is_analytics_tracking_cookie(name):
            return findings

        session_confidence = self._get_session_cookie_confidence(name)
        is_session_cookie = session_confidence in ("high", "medium")
        is_high_confidence_session = session_confidence == "high"
        is_sensitive = self._is_sensitive_cookie(name)

        if is_https and not secure:
            if is_sensitive:
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Sensitive Cookie Missing Secure Flag: {name}",
                        description=(
                            f"Cookie '{name}' is potentially sensitive but lacks the Secure flag. "
                            "It may be transmitted over unencrypted HTTP connections."
                        ),
                        cwe_id="CWE-614",
                        cwe_name="Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                        url=url,
                        evidence=f"Cookie: {name}; Secure=False",
                        remediation=f"Set the Secure flag on cookie '{name}'.",
                        cvss_score=6.5,
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
                        ],
                    )
                )
            else:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Cookie Missing Secure Flag: {name}",
                        description=(
                            f"Cookie '{name}' lacks the Secure flag on an HTTPS site. "
                            "Consider adding Secure to prevent transmission over HTTP."
                        ),
                        cwe_id="CWE-614",
                        cwe_name="Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                        url=url,
                        evidence=f"Cookie: {name}; Secure=False",
                        remediation=f"Set the Secure flag on cookie '{name}'.",
                        cvss_score=4.3,
                    )
                )

        if not httponly:
            if is_session_cookie:
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Session Cookie Missing HttpOnly: {name}",
                        description=(
                            f"Session cookie '{name}' lacks HttpOnly flag. "
                            "It can be accessed by JavaScript, enabling XSS-based session theft."
                        ),
                        cwe_id="CWE-1004",
                        cwe_name="Sensitive Cookie Without 'HttpOnly' Flag",
                        url=url,
                        evidence=f"Cookie: {name}; HttpOnly=False",
                        remediation=f"Set the HttpOnly flag on session cookie '{name}'.",
                        cvss_score=6.1,
                        references=[
                            "https://owasp.org/www-community/HttpOnly",
                        ],
                    )
                )
            elif is_sensitive:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Sensitive Cookie Missing HttpOnly: {name}",
                        description=(
                            f"Cookie '{name}' appears sensitive but lacks HttpOnly flag. "
                            "JavaScript code can access this cookie."
                        ),
                        cwe_id="CWE-1004",
                        cwe_name="Sensitive Cookie Without 'HttpOnly' Flag",
                        url=url,
                        evidence=f"Cookie: {name}; HttpOnly=False",
                        remediation=f"Set the HttpOnly flag on cookie '{name}'.",
                        cvss_score=4.3,
                    )
                )

        if samesite == "none":
            if not secure and is_https:
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"SameSite=None Without Secure: {name}",
                        description=(
                            f"Cookie '{name}' has SameSite=None but no Secure flag. "
                            "Modern browsers will reject this cookie."
                        ),
                        cwe_id="CWE-1275",
                        cwe_name="Sensitive Cookie with Improper SameSite Attribute",
                        url=url,
                        evidence=f"Cookie: {name}; SameSite=None; Secure=False",
                        remediation="Add Secure flag when using SameSite=None.",
                        cvss_score=5.3,
                    )
                )
            elif is_sensitive:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Sensitive Cookie with SameSite=None: {name}",
                        description=(
                            f"Cookie '{name}' has SameSite=None, allowing cross-site requests. "
                            "This may be vulnerable to CSRF attacks if not protected otherwise."
                        ),
                        cwe_id="CWE-1275",
                        cwe_name="Sensitive Cookie with Improper SameSite Attribute",
                        url=url,
                        evidence=f"Cookie: {name}; SameSite=None",
                        remediation="Consider using SameSite=Strict or SameSite=Lax.",
                        cvss_score=4.3,
                    )
                )
        elif not samesite and is_sensitive:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title=f"Cookie Missing SameSite Attribute: {name}",
                    description=(
                        f"Cookie '{name}' does not have an explicit SameSite attribute. "
                        "Modern browsers default to Lax, but explicit setting is recommended."
                    ),
                    cwe_id="CWE-1275",
                    cwe_name="Sensitive Cookie with Improper SameSite Attribute",
                    url=url,
                    evidence=f"Cookie: {name}; SameSite=not set",
                    remediation="Explicitly set SameSite=Strict or SameSite=Lax.",
                    cvss_score=3.1,
                )
            )

        # Only apply entropy check to HIGH confidence session cookies to reduce false positives
        if is_high_confidence_session and value:
            entropy = calculate_entropy(value)
            if entropy < self.MIN_ENTROPY:
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Low Entropy Session Token: {name}",
                        description=(
                            f"Session cookie '{name}' has low entropy ({entropy:.2f} bits/char). "
                            f"Minimum recommended is {self.MIN_ENTROPY} bits/char. "
                            "Low entropy tokens are vulnerable to brute-force attacks."
                        ),
                        cwe_id="CWE-331",
                        cwe_name="Insufficient Entropy",
                        url=url,
                        evidence=f"Cookie: {name}; Entropy={entropy:.2f} bits/char",
                        remediation=(
                            "Use cryptographically secure random number generator "
                            "for session tokens with at least 128 bits of entropy."
                        ),
                        cvss_score=7.5,
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length",
                        ],
                        metadata={"entropy": entropy},
                    )
                )

        if name.startswith("__Secure-"):
            if not secure:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"__Secure- Prefix Without Secure Flag: {name}",
                        description=(
                            f"Cookie '{name}' uses __Secure- prefix but lacks Secure flag. "
                            "Browsers may reject this cookie."
                        ),
                        cwe_id="CWE-614",
                        cwe_name="Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                        url=url,
                        evidence=f"Cookie: {name}; Secure=False",
                        remediation="Add Secure flag for __Secure- prefixed cookies.",
                        cvss_score=4.3,
                    )
                )

        if name.startswith("__Host-"):
            issues = []
            if not secure:
                issues.append("missing Secure flag")
            if domain:
                issues.append(f"has Domain attribute ({domain})")
            if path != "/":
                issues.append(f"Path is not '/' ({path})")

            if issues:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Invalid __Host- Cookie Configuration: {name}",
                        description=(
                            f"Cookie '{name}' uses __Host- prefix but: {', '.join(issues)}. "
                            "Browsers may reject this cookie."
                        ),
                        cwe_id="CWE-614",
                        cwe_name="Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                        url=url,
                        evidence=f"Cookie: {name}; Issues: {', '.join(issues)}",
                        remediation=(
                            "__Host- cookies must have Secure flag, "
                            "no Domain attribute, and Path=/"
                        ),
                        cvss_score=4.3,
                    )
                )

        if domain and domain.startswith("."):
            if is_session_cookie:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Session Cookie with Wide Domain Scope: {name}",
                        description=(
                            f"Session cookie '{name}' is scoped to '{domain}', "
                            "making it accessible to all subdomains. "
                            "A compromised subdomain could steal sessions."
                        ),
                        cwe_id="CWE-1275",
                        cwe_name="Sensitive Cookie with Improper SameSite Attribute",
                        url=url,
                        evidence=f"Cookie: {name}; Domain={domain}",
                        remediation=(
                            "Scope session cookies to specific subdomain "
                            "or use __Host- prefix."
                        ),
                        cvss_score=4.7,
                    )
                )

        return findings

    def _is_analytics_tracking_cookie(self, name: str) -> bool:
        """Check if cookie is a known analytics or tracking cookie."""
        name_lower = name.lower()
        for pattern in self.ANALYTICS_TRACKING_PATTERNS:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return True
        return False

    def _get_session_cookie_confidence(self, name: str) -> str:
        """
        Determine confidence level that a cookie is a session cookie.

        Returns:
            'high': Well-known session cookie identifiers (JSESSIONID, PHPSESSID, etc.)
            'medium': Likely session cookies based on naming patterns
            'low': Not detected as a session cookie
        """
        name_lower = name.lower()

        # Check high-confidence patterns first (exact matches for well-known identifiers)
        for pattern in self.HIGH_CONFIDENCE_SESSION_PATTERNS:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return "high"

        # Check medium-confidence patterns (word-boundary aware)
        for pattern in self.SESSION_COOKIE_PATTERNS:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return "medium"

        return "low"

    def _is_session_cookie(self, name: str) -> bool:
        """Check if cookie name suggests a session cookie."""
        return self._get_session_cookie_confidence(name) in ("high", "medium")

    def _is_sensitive_cookie(self, name: str) -> bool:
        """Check if cookie name suggests sensitive data."""
        name_lower = name.lower()
        for pattern in self.SENSITIVE_COOKIE_PATTERNS:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return True
        return False
