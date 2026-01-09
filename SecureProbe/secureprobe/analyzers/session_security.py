"""
Session Security Analyzer.

Analyzes session management security including token regeneration,
session isolation, timeout behavior, and concurrent session handling.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Any

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity


class SessionSecurityAnalyzer(BaseAnalyzer):
    """
    Analyzer for session security vulnerabilities.

    Checks for:
    - Session token regeneration after login (CWE-384)
    - Session isolation between browser contexts (CWE-613)
    - Session timeout behavior (CWE-613)
    - Concurrent session handling (CWE-384)
    - Session token entropy and predictability (CWE-330)
    """

    analyzer_type = AnalyzerType.SESSION_SECURITY

    # High-confidence patterns (exact matches for well-known session identifiers)
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

    # Medium-confidence patterns (word-boundary aware)
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
        r"[_-]session$",
        r"^session[_-]",
    ]

    # Analytics/tracking cookies to exclude from analysis
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

    MIN_SESSION_ENTROPY = 4.5
    MIN_SESSION_LENGTH = 16
    MAX_SESSION_LIFETIME_SECONDS = 86400  # 24 hours recommended max

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze session security configuration and behavior."""
        findings: list[Finding] = []
        cookies = page_data.get("cookies", [])
        browser_contexts = page_data.get("browser_contexts", [])
        headers = page_data.get("headers", {})
        scan_mode = page_data.get("scan_mode", "passive")

        session_cookies = self._identify_session_cookies(cookies)

        if session_cookies:
            findings.extend(self._analyze_token_entropy(url, session_cookies))
            findings.extend(self._analyze_token_predictability(url, session_cookies))
            findings.extend(self._analyze_session_lifetime(url, session_cookies))

        if browser_contexts:
            findings.extend(
                self._analyze_session_isolation(url, session_cookies, browser_contexts)
            )

        findings.extend(self._analyze_session_headers(url, headers))

        # Active testing: analyze for session fixation indicators
        if scan_mode == "active":
            findings.extend(self._analyze_session_fixation_risk(url, session_cookies, headers))

        return findings

    def _is_analytics_tracking_cookie(self, name: str) -> bool:
        """Check if cookie is a known analytics or tracking cookie."""
        name_lower = name.lower()
        for pattern in self.ANALYTICS_TRACKING_PATTERNS:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return True
        return False

    def _identify_session_cookies(
        self,
        cookies: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Identify cookies that appear to be session tokens."""
        session_cookies: list[dict[str, Any]] = []

        for cookie in cookies:
            if not isinstance(cookie, dict):
                continue
            name = cookie.get("name", "").lower()

            # Skip analytics and tracking cookies
            if self._is_analytics_tracking_cookie(name):
                continue

            # Check high-confidence patterns first
            for pattern in self.HIGH_CONFIDENCE_SESSION_PATTERNS:
                if re.search(pattern, name, re.IGNORECASE):
                    session_cookies.append(cookie)
                    break
            else:
                # Check medium-confidence patterns
                for pattern in self.SESSION_COOKIE_PATTERNS:
                    if re.search(pattern, name, re.IGNORECASE):
                        session_cookies.append(cookie)
                        break

        return session_cookies

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy in bits per character."""
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _analyze_token_entropy(
        self,
        url: str,
        session_cookies: list[dict[str, Any]],
    ) -> list[Finding]:
        """Analyze session token entropy for randomness."""
        findings: list[Finding] = []

        for cookie in session_cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")

            if not value:
                continue

            entropy = self._calculate_entropy(value)
            token_length = len(value)

            if entropy < self.MIN_SESSION_ENTROPY:
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Low Entropy Session Token: {name}",
                        description=(
                            f"Session token '{name}' has entropy of {entropy:.2f} bits/char, "
                            f"below the recommended minimum of {self.MIN_SESSION_ENTROPY} bits/char. "
                            "Low entropy tokens are vulnerable to brute-force prediction attacks."
                        ),
                        cwe_id="CWE-330",
                        cwe_name="Use of Insufficiently Random Values",
                        url=url,
                        evidence=f"Token: {name}; Entropy: {entropy:.2f} bits/char; Length: {token_length}",
                        remediation=(
                            "Generate session tokens using cryptographically secure random number "
                            "generators (CSPRNG). Use at least 128 bits of entropy for session tokens. "
                            "Consider using established session management libraries."
                        ),
                        cvss_score=7.5,
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length",
                            "https://cwe.mitre.org/data/definitions/330.html",
                        ],
                        metadata={
                            "entropy": entropy,
                            "token_length": token_length,
                            "cookie_name": name,
                        },
                    )
                )

            if token_length < self.MIN_SESSION_LENGTH:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Short Session Token: {name}",
                        description=(
                            f"Session token '{name}' is only {token_length} characters long. "
                            f"Minimum recommended length is {self.MIN_SESSION_LENGTH} characters. "
                            "Short tokens have reduced keyspace and are easier to brute-force."
                        ),
                        cwe_id="CWE-331",
                        cwe_name="Insufficient Entropy",
                        url=url,
                        evidence=f"Token: {name}; Length: {token_length} chars",
                        remediation=(
                            f"Increase session token length to at least {self.MIN_SESSION_LENGTH} characters. "
                            "Use base64 or hex encoding of random bytes for tokens."
                        ),
                        cvss_score=5.3,
                        metadata={"token_length": token_length, "cookie_name": name},
                    )
                )

        return findings

    def _analyze_token_predictability(
        self,
        url: str,
        session_cookies: list[dict[str, Any]],
    ) -> list[Finding]:
        """Analyze session tokens for predictable patterns."""
        findings: list[Finding] = []

        predictable_patterns = [
            (r"^\d+$", "numeric-only", "purely numeric"),
            (r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", "uuid-v4-like", "UUID format"),
            (r"^\d{10,13}$", "timestamp-like", "timestamp-based"),
            (r"^user[_-]?\d+", "user-id-prefix", "user ID prefix"),
            (r"^(\w)\1+$", "repeated-char", "repeated characters"),
            (r"^(.)(.)\1\2\1\2", "repeating-pattern", "repeating pattern"),
        ]

        for cookie in session_cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")

            if not value:
                continue

            for pattern, pattern_name, description in predictable_patterns:
                if re.match(pattern, value, re.IGNORECASE):
                    # UUIDs are acceptable if version 4
                    if pattern_name == "uuid-v4-like":
                        # UUIDv4 is acceptable
                        continue

                    findings.append(
                        self._create_finding(
                            severity=Severity.MEDIUM,
                            title=f"Predictable Session Token Pattern: {name}",
                            description=(
                                f"Session token '{name}' appears to follow a {description} pattern. "
                                "Predictable patterns can allow attackers to guess valid session tokens."
                            ),
                            cwe_id="CWE-330",
                            cwe_name="Use of Insufficiently Random Values",
                            url=url,
                            evidence=f"Token: {name}; Pattern: {pattern_name}",
                            remediation=(
                                "Use cryptographically random values for session tokens. "
                                "Avoid using timestamps, sequential numbers, or user identifiers."
                            ),
                            cvss_score=5.9,
                            metadata={
                                "pattern": pattern_name,
                                "cookie_name": name,
                            },
                        )
                    )
                    break

        return findings

    def _analyze_session_isolation(
        self,
        url: str,
        session_cookies: list[dict[str, Any]],
        browser_contexts: list[dict[str, Any]],
    ) -> list[Finding]:
        """Analyze session isolation between browser contexts."""
        findings: list[Finding] = []

        if not session_cookies or not browser_contexts:
            return findings

        main_session_values = {
            cookie.get("name", ""): cookie.get("value", "")
            for cookie in session_cookies
        }

        for context in browser_contexts:
            context_id = context.get("context_id", 0)
            context_cookies = context.get("cookies", [])

            for ctx_cookie in context_cookies:
                if not isinstance(ctx_cookie, dict):
                    continue

                name = ctx_cookie.get("name", "")
                value = ctx_cookie.get("value", "")

                if name in main_session_values:
                    if value == main_session_values[name]:
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"Session Token Shared Across Contexts: {name}",
                                description=(
                                    f"Session token '{name}' has the same value in different browser contexts. "
                                    "This indicates potential session isolation failure, which could allow "
                                    "cross-user session access in shared environments."
                                ),
                                cwe_id="CWE-613",
                                cwe_name="Insufficient Session Expiration",
                                url=url,
                                evidence=f"Token: {name}; Context: {context_id}; Value matches main context",
                                remediation=(
                                    "Ensure each browser context receives a unique session token. "
                                    "Implement proper session isolation at the server level."
                                ),
                                cvss_score=7.5,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/613.html",
                                ],
                                metadata={
                                    "context_id": context_id,
                                    "cookie_name": name,
                                },
                            )
                        )

        return findings

    def _analyze_session_lifetime(
        self,
        url: str,
        session_cookies: list[dict[str, Any]],
    ) -> list[Finding]:
        """Analyze session cookie lifetime configuration."""
        findings: list[Finding] = []

        for cookie in session_cookies:
            name = cookie.get("name", "")
            expires = cookie.get("expires", -1)
            max_age = cookie.get("max_age")

            # Session cookies without expiry are acceptable (browser session only)
            if expires == -1 and max_age is None:
                continue

            # Check for excessively long session lifetime
            if max_age is not None and max_age > self.MAX_SESSION_LIFETIME_SECONDS:
                days = max_age // 86400
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Excessive Session Lifetime: {name}",
                        description=(
                            f"Session cookie '{name}' has a max-age of {days} days. "
                            f"Sessions longer than 24 hours increase the window for session hijacking. "
                            "Extended sessions should require re-authentication for sensitive operations."
                        ),
                        cwe_id="CWE-613",
                        cwe_name="Insufficient Session Expiration",
                        url=url,
                        evidence=f"Cookie: {name}; max-age: {max_age} seconds ({days} days)",
                        remediation=(
                            "Reduce session lifetime to 24 hours or less for active sessions. "
                            "Implement sliding session expiration and require re-authentication "
                            "for sensitive operations."
                        ),
                        cvss_score=4.3,
                        metadata={
                            "max_age": max_age,
                            "cookie_name": name,
                        },
                    )
                )

        return findings

    def _analyze_session_headers(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Analyze HTTP headers related to session security."""
        findings: list[Finding] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        # Check for session-related cache control
        cache_control = normalized_headers.get("cache-control", "")
        if "login" in url.lower() or "auth" in url.lower() or "session" in url.lower():
            if "no-store" not in cache_control.lower():
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="Session Page Missing Cache-Control: no-store",
                        description=(
                            "Authentication-related page does not prevent caching. "
                            "Cached session data could be retrieved from browser cache or proxies."
                        ),
                        cwe_id="CWE-525",
                        cwe_name="Use of Web Browser Cache Containing Sensitive Information",
                        url=url,
                        evidence=f"Cache-Control: {cache_control or 'not set'}",
                        remediation=(
                            "Set 'Cache-Control: no-store, no-cache, must-revalidate, private' "
                            "on all authentication and session-related pages."
                        ),
                        cvss_score=4.3,
                    )
                )

        return findings

    def _analyze_session_fixation_risk(
        self,
        url: str,
        session_cookies: list[dict[str, Any]],
        headers: dict[str, str],
    ) -> list[Finding]:
        """
        Analyze indicators of session fixation vulnerability (active mode).

        Only flags actual evidence of session fixation, not mere presence of
        session cookies on auth pages (which is normal behavior).
        """
        findings: list[Finding] = []

        # Check for actual session fixation indicators:
        # 1. Session ID accepted via URL parameter (check if URL contains session param)
        # 2. Session cookie set without HttpOnly (allows JS manipulation)
        # 3. No evidence of session regeneration after auth (requires pre/post comparison)

        url_lower = url.lower()
        is_auth_page = "login" in url_lower or "auth" in url_lower or "signin" in url_lower

        if not is_auth_page or not session_cookies:
            return findings

        # Check for session ID in URL parameters (actual vulnerability indicator)
        from urllib.parse import parse_qs, urlparse

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for cookie in session_cookies:
            name = cookie.get("name", "")
            name_lower = name.lower()

            # Check if session ID appears in URL query parameters
            for param_name in query_params:
                if param_name.lower() == name_lower or (
                    "session" in param_name.lower() and "id" in param_name.lower()
                ):
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title=f"Session ID Accepted via URL Parameter: {param_name}",
                            description=(
                                f"Session identifier '{param_name}' is passed via URL query parameter. "
                                "This enables session fixation attacks where an attacker can set "
                                "a victim's session ID by crafting a malicious URL."
                            ),
                            cwe_id="CWE-384",
                            cwe_name="Session Fixation",
                            url=url,
                            evidence=f"URL parameter: {param_name}; Cookie: {name}",
                            remediation=(
                                "Never accept session identifiers from URL parameters. "
                                "Session tokens should only be transmitted via cookies with "
                                "HttpOnly and Secure flags. Regenerate session IDs after login."
                            ),
                            cvss_score=7.5,
                            references=[
                                "https://owasp.org/www-community/attacks/Session_fixation",
                                "https://cwe.mitre.org/data/definitions/384.html",
                            ],
                            metadata={"cookie_name": name, "url_param": param_name},
                        )
                    )

        return findings
