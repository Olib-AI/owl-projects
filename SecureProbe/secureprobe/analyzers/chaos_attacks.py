"""
Chaos Attacks Analyzer - Unconventional Security Testing.

Implements creative "silly" attack patterns that mimic the random
experimentation a curious teenager might try. These unconventional
approaches often succeed where methodical pentesting fails because
they test edge cases developers never considered.

This module is designed for authorized security testing only.
All tests require explicit scan_mode='active' to execute.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
import structlog
from dotenv import load_dotenv

# Add python-sdk to path for owl_browser imports before loading local modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "python-sdk"))

# Load environment variables
load_dotenv()

# Local imports after path setup and env loading  # noqa: E402
from secureprobe.analyzers.base import BaseAnalyzer  # noqa: E402
from secureprobe.models import AnalyzerType, Finding, Severity  # noqa: E402
from secureprobe.utils import safe_response_text  # noqa: E402

logger = structlog.get_logger(__name__)


def _get_browser_instance() -> Any:
    """
    Create a Browser instance with remote URL configuration if available.

    Loads OWL_BROWSER_URL and OWL_BROWSER_TOKEN from environment.
    Falls back to local browser if no remote configuration is present.

    Returns:
        Configured Browser instance
    """
    from owl_browser import Browser, RemoteConfig

    remote_url = os.getenv("OWL_BROWSER_URL")
    remote_token = os.getenv("OWL_BROWSER_TOKEN")

    if remote_url and remote_token:
        logger.debug(
            "chaos_analyzer_using_remote_browser",
            remote_url=remote_url,
            has_token=bool(remote_token),
        )
        remote_config = RemoteConfig(url=remote_url, token=remote_token)
        return Browser(remote=remote_config)
    else:
        logger.debug("chaos_analyzer_using_local_browser")
        return Browser()


class ChaosAttacksAnalyzer(BaseAnalyzer):
    """
    Analyzer implementing unconventional "chaos" attack patterns.

    These patterns mimic what a curious teenager might randomly try -
    unconventional approaches that often succeed because they test
    edge cases that developers never considered.

    Attack Patterns:
    1. Negative Price Attack - Negative numbers in quantity/price fields
    2. Unicode Confusion - Homograph attacks and zero-width characters
    3. Empty Array Injection - Empty arrays to crash parsers
    4. Self-XSS Escalation - Input reflection in admin-visible areas
    5. Browser Console Secrets - localStorage/sessionStorage inspection
    6. Absurd Input Lengths - Extremely long strings to trigger crashes
    7. HTTP Method Confusion - Wrong HTTP methods on endpoints
    8. Race Condition Spam - Rapid duplicate submissions
    9. Default Credential Check - Common default credentials
    10. URL Parameter Pollution - Hidden admin/debug parameters
    """

    analyzer_type = AnalyzerType.CHAOS_ATTACKS

    # Unicode lookalike characters for homograph attacks
    UNICODE_CONFUSABLES: dict[str, str] = {
        "a": "\u0430",  # Cyrillic 'a'
        "e": "\u0435",  # Cyrillic 'e'
        "o": "\u043e",  # Cyrillic 'o'
        "p": "\u0440",  # Cyrillic 'r' (looks like p)
        "c": "\u0441",  # Cyrillic 'c'
        "x": "\u0445",  # Cyrillic 'x'
        "i": "\u0456",  # Cyrillic 'i'
    }

    # Zero-width characters that might bypass uniqueness checks
    ZERO_WIDTH_CHARS: list[str] = [
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "\ufeff",  # Zero-width no-break space (BOM)
        "\u2060",  # Word joiner
    ]

    # Default credentials to test
    DEFAULT_CREDENTIALS: list[tuple[str, str]] = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("root", "root"),
        ("root", "password"),
        ("test", "test"),
        ("user", "user"),
        ("demo", "demo"),
        ("guest", "guest"),
        ("administrator", "administrator"),
        ("admin", ""),
        ("", ""),
    ]

    # Hidden URL parameters that might enable debug/admin features
    DEBUG_PARAMETERS: list[tuple[str, str]] = [
        ("admin", "true"),
        ("admin", "1"),
        ("debug", "true"),
        ("debug", "1"),
        ("test", "true"),
        ("internal", "1"),
        ("dev", "true"),
        ("role", "admin"),
        ("is_admin", "true"),
        ("superuser", "1"),
        ("bypass", "true"),
        ("skip_auth", "1"),
        ("mode", "debug"),
        ("env", "development"),
        ("_debug", "1"),
        ("__debug__", "true"),
    ]

    # HTTP methods to try on endpoints
    UNEXPECTED_METHODS: list[str] = [
        "DELETE",
        "PUT",
        "PATCH",
        "OPTIONS",
        "TRACE",
        "CONNECT",
    ]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Execute chaos attack patterns against the target.

        Args:
            url: Target URL
            page_data: Page data including HTML, forms, headers

        Returns:
            List of discovered findings
        """
        findings: list[Finding] = []
        scan_mode = page_data.get("scan_mode", "passive")

        # Chaos attacks are active-only - they involve sending payloads
        if scan_mode != "active":
            logger.debug(
                "chaos_attacks_skipped",
                reason="passive mode - chaos attacks require active mode",
            )
            return findings

        html_content = page_data.get("html", "")
        forms = page_data.get("forms", [])
        headers = page_data.get("headers", {})
        scripts = page_data.get("scripts", [])

        # Execute all chaos attack patterns (original 10)
        findings.extend(await self._attack_negative_price(url, forms))
        findings.extend(await self._attack_unicode_confusion(url, forms))
        findings.extend(await self._attack_empty_array_injection(url, forms))
        findings.extend(self._attack_self_xss_escalation(url, html_content, forms))
        findings.extend(await self._attack_browser_console_secrets(url))
        findings.extend(await self._attack_absurd_input_lengths(url, forms))
        findings.extend(await self._attack_http_method_confusion(url))
        findings.extend(await self._attack_race_condition_spam(url, forms))
        findings.extend(await self._attack_default_credentials(url, forms))
        findings.extend(await self._attack_url_parameter_pollution(url, html_content))

        # Execute new chaos attack patterns (15 more)
        # Konami-Style Pattern Attacks
        findings.extend(await self._attack_rapid_key_sequence(url))
        findings.extend(await self._attack_button_mash(url, forms))
        findings.extend(await self._attack_tab_order_exploitation(url, forms))

        # Overwhelm Logic Attacks
        findings.extend(await self._attack_login_bruteforce_lockout(url, forms))
        findings.extend(await self._attack_session_flood(url))
        findings.extend(await self._attack_form_resubmission_storm(url, forms))
        findings.extend(await self._attack_infinite_redirect_loop(url))
        findings.extend(await self._attack_memory_exhaustion_nested_json(url))

        # Novel Zero-Day Style Patterns
        findings.extend(await self._attack_timing_oracle(url, forms))
        findings.extend(await self._attack_clipboard_hijacking_check(url, html_content, scripts))
        findings.extend(self._attack_browser_history_sniffing(url, html_content))
        findings.extend(self._attack_autofill_harvesting(url, html_content, forms))
        findings.extend(await self._attack_serviceworker_persistence(url))
        findings.extend(self._attack_postmessage_origin_bypass(url, html_content, scripts))
        findings.extend(self._attack_drag_drop_data_exfil(url, html_content, scripts))

        return findings

    async def _attack_negative_price(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 1: Negative Price Attack.

        Many applications don't validate that quantities and prices are positive.
        Submitting negative values can result in refunds, free items, or credits.

        CWE-20: Improper Input Validation
        """
        findings: list[Finding] = []

        # Look for forms with price/quantity-like fields
        price_field_patterns = [
            r"price",
            r"quantity",
            r"qty",
            r"amount",
            r"total",
            r"cost",
            r"count",
            r"num",
            r"units",
        ]

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", form.get("action", "unknown"))
            form_action = form.get("action", url)
            inputs = form.get("inputs", [])

            vulnerable_fields: list[str] = []

            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue

                name = input_field.get("name", "").lower()
                input_type = input_field.get("type", "").lower()

                # Check if this looks like a numeric field
                if input_type in ["number", "text", "hidden", ""]:
                    for pattern in price_field_patterns:
                        if re.search(pattern, name, re.IGNORECASE):
                            vulnerable_fields.append(name)
                            break

            if vulnerable_fields:
                # Attempt to submit negative values
                try:
                    test_payload: dict[str, str] = {}
                    for field in vulnerable_fields:
                        test_payload[field] = "-1"

                    async with httpx.AsyncClient(
                        timeout=10.0,
                        verify=self.config.verify_ssl,
                        follow_redirects=True,
                    ) as client:
                        response = await client.post(
                            form_action,
                            data=test_payload,
                            headers={"User-Agent": self.config.user_agent},
                        )

                        # Check for indicators of success (no validation error)
                        error_indicators = [
                            "invalid",
                            "error",
                            "negative",
                            "must be positive",
                            "cannot be less than",
                            "must be greater than 0",
                        ]

                        response_lower = safe_response_text(response).lower()
                        has_error = any(ind in response_lower for ind in error_indicators)

                        if response.status_code in [200, 201, 302] and not has_error:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.HIGH,
                                    title=f"Negative Value Accepted: {', '.join(vulnerable_fields)}",
                                    description=(
                                        f"Form '{form_id}' accepts negative values in numeric fields: "
                                        f"{', '.join(vulnerable_fields)}. This could allow price manipulation, "
                                        "inventory fraud, or credit balance abuse."
                                    ),
                                    cwe_id="CWE-20",
                                    cwe_name="Improper Input Validation",
                                    url=form_action,
                                    evidence=f"Submitted {test_payload}; Status: {response.status_code}",
                                    remediation=(
                                        "Validate all numeric inputs server-side. Ensure quantities, "
                                        "prices, and amounts are positive. Use unsigned integer types "
                                        "where appropriate. Never trust client-side validation alone."
                                    ),
                                    cvss_score=8.6,
                                    references=[
                                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation",
                                    ],
                                    metadata={
                                        "form_id": form_id,
                                        "vulnerable_fields": vulnerable_fields,
                                        "test_payload": test_payload,
                                    },
                                )
                            )

                except Exception as e:
                    logger.debug("negative_price_test_error", error=str(e))

        return findings

    async def _attack_unicode_confusion(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 2: Unicode Confusion (Homograph Attack).

        Use lookalike Unicode characters to bypass unique username checks.
        "admin" with Cyrillic 'a' looks identical but is a different string.

        CWE-176: Improper Handling of Unicode Encoding
        """
        findings: list[Finding] = []

        # Look for registration/signup forms with username fields
        username_patterns = [
            r"user",
            r"name",
            r"login",
            r"email",
            r"account",
            r"handle",
        ]

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", form.get("action", "unknown"))
            form_action = form.get("action", url)
            inputs = form.get("inputs", [])

            # Check if this might be a registration form
            is_registration = any(
                kw in form_action.lower()
                for kw in ["register", "signup", "sign-up", "create", "join"]
            )

            if not is_registration:
                form_id_str = str(form_id) if form_id else ""
                is_registration = any(
                    kw in form_id_str.lower()
                    for kw in ["register", "signup", "sign-up", "create", "join"]
                )

            if not is_registration:
                continue

            username_field = None
            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue

                name = input_field.get("name", "").lower()
                for pattern in username_patterns:
                    if re.search(pattern, name, re.IGNORECASE):
                        username_field = input_field.get("name", "")
                        break
                if username_field:
                    break

            if username_field:
                # Test with Unicode confusable username
                confusable_admin = (
                    self.UNICODE_CONFUSABLES["a"] + "dmin"
                )  # Cyrillic 'a' + "dmin"

                try:
                    async with httpx.AsyncClient(
                        timeout=10.0,
                        verify=self.config.verify_ssl,
                        follow_redirects=True,
                    ) as client:
                        # First, check if normal 'admin' is taken (it should be)
                        test_payload = {
                            username_field: confusable_admin,
                            "password": "TestPassword123!",
                            "email": "test@example.com",
                        }

                        response = await client.post(
                            form_action,
                            data=test_payload,
                            headers={"User-Agent": self.config.user_agent},
                        )

                        # Check if the confusable was accepted
                        rejection_indicators = [
                            "already taken",
                            "already exists",
                            "username unavailable",
                            "username in use",
                            "reserved",
                        ]

                        response_lower = safe_response_text(response).lower()
                        was_rejected = any(
                            ind in response_lower for ind in rejection_indicators
                        )

                        if response.status_code in [200, 201, 302] and not was_rejected:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.HIGH,
                                    title="Unicode Homograph Attack Possible",
                                    description=(
                                        f"Registration form '{form_id}' accepts Unicode lookalike characters. "
                                        f"A username like '{confusable_admin}' (using Cyrillic 'a') may be "
                                        "indistinguishable from 'admin' but bypass uniqueness checks. "
                                        "This enables impersonation attacks."
                                    ),
                                    cwe_id="CWE-176",
                                    cwe_name="Improper Handling of Unicode Encoding",
                                    url=form_action,
                                    evidence=f"Submitted confusable username: {confusable_admin!r}",
                                    remediation=(
                                        "Normalize Unicode input using NFKC normalization before storage and comparison. "
                                        "Consider restricting usernames to ASCII characters. "
                                        "Use punycode detection for domain-like inputs."
                                    ),
                                    cvss_score=7.5,
                                    references=[
                                        "https://unicode.org/reports/tr36/",
                                        "https://cwe.mitre.org/data/definitions/176.html",
                                    ],
                                    metadata={
                                        "form_id": form_id,
                                        "username_field": username_field,
                                        "confusable_value": confusable_admin,
                                    },
                                )
                            )

                except Exception as e:
                    logger.debug("unicode_confusion_test_error", error=str(e))

        return findings

    async def _attack_empty_array_injection(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 3: Empty Array Injection.

        Send empty arrays or malformed JSON to endpoints expecting data.
        Many parsers crash or behave unexpectedly with empty collections.

        CWE-20: Improper Input Validation
        """
        findings: list[Finding] = []

        # Try various empty/malformed payloads against the URL
        empty_payloads = [
            ({"items": []}, "empty array"),
            ({"data": {}}, "empty object"),
            ({"values": None}, "null value"),
            ([], "root empty array"),
            ({}, "root empty object"),
        ]

        for payload, payload_desc in empty_payloads:
            try:
                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    response = await client.post(
                        url,
                        json=payload,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/json",
                        },
                    )

                    # Check for server errors indicating crash/unhandled exception
                    if response.status_code >= 500:
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title=f"Server Error on {payload_desc.title()} Input",
                                description=(
                                    f"Server returned {response.status_code} when sent {payload_desc}. "
                                    "This indicates improper handling of edge-case inputs and may "
                                    "reveal internal errors or enable denial of service."
                                ),
                                cwe_id="CWE-20",
                                cwe_name="Improper Input Validation",
                                url=url,
                                evidence=f"Payload: {json.dumps(payload)}; Status: {response.status_code}",
                                remediation=(
                                    "Validate all input arrays and objects for expected structure. "
                                    "Handle empty collections gracefully. Use schema validation "
                                    "(JSON Schema, Pydantic, etc.) for API inputs."
                                ),
                                cvss_score=5.3,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/20.html",
                                ],
                                metadata={
                                    "payload": payload,
                                    "payload_description": payload_desc,
                                    "status_code": response.status_code,
                                },
                            )
                        )
                        break  # Found vulnerability, stop testing this URL

                    # Check for stack traces in response
                    error_patterns = [
                        r"Traceback",
                        r"Exception",
                        r"Error:",
                        r"at line \d+",
                        r"Stack trace",
                    ]

                    for pattern in error_patterns:
                        if re.search(pattern, safe_response_text(response), re.IGNORECASE):
                            findings.append(
                                self._create_finding(
                                    severity=Severity.MEDIUM,
                                    title=f"Error Disclosure on {payload_desc.title()} Input",
                                    description=(
                                        f"Server disclosed error details when sent {payload_desc}. "
                                        "Error messages may reveal internal structure and aid attackers."
                                    ),
                                    cwe_id="CWE-209",
                                    cwe_name="Generation of Error Message Containing Sensitive Information",
                                    url=url,
                                    evidence=f"Payload: {json.dumps(payload)}; Error pattern: {pattern}",
                                    remediation=(
                                        "Implement proper error handling that logs details server-side "
                                        "but returns generic messages to clients. Validate inputs before processing."
                                    ),
                                    cvss_score=5.3,
                                    metadata={
                                        "payload": payload,
                                        "error_pattern": pattern,
                                    },
                                )
                            )
                            break

            except Exception as e:
                logger.debug("empty_array_test_error", error=str(e))

        return findings

    def _attack_self_xss_escalation(
        self,
        url: str,
        html_content: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 4: Self-XSS Escalation Analysis.

        Check if user input appears in places visible to administrators
        (error logs, admin panels, reports). Self-XSS becomes dangerous XSS
        when the victim is a privileged user viewing stored content.

        CWE-79: Cross-site Scripting
        """
        findings: list[Finding] = []

        # Look for admin-facing content that might display user input
        admin_reflection_patterns = [
            (r"user[\s_-]*input.*admin", "User input shown in admin context"),
            (r"submitted[\s_-]*by.*displayed", "User submission displayed"),
            (r"error[\s_-]*log.*contains", "Error log might contain user input"),
            (r"support[\s_-]*ticket", "Support ticket might show user input to staff"),
            (r"report[\s_-]*generated", "Report containing user data"),
            (r"notification.*sent.*to.*admin", "Admin notification with user content"),
            (r"moderation[\s_-]*queue", "Moderation queue displays user content"),
        ]

        for pattern, description in admin_reflection_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="Potential Self-XSS Escalation Vector",
                        description=(
                            f"Page contains pattern indicating user input may be displayed to admins: "
                            f"'{description}'. If input is not properly sanitized, self-XSS payloads "
                            "could execute in administrator context (escalated XSS)."
                        ),
                        cwe_id="CWE-79",
                        cwe_name="Improper Neutralization of Input During Web Page Generation",
                        url=url,
                        evidence=f"Pattern detected: {pattern}",
                        remediation=(
                            "Sanitize ALL user input before display, regardless of context. "
                            "Use context-aware encoding. Admin panels need the same XSS protection "
                            "as public pages - arguably more, given higher privileges."
                        ),
                        cvss_score=6.1,
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                        ],
                        metadata={"pattern": pattern, "description": description},
                    )
                )

        # Check for reflection of common test strings
        xss_test_strings = ["<script>", "javascript:", "onerror=", "onload="]
        for test_string in xss_test_strings:
            if test_string in html_content:
                # Check if it's in a context that suggests user input
                context_patterns = [
                    rf"value\s*=\s*['\"][^'\"]*{re.escape(test_string)}",
                    rf"<textarea[^>]*>[^<]*{re.escape(test_string)}",
                    rf"<div[^>]*class=['\"][^'\"]*user[^'\"]*['\"][^>]*>[^<]*{re.escape(test_string)}",
                ]

                for ctx_pattern in context_patterns:
                    if re.search(ctx_pattern, html_content, re.IGNORECASE):
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title="Unescaped XSS Payload in Page",
                                description=(
                                    f"Page contains unescaped XSS test string '{test_string}' "
                                    "in a user-controlled context. This indicates active XSS vulnerability."
                                ),
                                cwe_id="CWE-79",
                                cwe_name="Improper Neutralization of Input During Web Page Generation",
                                url=url,
                                evidence=f"Found: {test_string} in context matching {ctx_pattern}",
                                remediation=(
                                    "Implement proper output encoding. Use framework-provided "
                                    "escaping functions. Consider Content-Security-Policy headers."
                                ),
                                cvss_score=8.2,
                            )
                        )
                        break

        return findings

    async def _attack_browser_console_secrets(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 5: Browser Console Secrets.

        Use page.evaluate() to dump localStorage, sessionStorage, and
        window global variables. Developers often leave secrets in these
        client-accessible locations.

        CWE-922: Insecure Storage of Sensitive Information
        """
        findings: list[Finding] = []

        try:
            with _get_browser_instance() as browser:
                page = browser.new_page()
                page.goto(url, timeout=self.config.timeout * 1000)

                # Wait for page to settle
                with contextlib.suppress(Exception):
                    page.wait_for_network_idle(idle_time=500, timeout=5000)

                # Extract all client-side storage and global state
                secrets_script = """
                (() => {
                    const secrets = {
                        localStorage: {},
                        sessionStorage: {},
                        globalVars: {}
                    };

                    // Dump localStorage
                    try {
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            secrets.localStorage[key] = localStorage.getItem(key);
                        }
                    } catch (e) {}

                    // Dump sessionStorage
                    try {
                        for (let i = 0; i < sessionStorage.length; i++) {
                            const key = sessionStorage.key(i);
                            secrets.sessionStorage[key] = sessionStorage.getItem(key);
                        }
                    } catch (e) {}

                    // Check for common global secrets
                    const globalPatterns = [
                        '__INITIAL_STATE__',
                        '__PRELOADED_STATE__',
                        '__REDUX_STATE__',
                        '__NEXT_DATA__',
                        '__NUXT__',
                        'config',
                        'CONFIG',
                        'appConfig',
                        'APP_CONFIG',
                        'settings',
                        'SETTINGS',
                        'environment',
                        'ENV',
                        'apiKey',
                        'API_KEY',
                        'token',
                        'TOKEN',
                        'secret',
                        'SECRET',
                        'credentials',
                        'auth',
                        'user',
                        '__APP_DATA__',
                        'window.config',
                        'window.settings',
                    ];

                    for (const pattern of globalPatterns) {
                        try {
                            const value = eval(pattern);
                            if (value !== undefined && value !== null) {
                                // Truncate large objects
                                const strVal = JSON.stringify(value);
                                secrets.globalVars[pattern] = strVal.length > 1000
                                    ? strVal.substring(0, 1000) + '...'
                                    : strVal;
                            }
                        } catch (e) {}
                    }

                    return secrets;
                })()
                """

                result = page.evaluate(secrets_script, return_value=True)
                page.close()

                if not isinstance(result, dict):
                    return findings

                # Analyze localStorage
                local_storage = result.get("localStorage", {})
                sensitive_keys: list[str] = []
                secret_patterns = [
                    r"token",
                    r"key",
                    r"secret",
                    r"password",
                    r"api",
                    r"auth",
                    r"jwt",
                    r"session",
                    r"credential",
                    r"private",
                ]

                for key, value in local_storage.items():
                    if not key or not value:
                        continue
                    for pattern in secret_patterns:
                        if re.search(pattern, key, re.IGNORECASE):
                            sensitive_keys.append(key)
                            break
                    # Check value for secret-like patterns
                    if len(value) >= 20 and re.match(r"^[A-Za-z0-9_-]+$", value):
                        sensitive_keys.append(f"{key} (high-entropy value)")

                if sensitive_keys:
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title="Sensitive Data in localStorage",
                            description=(
                                f"Found {len(sensitive_keys)} potentially sensitive keys in localStorage: "
                                f"{', '.join(sensitive_keys[:5])}. localStorage is accessible to any "
                                "JavaScript on the page, including XSS payloads."
                            ),
                            cwe_id="CWE-922",
                            cwe_name="Insecure Storage of Sensitive Information",
                            url=url,
                            evidence=f"Sensitive keys: {', '.join(sensitive_keys[:10])}",
                            remediation=(
                                "Never store secrets, tokens, or sensitive data in localStorage. "
                                "Use secure HttpOnly cookies for session tokens. If client-side "
                                "storage is required, consider encrypting values."
                            ),
                            cvss_score=7.5,
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Insecure_Storage",
                            ],
                            metadata={
                                "sensitive_keys": sensitive_keys,
                                "total_keys": len(local_storage),
                            },
                        )
                    )

                # Analyze sessionStorage
                session_storage = result.get("sessionStorage", {})
                session_sensitive: list[str] = []

                for key, value in session_storage.items():
                    if not key or not value:
                        continue
                    for pattern in secret_patterns:
                        if re.search(pattern, key, re.IGNORECASE):
                            session_sensitive.append(key)
                            break

                if session_sensitive:
                    findings.append(
                        self._create_finding(
                            severity=Severity.MEDIUM,
                            title="Sensitive Data in sessionStorage",
                            description=(
                                f"Found {len(session_sensitive)} potentially sensitive keys in sessionStorage: "
                                f"{', '.join(session_sensitive[:5])}."
                            ),
                            cwe_id="CWE-922",
                            cwe_name="Insecure Storage of Sensitive Information",
                            url=url,
                            evidence=f"Sensitive keys: {', '.join(session_sensitive[:10])}",
                            remediation=(
                                "Avoid storing sensitive data in sessionStorage. "
                                "Use HttpOnly cookies for authentication tokens."
                            ),
                            cvss_score=5.3,
                            metadata={"sensitive_keys": session_sensitive},
                        )
                    )

                # Analyze global variables
                global_vars = result.get("globalVars", {})
                exposed_secrets: list[str] = []

                for var_name, var_value in global_vars.items():
                    if not var_value:
                        continue

                    # Check for exposed secrets in the value
                    value_lower = var_value.lower()
                    if any(
                        secret in value_lower
                        for secret in ["api_key", "secret", "password", "token", "private"]
                    ):
                        exposed_secrets.append(var_name)

                if exposed_secrets:
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title="Secrets Exposed in Global JavaScript Variables",
                            description=(
                                f"Found potential secrets in global window variables: "
                                f"{', '.join(exposed_secrets)}. These are accessible via browser console "
                                "and any JavaScript on the page."
                            ),
                            cwe_id="CWE-922",
                            cwe_name="Insecure Storage of Sensitive Information",
                            url=url,
                            evidence=f"Variables with secrets: {', '.join(exposed_secrets)}",
                            remediation=(
                                "Never expose secrets in client-side JavaScript. "
                                "Keep API keys and secrets server-side. "
                                "If data must be passed to frontend, use server-side rendering "
                                "or secure token exchange patterns."
                            ),
                            cvss_score=8.1,
                            metadata={"exposed_variables": exposed_secrets},
                        )
                    )

                # Check for __INITIAL_STATE__ or similar with sensitive data
                if "__INITIAL_STATE__" in global_vars or "__NEXT_DATA__" in global_vars:
                    state_var = global_vars.get(
                        "__INITIAL_STATE__", global_vars.get("__NEXT_DATA__", "")
                    )
                    if state_var and any(
                        kw in state_var.lower()
                        for kw in ["email", "user", "admin", "session", "role"]
                    ):
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title="User Data in Initial State Hydration",
                                description=(
                                    "Application exposes user/session data in __INITIAL_STATE__ or "
                                    "__NEXT_DATA__ global variable. This data is accessible to any "
                                    "JavaScript and may include sensitive user information."
                                ),
                                cwe_id="CWE-200",
                                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                                url=url,
                                evidence="User data found in state hydration variable",
                                remediation=(
                                    "Minimize data in initial state. Only include data that is "
                                    "appropriate for the current user's authorization level. "
                                    "Never include other users' data or admin-only information."
                                ),
                                cvss_score=5.3,
                            )
                        )

        except Exception as e:
            logger.debug("browser_console_secrets_error", error=str(e))

        return findings

    async def _attack_absurd_input_lengths(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 6: Absurd Input Lengths.

        Send extremely long strings (1MB+) to input fields.
        Many backends crash, reveal stack traces, or time out.

        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        # Generate absurdly long payloads
        long_payloads = [
            ("A" * 10000, "10KB string"),
            ("A" * 100000, "100KB string"),
            ("A" * 1000000, "1MB string"),
        ]

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", form.get("action", "unknown"))
            form_action = form.get("action", url)
            inputs = form.get("inputs", [])

            # Find text-like inputs to test
            text_fields: list[str] = []
            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue

                name = input_field.get("name", "")
                input_type = input_field.get("type", "").lower()

                if input_type in ["text", "textarea", "search", "email", "password", ""] and name:
                    text_fields.append(name)

            if not text_fields:
                continue

            # Test each payload size
            for payload, payload_desc in long_payloads:
                test_data = dict.fromkeys(text_fields[:3], payload)  # Limit fields

                try:
                    async with httpx.AsyncClient(
                        timeout=30.0,  # Longer timeout for large payloads
                        verify=self.config.verify_ssl,
                        follow_redirects=True,
                    ) as client:
                        response = await client.post(
                            form_action,
                            data=test_data,
                            headers={"User-Agent": self.config.user_agent},
                        )

                        # Check for server errors
                        if response.status_code >= 500:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.MEDIUM,
                                    title=f"Server Error on {payload_desc} Input",
                                    description=(
                                        f"Form '{form_id}' returned {response.status_code} when "
                                        f"submitted with {payload_desc} in input fields. "
                                        "This indicates inadequate input length validation and "
                                        "potential for denial of service."
                                    ),
                                    cwe_id="CWE-400",
                                    cwe_name="Uncontrolled Resource Consumption",
                                    url=form_action,
                                    evidence=f"Payload size: {payload_desc}; Status: {response.status_code}",
                                    remediation=(
                                        "Implement input length limits on all text fields. "
                                        "Use streaming parsers for large inputs. "
                                        "Set appropriate max_content_length in web server config."
                                    ),
                                    cvss_score=5.3,
                                    metadata={
                                        "form_id": form_id,
                                        "payload_size": len(payload),
                                        "fields_tested": text_fields[:3],
                                    },
                                )
                            )
                            break  # Found issue, no need to test larger

                        # Check for timeout-like behavior (response took very long)
                        # or error disclosure
                        response_text_lower = safe_response_text(response).lower()
                        if "timeout" in response_text_lower or "memory" in response_text_lower:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.MEDIUM,
                                    title=f"Resource Exhaustion Detected on {payload_desc}",
                                    description=(
                                        f"Server showed signs of resource exhaustion with {payload_desc}: "
                                        "timeout or memory errors mentioned in response."
                                    ),
                                    cwe_id="CWE-400",
                                    cwe_name="Uncontrolled Resource Consumption",
                                    url=form_action,
                                    evidence=f"Payload size: {payload_desc}",
                                    remediation="Implement strict input length limits.",
                                    cvss_score=5.3,
                                )
                            )
                            break

                except httpx.TimeoutException:
                    findings.append(
                        self._create_finding(
                            severity=Severity.MEDIUM,
                            title=f"Server Timeout on {payload_desc} Input",
                            description=(
                                f"Server timed out when form '{form_id}' was submitted with "
                                f"{payload_desc}. This could enable denial of service attacks."
                            ),
                            cwe_id="CWE-400",
                            cwe_name="Uncontrolled Resource Consumption",
                            url=form_action,
                            evidence=f"Payload size: {payload_desc}; Result: timeout",
                            remediation=(
                                "Implement input length validation before processing. "
                                "Use request size limits at the web server level."
                            ),
                            cvss_score=5.3,
                        )
                    )
                    break

                except Exception as e:
                    logger.debug("absurd_input_test_error", error=str(e))

        return findings

    async def _attack_http_method_confusion(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 7: HTTP Method Confusion.

        Try unexpected HTTP methods (DELETE, PUT, PATCH) on GET endpoints.
        Many frameworks auto-route these, potentially enabling data modification.

        CWE-749: Exposed Dangerous Method or Function
        """
        findings: list[Finding] = []

        for method in self.UNEXPECTED_METHODS:
            try:
                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    response = await client.request(
                        method,
                        url,
                        headers={"User-Agent": self.config.user_agent},
                    )

                    # Check if method is unexpectedly allowed
                    # 405 Method Not Allowed is the correct response for unsupported methods
                    # Method was accepted if not 405/501 and returns success status
                    if (
                        response.status_code not in [405, 501]
                        and response.status_code in [200, 201, 204, 302]
                    ):
                        severity = Severity.HIGH if method == "DELETE" else Severity.MEDIUM

                        findings.append(
                            self._create_finding(
                                severity=severity,
                                title=f"Unexpected HTTP Method Accepted: {method}",
                                description=(
                                    f"Endpoint accepts {method} requests with status {response.status_code}. "
                                    f"If this endpoint is not designed for {method}, it may indicate "
                                    "a misconfiguration allowing unintended data modification or deletion."
                                ),
                                cwe_id="CWE-749",
                                cwe_name="Exposed Dangerous Method or Function",
                                url=url,
                                evidence=f"Method: {method}; Status: {response.status_code}",
                                remediation=(
                                    "Explicitly restrict HTTP methods on each endpoint. "
                                    "Return 405 Method Not Allowed for unsupported methods. "
                                    "Use framework route decorators to specify allowed methods."
                                ),
                                cvss_score=7.5 if method == "DELETE" else 5.3,
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
                                ],
                                metadata={
                                    "method": method,
                                    "status_code": response.status_code,
                                },
                            )
                        )

            except Exception as e:
                logger.debug("http_method_test_error", method=method, error=str(e))

        return findings

    async def _attack_race_condition_spam(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 8: Race Condition Spam.

        Rapidly submit the same request multiple times simultaneously.
        Tests for race conditions in coupon codes, voting, limited offers.

        CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization
        """
        findings: list[Finding] = []

        # Look for forms that might be vulnerable to race conditions
        race_condition_patterns = [
            r"coupon",
            r"promo",
            r"discount",
            r"vote",
            r"like",
            r"upvote",
            r"downvote",
            r"redeem",
            r"claim",
            r"register",
            r"transfer",
            r"withdraw",
            r"purchase",
            r"buy",
            r"order",
        ]

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", form.get("action", "unknown"))
            form_action = form.get("action", url)
            form_id_str = str(form_id) if form_id else ""
            form_action_str = str(form_action) if form_action else ""

            # Check if form action or ID suggests race-vulnerable functionality
            is_race_target = False
            matched_pattern = ""

            for pattern in race_condition_patterns:
                if re.search(pattern, form_action_str, re.IGNORECASE) or re.search(
                    pattern, form_id_str, re.IGNORECASE
                ):
                    is_race_target = True
                    matched_pattern = pattern
                    break

            if not is_race_target:
                continue

            # Build minimal form data
            inputs = form.get("inputs", [])
            form_data: dict[str, str] = {}

            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue

                name = input_field.get("name", "")
                input_type = input_field.get("type", "").lower()

                if name and input_type not in ["submit", "button", "reset"]:
                    # Use dummy values
                    if "email" in name.lower():
                        form_data[name] = "test@example.com"
                    elif "password" in name.lower():
                        form_data[name] = "TestPassword123!"
                    else:
                        form_data[name] = "test_value"

            if not form_data:
                form_data["test"] = "value"

            # Capture loop variables for closure
            action_url = form_action
            data_payload = form_data.copy()

            # Attempt rapid parallel submissions
            async def submit_once(
                target_url: str, payload: dict[str, str]
            ) -> tuple[int, str]:
                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    response = await client.post(
                        target_url,
                        data=payload,
                        headers={"User-Agent": self.config.user_agent},
                    )
                    return response.status_code, safe_response_text(response)[:500]

            try:
                # Submit 10 times simultaneously
                results = await asyncio.gather(
                    *[submit_once(action_url, data_payload) for _ in range(10)],
                    return_exceptions=True,
                )

                # Analyze results
                successful = [
                    r for r in results if isinstance(r, tuple) and r[0] in [200, 201, 302]
                ]

                if len(successful) > 1:
                    # Multiple successful submissions - potential race condition
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title=f"Potential Race Condition: {matched_pattern.title()}",
                            description=(
                                f"Form '{form_id}' accepted {len(successful)} out of 10 "
                                f"simultaneous submissions. Pattern matched: '{matched_pattern}'. "
                                "This could enable coupon abuse, vote manipulation, "
                                "or double-spending vulnerabilities."
                            ),
                            cwe_id="CWE-362",
                            cwe_name="Concurrent Execution Using Shared Resource with Improper Synchronization",
                            url=form_action,
                            evidence=f"Successful submissions: {len(successful)}/10",
                            remediation=(
                                "Implement proper locking mechanisms (mutex, database locks). "
                                "Use unique constraint violations for one-time actions. "
                                "Consider optimistic locking with version counters. "
                                "Rate limit by user/session, not just IP."
                            ),
                            cvss_score=8.1,
                            references=[
                                "https://owasp.org/www-community/attacks/Race_Condition",
                                "https://cwe.mitre.org/data/definitions/362.html",
                            ],
                            metadata={
                                "form_id": form_id,
                                "pattern": matched_pattern,
                                "successful_submissions": len(successful),
                            },
                        )
                    )

            except Exception as e:
                logger.debug("race_condition_test_error", error=str(e))

        return findings

    async def _attack_default_credentials(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 9: Default Credential Check.

        Try common default username/password combinations on login forms.

        CWE-1392: Use of Default Credentials
        """
        findings: list[Finding] = []

        # Find login forms
        login_patterns = [
            r"login",
            r"signin",
            r"sign-in",
            r"auth",
            r"session",
        ]

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", form.get("action", "unknown"))
            form_action = form.get("action", url)
            form_id_str = str(form_id) if form_id else ""
            form_action_str = str(form_action) if form_action else ""

            # Check if this is a login form
            is_login = False
            for pattern in login_patterns:
                if re.search(pattern, form_action_str, re.IGNORECASE) or re.search(
                    pattern, form_id_str, re.IGNORECASE
                ):
                    is_login = True
                    break

            if not is_login:
                # Check for password field
                inputs = form.get("inputs", [])
                for input_field in inputs:
                    if (
                        isinstance(input_field, dict)
                        and input_field.get("type", "").lower() == "password"
                    ):
                        is_login = True
                        break

            if not is_login:
                continue

            # Identify username and password fields
            inputs = form.get("inputs", [])
            username_field = None
            password_field = None

            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue

                name = input_field.get("name", "").lower()
                input_type = input_field.get("type", "").lower()

                if input_type == "password" and not password_field:
                    password_field = input_field.get("name", "")
                elif any(
                    p in name for p in ["user", "name", "login", "email", "account"]
                ) and not username_field:
                    username_field = input_field.get("name", "")

            if not username_field or not password_field:
                continue

            # Try default credentials
            successful_creds: list[tuple[str, str]] = []

            for username, password in self.DEFAULT_CREDENTIALS:
                try:
                    async with httpx.AsyncClient(
                        timeout=10.0,
                        verify=self.config.verify_ssl,
                        follow_redirects=True,
                    ) as client:
                        login_data = {
                            username_field: username,
                            password_field: password,
                        }

                        response = await client.post(
                            form_action,
                            data=login_data,
                            headers={"User-Agent": self.config.user_agent},
                        )

                        # Check for successful login indicators
                        response_lower = safe_response_text(response).lower()

                        # Failure indicators
                        failure_indicators = [
                            "invalid",
                            "incorrect",
                            "wrong",
                            "failed",
                            "error",
                            "denied",
                            "unsuccessful",
                        ]

                        # Success indicators
                        success_indicators = [
                            "welcome",
                            "dashboard",
                            "logout",
                            "sign out",
                            "my account",
                            "profile",
                        ]

                        has_failure = any(
                            ind in response_lower for ind in failure_indicators
                        )
                        has_success = any(
                            ind in response_lower for ind in success_indicators
                        )

                        if not has_failure and (
                            has_success or response.status_code == 302
                        ):
                            successful_creds.append((username, password))

                except Exception as e:
                    logger.debug("default_cred_test_error", error=str(e))

            if successful_creds:
                findings.append(
                    self._create_finding(
                        severity=Severity.CRITICAL,
                        title="Default Credentials Accepted",
                        description=(
                            f"Login form '{form_id}' accepts default credentials. "
                            f"Successful logins with: {', '.join(f'{u}:{p}' for u, p in successful_creds[:3])}. "
                            "This is a critical security vulnerability."
                        ),
                        cwe_id="CWE-1392",
                        cwe_name="Use of Default Credentials",
                        url=form_action,
                        evidence=f"Accepted credentials: {successful_creds[:3]}",
                        remediation=(
                            "Change all default credentials immediately. "
                            "Implement forced password change on first login. "
                            "Use strong password policies. "
                            "Consider implementing account lockout after failed attempts."
                        ),
                        cvss_score=9.8,
                        references=[
                            "https://cwe.mitre.org/data/definitions/1392.html",
                            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                        ],
                        metadata={
                            "form_id": form_id,
                            "successful_credentials": [
                                {"username": u, "password": "***"}
                                for u, _ in successful_creds
                            ],
                        },
                    )
                )

        return findings

    async def _attack_url_parameter_pollution(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """
        Attack 10: URL Parameter Pollution.

        Add hidden debug/admin parameters to URLs. Many applications
        check for these without proper authorization.

        CWE-15: External Control of System or Configuration Setting
        """
        findings: list[Finding] = []

        parsed = urlparse(url)

        for param, value in self.DEBUG_PARAMETERS:
            try:
                # Add the parameter to the URL
                current_params = parse_qs(parsed.query)
                current_params[param] = [value]
                new_query = urlencode(current_params, doseq=True)
                test_url = urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        "",
                    )
                )

                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    response = await client.get(
                        test_url,
                        headers={"User-Agent": self.config.user_agent},
                    )

                    original_length = len(html_content)
                    new_response_text = safe_response_text(response)
                    new_length = len(new_response_text)

                    # Check for significant content changes
                    length_diff = abs(new_length - original_length)
                    length_ratio = (
                        length_diff / original_length if original_length > 0 else 0
                    )

                    # Check for debug/admin indicators in new content
                    new_content_lower = new_response_text.lower()
                    debug_indicators = [
                        "debug",
                        "admin",
                        "internal",
                        "hidden",
                        "developer",
                        "console",
                        "trace",
                        "stack",
                        "config",
                        "settings",
                        "environment",
                    ]

                    # Check if indicator appears in new content but not original
                    new_indicators: list[str] = []
                    for indicator in debug_indicators:
                        if indicator in new_content_lower and indicator not in html_content.lower():
                            new_indicators.append(indicator)

                    # Significant content change or new debug content
                    if length_ratio > 0.1 and new_indicators:
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"Hidden Parameter Enables Debug Features: {param}={value}",
                                description=(
                                    f"Adding '{param}={value}' to URL causes significant content changes "
                                    f"and reveals debug-related content. New indicators: {', '.join(new_indicators)}. "
                                    "This may expose internal information or admin functionality."
                                ),
                                cwe_id="CWE-15",
                                cwe_name="External Control of System or Configuration Setting",
                                url=test_url,
                                evidence=f"Parameter: {param}={value}; Content change: {length_ratio:.1%}; New indicators: {new_indicators}",
                                remediation=(
                                    "Remove all debug parameters from production code. "
                                    "Use proper authentication for admin/debug features. "
                                    "Never trust URL parameters for authorization decisions."
                                ),
                                cvss_score=7.5,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/15.html",
                                ],
                                metadata={
                                    "parameter": param,
                                    "value": value,
                                    "content_change_ratio": length_ratio,
                                    "new_indicators": new_indicators,
                                },
                            )
                        )
                        break  # Found a vulnerable parameter

                    # Check for direct admin access
                    if param in ["admin", "is_admin", "role", "superuser"]:
                        # Check if response shows admin content NOT present in original
                        # Use specific multi-word phrases to avoid false positives
                        admin_indicators = [
                            "admin panel",
                            "admin dashboard",
                            "user management",
                            "delete user",
                            "system settings",
                            "manage users",
                            "admin console",
                            "administrative access",
                        ]

                        original_lower = html_content.lower()
                        new_admin_indicators: list[str] = []
                        for admin_ind in admin_indicators:
                            # Only flag if indicator is NEW (not in original response)
                            if admin_ind in new_content_lower and admin_ind not in original_lower:
                                new_admin_indicators.append(admin_ind)

                        # Require at least one NEW admin indicator to report
                        if new_admin_indicators:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.CRITICAL,
                                    title=f"Admin Access via URL Parameter: {param}={value}",
                                    description=(
                                        f"Adding '{param}={value}' grants access to admin functionality. "
                                        f"New admin content detected: '{', '.join(new_admin_indicators)}'. "
                                        "This is a critical authorization bypass."
                                    ),
                                    cwe_id="CWE-284",
                                    cwe_name="Improper Access Control",
                                    url=test_url,
                                    evidence=f"Parameter: {param}={value}; New admin indicators: {new_admin_indicators}",
                                    remediation=(
                                        "IMMEDIATELY fix authorization checks. "
                                        "Never use URL parameters for role/permission decisions. "
                                        "Implement proper session-based authorization."
                                    ),
                                    cvss_score=9.8,
                                    metadata={"parameter": param, "new_admin_indicators": new_admin_indicators},
                                )
                            )
                            return findings  # Critical finding, stop testing

            except Exception as e:
                logger.debug("url_parameter_test_error", param=param, error=str(e))

        return findings

    # =========================================================================
    # NEW CHAOS ATTACK PATTERNS (15 MORE)
    # =========================================================================

    # -------------------------------------------------------------------------
    # KONAMI-STYLE PATTERN ATTACKS
    # -------------------------------------------------------------------------

    async def _attack_rapid_key_sequence(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 11: Rapid Key Sequence Injection (Konami Code Attack).

        Send keyboard event sequences (up,up,down,down,left,right,left,right,b,a)
        to trigger hidden debug modes or easter eggs that may expose vulnerabilities.

        CWE-489: Active Debug Code
        """
        findings: list[Finding] = []

        try:
            with _get_browser_instance() as browser:
                page = browser.new_page()
                page.goto(url, timeout=self.config.timeout * 1000)

                # Wait for page to settle
                with contextlib.suppress(Exception):
                    page.wait_for_network_idle(idle_time=500, timeout=5000)

                # Get initial page state
                initial_html = page.get_html()

                # Konami code sequence: up, up, down, down, left, right, left, right, b, a
                # Note: Only using arrow keys as letter keys require type_text() method
                konami_keys = [
                    "ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown",
                    "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight",
                ]

                # Execute konami code
                for key in konami_keys:
                    page.press_key(key)
                    await asyncio.sleep(0.05)  # Small delay between keys

                # Wait and check for changes
                await asyncio.sleep(0.5)
                post_konami_html = page.get_html()

                # Check for debug/admin panels appearing
                debug_indicators = [
                    "debug-panel", "debug-mode", "developer-tools",
                    "admin-console", "hidden-menu", "easter-egg",
                    "cheat-mode", "god-mode", "super-user",
                ]

                new_elements: list[str] = []
                for indicator in debug_indicators:
                    if indicator in post_konami_html.lower() and indicator not in initial_html.lower():
                        new_elements.append(indicator)

                # Check for significant content changes
                if len(post_konami_html) > len(initial_html) * 1.2 or new_elements:
                    findings.append(
                        self._create_finding(
                            severity=Severity.MEDIUM,
                            title="Hidden Debug Mode Triggered by Key Sequence",
                            description=(
                                "Application responds to Konami code or similar key sequences, "
                                f"revealing hidden functionality. New elements: {', '.join(new_elements) or 'content change detected'}. "
                                "Debug modes in production can expose sensitive functionality."
                            ),
                            cwe_id="CWE-489",
                            cwe_name="Active Debug Code",
                            url=url,
                            evidence=f"Key sequence triggered response. Content growth: {len(post_konami_html) - len(initial_html)} bytes",
                            remediation=(
                                "Remove all debug modes, easter eggs, and hidden features from production. "
                                "Use feature flags that are completely disabled in production builds."
                            ),
                            cvss_score=5.3,
                            metadata={"new_elements": new_elements},
                        )
                    )

                page.close()

        except Exception as e:
            logger.debug("rapid_key_sequence_error", error=str(e))

        return findings

    async def _attack_button_mash(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 12: Button Mash Attack.

        Rapidly click submit button 50+ times in 2 seconds to break rate limiters
        or cause duplicate submissions.

        CWE-799: Improper Control of Interaction Frequency
        """
        findings: list[Finding] = []

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", form.get("action", "unknown"))
            form_action = form.get("action", url)

            # Build form data
            inputs = form.get("inputs", [])
            form_data: dict[str, str] = {}
            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue
                name = input_field.get("name", "")
                input_type = input_field.get("type", "").lower()
                if name and input_type not in ["submit", "button", "reset"]:
                    form_data[name] = "test_value"

            if not form_data:
                continue

            # Rapid fire 50 submissions in ~2 seconds
            async def rapid_submit(target: str, data: dict[str, str]) -> tuple[int, float]:
                start = asyncio.get_event_loop().time()
                async with httpx.AsyncClient(
                    timeout=5.0,
                    verify=self.config.verify_ssl,
                ) as client:
                    resp = await client.post(target, data=data)
                    elapsed = asyncio.get_event_loop().time() - start
                    return resp.status_code, elapsed

            try:
                # Fire 50 requests as fast as possible
                tasks = [rapid_submit(form_action, form_data) for _ in range(50)]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                successful = [r for r in results if isinstance(r, tuple) and r[0] in [200, 201, 302]]
                errors = [r for r in results if isinstance(r, Exception)]

                # Check if rate limiting kicked in
                rate_limited = len(successful) < 25  # Less than half succeeded = rate limiting

                if not rate_limited and len(successful) >= 45:
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title=f"No Rate Limiting on Form Submission",
                            description=(
                                f"Form '{form_id}' accepted {len(successful)}/50 rapid submissions. "
                                "No rate limiting detected. This enables brute force attacks, "
                                "resource exhaustion, and duplicate transaction abuse."
                            ),
                            cwe_id="CWE-799",
                            cwe_name="Improper Control of Interaction Frequency",
                            url=form_action,
                            evidence=f"Successful submissions: {len(successful)}/50",
                            remediation=(
                                "Implement rate limiting per IP and per session. "
                                "Use CAPTCHA for sensitive actions. "
                                "Add exponential backoff for repeated submissions."
                            ),
                            cvss_score=7.5,
                            metadata={
                                "form_id": form_id,
                                "successful": len(successful),
                                "errors": len(errors),
                            },
                        )
                    )

            except Exception as e:
                logger.debug("button_mash_error", form_id=form_id, error=str(e))

        return findings

    async def _attack_tab_order_exploitation(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 13: Tab-Order Exploitation.

        Tab through form fields in reverse order, skip fields, submit incomplete.
        Tests if server-side validation depends on client-side field ordering.

        CWE-20: Improper Input Validation
        """
        findings: list[Finding] = []

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", form.get("action", "unknown"))
            form_action = form.get("action", url)
            inputs = form.get("inputs", [])

            # Get all required fields
            required_fields: list[str] = []
            all_fields: list[str] = []

            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue
                name = input_field.get("name", "")
                input_type = input_field.get("type", "").lower()
                required = input_field.get("required", False)

                if name and input_type not in ["submit", "button", "reset", "hidden"]:
                    all_fields.append(name)
                    if required:
                        required_fields.append(name)

            if not all_fields:
                continue

            # Test 1: Submit with only every other field filled
            sparse_data: dict[str, str] = {}
            for i, field in enumerate(all_fields):
                if i % 2 == 0:
                    sparse_data[field] = "test_value"

            try:
                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    response = await client.post(
                        form_action,
                        data=sparse_data,
                        headers={"User-Agent": self.config.user_agent},
                    )

                    # Check if partial submission was accepted
                    error_indicators = ["required", "missing", "invalid", "error", "please fill"]
                    has_error = any(ind in safe_response_text(response).lower() for ind in error_indicators)

                    if response.status_code in [200, 201, 302] and not has_error:
                        missing = [f for f in all_fields if f not in sparse_data]
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title="Form Accepts Partial/Incomplete Submissions",
                                description=(
                                    f"Form '{form_id}' accepted submission with only {len(sparse_data)}/{len(all_fields)} "
                                    f"fields filled. Missing fields: {', '.join(missing[:5])}. "
                                    "This may bypass required field validation."
                                ),
                                cwe_id="CWE-20",
                                cwe_name="Improper Input Validation",
                                url=form_action,
                                evidence=f"Submitted {len(sparse_data)} of {len(all_fields)} fields",
                                remediation=(
                                    "Validate all required fields server-side. "
                                    "Do not rely on client-side required attributes. "
                                    "Check for presence of all expected fields."
                                ),
                                cvss_score=5.3,
                                metadata={
                                    "form_id": form_id,
                                    "submitted_fields": list(sparse_data.keys()),
                                    "missing_fields": missing,
                                },
                            )
                        )

            except Exception as e:
                logger.debug("tab_order_test_error", error=str(e))

        return findings

    # -------------------------------------------------------------------------
    # OVERWHELM LOGIC ATTACKS
    # -------------------------------------------------------------------------

    async def _attack_login_bruteforce_lockout(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 14: Login Bruteforce Lockout Test.

        100 failed logins rapidly - check if account locks, check if lockout is bypassable.

        CWE-307: Improper Restriction of Excessive Authentication Attempts
        """
        findings: list[Finding] = []

        # Find login forms
        login_patterns = [r"login", r"signin", r"sign-in", r"auth"]

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", form.get("action", "unknown"))
            form_action = form.get("action", url)
            form_action_str = str(form_action).lower()
            form_id_str = str(form_id).lower()

            # Check if login form
            is_login = any(
                re.search(p, form_action_str) or re.search(p, form_id_str)
                for p in login_patterns
            )

            if not is_login:
                inputs = form.get("inputs", [])
                for inp in inputs:
                    if isinstance(inp, dict) and inp.get("type", "").lower() == "password":
                        is_login = True
                        break

            if not is_login:
                continue

            # Find username/password fields
            inputs = form.get("inputs", [])
            username_field = None
            password_field = None

            for inp in inputs:
                if not isinstance(inp, dict):
                    continue
                name = inp.get("name", "").lower()
                input_type = inp.get("type", "").lower()

                if input_type == "password" and not password_field:
                    password_field = inp.get("name", "")
                elif any(p in name for p in ["user", "name", "login", "email"]) and not username_field:
                    username_field = inp.get("name", "")

            if not username_field or not password_field:
                continue

            # Attempt 100 rapid failed logins
            async def failed_login(target: str, u_field: str, p_field: str, attempt: int) -> tuple[int, str]:
                async with httpx.AsyncClient(
                    timeout=5.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    resp = await client.post(
                        target,
                        data={u_field: "testuser", p_field: f"wrongpass{attempt}"},
                        headers={"User-Agent": self.config.user_agent},
                    )
                    return resp.status_code, safe_response_text(resp)[:500]

            try:
                # Fire 100 failed attempts in batches
                all_results: list[Any] = []
                for batch in range(10):  # 10 batches of 10
                    tasks = [
                        failed_login(form_action, username_field, password_field, batch * 10 + i)
                        for i in range(10)
                    ]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    all_results.extend(results)
                    await asyncio.sleep(0.1)  # Small delay between batches

                # Analyze results
                successful_attempts = [r for r in all_results if isinstance(r, tuple)]
                lockout_indicators = ["locked", "blocked", "too many", "rate limit", "captcha", "wait"]

                lockout_detected = False
                for _status, text in successful_attempts[-10:]:  # Check last 10
                    if any(ind in text.lower() for ind in lockout_indicators):
                        lockout_detected = True
                        break

                if not lockout_detected and len(successful_attempts) >= 90:
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title="No Account Lockout After 100 Failed Logins",
                            description=(
                                f"Login form '{form_id}' accepted {len(successful_attempts)} failed "
                                "login attempts without lockout or rate limiting. "
                                "This enables unlimited brute force attacks."
                            ),
                            cwe_id="CWE-307",
                            cwe_name="Improper Restriction of Excessive Authentication Attempts",
                            url=form_action,
                            evidence=f"100 failed attempts, no lockout detected",
                            remediation=(
                                "Implement account lockout after 5-10 failed attempts. "
                                "Use progressive delays (exponential backoff). "
                                "Require CAPTCHA after initial failures. "
                                "Log and alert on brute force patterns."
                            ),
                            cvss_score=8.1,
                            metadata={"form_id": form_id, "attempts": len(successful_attempts)},
                        )
                    )

            except Exception as e:
                logger.debug("login_bruteforce_test_error", error=str(e))

        return findings

    async def _attack_session_flood(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 15: Session Flood.

        Create 50 sessions simultaneously, check if server tracks them all or leaks.

        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        async def create_session(target: str, session_num: int) -> dict[str, Any] | None:
            async with httpx.AsyncClient(
                timeout=10.0,
                verify=self.config.verify_ssl,
                follow_redirects=True,
            ) as client:
                try:
                    resp = await client.get(
                        target,
                        headers={"User-Agent": f"SessionFlood-{session_num}"},
                    )
                    cookies = dict(resp.cookies)
                    session_headers = {
                        k: v for k, v in resp.headers.items()
                        if "session" in k.lower() or "token" in k.lower()
                    }
                    return {"cookies": cookies, "headers": session_headers, "status": resp.status_code}
                except Exception:
                    return None

        try:
            # Create 50 sessions simultaneously
            tasks = [create_session(url, i) for i in range(50)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            successful = [r for r in results if isinstance(r, dict)]
            session_ids: set[str] = set()

            for sess in successful:
                if sess and sess.get("cookies"):
                    for cookie_name, cookie_val in sess["cookies"].items():
                        if any(p in cookie_name.lower() for p in ["session", "sid", "token"]):
                            session_ids.add(f"{cookie_name}={cookie_val[:20]}...")

            if len(successful) >= 45:  # All sessions created
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="Server Accepts Unlimited Concurrent Sessions",
                        description=(
                            f"Server created {len(successful)}/50 concurrent sessions without limiting. "
                            f"Unique session identifiers seen: {len(session_ids)}. "
                            "This may enable session exhaustion DoS attacks."
                        ),
                        cwe_id="CWE-400",
                        cwe_name="Uncontrolled Resource Consumption",
                        url=url,
                        evidence=f"Created {len(successful)} concurrent sessions",
                        remediation=(
                            "Limit concurrent sessions per IP address. "
                            "Implement session timeout and cleanup. "
                            "Use session pooling with reasonable limits."
                        ),
                        cvss_score=5.3,
                        metadata={
                            "sessions_created": len(successful),
                            "unique_session_ids": len(session_ids),
                        },
                    )
                )

        except Exception as e:
            logger.debug("session_flood_error", error=str(e))

        return findings

    async def _attack_form_resubmission_storm(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 16: Form Resubmission Storm.

        Submit same form data 100 times via simulated browser back/forward.
        Tests for duplicate submission prevention (PRG pattern).

        CWE-352: Cross-Site Request Forgery (or duplicate submission)
        """
        findings: list[Finding] = []

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", form.get("action", "unknown"))
            form_action = form.get("action", url)
            inputs = form.get("inputs", [])

            # Build form data
            form_data: dict[str, str] = {}
            for inp in inputs:
                if not isinstance(inp, dict):
                    continue
                name = inp.get("name", "")
                input_type = inp.get("type", "").lower()
                if name and input_type not in ["submit", "button", "reset"]:
                    form_data[name] = f"resubmit_test_{name}"

            if not form_data:
                continue

            # Submit same data 100 times (simulating refresh/back-forward)
            async def resubmit(target: str, data: dict[str, str]) -> int:
                async with httpx.AsyncClient(
                    timeout=5.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=False,  # Don't follow to detect PRG
                ) as client:
                    resp = await client.post(target, data=data)
                    return resp.status_code

            try:
                tasks = [resubmit(form_action, form_data) for _ in range(100)]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                status_codes = [r for r in results if isinstance(r, int)]
                redirects = [s for s in status_codes if s in [302, 303]]

                # PRG pattern: POST should redirect to GET
                if len(redirects) < len(status_codes) * 0.5:  # Less than half redirect
                    findings.append(
                        self._create_finding(
                            severity=Severity.MEDIUM,
                            title="Missing POST-Redirect-GET Pattern",
                            description=(
                                f"Form '{form_id}' does not implement PRG pattern. "
                                f"Only {len(redirects)}/{len(status_codes)} submissions redirected. "
                                "This allows duplicate form submissions via back/forward/refresh."
                            ),
                            cwe_id="CWE-352",
                            cwe_name="Cross-Site Request Forgery",
                            url=form_action,
                            evidence=f"Redirects: {len(redirects)}/{len(status_codes)}",
                            remediation=(
                                "Implement POST-Redirect-GET pattern. "
                                "Use unique tokens to prevent duplicate submissions. "
                                "Implement idempotency keys for sensitive operations."
                            ),
                            cvss_score=5.3,
                            metadata={
                                "form_id": form_id,
                                "total_submissions": len(status_codes),
                                "redirects": len(redirects),
                            },
                        )
                    )

            except Exception as e:
                logger.debug("form_resubmission_error", error=str(e))

        return findings

    async def _attack_infinite_redirect_loop(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 17: Infinite Redirect Loop.

        Check if app handles circular redirects or crashes.

        CWE-835: Loop with Unreachable Exit Condition
        """
        findings: list[Finding] = []

        # Test common redirect-triggering patterns
        redirect_payloads = [
            f"{url}?redirect={url}",
            f"{url}?next={url}",
            f"{url}?return_url={url}",
            f"{url}?goto={url}",
            f"{url}?continue={url}",
            f"{url}?url={url}",
        ]

        for test_url in redirect_payloads:
            try:
                redirect_count = 0
                current_url = test_url

                async with httpx.AsyncClient(
                    timeout=30.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=False,
                ) as client:
                    for _ in range(20):  # Follow up to 20 redirects manually
                        resp = await client.get(current_url)

                        if resp.status_code in [301, 302, 303, 307, 308]:
                            redirect_count += 1
                            location = resp.headers.get("location", "")

                            # Check for loop back to original
                            if url in location or current_url == location:
                                findings.append(
                                    self._create_finding(
                                        severity=Severity.MEDIUM,
                                        title="Redirect Loop Detected",
                                        description=(
                                            f"Application creates redirect loop when given self-referencing URL. "
                                            f"Redirect count: {redirect_count}. "
                                            "This can cause browser hangs and DoS."
                                        ),
                                        cwe_id="CWE-835",
                                        cwe_name="Loop with Unreachable Exit Condition",
                                        url=test_url,
                                        evidence=f"Loop detected at redirect #{redirect_count}: {location}",
                                        remediation=(
                                            "Validate redirect URLs against allowlist. "
                                            "Limit redirect chain depth. "
                                            "Prevent redirects to the same or similar URLs."
                                        ),
                                        cvss_score=5.3,
                                        metadata={
                                            "test_url": test_url,
                                            "redirect_count": redirect_count,
                                        },
                                    )
                                )
                                break

                            current_url = location
                        else:
                            break

            except Exception as e:
                logger.debug("redirect_loop_test_error", url=test_url, error=str(e))

        return findings

    async def _attack_memory_exhaustion_nested_json(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 18: Memory Exhaustion via Deeply Nested JSON.

        Send nested JSON 1000 levels deep to crash JSON parsers.

        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        # Generate deeply nested JSON iteratively (avoid recursion limit)
        def generate_nested_iterative(depth: int) -> dict[str, Any]:
            result: dict[str, Any] = {"value": "bottom"}
            for _ in range(depth):
                result = {"nested": result}
            return result

        # Pre-generate payloads to avoid repeated computation
        nested_payloads: list[tuple[dict[str, Any], str]] = [
            (generate_nested_iterative(100), "100-level nesting"),
            (generate_nested_iterative(500), "500-level nesting"),
            (generate_nested_iterative(1000), "1000-level nesting"),
        ]

        for payload, desc in nested_payloads:
            try:
                async with httpx.AsyncClient(
                    timeout=30.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    response = await client.post(
                        url,
                        json=payload,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/json",
                        },
                    )

                    if response.status_code >= 500:
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title=f"Server Crash on {desc}",
                                description=(
                                    f"Server returned {response.status_code} when sent {desc}. "
                                    "Deep JSON nesting can exhaust stack or memory, causing DoS."
                                ),
                                cwe_id="CWE-400",
                                cwe_name="Uncontrolled Resource Consumption",
                                url=url,
                                evidence=f"Payload: {desc}; Status: {response.status_code}",
                                remediation=(
                                    "Limit JSON parsing depth. "
                                    "Use streaming parsers with depth limits. "
                                    "Set maximum request body size."
                                ),
                                cvss_score=5.3,
                                metadata={"nesting_depth": desc, "status": response.status_code},
                            )
                        )
                        break  # Found vulnerability

            except httpx.TimeoutException:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Server Timeout on {desc}",
                        description=(
                            f"Server timed out when processing {desc}. "
                            "This indicates potential for DoS via recursive parsing."
                        ),
                        cwe_id="CWE-400",
                        cwe_name="Uncontrolled Resource Consumption",
                        url=url,
                        evidence=f"Payload: {desc}; Result: timeout",
                        remediation="Limit JSON parsing depth and complexity.",
                        cvss_score=5.3,
                    )
                )
                break

            except Exception as e:
                logger.debug("nested_json_test_error", error=str(e))

        return findings

    # -------------------------------------------------------------------------
    # NOVEL ZERO-DAY STYLE PATTERNS
    # -------------------------------------------------------------------------

    async def _attack_timing_oracle(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 19: Timing Oracle Attack.

        Measure response time differences for valid vs invalid usernames.
        Enables user enumeration through timing side-channels.

        CWE-208: Observable Timing Discrepancy
        """
        findings: list[Finding] = []

        # Find login forms
        for form in forms:
            if not isinstance(form, dict):
                continue

            form_action = form.get("action", url)
            inputs = form.get("inputs", [])

            # Check for login form
            username_field = None
            password_field = None

            for inp in inputs:
                if not isinstance(inp, dict):
                    continue
                name = inp.get("name", "").lower()
                input_type = inp.get("type", "").lower()

                if input_type == "password":
                    password_field = inp.get("name", "")
                elif any(p in name for p in ["user", "email", "login", "name"]):
                    username_field = inp.get("name", "")

            if not username_field or not password_field:
                continue

            # Test timing differences
            async def measure_login_time(target: str, u_field: str, p_field: str, username: str) -> float:
                start = asyncio.get_event_loop().time()
                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    await client.post(
                        target,
                        data={u_field: username, p_field: "definitely_wrong_password_12345"},
                    )
                return asyncio.get_event_loop().time() - start

            try:
                # Test multiple times for statistical significance
                test_usernames = [
                    ("admin", "likely_exists"),
                    ("root", "likely_exists"),
                    ("user", "likely_exists"),
                    ("xyznonexistent12345", "unlikely_exists"),
                    ("aaaaanonuser99999", "unlikely_exists"),
                    ("zzzfakeuser00000", "unlikely_exists"),
                ]

                timing_results: dict[str, list[float]] = {"likely_exists": [], "unlikely_exists": []}

                for username, category in test_usernames:
                    for _ in range(3):  # 3 measurements each
                        timing = await measure_login_time(form_action, username_field, password_field, username)
                        timing_results[category].append(timing)

                # Calculate averages
                avg_existing = sum(timing_results["likely_exists"]) / len(timing_results["likely_exists"])
                avg_nonexisting = sum(timing_results["unlikely_exists"]) / len(timing_results["unlikely_exists"])

                # Check for significant timing difference (>10% difference)
                if avg_existing > 0 and avg_nonexisting > 0:
                    ratio = max(avg_existing, avg_nonexisting) / min(avg_existing, avg_nonexisting)

                    if ratio > 1.15:  # 15% difference threshold
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title="Timing Oracle Enables User Enumeration",
                                description=(
                                    f"Login form shows {ratio:.1%} timing difference between likely-valid "
                                    f"and invalid usernames. Avg existing: {avg_existing:.3f}s, "
                                    f"Avg non-existing: {avg_nonexisting:.3f}s. "
                                    "This timing side-channel enables user enumeration."
                                ),
                                cwe_id="CWE-208",
                                cwe_name="Observable Timing Discrepancy",
                                url=form_action,
                                evidence=f"Timing ratio: {ratio:.2f}x",
                                remediation=(
                                    "Normalize response times for valid/invalid users. "
                                    "Always perform same operations regardless of user existence. "
                                    "Use constant-time comparison functions. "
                                    "Add random delay jitter."
                                ),
                                cvss_score=5.3,
                                metadata={
                                    "avg_existing": avg_existing,
                                    "avg_nonexisting": avg_nonexisting,
                                    "timing_ratio": ratio,
                                },
                            )
                        )

            except Exception as e:
                logger.debug("timing_oracle_test_error", error=str(e))

        return findings

    async def _attack_clipboard_hijacking_check(
        self,
        url: str,
        html_content: str,
        scripts: list[str],
    ) -> list[Finding]:
        """
        Attack 20: Clipboard Hijacking Check.

        Test if site can read clipboard without permission (deprecated API abuse).

        CWE-200: Exposure of Sensitive Information
        """
        findings: list[Finding] = []

        # Check for clipboard access patterns in scripts
        clipboard_patterns = [
            r"navigator\.clipboard",
            r"document\.execCommand\(['\"]copy",
            r"document\.execCommand\(['\"]paste",
            r"clipboardData",
            r"ClipboardEvent",
            r"\.getData\(['\"]text",
            r"window\.clipboardData",
        ]

        suspicious_scripts: list[str] = []

        # Check inline scripts in HTML
        for pattern in clipboard_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                suspicious_scripts.append(f"HTML contains: {pattern}")

        # Check external scripts
        for script in scripts:
            if isinstance(script, str):
                for pattern in clipboard_patterns:
                    if re.search(pattern, script, re.IGNORECASE):
                        suspicious_scripts.append(f"Script contains: {pattern}")
                        break

        if suspicious_scripts:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Clipboard Access Detected",
                    description=(
                        f"Page contains {len(suspicious_scripts)} clipboard access patterns. "
                        "While modern APIs require permission, legacy APIs may be exploitable. "
                        "Patterns found: " + "; ".join(suspicious_scripts[:3])
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    url=url,
                    evidence=f"Clipboard patterns: {len(suspicious_scripts)}",
                    remediation=(
                        "Use Permissions API for clipboard access. "
                        "Never read clipboard without explicit user action. "
                        "Display what data was read from clipboard."
                    ),
                    cvss_score=3.1,
                    metadata={"patterns_found": suspicious_scripts},
                )
            )

        return findings

    def _attack_browser_history_sniffing(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """
        Attack 21: Browser History Sniffing.

        Check for CSS visited link timing attacks (:visited abuse).

        CWE-200: Exposure of Sensitive Information
        """
        findings: list[Finding] = []

        # Check for :visited CSS abuse patterns
        history_sniffing_patterns = [
            r":visited\s*\{[^}]*background",
            r":visited\s*\{[^}]*color\s*:",
            r":visited\s*\{[^}]*width",
            r":visited\s*\{[^}]*height",
            r":visited\s*\{[^}]*position",
            r"getComputedStyle.*:visited",
        ]

        suspicious_patterns: list[str] = []

        for pattern in history_sniffing_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                suspicious_patterns.append(pattern)

        # Check for suspicious link grids (many hidden links)
        hidden_link_pattern = r'<a[^>]*style=["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*href'
        if re.search(hidden_link_pattern, html_content, re.IGNORECASE):
            suspicious_patterns.append("hidden links detected")

        link_count = len(re.findall(r'<a\s+[^>]*href', html_content, re.IGNORECASE))
        if link_count > 50 and "display:none" in html_content.lower():
            suspicious_patterns.append(f"high link count ({link_count}) with hidden elements")

        if suspicious_patterns:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Potential Browser History Sniffing",
                    description=(
                        "Page contains patterns consistent with browser history sniffing attacks. "
                        f"Suspicious patterns: {', '.join(suspicious_patterns[:3])}. "
                        "Modern browsers limit :visited styling, but legacy attacks may work."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    url=url,
                    evidence=f"Patterns: {len(suspicious_patterns)}",
                    remediation=(
                        "Remove :visited styling that could leak information. "
                        "Do not use hidden links to probe history. "
                        "Follow privacy-respecting design principles."
                    ),
                    cvss_score=3.1,
                    metadata={"suspicious_patterns": suspicious_patterns},
                )
            )

        return findings

    def _attack_autofill_harvesting(
        self,
        url: str,
        html_content: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 22: Autofill Harvesting.

        Check for hidden form fields that capture browser autofill data.

        CWE-200: Exposure of Sensitive Information
        """
        findings: list[Finding] = []

        # Check for hidden autofill-targeted fields
        autofill_field_names = [
            "email", "mail", "e-mail",
            "password", "passwd", "pass",
            "credit", "card", "cc-",
            "address", "street", "city", "zip", "postal",
            "phone", "tel", "mobile",
            "ssn", "social", "security",
            "name", "firstname", "lastname",
        ]

        # Check HTML for hidden fields with autofill names
        hidden_autofill_fields: list[str] = []

        # Pattern for hidden inputs
        hidden_input_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']'
        hidden_matches = re.findall(hidden_input_pattern, html_content, re.IGNORECASE)

        for field_name in hidden_matches:
            for autofill_name in autofill_field_names:
                if autofill_name in field_name.lower():
                    hidden_autofill_fields.append(field_name)
                    break

        # Check for off-screen positioned fields
        offscreen_pattern = r'<input[^>]*style=["\'][^"\']*(?:left:\s*-\d+|position:\s*absolute)[^"\']*["\'][^>]*name=["\']([^"\']+)["\']'
        offscreen_matches = re.findall(offscreen_pattern, html_content, re.IGNORECASE)

        for field_name in offscreen_matches:
            for autofill_name in autofill_field_names:
                if autofill_name in field_name.lower():
                    hidden_autofill_fields.append(f"{field_name} (offscreen)")
                    break

        # Check form data
        for form in forms:
            if not isinstance(form, dict):
                continue

            inputs = form.get("inputs", [])
            for inp in inputs:
                if not isinstance(inp, dict):
                    continue

                name = inp.get("name", "").lower()
                input_type = inp.get("type", "").lower()

                # Hidden or off-screen with autofill name
                if input_type == "hidden":
                    for autofill_name in autofill_field_names:
                        if autofill_name in name:
                            hidden_autofill_fields.append(name)
                            break

        if hidden_autofill_fields:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="Hidden Autofill Harvesting Fields Detected",
                    description=(
                        f"Page contains {len(hidden_autofill_fields)} hidden fields with autofill-targeted names: "
                        f"{', '.join(hidden_autofill_fields[:5])}. "
                        "These may silently capture sensitive data from browser autofill."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    url=url,
                    evidence=f"Hidden autofill fields: {', '.join(hidden_autofill_fields)}",
                    remediation=(
                        "Remove hidden fields with sensitive-data names. "
                        "Use autocomplete='off' where appropriate. "
                        "Audit all form fields for necessity."
                    ),
                    cvss_score=7.5,
                    metadata={"hidden_fields": hidden_autofill_fields},
                )
            )

        return findings

    async def _attack_serviceworker_persistence(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 23: ServiceWorker Persistence Check.

        Check if malicious ServiceWorker could be registered for persistence.

        CWE-284: Improper Access Control
        """
        findings: list[Finding] = []

        try:
            with _get_browser_instance() as browser:
                page = browser.new_page()
                page.goto(url, timeout=self.config.timeout * 1000)

                # Wait for page to settle
                with contextlib.suppress(Exception):
                    page.wait_for_network_idle(idle_time=500, timeout=5000)

                # Check for service worker registrations and scope
                sw_check_script = """
                (() => {
                    const results = {
                        hasServiceWorker: false,
                        registrations: [],
                        scope: null,
                        canRegister: false,
                        swScripts: []
                    };

                    // Check for existing SW
                    if ('serviceWorker' in navigator) {
                        results.hasServiceWorker = true;

                        // Look for SW registration scripts
                        const scripts = document.querySelectorAll('script');
                        scripts.forEach(s => {
                            if (s.textContent && s.textContent.includes('serviceWorker.register')) {
                                results.swScripts.push(s.textContent.substring(0, 200));
                            }
                        });
                    }

                    // Check scope
                    results.scope = window.location.origin;

                    return results;
                })()
                """

                result = page.evaluate(sw_check_script, return_value=True)
                page.close()

                if isinstance(result, dict):
                    if result.get("swScripts"):
                        findings.append(
                            self._create_finding(
                                severity=Severity.INFO,
                                title="ServiceWorker Registration Detected",
                                description=(
                                    f"Page registers a ServiceWorker. Scope: {result.get('scope')}. "
                                    "ServiceWorkers provide persistence and can intercept requests. "
                                    "If compromised, they enable persistent XSS and MITM."
                                ),
                                cwe_id="CWE-284",
                                cwe_name="Improper Access Control",
                                url=url,
                                evidence=f"SW scripts found: {len(result.get('swScripts', []))}",
                                remediation=(
                                    "Audit ServiceWorker code for security issues. "
                                    "Implement CSP to restrict SW sources. "
                                    "Use subresource integrity for SW scripts."
                                ),
                                cvss_score=3.1,
                                metadata={"scope": result.get("scope"), "sw_count": len(result.get("swScripts", []))},
                            )
                        )

        except Exception as e:
            logger.debug("serviceworker_check_error", error=str(e))

        return findings

    def _attack_postmessage_origin_bypass(
        self,
        url: str,
        html_content: str,
        scripts: list[str],
    ) -> list[Finding]:
        """
        Attack 24: PostMessage Origin Bypass.

        Test window.postMessage handlers for origin validation.

        CWE-346: Origin Validation Error
        """
        findings: list[Finding] = []

        # Check for postMessage handlers without origin checks
        postmessage_patterns = [
            # Handler without origin check
            r'addEventListener\(["\']message["\'],\s*function\s*\([^)]*\)\s*\{(?:(?!origin).)*\}',
            r'addEventListener\(["\']message["\'],\s*\([^)]*\)\s*=>\s*\{(?:(?!origin).)*\}',
            r'onmessage\s*=\s*function\s*\([^)]*\)\s*\{(?:(?!origin).)*\}',
            # Wildcard origin
            r'\.postMessage\([^,]+,\s*["\'\*]',
        ]

        vulnerable_patterns: list[str] = []

        # Check HTML content
        for pattern in postmessage_patterns:
            if re.search(pattern, html_content, re.IGNORECASE | re.DOTALL):
                vulnerable_patterns.append(f"HTML: {pattern[:50]}")

        # Check external scripts
        for script in scripts:
            if isinstance(script, str):
                for pattern in postmessage_patterns:
                    if re.search(pattern, script, re.IGNORECASE | re.DOTALL):
                        vulnerable_patterns.append(f"Script: {pattern[:50]}")
                        break

        # Check for message handlers generally
        general_postmessage = r'addEventListener\(["\']message'
        has_handler = bool(re.search(general_postmessage, html_content, re.IGNORECASE))

        # Check for origin validation
        origin_check = r'\.origin\s*[!=]==?\s*["\']'
        has_origin_check = bool(re.search(origin_check, html_content, re.IGNORECASE))

        if has_handler and not has_origin_check:
            vulnerable_patterns.append("message handler without visible origin check")

        if vulnerable_patterns:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="PostMessage Handler Missing Origin Validation",
                    description=(
                        f"Page has {len(vulnerable_patterns)} postMessage handlers potentially missing origin validation. "
                        "Patterns: " + "; ".join(vulnerable_patterns[:3]) + ". "
                        "This enables cross-origin message injection attacks."
                    ),
                    cwe_id="CWE-346",
                    cwe_name="Origin Validation Error",
                    url=url,
                    evidence=f"Vulnerable patterns: {len(vulnerable_patterns)}",
                    remediation=(
                        "Always validate event.origin in message handlers. "
                        "Use allowlist of trusted origins. "
                        "Never use '*' as target origin in postMessage."
                    ),
                    cvss_score=7.5,
                    metadata={"patterns": vulnerable_patterns},
                )
            )

        return findings

    def _attack_drag_drop_data_exfil(
        self,
        url: str,
        html_content: str,
        scripts: list[str],
    ) -> list[Finding]:
        """
        Attack 25: Drag-Drop Data Exfiltration.

        Test if drag events leak sensitive data across origins.

        CWE-200: Exposure of Sensitive Information
        """
        findings: list[Finding] = []

        # Check for drag event handlers that may leak data
        drag_patterns = [
            r'ondragstart\s*=',
            r'ondrag\s*=',
            r'ondragend\s*=',
            r'addEventListener\(["\']dragstart',
            r'addEventListener\(["\']drag["\']',
            r'dataTransfer\.setData',
            r'dataTransfer\.getData',
        ]

        # Sensitive data patterns in drag context
        sensitive_drag_patterns = [
            r'dataTransfer\.setData\([^)]*(?:token|auth|session|key|password)',
            r'dataTransfer\.setData\([^)]*document\.cookie',
            r'dataTransfer\.setData\([^)]*localStorage',
            r'dataTransfer\.setData\([^)]*JSON\.stringify',
        ]

        found_drag_handlers: list[str] = []
        sensitive_leaks: list[str] = []

        # Check HTML
        for pattern in drag_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                found_drag_handlers.append(pattern)

        for pattern in sensitive_drag_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                sensitive_leaks.append(pattern)

        # Check scripts
        for script in scripts:
            if isinstance(script, str):
                for pattern in drag_patterns:
                    if re.search(pattern, script, re.IGNORECASE):
                        found_drag_handlers.append(f"script:{pattern}")
                        break

                for pattern in sensitive_drag_patterns:
                    if re.search(pattern, script, re.IGNORECASE):
                        sensitive_leaks.append(f"script:{pattern}")
                        break

        if sensitive_leaks:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="Sensitive Data Exposed via Drag Events",
                    description=(
                        f"Page exposes sensitive data through drag-and-drop events. "
                        f"Found {len(sensitive_leaks)} sensitive data transfer patterns. "
                        "Drag data can be read by cross-origin drop targets."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    url=url,
                    evidence=f"Sensitive patterns: {', '.join(sensitive_leaks[:3])}",
                    remediation=(
                        "Never put sensitive data in drag transfer. "
                        "Use token references instead of actual secrets. "
                        "Validate drop targets before data transfer."
                    ),
                    cvss_score=7.5,
                    metadata={
                        "drag_handlers": found_drag_handlers,
                        "sensitive_patterns": sensitive_leaks,
                    },
                )
            )
        elif found_drag_handlers:
            findings.append(
                self._create_finding(
                    severity=Severity.INFO,
                    title="Drag-and-Drop Handlers Detected",
                    description=(
                        f"Page implements drag-and-drop functionality with {len(found_drag_handlers)} handlers. "
                        "Review drag data for sensitive information exposure."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    url=url,
                    evidence=f"Drag handlers: {len(found_drag_handlers)}",
                    remediation="Audit drag data for sensitive content exposure.",
                    cvss_score=0.0,
                    metadata={"drag_handlers": found_drag_handlers},
                )
            )

        return findings
