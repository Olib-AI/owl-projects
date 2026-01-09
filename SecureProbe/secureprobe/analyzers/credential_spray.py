"""
Credential Spray Analyzer.

Detects login forms and tests common/default credentials that attackers
typically try first. ACTIVE MODE ONLY - requires explicit authorization.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlparse

import httpx
import structlog

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "python-sdk"))

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, ScanMode, Severity
from secureprobe.utils import safe_response_text

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Credential:
    """Username/password credential pair."""

    username: str
    password: str
    category: str = "generic"

    def __str__(self) -> str:
        return f"{self.username}:{self.password}"


@dataclass(slots=True)
class LoginAttemptResult:
    """Result of a single login attempt."""

    credential: Credential
    success: bool
    response_length: int
    status_code: int
    redirect_url: str | None = None
    has_session_cookie: bool = False
    success_indicators: list[str] = field(default_factory=list)
    failure_indicators: list[str] = field(default_factory=list)
    lockout_detected: bool = False


@dataclass(slots=True)
class LoginFormInfo:
    """Detected login form information."""

    form_url: str
    action_url: str
    method: str
    username_field: str
    password_field: str
    extra_fields: dict[str, str] = field(default_factory=dict)
    csrf_token_field: str | None = None
    csrf_token_value: str | None = None


class CredentialSprayAnalyzer(BaseAnalyzer):
    """
    Analyzer for testing default and common credentials.

    ACTIVE MODE ONLY: This analyzer performs actual login attempts
    and requires explicit authorization before use.

    Checks for:
    - Default administrative credentials (CWE-798)
    - Common weak passwords (CWE-521)
    - Technology-specific defaults (CWE-1188)
    - Business name-based credentials
    - Year-based password patterns
    """

    analyzer_type = AnalyzerType.CREDENTIAL_SPRAY

    # Login page URL patterns
    LOGIN_URL_PATTERNS: Final[frozenset[str]] = frozenset({
        "login", "signin", "sign-in", "auth", "authenticate",
        "logon", "log-on", "session", "account", "access",
        "admin", "portal", "sso", "oauth", "connect",
    })

    # Login form detection patterns
    LOGIN_FORM_INDICATORS: Final[frozenset[str]] = frozenset({
        "login", "signin", "log in", "sign in", "authenticate",
        "credentials", "username", "password", "enter your",
    })

    # Success indicators in response
    SUCCESS_INDICATORS: Final[tuple[str, ...]] = (
        "welcome", "dashboard", "logout", "sign out", "log out",
        "my account", "profile", "settings", "home page",
        "successfully logged", "login successful", "authenticated",
    )

    # Failure indicators in response
    FAILURE_INDICATORS: Final[tuple[str, ...]] = (
        "invalid", "incorrect", "failed", "error", "wrong",
        "unauthorized", "denied", "bad credentials", "try again",
        "does not match", "not found", "unknown user",
    )

    # Lockout indicators
    LOCKOUT_INDICATORS: Final[tuple[str, ...]] = (
        "locked", "blocked", "too many attempts", "rate limit",
        "temporarily disabled", "account suspended", "wait",
        "try again later", "exceeded", "maximum attempts",
    )

    # Generic default credentials
    GENERIC_CREDENTIALS: Final[tuple[Credential, ...]] = (
        Credential("admin", "admin", "generic_default"),
        Credential("admin", "password", "generic_default"),
        Credential("admin", "123456", "generic_default"),
        Credential("admin", "admin123", "generic_default"),
        Credential("admin", "password123", "generic_default"),
        Credential("root", "root", "generic_default"),
        Credential("root", "toor", "generic_default"),
        Credential("root", "password", "generic_default"),
        Credential("test", "test", "generic_default"),
        Credential("user", "user", "generic_default"),
        Credential("guest", "guest", "generic_default"),
        Credential("administrator", "administrator", "generic_default"),
        Credential("demo", "demo", "generic_default"),
        Credential("trial", "trial", "generic_default"),
    )

    # Keyboard pattern passwords
    KEYBOARD_PATTERNS: Final[tuple[str, ...]] = (
        "qwerty", "123456", "password1", "letmein",
        "abc123", "monkey", "dragon", "master",
        "qwerty123", "password!", "passw0rd",
    )

    # Year-based patterns
    YEAR_PATTERNS: Final[tuple[str, ...]] = (
        "2024", "2025", "2023",
    )

    # Technology-specific defaults
    TECH_CREDENTIALS: Final[tuple[Credential, ...]] = (
        Credential("postgres", "postgres", "database"),
        Credential("mysql", "mysql", "database"),
        Credential("sa", "sa", "database"),
        Credential("admin", "admin123", "application"),
        Credential("weblogic", "weblogic", "middleware"),
        Credential("tomcat", "tomcat", "middleware"),
        Credential("manager", "manager", "middleware"),
        Credential("cisco", "cisco", "network"),
        Credential("admin", "default", "device"),
    )

    # Common username field names
    USERNAME_FIELD_PATTERNS: Final[tuple[str, ...]] = (
        "username", "user", "email", "login", "userid", "user_id",
        "uname", "account", "name", "usr", "id", "mail",
    )

    # Common password field names
    PASSWORD_FIELD_PATTERNS: Final[tuple[str, ...]] = (
        "password", "passwd", "pass", "pwd", "secret", "credential",
    )

    def __init__(self, config: Any) -> None:
        """Initialize credential spray analyzer."""
        super().__init__(config)
        self._http_client: httpx.AsyncClient | None = None
        self._baseline_response_length: int = 0
        self._attempts_made: int = 0
        self._max_attempts: int = 50
        self._delay_between_attempts: float = 1.0
        self._lockout_detected: bool = False

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Analyze page for login forms and test credentials.

        Args:
            url: Current page URL
            page_data: Page data containing HTML, forms, etc.

        Returns:
            List of findings for weak/default credentials
        """
        findings: list[Finding] = []
        scan_mode = page_data.get("scan_mode", "passive")

        # CRITICAL: Only run in ACTIVE mode
        if scan_mode != ScanMode.ACTIVE.value:
            self.logger.debug(
                "credential_spray_skipped",
                reason="Requires ACTIVE scan mode",
                url=url,
            )
            return findings

        html = page_data.get("html", "")
        forms = page_data.get("forms", [])

        # Detect login forms
        login_forms = self._detect_login_forms(url, html, forms)

        if not login_forms:
            self.logger.debug("no_login_forms_detected", url=url)
            return findings

        # Extract business name for targeted credentials
        business_name = self._extract_business_name(url, html)
        self.logger.info(
            "login_forms_detected",
            url=url,
            form_count=len(login_forms),
            business_name=business_name,
        )

        # Build credential list
        credentials = self._build_credential_list(business_name)

        # Test each login form
        for login_form in login_forms:
            form_findings = await self._test_login_form(
                login_form, credentials, page_data
            )
            findings.extend(form_findings)

            if self._lockout_detected:
                self.logger.warning(
                    "lockout_detected_stopping",
                    url=url,
                    attempts_made=self._attempts_made,
                )
                break

        return findings

    def _detect_login_forms(
        self,
        url: str,
        html: str,
        forms: list[dict[str, Any]],
    ) -> list[LoginFormInfo]:
        """
        Detect login forms on the page.

        Args:
            url: Page URL
            html: HTML content
            forms: Extracted form data

        Returns:
            List of detected login forms
        """
        login_forms: list[LoginFormInfo] = []

        # Check URL for login indicators
        url_lower = url.lower()
        is_login_url = any(pattern in url_lower for pattern in self.LOGIN_URL_PATTERNS)

        # Analyze structured form data
        for form in forms:
            if not isinstance(form, dict):
                continue

            inputs = form.get("inputs", [])
            has_password = False
            username_field: str | None = None
            password_field: str | None = None
            extra_fields: dict[str, str] = {}
            csrf_field: str | None = None
            csrf_value: str | None = None

            for input_data in inputs:
                if not isinstance(input_data, dict):
                    continue

                input_name = input_data.get("name", "").lower()
                input_type = input_data.get("type", "").lower()

                # Detect password field
                if input_type == "password":
                    has_password = True
                    password_field = input_data.get("name", "")
                    continue

                # Detect username field
                if any(
                    pattern in input_name for pattern in self.USERNAME_FIELD_PATTERNS
                ):
                    username_field = input_data.get("name", "")
                    continue

                # Detect CSRF token
                if input_type == "hidden":
                    if any(
                        csrf in input_name
                        for csrf in ("csrf", "token", "_token", "xsrf", "nonce")
                    ):
                        csrf_field = input_data.get("name", "")
                        # CSRF value needs to be extracted from HTML
                        continue

                # Capture other hidden fields
                if input_type == "hidden" and input_name:
                    extra_fields[input_data.get("name", "")] = ""

            if has_password:
                action = form.get("action", url)
                method = form.get("method", "POST").upper()

                # Extract CSRF token value from HTML if field detected
                if csrf_field:
                    csrf_value = self._extract_csrf_value(html, csrf_field)

                login_forms.append(
                    LoginFormInfo(
                        form_url=url,
                        action_url=action if action else url,
                        method=method,
                        username_field=username_field or "username",
                        password_field=password_field or "password",
                        extra_fields=extra_fields,
                        csrf_token_field=csrf_field,
                        csrf_token_value=csrf_value,
                    )
                )

        # If no forms found via structured data, try HTML parsing
        if not login_forms:
            login_forms.extend(self._parse_login_forms_from_html(url, html))

        # Filter: if not a login URL, require explicit login indicators
        if not is_login_url and login_forms:
            html_lower = html.lower()
            has_login_indicator = any(
                ind in html_lower for ind in self.LOGIN_FORM_INDICATORS
            )
            if not has_login_indicator:
                # Not clearly a login form, be conservative
                return []

        return login_forms

    def _parse_login_forms_from_html(
        self,
        url: str,
        html: str,
    ) -> list[LoginFormInfo]:
        """Parse login forms directly from HTML content."""
        login_forms: list[LoginFormInfo] = []

        # Find all forms with password fields
        form_pattern = r"<form[^>]*>(.*?)</form>"
        forms = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)

        form_tag_pattern = r"<form([^>]*)>"
        form_tags = re.findall(form_tag_pattern, html, re.IGNORECASE)

        for form_attrs, form_content in zip(form_tags, forms, strict=False):
            # Check for password input
            if not re.search(
                r'<input[^>]*type\s*=\s*["\']?password', form_content, re.IGNORECASE
            ):
                continue

            # Extract form attributes
            action_match = re.search(
                r'action\s*=\s*["\']?([^"\'>\s]+)', form_attrs, re.IGNORECASE
            )
            method_match = re.search(
                r'method\s*=\s*["\']?([^"\'>\s]+)', form_attrs, re.IGNORECASE
            )

            action = action_match.group(1) if action_match else url
            method = (method_match.group(1) if method_match else "POST").upper()

            # Find username field
            username_field = self._find_username_field_in_html(form_content)
            password_field = self._find_password_field_in_html(form_content)

            # Find CSRF token
            csrf_field, csrf_value = self._find_csrf_in_html(form_content)

            login_forms.append(
                LoginFormInfo(
                    form_url=url,
                    action_url=action,
                    method=method,
                    username_field=username_field,
                    password_field=password_field,
                    csrf_token_field=csrf_field,
                    csrf_token_value=csrf_value,
                )
            )

        return login_forms

    def _find_username_field_in_html(self, form_content: str) -> str:
        """Find username/email field name in form HTML."""
        for pattern in self.USERNAME_FIELD_PATTERNS:
            match = re.search(
                rf'<input[^>]*name\s*=\s*["\']?([^"\'>\s]*{pattern}[^"\'>\s]*)',
                form_content,
                re.IGNORECASE,
            )
            if match:
                return match.group(1)

        # Fallback: find any text/email input
        match = re.search(
            r'<input[^>]*type\s*=\s*["\']?(?:text|email)["\']?[^>]*name\s*=\s*["\']?([^"\'>\s]+)',
            form_content,
            re.IGNORECASE,
        )
        return match.group(1) if match else "username"

    def _find_password_field_in_html(self, form_content: str) -> str:
        """Find password field name in form HTML."""
        match = re.search(
            r'<input[^>]*type\s*=\s*["\']?password["\']?[^>]*name\s*=\s*["\']?([^"\'>\s]+)',
            form_content,
            re.IGNORECASE,
        )
        if match:
            return match.group(1)

        # Alternative: name before type
        match = re.search(
            r'<input[^>]*name\s*=\s*["\']?([^"\'>\s]+)["\']?[^>]*type\s*=\s*["\']?password',
            form_content,
            re.IGNORECASE,
        )
        return match.group(1) if match else "password"

    def _find_csrf_in_html(self, form_content: str) -> tuple[str | None, str | None]:
        """Find CSRF token field and value in form HTML."""
        csrf_patterns = [
            r'<input[^>]*name\s*=\s*["\']?([^"\'>\s]*(?:csrf|token|_token|xsrf)[^"\'>\s]*)["\']?[^>]*value\s*=\s*["\']?([^"\'>\s]+)',
            r'<input[^>]*value\s*=\s*["\']?([^"\'>\s]+)["\']?[^>]*name\s*=\s*["\']?([^"\'>\s]*(?:csrf|token|_token|xsrf)[^"\'>\s]*)',
        ]

        for pattern in csrf_patterns:
            match = re.search(pattern, form_content, re.IGNORECASE)
            if match:
                groups = match.groups()
                # Determine which group is name vs value
                if "csrf" in groups[0].lower() or "token" in groups[0].lower():
                    return groups[0], groups[1]
                return groups[1], groups[0]

        return None, None

    def _extract_csrf_value(self, html: str, csrf_field: str) -> str | None:
        """Extract CSRF token value from HTML for a given field name."""
        patterns = [
            rf'<input[^>]*name\s*=\s*["\']?{re.escape(csrf_field)}["\']?[^>]*value\s*=\s*["\']?([^"\'>\s]+)',
            rf'<input[^>]*value\s*=\s*["\']?([^"\'>\s]+)["\']?[^>]*name\s*=\s*["\']?{re.escape(csrf_field)}',
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _extract_business_name(self, url: str, html: str) -> str | None:
        """
        Extract business/company name for targeted credential generation.

        Sources:
        - Domain name
        - Page title
        - Meta tags
        - Copyright footer
        """
        candidates: list[str] = []

        # Extract from domain
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove common TLDs and subdomains
        domain_parts = domain.replace("www.", "").split(".")
        if domain_parts:
            main_domain = domain_parts[0]
            if len(main_domain) >= 3 and main_domain not in ("com", "org", "net", "gov", "edu"):
                candidates.append(main_domain)

        # Extract from title
        title_match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        if title_match:
            title = title_match.group(1).strip()
            # Extract first significant word
            title_words = re.findall(r"\b[A-Za-z]{3,}\b", title)
            if title_words:
                candidates.append(title_words[0].lower())

        # Extract from meta tags
        meta_patterns = [
            r'<meta[^>]*name\s*=\s*["\']?(?:author|company|application-name)["\']?[^>]*content\s*=\s*["\']([^"\']+)',
            r'<meta[^>]*property\s*=\s*["\']?og:site_name["\']?[^>]*content\s*=\s*["\']([^"\']+)',
        ]
        for pattern in meta_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                name = match.group(1).strip().lower()
                if len(name) >= 3:
                    # Extract first word
                    first_word = re.match(r"[a-z]+", name)
                    if first_word:
                        candidates.append(first_word.group(0))

        # Extract from copyright
        copyright_pattern = r"(?:copyright|&copy;|\xa9)\s*(?:\d{4}\s*)?([A-Za-z][A-Za-z\s]{2,20})"
        copyright_match = re.search(copyright_pattern, html, re.IGNORECASE)
        if copyright_match:
            company = copyright_match.group(1).strip().lower()
            first_word = re.match(r"[a-z]+", company)
            if first_word:
                candidates.append(first_word.group(0))

        # Return the most promising candidate
        if candidates:
            # Prefer longer names, dedupe
            unique_candidates = list(dict.fromkeys(candidates))
            return max(unique_candidates, key=len)

        return None

    def _build_credential_list(
        self,
        business_name: str | None,
    ) -> list[Credential]:
        """
        Build comprehensive credential list for testing.

        Args:
            business_name: Extracted business name for targeted credentials

        Returns:
            Prioritized list of credentials to test
        """
        credentials: list[Credential] = []

        # 1. Generic defaults (highest priority)
        credentials.extend(self.GENERIC_CREDENTIALS)

        # 2. Tech-specific defaults
        credentials.extend(self.TECH_CREDENTIALS)

        # 3. Year-based patterns with admin
        for year in self.YEAR_PATTERNS:
            credentials.extend([
                Credential("admin", year, "year_pattern"),
                Credential("admin", f"password{year}", "year_pattern"),
            ])

        # 4. Keyboard patterns with admin
        for pattern in self.KEYBOARD_PATTERNS:
            credentials.append(Credential("admin", pattern, "keyboard_pattern"))

        # 5. Business name variations
        if business_name:
            bn = business_name.lower()
            business_creds = [
                Credential(bn, "password", "business"),
                Credential(bn, bn, "business"),
                Credential(bn, "123456", "business"),
                Credential("admin", bn, "business"),
                Credential(f"{bn}admin", "password", "business"),
                Credential(f"{bn}admin", bn, "business"),
            ]
            # Add year variations
            for year in self.YEAR_PATTERNS[:2]:
                business_creds.extend([
                    Credential(bn, f"{bn}{year}", "business_year"),
                    Credential(bn, year, "business_year"),
                    Credential("admin", f"{bn}{year}", "business_year"),
                ])
            credentials.extend(business_creds)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_credentials: list[Credential] = []
        for cred in credentials:
            key = f"{cred.username}:{cred.password}"
            if key not in seen:
                seen.add(key)
                unique_credentials.append(cred)

        return unique_credentials

    async def _test_login_form(
        self,
        login_form: LoginFormInfo,
        credentials: Sequence[Credential],
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Test login form with credential list.

        Args:
            login_form: Login form information
            credentials: Credentials to test
            page_data: Original page data

        Returns:
            Findings for successful credential attempts
        """
        findings: list[Finding] = []

        # Initialize HTTP client
        async with httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=self.config.timeout,
            follow_redirects=False,  # Handle redirects manually
        ) as client:
            self._http_client = client

            # Establish baseline (failed login)
            baseline = await self._get_baseline_response(login_form)

            # Test credentials
            for credential in credentials:
                if self._lockout_detected:
                    break

                if self._attempts_made >= self._max_attempts:
                    self.logger.warning(
                        "max_attempts_reached",
                        max=self._max_attempts,
                    )
                    break

                result = await self._attempt_login(
                    login_form, credential, baseline
                )

                self._attempts_made += 1

                if result.lockout_detected:
                    self._lockout_detected = True
                    findings.append(
                        self._create_lockout_finding(login_form.form_url, credential)
                    )
                    break

                if result.success:
                    findings.append(
                        self._create_credential_finding(
                            login_form, credential, result
                        )
                    )
                    self.logger.critical(
                        "default_credential_found",
                        url=login_form.action_url,
                        username=credential.username,
                        category=credential.category,
                    )

                # Rate limiting delay
                await asyncio.sleep(self._delay_between_attempts)

            self._http_client = None

        return findings

    async def _get_baseline_response(
        self,
        login_form: LoginFormInfo,
    ) -> LoginAttemptResult:
        """Get baseline response with known-invalid credentials."""
        invalid_cred = Credential(
            "invalid_user_12345",
            "invalid_pass_67890_xyz",
            "baseline",
        )
        return await self._attempt_login(login_form, invalid_cred, baseline=None)

    async def _attempt_login(
        self,
        login_form: LoginFormInfo,
        credential: Credential,
        baseline: LoginAttemptResult | None,
    ) -> LoginAttemptResult:
        """
        Attempt a single login with given credentials.

        Args:
            login_form: Login form details
            credential: Credentials to try
            baseline: Baseline failed response for comparison

        Returns:
            Login attempt result
        """
        if self._http_client is None:
            raise RuntimeError("HTTP client not initialized")

        # Build form data
        form_data: dict[str, str] = {
            login_form.username_field: credential.username,
            login_form.password_field: credential.password,
        }

        # Add extra fields
        form_data.update(login_form.extra_fields)

        # Add CSRF token if present
        if login_form.csrf_token_field and login_form.csrf_token_value:
            form_data[login_form.csrf_token_field] = login_form.csrf_token_value

        try:
            if login_form.method == "POST":
                response = await self._http_client.post(
                    login_form.action_url,
                    data=form_data,
                    headers={
                        "User-Agent": self.config.user_agent,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
            else:
                response = await self._http_client.get(
                    login_form.action_url,
                    params=form_data,
                    headers={"User-Agent": self.config.user_agent},
                )

            response_text = safe_response_text(response).lower()
            response_length = len(response_text)
            status_code = response.status_code

            # Check for lockout
            lockout_detected = any(
                ind in response_text for ind in self.LOCKOUT_INDICATORS
            )

            # Check redirect
            redirect_url: str | None = None
            if status_code in (301, 302, 303, 307, 308):
                redirect_url = response.headers.get("location")

            # Check for session cookie
            has_session_cookie = self._detect_session_cookie(response)

            # Analyze success/failure indicators
            success_indicators = [
                ind for ind in self.SUCCESS_INDICATORS if ind in response_text
            ]
            failure_indicators = [
                ind for ind in self.FAILURE_INDICATORS if ind in response_text
            ]

            # Determine success
            success = self._determine_login_success(
                baseline=baseline,
                response_length=response_length,
                status_code=status_code,
                redirect_url=redirect_url,
                has_session_cookie=has_session_cookie,
                success_indicators=success_indicators,
                failure_indicators=failure_indicators,
            )

            return LoginAttemptResult(
                credential=credential,
                success=success,
                response_length=response_length,
                status_code=status_code,
                redirect_url=redirect_url,
                has_session_cookie=has_session_cookie,
                success_indicators=success_indicators,
                failure_indicators=failure_indicators,
                lockout_detected=lockout_detected,
            )

        except httpx.RequestError as e:
            self.logger.debug(
                "login_attempt_failed",
                error=str(e),
                credential=str(credential),
            )
            return LoginAttemptResult(
                credential=credential,
                success=False,
                response_length=0,
                status_code=0,
            )

    def _detect_session_cookie(self, response: httpx.Response) -> bool:
        """Detect if response sets a session cookie."""
        session_indicators = (
            "session", "sess", "sid", "auth", "token", "jwt",
            "login", "user", "identity",
        )

        for cookie in response.cookies:
            cookie_name = cookie.lower() if isinstance(cookie, str) else ""
            if any(ind in cookie_name for ind in session_indicators):
                return True

        # Check Set-Cookie headers
        set_cookies = response.headers.get_list("set-cookie")
        for cookie_header in set_cookies:
            cookie_lower = cookie_header.lower()
            if any(ind in cookie_lower for ind in session_indicators):
                return True

        return False

    def _determine_login_success(
        self,
        baseline: LoginAttemptResult | None,
        response_length: int,
        status_code: int,
        redirect_url: str | None,
        has_session_cookie: bool,
        success_indicators: list[str],
        failure_indicators: list[str],
    ) -> bool:
        """
        Determine if login was successful based on response analysis.

        Uses multiple signals:
        - Response length difference from baseline
        - Redirect to dashboard/home
        - Session cookie set
        - Success indicators present
        - No failure indicators
        """
        score = 0

        # Failure indicators are strong negative signal
        if failure_indicators:
            return False

        # Success indicators present
        if success_indicators:
            score += 3

        # Session cookie set
        if has_session_cookie:
            score += 2

        # Redirect to dashboard-like URL
        if redirect_url:
            redirect_lower = redirect_url.lower()
            dashboard_patterns = (
                "dashboard", "home", "main", "portal", "account",
                "profile", "welcome", "index", "admin",
            )
            if any(pattern in redirect_lower for pattern in dashboard_patterns):
                score += 2
            # Redirect away from login page
            if "login" not in redirect_lower and "signin" not in redirect_lower:
                score += 1

        # Response length significantly different from baseline
        if baseline and baseline.response_length > 0:
            length_diff = abs(response_length - baseline.response_length)
            length_ratio = length_diff / baseline.response_length
            if length_ratio > 0.3:  # More than 30% difference
                score += 1

        # 2XX status with positive signals
        if 200 <= status_code < 300 and score >= 2:
            return True

        # 3XX redirect with session cookie
        if 300 <= status_code < 400 and has_session_cookie:
            return True

        return score >= 4

    def _create_credential_finding(
        self,
        login_form: LoginFormInfo,
        credential: Credential,
        result: LoginAttemptResult,
    ) -> Finding:
        """Create finding for successful credential test."""
        return self._create_finding(
            severity=Severity.CRITICAL,
            title=f"Default/Weak Credential: {credential.username}",
            description=(
                f"Login form at {login_form.action_url} accepts default or common "
                f"credential combination. Username '{credential.username}' with "
                f"a {credential.category} password was accepted. "
                "This allows unauthorized access to the application."
            ),
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            url=login_form.form_url,
            evidence=(
                f"Username: {credential.username}; "
                f"Password category: {credential.category}; "
                f"Status: {result.status_code}; "
                f"Session cookie: {result.has_session_cookie}; "
                f"Success indicators: {', '.join(result.success_indicators[:3]) or 'none'}"
            ),
            remediation=(
                "1. Immediately change all default credentials. "
                "2. Implement strong password requirements. "
                "3. Enable multi-factor authentication. "
                "4. Implement account lockout after failed attempts. "
                "5. Monitor for brute-force attacks. "
                "6. Never use default credentials in production."
            ),
            cvss_score=9.8,
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials",
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://cwe.mitre.org/data/definitions/521.html",
            ],
            metadata={
                "credential_category": credential.category,
                "username": credential.username,
                "login_url": login_form.action_url,
                "redirect_url": result.redirect_url,
                "session_cookie_set": result.has_session_cookie,
            },
        )

    def _create_lockout_finding(
        self,
        url: str,
        last_credential: Credential,
    ) -> Finding:
        """Create finding for account lockout detection."""
        return self._create_finding(
            severity=Severity.INFO,
            title="Account Lockout Mechanism Detected",
            description=(
                f"Login form at {url} implements account lockout or rate limiting. "
                "Credential testing was stopped to avoid service disruption. "
                "This is a positive security control."
            ),
            cwe_id="CWE-307",
            cwe_name="Improper Restriction of Excessive Authentication Attempts",
            url=url,
            evidence=(
                f"Lockout detected after {self._attempts_made} attempts; "
                f"Last credential tested: {last_credential.username}"
            ),
            remediation=(
                "Account lockout is properly implemented. Ensure lockout "
                "threshold is appropriate (5-10 attempts) and lockout "
                "duration prevents brute-force attacks."
            ),
            cvss_score=0.0,
            metadata={
                "attempts_before_lockout": self._attempts_made,
                "lockout_detected": True,
            },
        )
