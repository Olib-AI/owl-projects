"""
Form Security Analyzer.

Analyzes HTML forms for CSRF protection, XSS vectors, autocomplete
settings, and input validation issues.
"""

from __future__ import annotations

import re
from typing import Any

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity


class FormAnalyzer(BaseAnalyzer):
    """
    Analyzer for form security issues.

    Checks for:
    - Missing CSRF tokens
    - XSS attack vectors in form inputs
    - Autocomplete on sensitive fields
    - Input validation issues
    - Insecure form actions (HTTP on HTTPS)
    - Missing form validation attributes
    """

    analyzer_type = AnalyzerType.FORM

    # Modern CSRF protection indicators
    JWT_HEADER_PATTERNS = frozenset({
        "authorization",
        "x-auth-token",
        "x-access-token",
        "x-jwt-token",
    })

    # Custom headers that prove same-origin (cannot be set cross-origin without CORS)
    CUSTOM_HEADER_PATTERNS = frozenset({
        "x-requested-with",
        "x-csrf-token",
        "x-xsrf-token",
    })

    CSRF_TOKEN_PATTERNS = [
        r"csrf",
        r"xsrf",
        r"_token",
        r"authenticity_token",
        r"__requestverificationtoken",
        r"antiforgery",
        r"csrfmiddlewaretoken",
        r"_csrf_token",
        r"csrf_token",
        r"__csrf",
        r"nonce",
    ]

    SENSITIVE_INPUT_TYPES = [
        "password",
        "credit-card",
        "cc-number",
        "cc-exp",
        "cc-csc",
        "ssn",
        "social-security",
    ]

    SENSITIVE_INPUT_PATTERNS = [
        r"password",
        r"passwd",
        r"pwd",
        r"secret",
        r"credit",
        r"card",
        r"ccnum",
        r"cvv",
        r"cvc",
        r"csc",
        r"ssn",
        r"social",
        r"pin",
        r"security",
    ]

    XSS_DANGEROUS_ATTRIBUTES = [
        r"on\w+\s*=",
        r"javascript:",
        r"data:",
        r"vbscript:",
    ]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze forms for security issues."""
        findings: list[Finding] = []
        html = page_data.get("html", "")
        forms = page_data.get("forms", [])
        cookies = page_data.get("cookies", [])
        headers = page_data.get("headers", {})

        if not html and not forms:
            return findings

        # Detect alternative CSRF protections at page level
        alt_csrf_info = self._detect_alternative_csrf_protection(cookies, headers, html)

        if isinstance(forms, list) and forms:
            for form in forms:
                if isinstance(form, dict):
                    findings.extend(self._analyze_form_data(url, form, alt_csrf_info))
        else:
            findings.extend(self._analyze_html_forms(url, html, alt_csrf_info))

        return findings

    def _analyze_html_forms(
        self,
        url: str,
        html: str,
        alt_csrf_info: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Analyze forms extracted from HTML."""
        findings: list[Finding] = []
        alt_csrf_info = alt_csrf_info or {}

        form_pattern = r"<form[^>]*>(.*?)</form>"
        forms = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)

        form_tags = re.findall(r"<form([^>]*)>", html, re.IGNORECASE)

        for i, (form_attrs, form_content) in enumerate(zip(form_tags, forms, strict=False)):
            form_id = self._extract_attribute(form_attrs, "id") or f"form_{i}"
            form_action = self._extract_attribute(form_attrs, "action") or url
            form_method = self._extract_attribute(form_attrs, "method") or "get"

            findings.extend(
                self._check_form_security(
                    url, form_id, form_attrs, form_content, form_action, form_method, alt_csrf_info
                )
            )

        return findings

    def _analyze_form_data(
        self,
        url: str,
        form: dict[str, Any],
        alt_csrf_info: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Analyze form from structured data."""
        findings: list[Finding] = []
        alt_csrf_info = alt_csrf_info or {}

        form_id = form.get("id", form.get("name", "unknown_form"))
        form_action = form.get("action", url)
        form_method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])

        if form_method == "post":
            findings.extend(self._check_csrf_in_inputs(url, form_id, inputs, alt_csrf_info))

        for input_data in inputs:
            if isinstance(input_data, dict):
                findings.extend(
                    self._analyze_input(url, form_id, input_data)
                )

        if form_action:
            findings.extend(self._check_form_action(url, form_id, form_action))

        return findings

    def _check_form_security(
        self,
        url: str,
        form_id: str,
        form_attrs: str,
        form_content: str,
        form_action: str,
        form_method: str,
        alt_csrf_info: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Check form for security issues."""
        findings: list[Finding] = []
        alt_csrf_info = alt_csrf_info or {}

        if form_method.lower() == "post":
            has_csrf = self._has_csrf_token(form_content)
            if not has_csrf:
                # Check for JavaScript form submission indicators
                has_js_submit = self._has_javascript_submission(form_attrs, form_content)

                # Determine severity based on alternative protections
                severity, cvss, mitigation_notes = self._assess_csrf_severity(
                    alt_csrf_info, has_js_submit
                )

                description = (
                    f"POST form '{form_id}' does not contain a CSRF token. "
                    "This may make the form vulnerable to Cross-Site Request Forgery attacks."
                )
                if mitigation_notes:
                    description += f" {mitigation_notes}"

                findings.append(
                    self._create_finding(
                        severity=severity,
                        title=f"Form Missing CSRF Token: {form_id}",
                        description=description,
                        cwe_id="CWE-352",
                        cwe_name="Cross-Site Request Forgery (CSRF)",
                        url=url,
                        evidence=f"Form ID: {form_id}; Method: POST; No CSRF token found",
                        remediation=(
                            "Add a CSRF token to the form. Use your framework's built-in "
                            "CSRF protection mechanism."
                        ),
                        cvss_score=cvss,
                        references=[
                            "https://owasp.org/www-community/attacks/csrf",
                        ],
                        metadata={
                            "form_id": form_id,
                            "alternative_protections": alt_csrf_info,
                        },
                    )
                )

        input_pattern = r"<input([^>]*)/?>"
        inputs = re.findall(input_pattern, form_content, re.IGNORECASE)

        for input_attrs in inputs:
            findings.extend(self._analyze_input_attrs(url, form_id, input_attrs))

        if form_action.startswith("http://") and url.startswith("https://"):
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title=f"Form Submits to HTTP from HTTPS: {form_id}",
                    description=(
                        f"Form '{form_id}' on HTTPS page submits to HTTP action. "
                        "Form data will be transmitted in cleartext."
                    ),
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    url=url,
                    evidence=f"Action: {form_action}",
                    remediation="Change form action to use HTTPS.",
                    cvss_score=7.5,
                )
            )

        for dangerous in self.XSS_DANGEROUS_ATTRIBUTES:
            if re.search(dangerous, form_attrs, re.IGNORECASE):
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Potential XSS Vector in Form: {form_id}",
                        description=(
                            f"Form '{form_id}' contains potentially dangerous attributes "
                            f"that may enable XSS attacks."
                        ),
                        cwe_id="CWE-79",
                        cwe_name="Improper Neutralization of Input During Web Page Generation",
                        url=url,
                        evidence="Dangerous pattern found in form attributes",
                        remediation="Remove inline event handlers and javascript: URLs.",
                        cvss_score=6.1,
                    )
                )
                break

        return findings

    def _has_csrf_token(self, form_content: str) -> bool:
        """Check if form contains a CSRF token."""
        content_lower = form_content.lower()

        for pattern in self.CSRF_TOKEN_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                hidden_input = re.search(
                    rf'<input[^>]*type\s*=\s*["\']?hidden["\']?[^>]*name\s*=\s*["\']?[^"\']*{pattern}[^"\']*["\']?',
                    content_lower,
                    re.IGNORECASE,
                )
                if hidden_input:
                    return True
                name_first = re.search(
                    rf'<input[^>]*name\s*=\s*["\']?[^"\']*{pattern}[^"\']*["\']?[^>]*type\s*=\s*["\']?hidden["\']?',
                    content_lower,
                    re.IGNORECASE,
                )
                if name_first:
                    return True

        return False

    def _check_csrf_in_inputs(
        self,
        url: str,
        form_id: str,
        inputs: list[dict[str, Any]],
        alt_csrf_info: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Check for CSRF token in input list."""
        findings: list[Finding] = []
        alt_csrf_info = alt_csrf_info or {}

        has_csrf = False
        for input_data in inputs:
            name = input_data.get("name", "").lower()
            input_type = input_data.get("type", "").lower()

            for pattern in self.CSRF_TOKEN_PATTERNS:
                if re.search(pattern, name, re.IGNORECASE) and input_type == "hidden":
                    has_csrf = True
                    break
            if has_csrf:
                break

        if not has_csrf:
            # Determine severity based on alternative protections
            severity, cvss, mitigation_notes = self._assess_csrf_severity(alt_csrf_info)

            description = (
                f"POST form '{form_id}' does not contain a CSRF token. "
                "This may make the form vulnerable to CSRF attacks."
            )
            if mitigation_notes:
                description += f" {mitigation_notes}"

            findings.append(
                self._create_finding(
                    severity=severity,
                    title=f"Form Missing CSRF Token: {form_id}",
                    description=description,
                    cwe_id="CWE-352",
                    cwe_name="Cross-Site Request Forgery (CSRF)",
                    url=url,
                    evidence=f"Form ID: {form_id}; No CSRF token input found",
                    remediation="Add a CSRF token to the form.",
                    cvss_score=cvss,
                    references=[
                        "https://owasp.org/www-community/attacks/csrf",
                    ],
                    metadata={"alternative_protections": alt_csrf_info},
                )
            )

        return findings

    def _analyze_input(
        self,
        url: str,
        form_id: str,
        input_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze individual input from structured data."""
        findings: list[Finding] = []

        name = input_data.get("name", "")
        input_type = input_data.get("type", "text").lower()
        autocomplete = input_data.get("autocomplete", "")

        is_sensitive = self._is_sensitive_input(name, input_type)

        if is_sensitive and autocomplete.lower() != "off":
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title=f"Sensitive Input Without autocomplete=off: {name}",
                    description=(
                        f"Sensitive input '{name}' in form '{form_id}' does not have "
                        "autocomplete disabled. Browser may cache sensitive data."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence=f"Input: {name}; autocomplete={autocomplete or 'not set'}",
                    remediation="Add autocomplete='off' to sensitive input fields.",
                    cvss_score=4.3,
                )
            )

        is_password_field = input_type == "password"
        has_invalid_autocomplete = autocomplete.lower() not in ["off", "new-password", "current-password"]
        if is_password_field and has_invalid_autocomplete:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title=f"Password Field Missing Proper Autocomplete: {name}",
                    description=(
                        f"Password field '{name}' should have autocomplete set to "
                        "'new-password' or 'current-password' for proper browser handling."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence=f"Password input: {name}; autocomplete={autocomplete or 'not set'}",
                    remediation=(
                        "Use autocomplete='new-password' for registration or "
                        "'current-password' for login fields."
                    ),
                    cvss_score=3.1,
                )
            )

        return findings

    def _analyze_input_attrs(
        self,
        url: str,
        form_id: str,
        input_attrs: str,
    ) -> list[Finding]:
        """Analyze input from raw HTML attributes."""
        findings: list[Finding] = []

        name = self._extract_attribute(input_attrs, "name") or ""
        input_type = self._extract_attribute(input_attrs, "type") or "text"
        autocomplete = self._extract_attribute(input_attrs, "autocomplete") or ""

        is_sensitive = self._is_sensitive_input(name, input_type)

        if input_type.lower() == "password":
            if autocomplete.lower() not in ["off", "new-password", "current-password", ""]:
                pass
            elif not autocomplete:
                findings.append(
                    self._create_finding(
                        severity=Severity.LOW,
                        title=f"Password Field Without Explicit Autocomplete: {name or 'unnamed'}",
                        description=(
                            "Password field does not explicitly set autocomplete attribute."
                        ),
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information",
                        url=url,
                        evidence="Input type=password; autocomplete not set",
                        remediation="Set autocomplete='new-password' or 'current-password'.",
                        cvss_score=2.1,
                    )
                )

        has_missing_autocomplete = autocomplete.lower() not in ["off", "new-password", "current-password"]
        is_non_password_sensitive = is_sensitive and input_type.lower() != "password"
        if is_non_password_sensitive and has_missing_autocomplete:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title=f"Sensitive Input Without autocomplete=off: {name}",
                    description=(
                        f"Input '{name}' appears to handle sensitive data but "
                        "does not have autocomplete disabled."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    url=url,
                    evidence=f"Input: {name}; autocomplete={autocomplete or 'not set'}",
                    remediation="Add autocomplete='off' to sensitive input fields.",
                    cvss_score=4.3,
                )
            )

        for dangerous in self.XSS_DANGEROUS_ATTRIBUTES:
            if re.search(dangerous, input_attrs, re.IGNORECASE):
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Potential XSS Vector in Input: {name or 'unnamed'}",
                        description=(
                            "Input element contains potentially dangerous attributes."
                        ),
                        cwe_id="CWE-79",
                        cwe_name="Improper Neutralization of Input During Web Page Generation",
                        url=url,
                        evidence="Dangerous pattern in input attributes",
                        remediation="Remove inline event handlers from input elements.",
                        cvss_score=6.1,
                    )
                )
                break

        return findings

    def _check_form_action(
        self,
        url: str,
        form_id: str,
        form_action: str,
    ) -> list[Finding]:
        """Check form action URL for security issues."""
        findings: list[Finding] = []

        if form_action.startswith("http://") and url.startswith("https://"):
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title=f"Form Action Uses HTTP on HTTPS Page: {form_id}",
                    description=(
                        f"Form '{form_id}' submits to HTTP URL while page is served over HTTPS."
                    ),
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    url=url,
                    evidence=f"Action: {form_action}",
                    remediation="Use HTTPS for form action URLs.",
                    cvss_score=7.5,
                )
            )

        return findings

    def _is_sensitive_input(self, name: str, input_type: str) -> bool:
        """Determine if input handles sensitive data."""
        if input_type.lower() in self.SENSITIVE_INPUT_TYPES:
            return True

        name_lower = name.lower()
        for pattern in self.SENSITIVE_INPUT_PATTERNS:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return True

        return False

    def _extract_attribute(self, attrs: str, attr_name: str) -> str | None:
        """Extract attribute value from HTML attribute string."""
        pattern = rf'{attr_name}\s*=\s*["\']?([^"\'>\s]*)["\']?'
        match = re.search(pattern, attrs, re.IGNORECASE)
        return match.group(1) if match else None

    def _detect_alternative_csrf_protection(
        self,
        cookies: list[dict[str, Any]] | list[str],
        headers: dict[str, str],
        html_content: str,
    ) -> dict[str, Any]:
        """
        Detect modern CSRF protection mechanisms that may replace traditional tokens.

        Returns a dictionary with detected protections and their details.
        """
        protections: dict[str, Any] = {
            "has_samesite_strict": False,
            "has_samesite_lax": False,
            "has_custom_headers": False,
            "has_jwt_auth": False,
            "custom_header_names": [],
            "samesite_cookies": [],
        }

        # Check SameSite cookie attribute (modern CSRF protection)
        for cookie in cookies:
            if isinstance(cookie, dict):
                cookie_name = cookie.get("name", "")
                samesite = cookie.get("sameSite", "").lower()
            elif isinstance(cookie, str):
                # Parse Set-Cookie header string
                cookie_name = cookie.split("=")[0] if "=" in cookie else ""
                samesite_match = re.search(r"samesite\s*=\s*(\w+)", cookie, re.IGNORECASE)
                samesite = samesite_match.group(1).lower() if samesite_match else ""
            else:
                continue

            if samesite == "strict":
                protections["has_samesite_strict"] = True
                protections["samesite_cookies"].append(cookie_name)
            elif samesite == "lax":
                protections["has_samesite_lax"] = True
                protections["samesite_cookies"].append(cookie_name)

        # Check for custom headers in response that indicate AJAX-based submission
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        for header_pattern in self.CUSTOM_HEADER_PATTERNS:
            if header_pattern in normalized_headers:
                protections["has_custom_headers"] = True
                protections["custom_header_names"].append(header_pattern)

        # Check for JWT authentication headers
        for jwt_header in self.JWT_HEADER_PATTERNS:
            if jwt_header in normalized_headers:
                protections["has_jwt_auth"] = True
                break

        # Check HTML for JWT/token patterns in JavaScript
        jwt_patterns = [
            r"localStorage\.(?:get|set)Item\s*\(\s*['\"](?:token|jwt|access_token)",
            r"sessionStorage\.(?:get|set)Item\s*\(\s*['\"](?:token|jwt|access_token)",
            r"['\"]Authorization['\"]:\s*['\"]Bearer\s+",
            r"headers\s*:\s*\{[^}]*['\"]X-(?:CSRF|XSRF)-Token['\"]",
        ]
        for pattern in jwt_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                protections["has_jwt_auth"] = True
                break

        return protections

    def _has_javascript_submission(self, form_attrs: str, form_content: str) -> bool:
        """
        Detect if form is likely submitted via JavaScript/AJAX.

        JavaScript submissions can add custom headers that prove same-origin.
        """
        # Check for onsubmit handlers
        if re.search(r"onsubmit\s*=", form_attrs, re.IGNORECASE):
            return True

        # Check for event.preventDefault patterns in content
        if re.search(r"\.preventDefault\s*\(\s*\)", form_content, re.IGNORECASE):
            return True

        # Check for fetch/XMLHttpRequest patterns
        ajax_patterns = [
            r"fetch\s*\(",
            r"XMLHttpRequest",
            r"\$\.(?:ajax|post|get)\s*\(",
            r"axios\.",
            r"\.submit\s*\(\s*\)",
        ]
        return any(re.search(pattern, form_content, re.IGNORECASE) for pattern in ajax_patterns)

    def _assess_csrf_severity(
        self,
        alt_csrf_info: dict[str, Any],
        has_js_submit: bool = False,
    ) -> tuple[Severity, float, str]:
        """
        Assess CSRF vulnerability severity based on alternative protections.

        Returns (severity, cvss_score, mitigation_notes).
        """
        mitigations: list[str] = []

        # SameSite=Strict provides strong CSRF protection
        if alt_csrf_info.get("has_samesite_strict"):
            mitigations.append(
                "SameSite=Strict cookies detected, which prevents cross-site request inclusion"
            )
            return (
                Severity.LOW,
                2.0,
                "However, " + "; ".join(mitigations) + ".",
            )

        # SameSite=Lax provides protection for non-GET requests
        if alt_csrf_info.get("has_samesite_lax"):
            mitigations.append(
                "SameSite=Lax cookies detected, which prevents CSRF on POST requests from cross-site navigation"
            )

        # JWT authentication is stateless and immune to traditional CSRF
        if alt_csrf_info.get("has_jwt_auth"):
            mitigations.append(
                "JWT/Bearer token authentication detected, which is stateless and typically CSRF-immune"
            )

        # Custom headers prove same-origin
        if alt_csrf_info.get("has_custom_headers"):
            header_names = alt_csrf_info.get("custom_header_names", [])
            mitigations.append(
                f"Custom headers ({', '.join(header_names)}) detected, which prove same-origin requests"
            )

        # JavaScript submission can add custom headers
        if has_js_submit:
            mitigations.append(
                "Form appears to use JavaScript submission, which can add custom CSRF headers"
            )

        if len(mitigations) >= 2:
            # Multiple alternative protections - likely intentional stateless auth
            return (
                Severity.LOW,
                2.0,
                "However, " + "; ".join(mitigations) + ".",
            )
        elif mitigations:
            # Single alternative protection - lower severity but still worth noting
            return (
                Severity.MEDIUM,
                4.5,
                "However, " + "; ".join(mitigations) + ".",
            )

        # No alternative protections detected
        return (Severity.HIGH, 8.0, "")
