"""
Input Validation Analyzer.

Analyzes input sanitization effectiveness, reflection points,
encoding behavior, and boundary conditions for authorized security testing.
"""

from __future__ import annotations

import html
import math
import re
import urllib.parse
from collections import Counter
from typing import Any

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity


class InputValidationAnalyzer(BaseAnalyzer):
    """
    Analyzer for input validation vulnerabilities.

    Checks for:
    - Input sanitization effectiveness (CWE-79, CWE-89)
    - Reflection points in responses (CWE-79)
    - Encoding/decoding behavior (CWE-116)
    - Boundary conditions (CWE-20)
    - Output encoding in different contexts (CWE-838)
    """

    analyzer_type = AnalyzerType.INPUT_VALIDATION

    # Common test strings for identifying reflection (passive detection)
    REFLECTION_MARKERS = [
        "searchquery",
        "userInput",
        "inputValue",
        "formData",
    ]

    # Patterns indicating potential XSS sinks in JavaScript
    # NOTE: These are potential sinks, not confirmed vulnerabilities.
    # Data flow analysis would be required to confirm exploitability.
    XSS_SINK_PATTERNS = [
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"document\.write\s*\(",
        r"document\.writeln\s*\(",
        r"eval\s*\(",
        r"setTimeout\s*\(\s*['\"]",
        r"setInterval\s*\(\s*['\"]",
        r"new\s+Function\s*\(",
        r"\.insertAdjacentHTML\s*\(",
        r"\$\s*\(\s*['\"]<",
        r"jQuery\s*\(\s*['\"]<",
        r"v-html\s*=",
        r"dangerouslySetInnerHTML",
        r"\[innerHTML\]",
    ]

    # Known framework/library patterns that handle XSS safely
    # These indicate the sink is likely used in a safe context
    FRAMEWORK_SAFE_PATTERNS = frozenset({
        "react",
        "vue",
        "angular",
        "svelte",
        "ember",
        "backbone",
        "next",
        "nuxt",
        "gatsby",
    })

    # Common low-entropy parameter values that are unlikely attack vectors
    LOW_ENTROPY_VALUES = frozenset({
        # Pagination
        "1", "2", "3", "4", "5", "10", "20", "25", "50", "100",
        # Boolean flags
        "true", "false", "yes", "no", "on", "off",
        # Sort orders
        "asc", "desc", "ascending", "descending",
        # Common status values
        "active", "inactive", "pending", "approved", "rejected",
        # Language codes
        "en", "es", "fr", "de", "it", "pt", "ru", "zh", "ja", "ko",
        "en-us", "en-gb", "es-es", "fr-fr", "de-de",
        # Date formats
        "date", "time", "datetime",
        # View modes
        "list", "grid", "table", "card", "compact", "expanded",
    })

    # Patterns indicating potential SQL injection sinks
    SQL_INDICATOR_PATTERNS = [
        r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+",
        r"(?:UNION|JOIN)\s+(?:ALL\s+)?SELECT",
        r"(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"(?:OR|AND)\s+['\"]?[\w]+['\"]?\s*=\s*['\"]?[\w]+",
        r"['\"];\s*(?:SELECT|DROP|INSERT|UPDATE|DELETE)",
        r"--\s*$",
        r"/\*.*\*/",
    ]

    # Patterns for detecting template injection
    TEMPLATE_INJECTION_PATTERNS = [
        r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}",
        r"\$\{\s*\d+\s*\*\s*\d+\s*\}",
        r"<%.*%>",
        r"\{\%.*\%\}",
        r"#\{.*\}",
    ]

    # Characters that should be encoded in different contexts
    HTML_DANGEROUS_CHARS = ["<", ">", '"', "'", "&"]
    JS_DANGEROUS_CHARS = ["'", '"', "\\", "/", "<", ">"]
    URL_DANGEROUS_CHARS = ["<", ">", '"', "'", " ", "#", "%"]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze input validation and encoding behavior."""
        findings: list[Finding] = []
        html_content = page_data.get("html", "")
        scripts = page_data.get("scripts", [])
        forms = page_data.get("forms", [])
        headers = page_data.get("headers", {})
        scan_mode = page_data.get("scan_mode", "passive")

        # Passive analysis
        findings.extend(self._analyze_xss_sinks(url, html_content, scripts))
        findings.extend(self._analyze_form_validation(url, forms))
        findings.extend(self._analyze_content_type(url, headers))
        findings.extend(self._analyze_reflection_patterns(url, html_content))
        findings.extend(self._analyze_encoding_issues(url, html_content))

        # Active mode includes additional test-based analysis
        if scan_mode == "active":
            findings.extend(self._analyze_sql_indicators(url, html_content, scripts))
            findings.extend(self._analyze_template_injection(url, html_content))

        return findings

    def _analyze_xss_sinks(
        self,
        url: str,
        html_content: str,
        scripts: list[Any],
    ) -> list[Finding]:
        """Identify dangerous JavaScript patterns that could enable XSS."""
        findings: list[Finding] = []
        all_content = html_content

        for script in scripts:
            if isinstance(script, str):
                all_content += "\n" + script

        # Check if page uses a known framework with built-in XSS protection
        framework_detected = self._detect_framework(all_content)

        sink_findings: dict[str, list[str]] = {}

        for pattern in self.XSS_SINK_PATTERNS:
            matches = re.findall(pattern, all_content, re.IGNORECASE)
            if matches:
                pattern_name = pattern.split("\\")[0].replace(r"\.", ".").strip(".(")
                if pattern_name not in sink_findings:
                    sink_findings[pattern_name] = []
                sink_findings[pattern_name].extend(matches[:3])

        if sink_findings:
            sink_list = list(sink_findings.keys())

            # Determine severity based on framework context
            if framework_detected:
                # Framework detected - sinks are likely intentional and properly sanitized
                severity = Severity.LOW
                cvss = 3.1
                framework_note = (
                    f" Note: {framework_detected} framework detected, which typically "
                    "handles XSS protection. These sinks may be intentional and safe."
                )
            else:
                # No framework - potential risk, but still needs data flow analysis
                severity = Severity.LOW  # Lowered from MEDIUM - no confirmed data flow
                cvss = 3.7
                framework_note = ""

            findings.append(
                self._create_finding(
                    severity=severity,
                    title="Potential JavaScript Sinks Detected (Requires Data Flow Analysis)",
                    description=(
                        f"Found {len(sink_findings)} types of JavaScript patterns "
                        "that could enable DOM-based XSS if user input reaches them without sanitization: "
                        f"{', '.join(sink_list[:5])}. "
                        "This is a potential sink identification, not a confirmed vulnerability. "
                        "Manual data flow analysis is required to determine exploitability."
                        f"{framework_note}"
                    ),
                    cwe_id="CWE-79",
                    cwe_name="Improper Neutralization of Input During Web Page Generation",
                    url=url,
                    evidence=f"Potential sinks: {', '.join(sink_list[:5])}",
                    remediation=(
                        "Use safe DOM manipulation methods like textContent instead of innerHTML. "
                        "Sanitize user input before passing to eval(), setTimeout(), or similar functions. "
                        "Consider using Content-Security-Policy to mitigate XSS impact."
                    ),
                    cvss_score=cvss,
                    references=[
                        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                        "https://cwe.mitre.org/data/definitions/79.html",
                    ],
                    metadata={
                        "sinks": sink_list,
                        "framework_detected": framework_detected,
                        "requires_data_flow_analysis": True,
                    },
                )
            )

        return findings

    def _detect_framework(self, content: str) -> str | None:
        """
        Detect if content uses a known JavaScript framework with XSS protection.

        Returns framework name if detected, None otherwise.
        """
        content_lower = content.lower()

        # React detection
        react_indicators = ["react", "reactdom", "createelement", "_jsx", "usestate", "useeffect"]
        if (
            any(indicator in content_lower for indicator in react_indicators)
            and ("dangerouslysetinnerhtml" not in content_lower or "react" in content_lower)
        ):
            return "React"

        # Vue.js detection
        if any(indicator in content_lower for indicator in [
            "vue", "v-bind", "v-model", "v-if", "v-for", "createapp"
        ]):
            return "Vue.js"

        # Angular detection
        if any(indicator in content_lower for indicator in [
            "angular", "ng-", "[ngfor]", "[ngif]", "@angular", "ngoninit"
        ]):
            return "Angular"

        # Svelte detection
        if any(indicator in content_lower for indicator in ["svelte", "{#each", "{#if"]):
            return "Svelte"

        # Next.js/Nuxt detection
        if "__next" in content_lower or "_next" in content_lower:
            return "Next.js"
        if "__nuxt" in content_lower or "_nuxt" in content_lower:
            return "Nuxt.js"

        return None

    def _analyze_form_validation(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """Analyze form inputs for missing client-side validation."""
        findings: list[Finding] = []

        sensitive_field_patterns = {
            "email": r"email|mail|e-mail",
            "password": r"password|passwd|pwd|pass",
            "phone": r"phone|tel|mobile|cell",
            "credit_card": r"card|cc|credit|cvv|cvc",
            "ssn": r"ssn|social|taxid",
            "url": r"url|website|link|href",
            "date": r"date|birthday|dob|birth",
        }

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_id = form.get("id", "") or form.get("action", "unknown")
            inputs = form.get("inputs", [])

            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue

                name = input_field.get("name", "").lower()
                input_type = input_field.get("type", "text").lower()

                # Check for sensitive fields without proper type
                for field_type, pattern in sensitive_field_patterns.items():
                    if re.search(pattern, name, re.IGNORECASE):
                        expected_types = {
                            "email": "email",
                            "password": "password",
                            "phone": "tel",
                            "url": "url",
                            "date": "date",
                        }

                        expected = expected_types.get(field_type)
                        if expected and input_type not in [expected, "hidden"]:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.LOW,
                                    title=f"Input Field Missing Proper Type: {name}",
                                    description=(
                                        f"Input field '{name}' appears to collect {field_type} data "
                                        f"but uses type='{input_type}' instead of type='{expected}'. "
                                        "Proper input types enable browser validation and mobile keyboard hints."
                                    ),
                                    cwe_id="CWE-20",
                                    cwe_name="Improper Input Validation",
                                    url=url,
                                    evidence=f"Form: {form_id}; Field: {name}; Type: {input_type}",
                                    remediation=f"Use type='{expected}' for {field_type} input fields.",
                                    cvss_score=2.1,
                                    metadata={
                                        "form_id": form_id,
                                        "field_name": name,
                                        "current_type": input_type,
                                        "expected_type": expected,
                                    },
                                )
                            )

                # Check for autocomplete on sensitive fields
                autocomplete = input_field.get("autocomplete", "")
                is_sensitive_field = re.search(r"password|credit|cvv|ssn", name, re.IGNORECASE)
                needs_autocomplete_fix = autocomplete != "off" and autocomplete != "new-password"
                if is_sensitive_field and needs_autocomplete_fix:
                    findings.append(
                            self._create_finding(
                                severity=Severity.LOW,
                                title=f"Sensitive Field Without Autocomplete Restriction: {name}",
                                description=(
                                    f"Sensitive field '{name}' does not disable autocomplete. "
                                    "Browsers may cache sensitive data for autofill."
                                ),
                                cwe_id="CWE-525",
                                cwe_name="Use of Web Browser Cache Containing Sensitive Information",
                                url=url,
                                evidence=f"Field: {name}; autocomplete: {autocomplete or 'not set'}",
                                remediation=(
                                    "Add autocomplete='off' or autocomplete='new-password' "
                                    "to sensitive form fields."
                                ),
                                cvss_score=2.1,
                                metadata={"field_name": name},
                            )
                        )

        return findings

    def _analyze_content_type(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Analyze Content-Type header for proper charset and encoding."""
        findings: list[Finding] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        content_type = normalized_headers.get("content-type", "")

        if not content_type:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Missing Content-Type Header",
                    description=(
                        "Response is missing Content-Type header. "
                        "Without explicit content type, browsers may misinterpret content "
                        "or use content sniffing, potentially leading to XSS."
                    ),
                    cwe_id="CWE-436",
                    cwe_name="Interpretation Conflict",
                    url=url,
                    evidence="Content-Type header not present",
                    remediation=(
                        "Set Content-Type header with appropriate MIME type and charset, "
                        "e.g., 'Content-Type: text/html; charset=utf-8'"
                    ),
                    cvss_score=4.3,
                )
            )
        elif "text/html" in content_type.lower() and "charset" not in content_type.lower():
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="Content-Type Missing Charset",
                    description=(
                        f"Content-Type '{content_type}' does not specify charset. "
                        "Missing charset can lead to encoding-based XSS attacks."
                    ),
                    cwe_id="CWE-838",
                    cwe_name="Inappropriate Encoding for Output Context",
                    url=url,
                    evidence=f"Content-Type: {content_type}",
                    remediation="Add charset specification: 'Content-Type: text/html; charset=utf-8'",
                    cvss_score=3.1,
                )
            )

        return findings

    def _analyze_reflection_patterns(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """Detect potential reflection points where user input appears in output."""
        findings: list[Finding] = []

        # Parse URL parameters
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)

        reflected_params: list[str] = []
        safe_reflections: list[str] = []

        for param, values in query_params.items():
            for value in values:
                # Minimum length of 5 characters (increased from 3)
                if len(value) < 5:
                    continue

                # Skip common low-entropy values that are unlikely attack vectors
                if value.lower() in self.LOW_ENTROPY_VALUES:
                    continue

                # Skip purely numeric values (pagination, IDs)
                if value.isdigit():
                    continue

                # Check entropy - low entropy values are likely not attack vectors
                if self._calculate_entropy(value) < 2.0:
                    continue

                # Check if value is reflected in HTML
                if value not in html_content:
                    continue

                # Check if reflection is in a safe context
                reflection_context = self._analyze_reflection_context(value, html_content)

                if reflection_context["is_safe"]:
                    safe_reflections.append(f"{param}={value[:20]} ({reflection_context['context']})")
                else:
                    reflected_params.append(f"{param}={value[:20]}")

        if reflected_params:
            # Determine severity based on reflection context
            severity = Severity.MEDIUM
            cvss = 5.3  # Lowered from 6.1 - no confirmed XSS, just reflection

            description = (
                f"Found {len(reflected_params)} URL parameter(s) reflected in the HTML response. "
                "Reflected parameters could be vulnerable to reflected XSS if not properly encoded."
            )

            if safe_reflections:
                description += (
                    f" Additionally, {len(safe_reflections)} parameter(s) appear to be reflected "
                    "in safe contexts (quoted strings, comments)."
                )

            findings.append(
                self._create_finding(
                    severity=severity,
                    title="URL Parameters Reflected in Response",
                    description=description,
                    cwe_id="CWE-79",
                    cwe_name="Improper Neutralization of Input During Web Page Generation",
                    url=url,
                    evidence=f"Reflected parameters: {', '.join(reflected_params[:5])}",
                    remediation=(
                        "Ensure all user input is properly HTML-encoded before reflection. "
                        "Use context-aware output encoding (HTML, JavaScript, URL, CSS)."
                    ),
                    cvss_score=cvss,
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                    ],
                    metadata={
                        "reflected_params": reflected_params[:10],
                        "safe_reflections": safe_reflections[:5],
                    },
                )
            )

        return findings

    def _calculate_entropy(self, value: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Low entropy values (< 2.0) are likely common/predictable values.
        High entropy values are more likely to be unique/user-controlled.
        """
        if not value:
            return 0.0

        counter = Counter(value.lower())
        length = len(value)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _analyze_reflection_context(
        self,
        value: str,
        html_content: str,
    ) -> dict[str, Any]:
        """
        Analyze the context in which a value is reflected in HTML.

        Returns dict with:
        - is_safe: bool indicating if reflection appears to be in a safe context
        - context: string describing the context
        """
        # Find the position of reflection
        pos = html_content.find(value)
        if pos == -1:
            return {"is_safe": False, "context": "not found"}

        # Get surrounding context (100 chars before and after)
        start = max(0, pos - 100)
        end = min(len(html_content), pos + len(value) + 100)
        context = html_content[start:end]

        # Check if inside HTML comment
        if "<!--" in context[:context.find(value) - start + 10]:
            comment_start = context.rfind("<!--", 0, context.find(value))
            comment_end = context.find("-->", context.find(value))
            if comment_start != -1 and (comment_end == -1 or comment_end > context.find(value)):
                return {"is_safe": True, "context": "HTML comment"}

        # Check if inside a quoted attribute value (properly escaped)
        # Look for patterns like: attribute="...value..."
        value_pos = context.find(value)
        before_value = context[:value_pos]

        # Count quotes before value
        double_quotes_before = before_value.count('"') - before_value.count('\\"')
        single_quotes_before = before_value.count("'") - before_value.count("\\'")

        # Check if inside double-quoted string with no dangerous chars
        is_in_double_quote = double_quotes_before % 2 == 1
        has_no_dangerous_chars_dq = '"' not in value and '<' not in value and '>' not in value
        if is_in_double_quote and has_no_dangerous_chars_dq:
            return {"is_safe": True, "context": "double-quoted attribute"}

        # Check if inside single-quoted string with no dangerous chars
        is_in_single_quote = single_quotes_before % 2 == 1
        has_no_dangerous_chars_sq = "'" not in value and '<' not in value and '>' not in value
        if is_in_single_quote and has_no_dangerous_chars_sq:
            return {"is_safe": True, "context": "single-quoted attribute"}

        # Check if value appears to be HTML-encoded
        encoded_value = html.escape(value)
        if encoded_value != value and encoded_value in html_content:
            return {"is_safe": True, "context": "HTML-encoded"}

        return {"is_safe": False, "context": "potentially unsafe"}

    def _analyze_encoding_issues(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """Detect potential encoding issues in HTML content."""
        findings: list[Finding] = []

        # Check for unencoded special characters in dangerous contexts
        # Look for patterns suggesting improper encoding

        # Pattern: JavaScript strings containing unescaped user-looking data
        js_string_pattern = r'(?:var|let|const)\s+\w+\s*=\s*["\']([^"\']{10,})["\']'
        js_matches = re.findall(js_string_pattern, html_content)

        for match in js_matches[:5]:
            for char in self.JS_DANGEROUS_CHARS:
                if char in match and char not in ["\\"]:
                    findings.append(
                        self._create_finding(
                            severity=Severity.LOW,
                            title="Potentially Unescaped Content in JavaScript Context",
                            description=(
                                "Found content in JavaScript string context that may contain "
                                "unescaped special characters. This could indicate insufficient "
                                "output encoding for JavaScript context."
                            ),
                            cwe_id="CWE-838",
                            cwe_name="Inappropriate Encoding for Output Context",
                            url=url,
                            evidence=f"JavaScript string with special char: {char}",
                            remediation=(
                                "Use JavaScript-specific encoding for dynamic values in JS context. "
                                "Consider using JSON.stringify() for embedding data in scripts."
                            ),
                            cvss_score=3.1,
                        )
                    )
                    break

        return findings

    def _analyze_sql_indicators(
        self,
        url: str,
        html_content: str,
        scripts: list[Any],
    ) -> list[Finding]:
        """Detect SQL-like patterns in responses (active mode indicator)."""
        findings: list[Finding] = []

        all_content = html_content.lower()
        for script in scripts:
            if isinstance(script, str):
                all_content += "\n" + script.lower()

        sql_errors = [
            (r"sql syntax.*mysql", "MySQL"),
            (r"postgresql.*error", "PostgreSQL"),
            (r"oracle.*error|ora-\d+", "Oracle"),
            (r"microsoft.*sql.*server|mssql", "MSSQL"),
            (r"sqlite.*error", "SQLite"),
            (r"syntax error.*near", "Generic SQL"),
            (r"unterminated.*string.*literal", "SQL String Error"),
        ]

        for pattern, db_type in sql_errors:
            if re.search(pattern, all_content, re.IGNORECASE):
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"SQL Error Message Disclosed: {db_type}",
                        description=(
                            f"Response contains {db_type} error message. "
                            "SQL error disclosure indicates potential SQL injection vulnerability "
                            "and leaks database technology information."
                        ),
                        cwe_id="CWE-89",
                        cwe_name="SQL Injection",
                        url=url,
                        evidence=f"Database type: {db_type}; Pattern matched: {pattern}",
                        remediation=(
                            "Use parameterized queries or prepared statements. "
                            "Implement proper error handling that does not expose database errors. "
                            "Configure application to show generic error messages in production."
                        ),
                        cvss_score=9.8,
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cwe.mitre.org/data/definitions/89.html",
                        ],
                    )
                )
                break

        return findings

    def _analyze_template_injection(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """Detect potential template injection patterns (active mode)."""
        findings: list[Finding] = []

        for pattern in self.TEMPLATE_INJECTION_PATTERNS:
            if re.search(pattern, html_content, re.IGNORECASE):
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title="Potential Template Injection Pattern Detected",
                        description=(
                            "Response contains template expression patterns that could indicate "
                            "Server-Side Template Injection (SSTI) vulnerability if user input "
                            "is being processed by a template engine."
                        ),
                        cwe_id="CWE-94",
                        cwe_name="Improper Control of Generation of Code",
                        url=url,
                        evidence=f"Template pattern: {pattern}",
                        remediation=(
                            "Never pass user input directly to template engines. "
                            "Use sandboxed template environments. "
                            "Validate and sanitize all input before template processing."
                        ),
                        cvss_score=9.8,
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
                        ],
                    )
                )
                break

        return findings
