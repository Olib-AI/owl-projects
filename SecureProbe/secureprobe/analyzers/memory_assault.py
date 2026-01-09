"""
Memory Assault Analyzer - Memory Vulnerability Detection.

Implements original attack patterns to detect memory leaks, overflows,
and memory exhaustion vulnerabilities on servers. These patterns use
incremental probing to detect weaknesses WITHOUT causing actual DoS.

Each attack uses:
- Incremental probing (start small, detect weakness)
- Response time/memory indicators
- Safety limits to prevent server crashes

CWE References:
- CWE-400: Uncontrolled Resource Consumption
- CWE-770: Allocation of Resources Without Limits or Throttling
- CWE-789: Memory Allocation with Excessive Size Value
- CWE-776: Improper Restriction of Recursive Entity References
- CWE-409: Improper Handling of Highly Compressed Data

This module is designed for authorized security testing only.
All tests require explicit scan_mode='active' to execute.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog
from dotenv import load_dotenv

# Add python-sdk to path for owl_browser imports before loading local modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "python-sdk"))

# Load environment variables
load_dotenv()

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity
from secureprobe.utils import safe_response_text

logger = structlog.get_logger(__name__)


def _get_browser_instance() -> Any:
    """
    Create a Browser instance with remote URL configuration if available.

    Returns:
        Configured Browser instance
    """
    from owl_browser import Browser, RemoteConfig

    remote_url = os.getenv("OWL_BROWSER_URL")
    remote_token = os.getenv("OWL_BROWSER_TOKEN")

    if remote_url and remote_token:
        logger.debug(
            "memory_assault_using_remote_browser",
            remote_url=remote_url,
            has_token=bool(remote_token),
        )
        remote_config = RemoteConfig(url=remote_url, token=remote_token)
        return Browser(remote=remote_config)
    else:
        logger.debug("memory_assault_using_local_browser")
        return Browser()


class MemoryAssaultAnalyzer(BaseAnalyzer):
    """
    Analyzer implementing memory assault attack patterns.

    Detects server-side memory vulnerabilities through incremental
    probing techniques that identify weaknesses without causing
    actual denial of service.

    Attack Patterns:
    1. Regex Catastrophic Backtracking (ReDoS timing oracle)
    2. JSON Bomb Detection (nested JSON depth attack)
    3. XML Billion Laughs Variant (JSON/YAML entity expansion)
    4. Multipart Bomb (form data with many parts)
    5. Header Flooding (excessive headers)
    6. Cookie Jar Overflow (excessive cookies)
    7. Chunked Encoding Abuse (memory leak via tiny chunks)
    8. GraphQL Depth Bomb (nested query attack)
    9. WebSocket Frame Flooding (rapid frame detection)
    10. Decompression Bomb Detection (gzip bomb test)
    11. Array Index Overflow (large index allocation)
    12. String Multiplication Attack (template injection)
    """

    analyzer_type = AnalyzerType.MEMORY_ASSAULT

    # Safety limits - designed to detect NOT crash
    MAX_PROBE_DEPTH: int = 50  # Max nesting depth for probes
    MAX_HEADERS: int = 100  # Max headers to test
    MAX_COOKIES: int = 50  # Max cookies to test
    MAX_MULTIPART_PARTS: int = 100  # Max multipart parts
    TIMING_THRESHOLD_MS: float = 500.0  # Response slowdown indicator
    BASELINE_REQUESTS: int = 3  # Requests for baseline timing

    # ReDoS patterns that cause exponential backtracking
    REDOS_PATTERNS: list[tuple[str, str]] = [
        # Pattern name, Evil input generator description
        ("email_validation", "a" * 25 + "@"),
        ("url_validation", "a" * 30 + "://"),
        ("nested_groups", "a" * 20 + "!" * 20),
        ("alternation_bomb", "aaaaaaaaaaaaaaaaaaaab"),
        ("backref_bomb", "aaaaaaaaaaaaaaaaaaaaX"),
    ]

    # Common endpoints that might accept various content types
    API_ENDPOINTS: list[str] = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        "/query",
        "/data",
        "/webhook",
        "/callback",
    ]

    # Template engine patterns for string multiplication
    TEMPLATE_PATTERNS: list[tuple[str, str]] = [
        ("jinja2", "{{ 'A' * 1000000 }}"),
        ("django", "{% for i in range(1000000) %}A{% endfor %}"),
        ("erb", "<%= 'A' * 1000000 %>"),
        ("twig", "{{ 'A'|repeat(1000000) }}"),
        ("freemarker", "${'A'?repeat(1000000)}"),
        ("velocity", "#foreach($i in [1..1000000])A#end"),
        ("mako", "${'A' * 1000000}"),
        ("thymeleaf", "[[${T(String).format('%1000000s', 'A')}]]"),
    ]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Execute memory assault attack patterns against the target.

        Args:
            url: Target URL
            page_data: Page data including HTML, forms, headers

        Returns:
            List of discovered findings
        """
        findings: list[Finding] = []
        scan_mode = page_data.get("scan_mode", "passive")

        # Memory assault attacks are active-only
        if scan_mode != "active":
            logger.debug(
                "memory_assault_skipped",
                reason="passive mode - memory assault requires active mode",
            )
            return findings

        html_content = page_data.get("html", "")
        forms = page_data.get("forms", [])
        headers = page_data.get("headers", {})

        # Execute all 12 memory assault patterns
        findings.extend(await self._attack_regex_catastrophic_backtracking(url, forms))
        findings.extend(await self._attack_json_bomb(url, headers))
        findings.extend(await self._attack_billion_laughs_variant(url, headers))
        findings.extend(await self._attack_multipart_bomb(url, forms))
        findings.extend(await self._attack_header_flooding(url))
        findings.extend(await self._attack_cookie_jar_overflow(url))
        findings.extend(await self._attack_chunked_encoding_abuse(url))
        findings.extend(await self._attack_graphql_depth_bomb(url, html_content))
        findings.extend(await self._attack_websocket_frame_flooding(url))
        findings.extend(await self._attack_decompression_bomb(url, headers))
        findings.extend(await self._attack_array_index_overflow(url, forms))
        findings.extend(await self._attack_string_multiplication(url, forms))

        return findings

    async def _get_baseline_timing(self, url: str) -> float:
        """
        Get baseline response time for comparison.

        Returns:
            Average response time in milliseconds
        """
        times: list[float] = []

        async with httpx.AsyncClient(
            timeout=30.0,
            verify=self.config.verify_ssl,
            follow_redirects=True,
        ) as client:
            for _ in range(self.BASELINE_REQUESTS):
                start = time.perf_counter()
                try:
                    await client.get(
                        url,
                        headers={"User-Agent": self.config.user_agent},
                    )
                    elapsed = (time.perf_counter() - start) * 1000
                    times.append(elapsed)
                except Exception:
                    pass
                await asyncio.sleep(0.1)

        return sum(times) / len(times) if times else 100.0

    async def _attack_regex_catastrophic_backtracking(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 1: Regex Catastrophic Backtracking (ReDoS).

        Send input that causes exponential regex processing, exhausting
        memory and CPU. Detect via timing oracle without full DoS.

        CWE-1333: Inefficient Regular Expression Complexity
        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        # Get baseline timing
        baseline_ms = await self._get_baseline_timing(url)
        threshold_ms = baseline_ms * 3  # 3x slowdown indicates issue

        # ReDoS payloads targeting common validation patterns
        redos_payloads = [
            # Email validation ReDoS
            ("email", "a" * 30 + "@" + "a" * 30 + "."),
            # URL validation ReDoS
            ("url", "http://" + "a" * 50 + "." + "a" * 50),
            # Phone validation ReDoS
            ("phone", "+" + "1" * 50 + "-" + "1" * 50),
            # Name validation ReDoS
            ("name", " " + "a" * 100 + " "),
            # Path traversal regex
            ("path", "../" * 50 + "x"),
        ]

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_action = form.get("action", url)
            inputs = form.get("inputs", [])

            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue

                field_name = input_field.get("name", "")
                field_type = input_field.get("type", "").lower()

                if not field_name or field_type in ["hidden", "submit", "button"]:
                    continue

                # Test each ReDoS payload
                for payload_type, payload in redos_payloads:
                    try:
                        async with httpx.AsyncClient(
                            timeout=30.0,
                            verify=self.config.verify_ssl,
                            follow_redirects=True,
                        ) as client:
                            start = time.perf_counter()
                            await client.post(
                                form_action,
                                data={field_name: payload},
                                headers={"User-Agent": self.config.user_agent},
                            )
                            elapsed_ms = (time.perf_counter() - start) * 1000

                            if elapsed_ms > threshold_ms:
                                findings.append(
                                    self._create_finding(
                                        severity=Severity.HIGH,
                                        title=f"ReDoS Vulnerability: {field_name}",
                                        description=(
                                            f"Field '{field_name}' shows significant response delay "
                                            f"({elapsed_ms:.0f}ms vs {baseline_ms:.0f}ms baseline) "
                                            f"when processing regex-heavy input. This indicates "
                                            f"catastrophic backtracking in input validation regex. "
                                            f"Payload type: {payload_type}"
                                        ),
                                        cwe_id="CWE-1333",
                                        cwe_name="Inefficient Regular Expression Complexity",
                                        url=form_action,
                                        evidence=f"Baseline: {baseline_ms:.0f}ms, Attack: {elapsed_ms:.0f}ms, Ratio: {elapsed_ms/baseline_ms:.1f}x",
                                        remediation=(
                                            "1. Use atomic groups or possessive quantifiers\n"
                                            "2. Implement regex timeout limits\n"
                                            "3. Use simpler validation logic where possible\n"
                                            "4. Test regexes with ReDoS detectors before deployment"
                                        ),
                                        cvss_score=7.5,
                                        references=[
                                            "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
                                        ],
                                        metadata={
                                            "field_name": field_name,
                                            "payload_type": payload_type,
                                            "baseline_ms": baseline_ms,
                                            "attack_ms": elapsed_ms,
                                        },
                                    )
                                )
                                break  # One finding per field

                    except httpx.TimeoutException:
                        # Timeout is strong indicator of ReDoS
                        findings.append(
                            self._create_finding(
                                severity=Severity.CRITICAL,
                                title=f"Critical ReDoS: {field_name} caused timeout",
                                description=(
                                    f"Field '{field_name}' caused request timeout when processing "
                                    f"regex-heavy input. This is a severe ReDoS vulnerability "
                                    f"that can cause denial of service."
                                ),
                                cwe_id="CWE-1333",
                                cwe_name="Inefficient Regular Expression Complexity",
                                url=form_action,
                                evidence=f"Request timed out with payload type: {payload_type}",
                                remediation=(
                                    "CRITICAL: Implement immediate regex timeout limits. "
                                    "Review and replace vulnerable regex patterns."
                                ),
                                cvss_score=9.0,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/1333.html",
                                ],
                                metadata={
                                    "field_name": field_name,
                                    "payload_type": payload_type,
                                    "timeout": True,
                                },
                            )
                        )
                        break

                    except Exception as e:
                        logger.debug("redos_test_error", field=field_name, error=str(e))

        return findings

    async def _attack_json_bomb(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """
        Attack 2: JSON Bomb Detection.

        Send deeply nested JSON to exhaust parser memory.
        Uses incremental depth to detect weakness threshold.

        CWE-400: Uncontrolled Resource Consumption
        CWE-770: Allocation of Resources Without Limits
        """
        findings: list[Finding] = []

        # Check if server accepts JSON
        content_type = headers.get("content-type", "").lower()

        # Find potential JSON endpoints
        test_urls = [url]
        for endpoint in self.API_ENDPOINTS:
            parsed = urlparse(url)
            api_url = f"{parsed.scheme}://{parsed.netloc}{endpoint}"
            test_urls.append(api_url)

        async with httpx.AsyncClient(
            timeout=30.0,
            verify=self.config.verify_ssl,
            follow_redirects=True,
        ) as client:
            for test_url in test_urls:
                # Test incremental nesting depths
                for depth in [10, 20, 30, 40, 50]:
                    # Build nested JSON: {"a":{"a":{"a":...}}}
                    nested_json = self._build_nested_json(depth)

                    try:
                        start = time.perf_counter()
                        response = await client.post(
                            test_url,
                            content=nested_json,
                            headers={
                                "User-Agent": self.config.user_agent,
                                "Content-Type": "application/json",
                            },
                        )
                        elapsed_ms = (time.perf_counter() - start) * 1000

                        # Check for memory exhaustion indicators
                        if response.status_code == 500:
                            error_indicators = ["memory", "stack", "overflow", "recursion"]
                            response_text = safe_response_text(response).lower()

                            if any(ind in response_text for ind in error_indicators):
                                findings.append(
                                    self._create_finding(
                                        severity=Severity.HIGH,
                                        title=f"JSON Bomb Vulnerability at depth {depth}",
                                        description=(
                                            f"Server crashed at JSON nesting depth {depth}. "
                                            f"Memory exhaustion indicators detected in error response. "
                                            f"Attackers can exploit this to cause DoS."
                                        ),
                                        cwe_id="CWE-400",
                                        cwe_name="Uncontrolled Resource Consumption",
                                        url=test_url,
                                        evidence=f"500 error at depth {depth}: {response_text[:200]}",
                                        remediation=(
                                            "1. Limit JSON parsing depth (e.g., max 20 levels)\n"
                                            "2. Use streaming JSON parsers\n"
                                            "3. Set memory limits for request parsing\n"
                                            "4. Implement request size limits"
                                        ),
                                        cvss_score=7.5,
                                        references=[
                                            "https://cwe.mitre.org/data/definitions/400.html",
                                        ],
                                        metadata={
                                            "depth": depth,
                                            "status_code": response.status_code,
                                        },
                                    )
                                )
                                break

                        # Check for significant slowdown
                        if elapsed_ms > self.TIMING_THRESHOLD_MS * 2:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.MEDIUM,
                                    title=f"JSON Depth causes slowdown at depth {depth}",
                                    description=(
                                        f"Server shows significant slowdown ({elapsed_ms:.0f}ms) "
                                        f"when processing deeply nested JSON (depth {depth}). "
                                        f"This may indicate vulnerability to JSON bomb attacks."
                                    ),
                                    cwe_id="CWE-770",
                                    cwe_name="Allocation of Resources Without Limits",
                                    url=test_url,
                                    evidence=f"Response time: {elapsed_ms:.0f}ms at depth {depth}",
                                    remediation=(
                                        "Implement JSON depth limits in your parser configuration."
                                    ),
                                    cvss_score=5.3,
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/770.html",
                                    ],
                                    metadata={
                                        "depth": depth,
                                        "response_time_ms": elapsed_ms,
                                    },
                                )
                            )
                            break

                    except httpx.TimeoutException:
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"JSON Bomb caused timeout at depth {depth}",
                                description=(
                                    f"Deeply nested JSON (depth {depth}) caused request timeout. "
                                    f"Server is vulnerable to JSON bomb DoS attacks."
                                ),
                                cwe_id="CWE-400",
                                cwe_name="Uncontrolled Resource Consumption",
                                url=test_url,
                                evidence=f"Timeout at depth {depth}",
                                remediation="Implement strict JSON depth limits.",
                                cvss_score=7.5,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/400.html",
                                ],
                                metadata={"depth": depth, "timeout": True},
                            )
                        )
                        break

                    except Exception as e:
                        logger.debug("json_bomb_test_error", url=test_url, error=str(e))

        return findings

    def _build_nested_json(self, depth: int) -> str:
        """Build deeply nested JSON string."""
        result = '{"v":1'
        for _ in range(depth):
            result = '{"a":' + result + "}"
        return result + "}"

    async def _attack_billion_laughs_variant(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """
        Attack 3: Billion Laughs Variant (JSON/YAML Entity Expansion).

        Modern variant using reference expansion in JSON schemas,
        YAML anchors, or GraphQL fragments to cause exponential growth.

        CWE-776: Improper Restriction of Recursive Entity References
        """
        findings: list[Finding] = []

        # Test YAML anchor expansion
        yaml_bomb = """
anchors:
  - &a ["lol","lol","lol","lol","lol"]
  - &b [*a,*a,*a,*a,*a]
  - &c [*b,*b,*b,*b,*b]
  - &d [*c,*c,*c,*c,*c]
data: *d
"""

        # Test JSON with repeated references (in schemas that support $ref)
        json_ref_bomb = json.dumps({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "definitions": {
                "a": {"type": "array", "items": {"type": "string"}},
                "b": {"allOf": [{"$ref": "#/definitions/a"}] * 10},
                "c": {"allOf": [{"$ref": "#/definitions/b"}] * 10},
            },
            "type": "object",
            "properties": {
                "data": {"$ref": "#/definitions/c"}
            }
        })

        test_urls = [url]
        for endpoint in ["/api", "/config", "/schema", "/webhook"]:
            parsed = urlparse(url)
            test_urls.append(f"{parsed.scheme}://{parsed.netloc}{endpoint}")

        async with httpx.AsyncClient(
            timeout=30.0,
            verify=self.config.verify_ssl,
            follow_redirects=True,
        ) as client:
            for test_url in test_urls:
                # Test YAML bomb
                try:
                    start = time.perf_counter()
                    response = await client.post(
                        test_url,
                        content=yaml_bomb,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/yaml",
                        },
                    )
                    elapsed_ms = (time.perf_counter() - start) * 1000

                    if response.status_code == 500 or elapsed_ms > self.TIMING_THRESHOLD_MS * 3:
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title="YAML Anchor Expansion Vulnerability",
                                description=(
                                    "Server is vulnerable to YAML anchor expansion attack "
                                    "(Billion Laughs variant). Recursive anchor references "
                                    "can cause exponential memory growth."
                                ),
                                cwe_id="CWE-776",
                                cwe_name="Improper Restriction of Recursive Entity References",
                                url=test_url,
                                evidence=f"Status: {response.status_code}, Time: {elapsed_ms:.0f}ms",
                                remediation=(
                                    "1. Use safe YAML loaders (yaml.safe_load in Python)\n"
                                    "2. Limit anchor recursion depth\n"
                                    "3. Set memory limits for YAML parsing"
                                ),
                                cvss_score=7.5,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/776.html",
                                    "https://en.wikipedia.org/wiki/Billion_laughs_attack",
                                ],
                                metadata={"content_type": "yaml", "elapsed_ms": elapsed_ms},
                            )
                        )

                except Exception as e:
                    logger.debug("yaml_bomb_test_error", url=test_url, error=str(e))

                # Test JSON $ref bomb
                try:
                    start = time.perf_counter()
                    response = await client.post(
                        test_url,
                        content=json_ref_bomb,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/json",
                        },
                    )
                    elapsed_ms = (time.perf_counter() - start) * 1000

                    if response.status_code == 500 or elapsed_ms > self.TIMING_THRESHOLD_MS * 3:
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title="JSON Schema Reference Expansion Issue",
                                description=(
                                    "Server shows signs of vulnerability to JSON Schema "
                                    "$ref expansion attacks. Recursive references can "
                                    "cause memory exhaustion."
                                ),
                                cwe_id="CWE-776",
                                cwe_name="Improper Restriction of Recursive Entity References",
                                url=test_url,
                                evidence=f"Status: {response.status_code}, Time: {elapsed_ms:.0f}ms",
                                remediation="Limit JSON Schema $ref recursion depth.",
                                cvss_score=5.3,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/776.html",
                                ],
                                metadata={"content_type": "json", "elapsed_ms": elapsed_ms},
                            )
                        )

                except Exception as e:
                    logger.debug("json_ref_bomb_test_error", url=test_url, error=str(e))

        return findings

    async def _attack_multipart_bomb(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 4: Multipart Bomb.

        Send multipart form with thousands of parts to exhaust
        server memory during form parsing.

        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        # Find forms with file upload or multipart capability
        for form in forms:
            if not isinstance(form, dict):
                continue

            form_action = form.get("action", url)
            form_method = form.get("method", "get").lower()

            if form_method != "post":
                continue

            # Test incremental part counts
            for part_count in [10, 50, 100]:
                try:
                    # Build multipart with many parts
                    files: dict[str, tuple[str, str]] = {}
                    for i in range(part_count):
                        files[f"field_{i}"] = (f"file_{i}.txt", f"content_{i}")

                    async with httpx.AsyncClient(
                        timeout=30.0,
                        verify=self.config.verify_ssl,
                        follow_redirects=True,
                    ) as client:
                        start = time.perf_counter()
                        response = await client.post(
                            form_action,
                            files=files,
                            headers={"User-Agent": self.config.user_agent},
                        )
                        elapsed_ms = (time.perf_counter() - start) * 1000

                        # Check for memory issues
                        if response.status_code == 500:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.HIGH,
                                    title=f"Multipart Bomb: Server crashed at {part_count} parts",
                                    description=(
                                        f"Server returned 500 error when processing multipart "
                                        f"form with {part_count} parts. This indicates "
                                        f"vulnerability to multipart bomb DoS attacks."
                                    ),
                                    cwe_id="CWE-400",
                                    cwe_name="Uncontrolled Resource Consumption",
                                    url=form_action,
                                    evidence=f"500 at {part_count} parts, time: {elapsed_ms:.0f}ms",
                                    remediation=(
                                        "1. Limit maximum number of multipart parts\n"
                                        "2. Set per-request memory limits\n"
                                        "3. Use streaming multipart parsers"
                                    ),
                                    cvss_score=7.5,
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/400.html",
                                    ],
                                    metadata={"part_count": part_count},
                                )
                            )
                            break

                        if elapsed_ms > self.TIMING_THRESHOLD_MS * 2:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.MEDIUM,
                                    title=f"Multipart processing slowdown at {part_count} parts",
                                    description=(
                                        f"Server shows slowdown ({elapsed_ms:.0f}ms) when "
                                        f"processing multipart with {part_count} parts."
                                    ),
                                    cwe_id="CWE-770",
                                    cwe_name="Allocation of Resources Without Limits",
                                    url=form_action,
                                    evidence=f"Time: {elapsed_ms:.0f}ms at {part_count} parts",
                                    remediation="Limit multipart form field count.",
                                    cvss_score=5.3,
                                    metadata={"part_count": part_count, "elapsed_ms": elapsed_ms},
                                )
                            )
                            break

                except httpx.TimeoutException:
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title=f"Multipart Bomb timeout at {part_count} parts",
                            description=(
                                f"Multipart form with {part_count} parts caused timeout."
                            ),
                            cwe_id="CWE-400",
                            cwe_name="Uncontrolled Resource Consumption",
                            url=form_action,
                            evidence=f"Timeout at {part_count} parts",
                            remediation="Implement strict multipart limits.",
                            cvss_score=7.5,
                            metadata={"part_count": part_count, "timeout": True},
                        )
                    )
                    break

                except Exception as e:
                    logger.debug("multipart_bomb_error", error=str(e))

        return findings

    async def _attack_header_flooding(self, url: str) -> list[Finding]:
        """
        Attack 5: Header Flooding.

        Send request with many headers to overflow header buffer
        and exhaust memory.

        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        # Test incremental header counts
        for header_count in [20, 50, 100]:
            try:
                headers = {"User-Agent": self.config.user_agent}
                for i in range(header_count):
                    headers[f"X-Custom-Header-{i}"] = f"value-{i}-{'x' * 100}"

                async with httpx.AsyncClient(
                    timeout=30.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    start = time.perf_counter()
                    response = await client.get(url, headers=headers)
                    elapsed_ms = (time.perf_counter() - start) * 1000

                    # Check for header limit errors
                    if response.status_code in [400, 431]:
                        # 431 = Request Header Fields Too Large - good!
                        logger.debug("header_limit_enforced", count=header_count)
                        break

                    if response.status_code == 500:
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"Header Flooding: Server error at {header_count} headers",
                                description=(
                                    f"Server crashed with {header_count} custom headers. "
                                    f"No proper header count limit is enforced."
                                ),
                                cwe_id="CWE-400",
                                cwe_name="Uncontrolled Resource Consumption",
                                url=url,
                                evidence=f"500 error at {header_count} headers",
                                remediation=(
                                    "1. Configure web server to limit header count\n"
                                    "2. Set maximum header size limits\n"
                                    "3. Return 431 for excessive headers"
                                ),
                                cvss_score=7.5,
                                references=[
                                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/431",
                                ],
                                metadata={"header_count": header_count},
                            )
                        )
                        break

                    if elapsed_ms > self.TIMING_THRESHOLD_MS * 2:
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title=f"Header processing slowdown at {header_count} headers",
                                description=(
                                    f"Server shows slowdown ({elapsed_ms:.0f}ms) "
                                    f"processing {header_count} headers."
                                ),
                                cwe_id="CWE-770",
                                cwe_name="Allocation of Resources Without Limits",
                                url=url,
                                evidence=f"Time: {elapsed_ms:.0f}ms at {header_count} headers",
                                remediation="Implement header count limits.",
                                cvss_score=5.3,
                                metadata={"header_count": header_count, "elapsed_ms": elapsed_ms},
                            )
                        )
                        break

            except httpx.TimeoutException:
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Header Flooding timeout at {header_count} headers",
                        description=f"Request with {header_count} headers caused timeout.",
                        cwe_id="CWE-400",
                        cwe_name="Uncontrolled Resource Consumption",
                        url=url,
                        evidence=f"Timeout at {header_count} headers",
                        remediation="Configure strict header limits.",
                        cvss_score=7.5,
                        metadata={"header_count": header_count, "timeout": True},
                    )
                )
                break

            except Exception as e:
                logger.debug("header_flooding_error", error=str(e))

        return findings

    async def _attack_cookie_jar_overflow(self, url: str) -> list[Finding]:
        """
        Attack 6: Cookie Jar Overflow.

        Test if response handling properly limits Set-Cookie headers.
        Servers that reflect many cookies back can exhaust client memory.

        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        # Send request with many cookies to see if server echoes them
        for cookie_count in [20, 50]:
            try:
                cookies = {f"cookie_{i}": f"value_{'x' * 100}_{i}" for i in range(cookie_count)}

                async with httpx.AsyncClient(
                    timeout=30.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    response = await client.get(
                        url,
                        cookies=cookies,
                        headers={"User-Agent": self.config.user_agent},
                    )

                    # Count Set-Cookie headers in response
                    set_cookies = response.headers.get_list("set-cookie")

                    if len(set_cookies) > 50:
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title=f"Excessive Set-Cookie headers: {len(set_cookies)}",
                                description=(
                                    f"Server returns {len(set_cookies)} Set-Cookie headers. "
                                    f"This can be exploited to overflow client cookie storage "
                                    f"and exhaust browser memory."
                                ),
                                cwe_id="CWE-400",
                                cwe_name="Uncontrolled Resource Consumption",
                                url=url,
                                evidence=f"{len(set_cookies)} Set-Cookie headers",
                                remediation=(
                                    "1. Limit Set-Cookie headers per response\n"
                                    "2. Consolidate cookies where possible\n"
                                    "3. Review cookie generation logic"
                                ),
                                cvss_score=4.3,
                                metadata={"set_cookie_count": len(set_cookies)},
                            )
                        )
                        break

                    # Check for cookie reflection vulnerability
                    if len(set_cookies) >= cookie_count * 0.8:
                        findings.append(
                            self._create_finding(
                                severity=Severity.LOW,
                                title="Cookie Reflection Detected",
                                description=(
                                    f"Server reflects back {len(set_cookies)} cookies when "
                                    f"{cookie_count} were sent. This could be exploited for "
                                    f"cookie jar overflow attacks."
                                ),
                                cwe_id="CWE-400",
                                cwe_name="Uncontrolled Resource Consumption",
                                url=url,
                                evidence=f"Sent {cookie_count}, received {len(set_cookies)} Set-Cookie",
                                remediation="Review cookie handling to prevent reflection.",
                                cvss_score=3.1,
                                metadata={
                                    "sent": cookie_count,
                                    "reflected": len(set_cookies),
                                },
                            )
                        )

            except Exception as e:
                logger.debug("cookie_overflow_error", error=str(e))

        return findings

    async def _attack_chunked_encoding_abuse(self, url: str) -> list[Finding]:
        """
        Attack 7: Chunked Encoding Abuse.

        Send request with many tiny chunks to hold connections
        and potentially leak memory via chunked transfer handling.

        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        # Build chunked request body with many tiny chunks
        chunk_counts = [100, 500]

        for chunk_count in chunk_counts:
            try:
                async with httpx.AsyncClient(
                    timeout=60.0,
                    verify=self.config.verify_ssl,
                ) as client:
                    start = time.perf_counter()
                    try:
                        response = await client.post(
                            url,
                            content=b"x" * chunk_count,
                            headers={
                                "User-Agent": self.config.user_agent,
                                "Transfer-Encoding": "chunked",
                                "Content-Type": "application/octet-stream",
                            },
                        )
                        elapsed_ms = (time.perf_counter() - start) * 1000

                        if response.status_code == 500:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.MEDIUM,
                                    title="Chunked Encoding handling issue",
                                    description=(
                                        "Server shows issues handling chunked transfer "
                                        "encoding. This may indicate memory management "
                                        "problems with streaming requests."
                                    ),
                                    cwe_id="CWE-400",
                                    cwe_name="Uncontrolled Resource Consumption",
                                    url=url,
                                    evidence=f"500 error with chunked encoding, {elapsed_ms:.0f}ms",
                                    remediation=(
                                        "Review chunked transfer handling. "
                                        "Implement streaming limits."
                                    ),
                                    cvss_score=5.3,
                                    metadata={"chunk_count": chunk_count, "elapsed_ms": elapsed_ms},
                                )
                            )
                            break

                    except httpx.TimeoutException:
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title="Chunked Encoding timeout",
                                description=(
                                    "Chunked encoding request caused timeout. "
                                    "Server may be holding connections indefinitely."
                                ),
                                cwe_id="CWE-400",
                                cwe_name="Uncontrolled Resource Consumption",
                                url=url,
                                evidence="Timeout with chunked encoding",
                                remediation="Implement chunked transfer timeout limits.",
                                cvss_score=5.3,
                                metadata={"timeout": True},
                            )
                        )
                        break

            except Exception as e:
                logger.debug("chunked_encoding_error", error=str(e))

        return findings

    async def _attack_graphql_depth_bomb(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """
        Attack 8: GraphQL Depth Bomb.

        Send deeply nested GraphQL queries to exhaust resolver memory.

        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        # Detect GraphQL endpoints
        graphql_indicators = [
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "graphiql",
            "__schema",
        ]

        has_graphql = any(ind in html_content.lower() for ind in graphql_indicators)
        has_graphql = has_graphql or any(ind in url.lower() for ind in graphql_indicators)

        if not has_graphql:
            # Try common GraphQL paths
            parsed = urlparse(url)
            graphql_urls = [
                f"{parsed.scheme}://{parsed.netloc}/graphql",
                f"{parsed.scheme}://{parsed.netloc}/api/graphql",
            ]
        else:
            graphql_urls = [url]

        for gql_url in graphql_urls:
            # Test incremental query depths
            for depth in [5, 10, 20, 30]:
                try:
                    # Build deeply nested query
                    nested_query = self._build_graphql_depth_query(depth)

                    async with httpx.AsyncClient(
                        timeout=30.0,
                        verify=self.config.verify_ssl,
                        follow_redirects=True,
                    ) as client:
                        start = time.perf_counter()
                        response = await client.post(
                            gql_url,
                            json={"query": nested_query},
                            headers={
                                "User-Agent": self.config.user_agent,
                                "Content-Type": "application/json",
                            },
                        )
                        elapsed_ms = (time.perf_counter() - start) * 1000

                        # Check for depth limit enforcement
                        response_text = safe_response_text(response).lower()

                        if "depth" in response_text and "exceeded" in response_text:
                            # Good - depth limit is enforced
                            logger.debug("graphql_depth_limit_enforced", depth=depth)
                            break

                        if response.status_code == 500:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.HIGH,
                                    title=f"GraphQL Depth Bomb: Server error at depth {depth}",
                                    description=(
                                        f"GraphQL endpoint crashed at query depth {depth}. "
                                        f"No depth limit is enforced, allowing DoS via "
                                        f"deeply nested queries."
                                    ),
                                    cwe_id="CWE-400",
                                    cwe_name="Uncontrolled Resource Consumption",
                                    url=gql_url,
                                    evidence=f"500 error at depth {depth}",
                                    remediation=(
                                        "1. Implement query depth limiting\n"
                                        "2. Use query complexity analysis\n"
                                        "3. Set resolver timeout limits\n"
                                        "4. Consider persisted queries"
                                    ),
                                    cvss_score=7.5,
                                    references=[
                                        "https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/",
                                    ],
                                    metadata={"depth": depth},
                                )
                            )
                            break

                        if elapsed_ms > self.TIMING_THRESHOLD_MS * 3:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.MEDIUM,
                                    title=f"GraphQL slowdown at depth {depth}",
                                    description=(
                                        f"GraphQL query with depth {depth} caused "
                                        f"significant slowdown ({elapsed_ms:.0f}ms)."
                                    ),
                                    cwe_id="CWE-770",
                                    cwe_name="Allocation of Resources Without Limits",
                                    url=gql_url,
                                    evidence=f"Time: {elapsed_ms:.0f}ms at depth {depth}",
                                    remediation="Implement GraphQL query depth limits.",
                                    cvss_score=5.3,
                                    metadata={"depth": depth, "elapsed_ms": elapsed_ms},
                                )
                            )
                            break

                except httpx.TimeoutException:
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title=f"GraphQL Depth Bomb timeout at depth {depth}",
                            description=f"Nested query (depth {depth}) caused timeout.",
                            cwe_id="CWE-400",
                            cwe_name="Uncontrolled Resource Consumption",
                            url=gql_url,
                            evidence=f"Timeout at depth {depth}",
                            remediation="Implement strict depth limits.",
                            cvss_score=7.5,
                            metadata={"depth": depth, "timeout": True},
                        )
                    )
                    break

                except Exception as e:
                    logger.debug("graphql_depth_bomb_error", error=str(e))

        return findings

    def _build_graphql_depth_query(self, depth: int) -> str:
        """Build deeply nested GraphQL introspection query."""
        # Use __typename which exists on all GraphQL types
        inner = "__typename"
        for _ in range(depth):
            inner = f"__schema {{ types {{ name fields {{ {inner} }} }} }}"
        return f"query {{ {inner} }}"

    async def _attack_websocket_frame_flooding(self, url: str) -> list[Finding]:
        """
        Attack 9: WebSocket Frame Flooding.

        Detect if WebSocket endpoint handles memory properly under
        rapid frame transmission.

        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        # Convert http to ws URL
        ws_url = url.replace("https://", "wss://").replace("http://", "ws://")

        # Try common WebSocket paths
        parsed = urlparse(url)
        ws_urls = [
            ws_url,
            f"wss://{parsed.netloc}/ws",
            f"wss://{parsed.netloc}/websocket",
            f"wss://{parsed.netloc}/socket",
            f"ws://{parsed.netloc}/ws",
        ]

        try:
            import websockets
        except ImportError:
            logger.debug("websockets not installed, skipping ws flood test")
            return findings

        for test_ws_url in ws_urls:
            try:
                import websockets

                async with websockets.connect(
                    test_ws_url,
                    close_timeout=5,
                    open_timeout=10,
                ) as ws:
                    # Send rapid small frames
                    frame_count = 100
                    start = time.perf_counter()

                    for i in range(frame_count):
                        await ws.send(f"frame_{i}")

                    elapsed_ms = (time.perf_counter() - start) * 1000

                    # Check if all frames were accepted
                    avg_frame_time = elapsed_ms / frame_count

                    if avg_frame_time < 1:  # Less than 1ms per frame - no rate limiting
                        findings.append(
                            self._create_finding(
                                severity=Severity.LOW,
                                title="WebSocket accepts rapid frames without rate limiting",
                                description=(
                                    f"WebSocket endpoint accepts {frame_count} frames in "
                                    f"{elapsed_ms:.0f}ms ({avg_frame_time:.2f}ms/frame). "
                                    f"No rate limiting detected - potential DoS vector."
                                ),
                                cwe_id="CWE-400",
                                cwe_name="Uncontrolled Resource Consumption",
                                url=test_ws_url,
                                evidence=f"{frame_count} frames in {elapsed_ms:.0f}ms",
                                remediation=(
                                    "1. Implement WebSocket frame rate limiting\n"
                                    "2. Set maximum frames per second\n"
                                    "3. Monitor connection memory usage"
                                ),
                                cvss_score=4.3,
                                metadata={
                                    "frame_count": frame_count,
                                    "elapsed_ms": elapsed_ms,
                                    "avg_frame_time_ms": avg_frame_time,
                                },
                            )
                        )

                    await ws.close()

            except ImportError:
                logger.debug("websockets library not available")
                break

            except Exception as e:
                logger.debug("websocket_flood_error", url=test_ws_url, error=str(e))

        return findings

    async def _attack_decompression_bomb(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """
        Attack 10: Decompression Bomb Detection.

        Test if server decompresses gzip content without size limits.
        A small gzip can expand to gigabytes, exhausting memory.

        CWE-409: Improper Handling of Highly Compressed Data (Zip Bomb)
        """
        findings: list[Finding] = []

        # Create a small gzip that expands to a larger size
        # NOT a true bomb - just a test payload
        test_data = b"A" * 10000  # 10KB uncompressed
        compressed = gzip.compress(test_data, compresslevel=9)
        compression_ratio = len(test_data) / len(compressed)

        # Test increasingly compressed payloads
        test_payloads = [
            (b"B" * 10000, "10KB"),
            (b"C" * 100000, "100KB"),
            (b"D" * 500000, "500KB"),
        ]

        for uncompressed_data, size_label in test_payloads:
            try:
                compressed_payload = gzip.compress(uncompressed_data, compresslevel=9)
                ratio = len(uncompressed_data) / len(compressed_payload)

                async with httpx.AsyncClient(
                    timeout=30.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    start = time.perf_counter()
                    response = await client.post(
                        url,
                        content=compressed_payload,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Encoding": "gzip",
                            "Content-Type": "application/octet-stream",
                        },
                    )
                    elapsed_ms = (time.perf_counter() - start) * 1000

                    # Server should either:
                    # 1. Reject with 413 (Payload Too Large) after decompression
                    # 2. Return 415 (Unsupported Media Type)
                    # 3. Process normally

                    if response.status_code == 500:
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"Decompression Bomb: Server crashed on {size_label}",
                                description=(
                                    f"Server crashed when decompressing gzip payload that "
                                    f"expands to {size_label} (ratio {ratio:.1f}x). "
                                    f"No decompression limit is enforced."
                                ),
                                cwe_id="CWE-409",
                                cwe_name="Improper Handling of Highly Compressed Data",
                                url=url,
                                evidence=f"500 on {size_label}, ratio {ratio:.1f}x",
                                remediation=(
                                    "1. Limit decompressed content size\n"
                                    "2. Set compression ratio limits\n"
                                    "3. Use streaming decompression with checks\n"
                                    "4. Monitor memory during decompression"
                                ),
                                cvss_score=7.5,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/409.html",
                                    "https://en.wikipedia.org/wiki/Zip_bomb",
                                ],
                                metadata={
                                    "uncompressed_size": size_label,
                                    "compression_ratio": ratio,
                                },
                            )
                        )
                        break

                    if elapsed_ms > self.TIMING_THRESHOLD_MS * 3:
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title=f"Decompression slowdown on {size_label}",
                                description=(
                                    f"Server shows slowdown ({elapsed_ms:.0f}ms) "
                                    f"decompressing {size_label} payload."
                                ),
                                cwe_id="CWE-409",
                                cwe_name="Improper Handling of Highly Compressed Data",
                                url=url,
                                evidence=f"Time: {elapsed_ms:.0f}ms for {size_label}",
                                remediation="Implement decompression limits.",
                                cvss_score=5.3,
                                metadata={
                                    "size": size_label,
                                    "elapsed_ms": elapsed_ms,
                                },
                            )
                        )
                        break

            except httpx.TimeoutException:
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Decompression Bomb timeout on {size_label}",
                        description=f"Decompression of {size_label} caused timeout.",
                        cwe_id="CWE-409",
                        cwe_name="Improper Handling of Highly Compressed Data",
                        url=url,
                        evidence=f"Timeout on {size_label}",
                        remediation="Implement strict decompression limits.",
                        cvss_score=7.5,
                        metadata={"size": size_label, "timeout": True},
                    )
                )
                break

            except Exception as e:
                logger.debug("decompression_bomb_error", error=str(e))

        return findings

    async def _attack_array_index_overflow(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 11: Array Index Overflow.

        Send array indices like [999999999] to cause massive
        memory allocation in array handling.

        CWE-789: Memory Allocation with Excessive Size Value
        """
        findings: list[Finding] = []

        # Payloads with huge array indices
        overflow_payloads = [
            ("array_index", "data[999999999]", "value"),
            ("array_index", "items[2147483647]", "x"),  # Max int32
            ("array_index", "arr[4294967295]", "y"),  # Max uint32
            ("nested_array", "a[1000000][1000000]", "z"),
        ]

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_action = form.get("action", url)

            for payload_name, key, value in overflow_payloads:
                try:
                    async with httpx.AsyncClient(
                        timeout=30.0,
                        verify=self.config.verify_ssl,
                        follow_redirects=True,
                    ) as client:
                        start = time.perf_counter()
                        response = await client.post(
                            form_action,
                            data={key: value},
                            headers={"User-Agent": self.config.user_agent},
                        )
                        elapsed_ms = (time.perf_counter() - start) * 1000

                        if response.status_code == 500:
                            error_text = safe_response_text(response).lower()
                            memory_indicators = [
                                "memory", "allocation", "out of", "cannot allocate",
                                "overflow", "size", "limit"
                            ]

                            if any(ind in error_text for ind in memory_indicators):
                                findings.append(
                                    self._create_finding(
                                        severity=Severity.HIGH,
                                        title=f"Array Index Overflow: {payload_name}",
                                        description=(
                                            f"Server crashed when processing large array "
                                            f"index in '{key}'. Memory allocation error "
                                            f"indicates vulnerability to index overflow."
                                        ),
                                        cwe_id="CWE-789",
                                        cwe_name="Memory Allocation with Excessive Size Value",
                                        url=form_action,
                                        evidence=f"500 with memory error on {key}",
                                        remediation=(
                                            "1. Validate array indices against maximum size\n"
                                            "2. Use sparse arrays or maps for large indices\n"
                                            "3. Reject unreasonably large indices"
                                        ),
                                        cvss_score=7.5,
                                        references=[
                                            "https://cwe.mitre.org/data/definitions/789.html",
                                        ],
                                        metadata={"payload": key},
                                    )
                                )
                                break

                        if elapsed_ms > self.TIMING_THRESHOLD_MS * 2:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.MEDIUM,
                                    title="Array Index processing slowdown",
                                    description=(
                                        f"Server shows slowdown ({elapsed_ms:.0f}ms) "
                                        f"processing large array index '{key}'."
                                    ),
                                    cwe_id="CWE-789",
                                    cwe_name="Memory Allocation with Excessive Size Value",
                                    url=form_action,
                                    evidence=f"Time: {elapsed_ms:.0f}ms for {key}",
                                    remediation="Validate array indices server-side.",
                                    cvss_score=5.3,
                                    metadata={"payload": key, "elapsed_ms": elapsed_ms},
                                )
                            )
                            break

                except httpx.TimeoutException:
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title=f"Array Index caused timeout: {key}",
                            description=f"Large array index '{key}' caused timeout.",
                            cwe_id="CWE-789",
                            cwe_name="Memory Allocation with Excessive Size Value",
                            url=form_action,
                            evidence=f"Timeout on {key}",
                            remediation="Implement array index validation.",
                            cvss_score=7.5,
                            metadata={"payload": key, "timeout": True},
                        )
                    )
                    break

                except Exception as e:
                    logger.debug("array_index_error", error=str(e))

        # Also test JSON endpoints
        parsed = urlparse(url)
        api_urls = [
            f"{parsed.scheme}://{parsed.netloc}/api",
            url,
        ]

        for api_url in api_urls:
            try:
                # JSON payload with large array indices
                json_payload = {
                    "data": {str(i): "x" for i in [0, 999999999, 2147483647]},
                    "array": ["x"] * 10,  # Normal array
                }

                async with httpx.AsyncClient(
                    timeout=30.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    response = await client.post(
                        api_url,
                        json=json_payload,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/json",
                        },
                    )

                    if response.status_code == 500:
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title="JSON Object with large keys causes error",
                                description=(
                                    "Server crashed processing JSON with extremely "
                                    "large numeric keys in object."
                                ),
                                cwe_id="CWE-789",
                                cwe_name="Memory Allocation with Excessive Size Value",
                                url=api_url,
                                evidence="500 on JSON with large keys",
                                remediation="Validate JSON structure and key sizes.",
                                cvss_score=5.3,
                                metadata={"format": "json"},
                            )
                        )

            except Exception as e:
                logger.debug("json_array_index_error", url=api_url, error=str(e))

        return findings

    async def _attack_string_multiplication(
        self,
        url: str,
        forms: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 12: String Multiplication Attack.

        Send payloads like "A"*10000000 targeting template engines
        that might execute multiplication expressions.

        CWE-94: Improper Control of Generation of Code
        CWE-400: Uncontrolled Resource Consumption
        """
        findings: list[Finding] = []

        # Template engine payloads that attempt string multiplication
        # Using smaller safe sizes for detection
        template_payloads = [
            ("jinja2_basic", "{{ 'X' * 100000 }}"),
            ("jinja2_range", "{% for i in range(100000) %}X{% endfor %}"),
            ("django", "{% widthratio 100000 1 1 %}"),
            ("erb", "<%= 'X' * 100000 %>"),
            ("twig", "{{ 'X'|repeat(100000) }}"),
            ("freemarker", "${'X'?repeat(100000)}"),
            ("velocity", "#foreach($i in [1..100000])X#end"),
            ("mako", "${'X' * 100000}"),
            ("pebble", "{{ 'X' * 100000 }}"),
            ("expression_lang", "${100000 * 'X'}"),
            ("ssti_generic", "${{100000*'X'}}"),
        ]

        for form in forms:
            if not isinstance(form, dict):
                continue

            form_action = form.get("action", url)
            inputs = form.get("inputs", [])

            for input_field in inputs:
                if not isinstance(input_field, dict):
                    continue

                field_name = input_field.get("name", "")
                field_type = input_field.get("type", "").lower()

                if not field_name or field_type in ["hidden", "submit", "button", "file"]:
                    continue

                for template_name, payload in template_payloads:
                    try:
                        async with httpx.AsyncClient(
                            timeout=30.0,
                            verify=self.config.verify_ssl,
                            follow_redirects=True,
                        ) as client:
                            start = time.perf_counter()
                            response = await client.post(
                                form_action,
                                data={field_name: payload},
                                headers={"User-Agent": self.config.user_agent},
                            )
                            elapsed_ms = (time.perf_counter() - start) * 1000

                            # Check if payload was executed
                            response_text = safe_response_text(response)

                            # If we see many X's, the template was executed
                            if "XXXXX" * 100 in response_text:
                                findings.append(
                                    self._create_finding(
                                        severity=Severity.CRITICAL,
                                        title=f"SSTI String Multiplication: {template_name}",
                                        description=(
                                            f"Template injection in field '{field_name}' "
                                            f"allows string multiplication. Template type: "
                                            f"{template_name}. This is both an SSTI and "
                                            f"a memory exhaustion vulnerability."
                                        ),
                                        cwe_id="CWE-94",
                                        cwe_name="Improper Control of Generation of Code",
                                        url=form_action,
                                        evidence=f"Payload {template_name} executed, produced repeated chars",
                                        remediation=(
                                            "1. CRITICAL: Fix Server-Side Template Injection\n"
                                            "2. Use sandboxed template environments\n"
                                            "3. Disable dangerous template features\n"
                                            "4. Never pass user input directly to templates"
                                        ),
                                        cvss_score=9.8,
                                        references=[
                                            "https://portswigger.net/research/server-side-template-injection",
                                            "https://cwe.mitre.org/data/definitions/94.html",
                                        ],
                                        metadata={
                                            "field": field_name,
                                            "template_type": template_name,
                                        },
                                    )
                                )
                                return findings  # Critical finding - stop

                            if response.status_code == 500:
                                error_text = safe_response_text(response).lower()
                                memory_indicators = ["memory", "allocation", "heap", "stack"]

                                if any(ind in error_text for ind in memory_indicators):
                                    findings.append(
                                        self._create_finding(
                                            severity=Severity.HIGH,
                                            title=f"Template engine memory exhaustion: {template_name}",
                                            description=(
                                                f"Field '{field_name}' shows memory exhaustion "
                                                f"when processing template payload. Template "
                                                f"type: {template_name}."
                                            ),
                                            cwe_id="CWE-400",
                                            cwe_name="Uncontrolled Resource Consumption",
                                            url=form_action,
                                            evidence=f"500 with memory error on {template_name}",
                                            remediation="Disable template execution on user input.",
                                            cvss_score=7.5,
                                            metadata={
                                                "field": field_name,
                                                "template_type": template_name,
                                            },
                                        )
                                    )
                                    break

                            if elapsed_ms > self.TIMING_THRESHOLD_MS * 3:
                                findings.append(
                                    self._create_finding(
                                        severity=Severity.MEDIUM,
                                        title=f"Template processing slowdown: {template_name}",
                                        description=(
                                            f"Field '{field_name}' shows slowdown "
                                            f"({elapsed_ms:.0f}ms) on template payload."
                                        ),
                                        cwe_id="CWE-400",
                                        cwe_name="Uncontrolled Resource Consumption",
                                        url=form_action,
                                        evidence=f"Time: {elapsed_ms:.0f}ms on {template_name}",
                                        remediation="Review template processing.",
                                        cvss_score=5.3,
                                        metadata={
                                            "field": field_name,
                                            "elapsed_ms": elapsed_ms,
                                        },
                                    )
                                )
                                break

                    except httpx.TimeoutException:
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"Template payload timeout: {template_name}",
                                description=(
                                    f"Template payload in '{field_name}' caused timeout. "
                                    f"Possible SSTI or resource exhaustion."
                                ),
                                cwe_id="CWE-400",
                                cwe_name="Uncontrolled Resource Consumption",
                                url=form_action,
                                evidence=f"Timeout on {template_name}",
                                remediation="Review template processing and input sanitization.",
                                cvss_score=7.5,
                                metadata={
                                    "field": field_name,
                                    "template_type": template_name,
                                    "timeout": True,
                                },
                            )
                        )
                        break

                    except Exception as e:
                        logger.debug("template_attack_error", error=str(e))

        return findings
