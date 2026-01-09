"""
Cryptographic Analysis Analyzer.

Analyzes cryptographic implementations including JWT tokens,
key management, and secure transport enforcement.
"""

from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from typing import Any

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity


class CryptoAnalyzer(BaseAnalyzer):
    """
    Analyzer for cryptographic vulnerabilities.

    Checks for:
    - JWT implementation issues (CWE-347)
    - Weak cryptographic configurations (CWE-327)
    - Token entropy and randomness (CWE-330)
    - Secure transport enforcement (CWE-319)
    - Key management practices (CWE-321)
    """

    analyzer_type = AnalyzerType.CRYPTO_ANALYSIS

    # JWT truly weak/dangerous algorithms
    JWT_WEAK_ALGORITHMS = ["none"]
    JWT_NONE_ALGORITHM = "none"
    # JWT symmetric algorithms (not weak, but worth noting for context)
    JWT_SYMMETRIC_ALGORITHMS = ["hs256", "hs384", "hs512"]

    # Weak key indicators in responses
    WEAK_KEY_PATTERNS = [
        r"(?:secret|key|password)\s*[:=]\s*['\"]?(password|secret|123456|admin|test|default)['\"]?",
        r"(?:api[_-]?key|token)\s*[:=]\s*['\"]?[a-z0-9]{1,8}['\"]?",
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        r"-----BEGIN\s+(?:EC\s+)?PRIVATE\s+KEY-----",
    ]

    # Patterns indicating cryptographic operations
    CRYPTO_PATTERNS = {
        "md5": r"['\"]?md5['\"]?|MD5|\.md5\(|hashlib\.md5",
        "sha1": r"['\"]?sha1['\"]?|SHA1|\.sha1\(|hashlib\.sha1",
        "des": r"\bDES\b|des[_-]?cbc|des[_-]?ecb",
        "3des": r"3DES|triple[_-]?des|des[_-]?ede",
        "rc4": r"\bRC4\b|arc4|arcfour",
        "ecb_mode": r"ECB|ecb[_-]mode",
    }

    MIN_TOKEN_ENTROPY = 4.0

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze cryptographic implementations."""
        findings: list[Finding] = []
        html_content = page_data.get("html", "")
        scripts = page_data.get("scripts", [])
        headers = page_data.get("headers", {})
        cookies = page_data.get("cookies", [])
        scan_mode = page_data.get("scan_mode", "passive")

        # Combine all content for analysis
        all_content = html_content
        for script in scripts:
            if isinstance(script, str):
                all_content += "\n" + script

        # Passive analysis
        findings.extend(self._analyze_jwt_tokens(url, headers, cookies, all_content))
        findings.extend(self._analyze_transport_security(url, headers))
        findings.extend(self._analyze_token_entropy(url, cookies))

        # Active mode analysis
        if scan_mode == "active":
            findings.extend(self._analyze_weak_crypto(url, all_content))
            findings.extend(self._analyze_key_exposure(url, all_content))

        return findings

    def _analyze_jwt_tokens(
        self,
        url: str,
        headers: dict[str, str],
        cookies: list[dict[str, Any]],
        content: str,
    ) -> list[Finding]:
        """Analyze JWT tokens for security issues."""
        findings: list[Finding] = []

        # JWT pattern: header.payload.signature (base64url encoded)
        jwt_pattern = r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"

        jwt_tokens: list[str] = []

        # Check headers
        for key, value in headers.items():
            if "authorization" in key.lower() or "token" in key.lower():
                matches = re.findall(jwt_pattern, str(value))
                jwt_tokens.extend(matches)

        # Check cookies
        for cookie in cookies:
            if isinstance(cookie, dict):
                value = cookie.get("value", "")
                matches = re.findall(jwt_pattern, value)
                jwt_tokens.extend(matches)

        # Check content
        content_matches = re.findall(jwt_pattern, content)
        jwt_tokens.extend(content_matches)

        # Deduplicate
        jwt_tokens = list(set(jwt_tokens))

        for token in jwt_tokens[:5]:  # Limit analysis
            findings.extend(self._analyze_single_jwt(url, token))

        return findings

    def _analyze_single_jwt(
        self,
        url: str,
        token: str,
    ) -> list[Finding]:
        """Analyze a single JWT token for vulnerabilities."""
        findings: list[Finding] = []

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return findings

            # Decode header (with padding fix)
            header_b64 = parts[0]
            header_b64 += "=" * (4 - len(header_b64) % 4)
            header_bytes = base64.urlsafe_b64decode(header_b64)
            header = json.loads(header_bytes.decode("utf-8"))

            alg = header.get("alg", "").lower()
            typ = header.get("typ", "")

            # Check for 'none' algorithm
            if alg == self.JWT_NONE_ALGORITHM:
                findings.append(
                    self._create_finding(
                        severity=Severity.CRITICAL,
                        title="JWT Token Uses 'none' Algorithm",
                        description=(
                            "JWT token is configured with algorithm 'none', which means "
                            "no signature verification is performed. Attackers can forge "
                            "tokens by simply modifying the payload."
                        ),
                        cwe_id="CWE-347",
                        cwe_name="Improper Verification of Cryptographic Signature",
                        url=url,
                        evidence=f"JWT algorithm: {alg}",
                        remediation=(
                            "Never accept 'none' algorithm in production. "
                            "Explicitly whitelist allowed algorithms (RS256, ES256). "
                            "Reject tokens that don't match expected algorithm."
                        ),
                        cvss_score=9.8,
                        references=[
                            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                            "https://cwe.mitre.org/data/definitions/347.html",
                        ],
                        metadata={"algorithm": alg, "jwt_header": header},
                    )
                )

            # Note symmetric algorithms usage - not a vulnerability, but informational
            if alg in self.JWT_SYMMETRIC_ALGORITHMS:
                findings.append(
                    self._create_finding(
                        severity=Severity.INFO,
                        title=f"JWT Uses Symmetric (HMAC) Algorithm: {alg.upper()}",
                        description=(
                            f"JWT uses symmetric HMAC algorithm {alg.upper()}. "
                            "This is NOT inherently insecure - HMAC algorithms are appropriate for:\n"
                            "- Single-server applications\n"
                            "- Controlled environments where secret can be securely shared\n"
                            "- Internal microservices with shared secrets\n\n"
                            "Consider asymmetric algorithms (RS256, ES256) when:\n"
                            "- Multiple services need to verify tokens but shouldn't sign them\n"
                            "- Public key verification is required\n"
                            "- Distributed systems without secure secret sharing"
                        ),
                        cwe_id="CWE-327",
                        cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                        url=url,
                        evidence=f"JWT algorithm: {alg}",
                        remediation=(
                            "No action required if using HMAC intentionally with a strong secret. "
                            "Ensure HMAC secret is at least 256 bits (32 bytes) of cryptographically "
                            "random data. Consider asymmetric algorithms for distributed verification."
                        ),
                        cvss_score=0.0,
                        metadata={"algorithm": alg, "confidence": "informational"},
                    )
                )

            # Decode payload to check for sensitive data
            payload_b64 = parts[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes.decode("utf-8"))

            # Check for sensitive claims in payload
            sensitive_claims = ["password", "secret", "private_key", "api_key", "credit_card"]
            exposed_sensitive = [
                claim for claim in sensitive_claims if claim in str(payload).lower()
            ]

            if exposed_sensitive:
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title="JWT Contains Potentially Sensitive Data",
                        description=(
                            f"JWT payload appears to contain sensitive data fields: {exposed_sensitive}. "
                            "JWT payloads are only base64-encoded, not encrypted, and can be "
                            "read by anyone with access to the token."
                        ),
                        cwe_id="CWE-312",
                        cwe_name="Cleartext Storage of Sensitive Information",
                        url=url,
                        evidence=f"Sensitive claims detected: {exposed_sensitive}",
                        remediation=(
                            "Never store sensitive data in JWT payloads. "
                            "Use JWE (encrypted JWT) if payload confidentiality is required. "
                            "Store sensitive data server-side and reference by ID."
                        ),
                        cvss_score=7.5,
                        metadata={"sensitive_claims": exposed_sensitive},
                    )
                )

            # Check for missing expiration
            if "exp" not in payload:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="JWT Token Missing Expiration Claim",
                        description=(
                            "JWT does not contain 'exp' (expiration) claim. "
                            "Tokens without expiration remain valid indefinitely, "
                            "increasing the window for misuse if compromised."
                        ),
                        cwe_id="CWE-613",
                        cwe_name="Insufficient Session Expiration",
                        url=url,
                        evidence="JWT payload missing 'exp' claim",
                        remediation=(
                            "Always include 'exp' claim with reasonable expiration time. "
                            "Implement token refresh mechanism for long-lived sessions."
                        ),
                        cvss_score=5.3,
                    )
                )

        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            # Malformed JWT, skip analysis
            pass

        return findings

    def _analyze_transport_security(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Analyze secure transport enforcement."""
        findings: list[Finding] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        # Check if using HTTPS
        if not url.startswith("https://"):
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="Insecure HTTP Transport",
                    description=(
                        "Site is accessed over HTTP instead of HTTPS. "
                        "All data, including credentials and session tokens, "
                        "is transmitted in cleartext."
                    ),
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    url=url,
                    evidence="URL scheme: http://",
                    remediation=(
                        "Implement HTTPS with valid TLS certificate. "
                        "Redirect all HTTP requests to HTTPS. "
                        "Enable HSTS to prevent protocol downgrade."
                    ),
                    cvss_score=7.5,
                )
            )

        # Check for Strict-Transport-Security
        hsts = normalized_headers.get("strict-transport-security", "")
        if url.startswith("https://") and not hsts:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Missing HSTS Header",
                    description=(
                        "HTTPS site does not set Strict-Transport-Security header. "
                        "Users may be vulnerable to protocol downgrade attacks."
                    ),
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    url=url,
                    evidence="Strict-Transport-Security header not present",
                    remediation=(
                        "Add HSTS header: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    ),
                    cvss_score=5.3,
                )
            )

        return findings

    def _analyze_token_entropy(
        self,
        url: str,
        cookies: list[dict[str, Any]],
    ) -> list[Finding]:
        """Analyze entropy of tokens and session identifiers."""
        findings: list[Finding] = []

        token_patterns = ["token", "session", "auth", "key", "csrf", "xsrf"]

        for cookie in cookies:
            if not isinstance(cookie, dict):
                continue

            name = cookie.get("name", "").lower()
            value = cookie.get("value", "")

            if not value or len(value) < 8:
                continue

            is_token = any(pattern in name for pattern in token_patterns)
            if not is_token:
                continue

            entropy = self._calculate_entropy(value)

            if entropy < self.MIN_TOKEN_ENTROPY:
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Low Entropy Security Token: {name}",
                        description=(
                            f"Token '{name}' has entropy of {entropy:.2f} bits/char, "
                            f"below minimum {self.MIN_TOKEN_ENTROPY}. Low entropy tokens "
                            "are vulnerable to prediction and brute-force attacks."
                        ),
                        cwe_id="CWE-330",
                        cwe_name="Use of Insufficiently Random Values",
                        url=url,
                        evidence=f"Token: {name}; Entropy: {entropy:.2f}",
                        remediation=(
                            "Generate tokens using cryptographically secure random generators. "
                            "Use at least 128 bits of entropy for security tokens."
                        ),
                        cvss_score=7.5,
                        metadata={"entropy": entropy, "token_name": name},
                    )
                )

        return findings

    def _analyze_weak_crypto(
        self,
        url: str,
        content: str,
    ) -> list[Finding]:
        """Detect usage of weak cryptographic algorithms (active mode)."""
        findings: list[Finding] = []

        weak_crypto_found: dict[str, str] = {}

        for algo_name, pattern in self.CRYPTO_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                weak_crypto_found[algo_name] = pattern

        if weak_crypto_found:
            algo_list = list(weak_crypto_found.keys())

            severity = Severity.HIGH
            cvss = 7.5
            if "md5" in algo_list or "sha1" in algo_list:
                severity = Severity.MEDIUM
                cvss = 5.3

            findings.append(
                self._create_finding(
                    severity=severity,
                    title=f"Weak Cryptographic Algorithm Detected: {', '.join(algo_list)}",
                    description=(
                        f"Found references to weak cryptographic algorithms: {', '.join(algo_list)}. "
                        "These algorithms have known vulnerabilities and should not be used "
                        "for security-sensitive operations."
                    ),
                    cwe_id="CWE-327",
                    cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                    url=url,
                    evidence=f"Weak algorithms: {', '.join(algo_list)}",
                    remediation=(
                        "Replace weak algorithms: "
                        "- MD5/SHA1 -> SHA-256 or SHA-3 for hashing, "
                        "- DES/3DES/RC4 -> AES-256-GCM for encryption, "
                        "- ECB mode -> GCM or CBC with HMAC."
                    ),
                    cvss_score=cvss,
                    references=[
                        "https://cwe.mitre.org/data/definitions/327.html",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
                    ],
                    metadata={"algorithms": algo_list},
                )
            )

        return findings

    def _analyze_key_exposure(
        self,
        url: str,
        content: str,
    ) -> list[Finding]:
        """Detect exposed cryptographic keys or weak key patterns (active mode)."""
        findings: list[Finding] = []

        for pattern in self.WEAK_KEY_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Check for private key exposure
                if "PRIVATE KEY" in pattern:
                    findings.append(
                        self._create_finding(
                            severity=Severity.CRITICAL,
                            title="Private Key Exposed in Response",
                            description=(
                                "A private cryptographic key appears to be exposed in the response. "
                                "Private keys must never be transmitted to clients or stored "
                                "in publicly accessible locations."
                            ),
                            cwe_id="CWE-321",
                            cwe_name="Use of Hard-coded Cryptographic Key",
                            url=url,
                            evidence="Private key header detected in response",
                            remediation=(
                                "Remove private keys from responses immediately. "
                                "Rotate the compromised key. "
                                "Store keys securely in HSMs or secret managers."
                            ),
                            cvss_score=9.8,
                        )
                    )
                else:
                    findings.append(
                        self._create_finding(
                            severity=Severity.HIGH,
                            title="Weak or Hardcoded Secret Detected",
                            description=(
                                "Found what appears to be a weak or hardcoded secret/key. "
                                "Hardcoded credentials are easily discovered and enable unauthorized access."
                            ),
                            cwe_id="CWE-798",
                            cwe_name="Use of Hard-coded Credentials",
                            url=url,
                            evidence=f"Pattern matched: {pattern[:50]}...",
                            remediation=(
                                "Remove hardcoded credentials. "
                                "Use environment variables or secret management systems. "
                                "Rotate any exposed credentials immediately."
                            ),
                            cvss_score=7.5,
                        )
                    )
                break

        return findings

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
