"""
TLS/SSL Security Analyzer.

Analyzes TLS configuration including certificate validation,
cipher suites, and HSTS preload status.
"""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity


class TLSAnalyzer(BaseAnalyzer):
    """
    Analyzer for TLS/SSL security.

    Checks for:
    - Certificate validity and expiration
    - Weak cipher suites
    - Protocol version (TLS 1.2+)
    - HSTS preload eligibility
    - Certificate chain issues
    - Self-signed certificates
    """

    analyzer_type = AnalyzerType.TLS

    WEAK_CIPHERS = [
        "RC4",
        "DES",
        "3DES",
        "MD5",
        "NULL",
        "EXPORT",
        "ANON",
        "ADH",
        "AECDH",
    ]

    WEAK_PROTOCOLS = [
        "SSLv2",
        "SSLv3",
        "TLSv1",
        "TLSv1.0",
        "TLSv1.1",
    ]

    CERT_EXPIRY_WARNING_DAYS = 30

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze TLS configuration."""
        findings: list[Finding] = []

        if not url.startswith("https://"):
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="Site Not Using HTTPS",
                    description=(
                        "The site is served over HTTP instead of HTTPS. "
                        "All data transmitted is vulnerable to interception."
                    ),
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    url=url,
                    evidence="URL scheme: http://",
                    remediation="Configure the server to use HTTPS with a valid certificate.",
                    cvss_score=7.5,
                )
            )
            return findings

        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        if not hostname:
            return findings

        try:
            findings.extend(await self._check_certificate(url, hostname, port))
            findings.extend(await self._check_protocol_and_ciphers(url, hostname, port))
        except Exception as e:
            self.logger.warning("tls_analysis_error", url=url, error=str(e))
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="TLS Analysis Failed",
                    description=f"Could not complete TLS analysis: {str(e)}",
                    cwe_id="CWE-295",
                    cwe_name="Improper Certificate Validation",
                    url=url,
                    evidence=str(e),
                    remediation="Ensure the server is properly configured for TLS.",
                    cvss_score=5.3,
                )
            )

        findings.extend(self._check_hsts_preload(url, page_data.get("headers", {})))

        return findings

    async def _check_certificate(
        self,
        url: str,
        hostname: str,
        port: int,
    ) -> list[Finding]:
        """Check TLS certificate validity."""
        findings: list[Finding] = []

        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    if cert:
                        findings.extend(
                            self._analyze_certificate(url, hostname, cert)
                        )

        except ssl.SSLCertVerificationError as e:
            findings.append(
                self._create_finding(
                    severity=Severity.CRITICAL,
                    title="TLS Certificate Verification Failed",
                    description=(
                        f"Certificate verification failed: {str(e)}. "
                        "This may indicate a self-signed certificate, expired certificate, "
                        "or hostname mismatch."
                    ),
                    cwe_id="CWE-295",
                    cwe_name="Improper Certificate Validation",
                    url=url,
                    evidence=str(e),
                    remediation=(
                        "Obtain a valid certificate from a trusted CA. "
                        "Ensure the certificate matches the domain name."
                    ),
                    cvss_score=9.1,
                )
            )
        except ssl.SSLError as e:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="TLS Connection Error",
                    description=f"TLS handshake failed: {str(e)}",
                    cwe_id="CWE-295",
                    cwe_name="Improper Certificate Validation",
                    url=url,
                    evidence=str(e),
                    remediation="Review TLS configuration on the server.",
                    cvss_score=7.5,
                )
            )
        except (socket.timeout, socket.error) as e:
            self.logger.warning("socket_error", hostname=hostname, error=str(e))

        return findings

    def _analyze_certificate(
        self,
        url: str,
        hostname: str,
        cert: dict[str, Any],
    ) -> list[Finding]:
        """Analyze certificate details."""
        findings: list[Finding] = []

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_until_expiry = (expiry - now).days

                if days_until_expiry < 0:
                    findings.append(
                        self._create_finding(
                            severity=Severity.CRITICAL,
                            title="TLS Certificate Expired",
                            description=(
                                f"The TLS certificate expired {abs(days_until_expiry)} days ago. "
                                "Browsers will show security warnings."
                            ),
                            cwe_id="CWE-298",
                            cwe_name="Improper Validation of Certificate Expiration",
                            url=url,
                            evidence=f"Certificate expired on {not_after}",
                            remediation="Renew the TLS certificate immediately.",
                            cvss_score=9.1,
                            metadata={"expiry_date": not_after, "days_expired": abs(days_until_expiry)},
                        )
                    )
                elif days_until_expiry < self.CERT_EXPIRY_WARNING_DAYS:
                    findings.append(
                        self._create_finding(
                            severity=Severity.MEDIUM,
                            title="TLS Certificate Expiring Soon",
                            description=(
                                f"The TLS certificate expires in {days_until_expiry} days. "
                                "Plan for renewal to avoid service disruption."
                            ),
                            cwe_id="CWE-298",
                            cwe_name="Improper Validation of Certificate Expiration",
                            url=url,
                            evidence=f"Certificate expires on {not_after}",
                            remediation="Renew the TLS certificate before expiration.",
                            cvss_score=4.3,
                            metadata={"expiry_date": not_after, "days_remaining": days_until_expiry},
                        )
                    )
            except ValueError:
                pass

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        if subject == issuer:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="Self-Signed TLS Certificate",
                    description=(
                        "The certificate is self-signed and not issued by a trusted CA. "
                        "Browsers will show security warnings."
                    ),
                    cwe_id="CWE-295",
                    cwe_name="Improper Certificate Validation",
                    url=url,
                    evidence=f"Subject and Issuer match: {subject.get('commonName', 'Unknown')}",
                    remediation="Obtain a certificate from a trusted Certificate Authority.",
                    cvss_score=7.5,
                )
            )

        san = cert.get("subjectAltName", [])
        cn = subject.get("commonName", "")
        valid_names = [cn] + [name for type_, name in san if type_ == "DNS"]

        hostname_matches = False
        for name in valid_names:
            if name.startswith("*."):
                wildcard_domain = name[2:]
                if hostname.endswith(wildcard_domain) and hostname.count(".") == name.count("."):
                    hostname_matches = True
                    break
            elif name == hostname:
                hostname_matches = True
                break

        if not hostname_matches:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="Certificate Hostname Mismatch",
                    description=(
                        f"Certificate is not valid for hostname '{hostname}'. "
                        f"Valid names: {', '.join(valid_names[:5])}"
                    ),
                    cwe_id="CWE-297",
                    cwe_name="Improper Validation of Certificate with Host Mismatch",
                    url=url,
                    evidence=f"Hostname: {hostname}; Certificate names: {', '.join(valid_names[:5])}",
                    remediation="Ensure the certificate includes the correct hostname.",
                    cvss_score=7.5,
                )
            )

        return findings

    async def _check_protocol_and_ciphers(
        self,
        url: str,
        hostname: str,
        port: int,
    ) -> list[Finding]:
        """Check TLS protocol version and cipher suites."""
        findings: list[Finding] = []

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    if protocol and protocol in self.WEAK_PROTOCOLS:
                        findings.append(
                            self._create_finding(
                                severity=Severity.HIGH,
                                title=f"Weak TLS Protocol: {protocol}",
                                description=(
                                    f"Server negotiated {protocol}, which has known vulnerabilities. "
                                    "Modern browsers may refuse connections."
                                ),
                                cwe_id="CWE-326",
                                cwe_name="Inadequate Encryption Strength",
                                url=url,
                                evidence=f"Protocol: {protocol}",
                                remediation="Configure the server to use TLS 1.2 or TLS 1.3 only.",
                                cvss_score=7.5,
                            )
                        )

                    if cipher:
                        cipher_name = cipher[0]
                        for weak in self.WEAK_CIPHERS:
                            if weak in cipher_name.upper():
                                findings.append(
                                    self._create_finding(
                                        severity=Severity.HIGH,
                                        title=f"Weak Cipher Suite: {cipher_name}",
                                        description=(
                                            f"Server is using weak cipher suite containing {weak}. "
                                            "This may be vulnerable to known attacks."
                                        ),
                                        cwe_id="CWE-326",
                                        cwe_name="Inadequate Encryption Strength",
                                        url=url,
                                        evidence=f"Cipher: {cipher_name}",
                                        remediation="Configure server to use strong cipher suites only.",
                                        cvss_score=7.5,
                                    )
                                )
                                break

        except Exception as e:
            self.logger.debug("cipher_check_error", hostname=hostname, error=str(e))

        return findings

    def _check_hsts_preload(
        self,
        url: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Check HSTS preload eligibility."""
        findings: list[Finding] = []

        normalized_headers = {k.lower(): v for k, v in headers.items()}
        hsts = normalized_headers.get("strict-transport-security", "")

        if hsts:
            has_preload = "preload" in hsts.lower()
            has_include_subdomains = "includesubdomains" in hsts.lower()
            max_age_match = __import__("re").search(r"max-age=(\d+)", hsts, __import__("re").IGNORECASE)
            max_age = int(max_age_match.group(1)) if max_age_match else 0

            if has_preload:
                issues = []
                if not has_include_subdomains:
                    issues.append("missing includeSubDomains")
                if max_age < 31536000:
                    issues.append(f"max-age too short ({max_age} < 31536000)")

                if issues:
                    findings.append(
                        self._create_finding(
                            severity=Severity.LOW,
                            title="HSTS Preload Requirements Not Met",
                            description=(
                                f"HSTS header has preload directive but: {', '.join(issues)}. "
                                "Site may not be accepted to HSTS preload list."
                            ),
                            cwe_id="CWE-319",
                            cwe_name="Cleartext Transmission of Sensitive Information",
                            url=url,
                            evidence=f"HSTS: {hsts}",
                            remediation=(
                                "For HSTS preload: max-age >= 31536000, "
                                "includeSubDomains, and preload are required."
                            ),
                            cvss_score=3.1,
                            references=["https://hstspreload.org/"],
                        )
                    )

        return findings
