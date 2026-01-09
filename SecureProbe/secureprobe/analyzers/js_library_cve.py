"""
JavaScript Library CVE Detection Analyzer.

Implements 10 novel detection techniques for identifying vulnerable JavaScript
libraries that typical scanners miss:

1. Source Map Leakage - Extract versions from .map files
2. NPM Package Metadata - Detect exposed package.json files
3. JS Comment Fingerprinting - Parse license headers for versions
4. Error Message Fingerprinting - Trigger errors revealing versions
5. Prototype Pollution Probing - Detect __proto__ pollution vectors
6. DOM Clobbering Detection - Check for DOM clobbering vulnerabilities
7. CDN Version Inference - Parse CDN URLs for exact versions
8. Webpack Chunk Analysis - Analyze webpack chunks for bundled libs
9. JSONP Callback Injection - Test JSONP endpoints for XSS
10. Subresource Integrity Bypass - Detect missing/weak SRI hashes
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urljoin, urlparse

from secureprobe.analyzers.base import BaseAnalyzer
from secureprobe.models import AnalyzerType, Finding, Severity

if TYPE_CHECKING:
    pass


@dataclass(frozen=True, slots=True)
class CVEEntry:
    """Represents a known CVE for a JavaScript library."""

    cve_id: str
    library: str
    affected_versions: tuple[str, ...]  # Versions affected (simplified ranges)
    max_safe_version: str  # First safe version
    cvss_score: float
    severity: Severity
    description: str


# Curated CVE database for common JavaScript libraries
# Uses version comparison markers: '<' means less than max_safe_version is vulnerable
JS_LIBRARY_CVES: dict[str, list[CVEEntry]] = {
    "jquery": [
        CVEEntry(
            cve_id="CVE-2020-11022",
            library="jquery",
            affected_versions=("1.0.3", "1.12.4", "2.0.0", "2.2.4", "3.0.0", "3.4.1"),
            max_safe_version="3.5.0",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="XSS via HTML passed to DOM manipulation methods",
        ),
        CVEEntry(
            cve_id="CVE-2020-11023",
            library="jquery",
            affected_versions=("1.0.3", "3.4.1"),
            max_safe_version="3.5.0",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="XSS in jQuery.htmlPrefilter",
        ),
        CVEEntry(
            cve_id="CVE-2019-11358",
            library="jquery",
            affected_versions=("1.0.0", "3.3.1"),
            max_safe_version="3.4.0",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="Prototype pollution in jQuery.extend",
        ),
        CVEEntry(
            cve_id="CVE-2015-9251",
            library="jquery",
            affected_versions=("1.0.0", "2.2.4"),
            max_safe_version="3.0.0",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="XSS via cross-domain ajax request",
        ),
    ],
    "angular": [
        CVEEntry(
            cve_id="CVE-2022-25869",
            library="angular",
            affected_versions=("1.0.0", "1.8.2"),
            max_safe_version="1.8.3",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="XSS via angular.copy() prototype pollution",
        ),
        CVEEntry(
            cve_id="CVE-2020-7676",
            library="angular",
            affected_versions=("1.0.0", "1.7.9"),
            max_safe_version="1.8.0",
            cvss_score=5.4,
            severity=Severity.MEDIUM,
            description="Prototype pollution via merge/extend functions",
        ),
        CVEEntry(
            cve_id="CVE-2019-14863",
            library="angular",
            affected_versions=("1.0.0", "1.7.8"),
            max_safe_version="1.7.9",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="XSS via SVG elements",
        ),
    ],
    "react": [
        CVEEntry(
            cve_id="CVE-2018-6341",
            library="react",
            affected_versions=("0.0.1", "16.3.0"),
            max_safe_version="16.3.1",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="XSS via dangerouslySetInnerHTML",
        ),
        CVEEntry(
            cve_id="CVE-2018-6343",
            library="react",
            affected_versions=("16.0.0", "16.4.1"),
            max_safe_version="16.4.2",
            cvss_score=5.9,
            severity=Severity.MEDIUM,
            description="SSR XSS attack vector",
        ),
    ],
    "lodash": [
        CVEEntry(
            cve_id="CVE-2021-23337",
            library="lodash",
            affected_versions=("0.0.1", "4.17.20"),
            max_safe_version="4.17.21",
            cvss_score=7.2,
            severity=Severity.HIGH,
            description="Command injection via template function",
        ),
        CVEEntry(
            cve_id="CVE-2020-28500",
            library="lodash",
            affected_versions=("0.0.1", "4.17.20"),
            max_safe_version="4.17.21",
            cvss_score=5.3,
            severity=Severity.MEDIUM,
            description="ReDoS in trim functions",
        ),
        CVEEntry(
            cve_id="CVE-2020-8203",
            library="lodash",
            affected_versions=("0.0.1", "4.17.18"),
            max_safe_version="4.17.19",
            cvss_score=7.4,
            severity=Severity.HIGH,
            description="Prototype pollution in zipObjectDeep",
        ),
        CVEEntry(
            cve_id="CVE-2019-10744",
            library="lodash",
            affected_versions=("0.0.1", "4.17.11"),
            max_safe_version="4.17.12",
            cvss_score=9.1,
            severity=Severity.CRITICAL,
            description="Prototype pollution via defaultsDeep",
        ),
    ],
    "bootstrap": [
        CVEEntry(
            cve_id="CVE-2019-8331",
            library="bootstrap",
            affected_versions=("3.0.0", "3.4.0", "4.0.0", "4.3.0"),
            max_safe_version="4.3.1",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="XSS in tooltip/popover data-template attribute",
        ),
        CVEEntry(
            cve_id="CVE-2018-20676",
            library="bootstrap",
            affected_versions=("3.0.0", "4.1.1"),
            max_safe_version="4.1.2",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="XSS in tooltip data-container attribute",
        ),
        CVEEntry(
            cve_id="CVE-2018-14042",
            library="bootstrap",
            affected_versions=("3.0.0", "4.1.1"),
            max_safe_version="4.1.2",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="XSS in collapse plugin data-parent attribute",
        ),
    ],
    "vue": [
        CVEEntry(
            cve_id="CVE-2024-6783",
            library="vue",
            affected_versions=("2.0.0", "2.7.15"),
            max_safe_version="2.7.16",
            cvss_score=5.3,
            severity=Severity.MEDIUM,
            description="ReDoS in parseHTML function",
        ),
        CVEEntry(
            cve_id="CVE-2018-11235",
            library="vue",
            affected_versions=("2.0.0", "2.5.16"),
            max_safe_version="2.5.17",
            cvss_score=6.1,
            severity=Severity.MEDIUM,
            description="XSS via v-bind SVG attribute",
        ),
    ],
    "moment": [
        CVEEntry(
            cve_id="CVE-2022-31129",
            library="moment",
            affected_versions=("0.0.1", "2.29.3"),
            max_safe_version="2.29.4",
            cvss_score=7.5,
            severity=Severity.HIGH,
            description="ReDoS in parsing function",
        ),
        CVEEntry(
            cve_id="CVE-2022-24785",
            library="moment",
            affected_versions=("0.0.1", "2.29.1"),
            max_safe_version="2.29.2",
            cvss_score=7.5,
            severity=Severity.HIGH,
            description="Path traversal in locale function",
        ),
    ],
    "handlebars": [
        CVEEntry(
            cve_id="CVE-2021-23369",
            library="handlebars",
            affected_versions=("0.0.1", "4.7.6"),
            max_safe_version="4.7.7",
            cvss_score=9.8,
            severity=Severity.CRITICAL,
            description="Arbitrary code execution via prototype pollution",
        ),
        CVEEntry(
            cve_id="CVE-2019-20920",
            library="handlebars",
            affected_versions=("0.0.1", "4.5.2"),
            max_safe_version="4.5.3",
            cvss_score=8.1,
            severity=Severity.HIGH,
            description="RCE via lookup helper",
        ),
    ],
    "underscore": [
        CVEEntry(
            cve_id="CVE-2021-23358",
            library="underscore",
            affected_versions=("0.0.1", "1.12.0"),
            max_safe_version="1.12.1",
            cvss_score=7.2,
            severity=Severity.HIGH,
            description="Arbitrary code execution via template function",
        ),
    ],
    "axios": [
        CVEEntry(
            cve_id="CVE-2023-45857",
            library="axios",
            affected_versions=("0.8.1", "1.5.1"),
            max_safe_version="1.6.0",
            cvss_score=6.5,
            severity=Severity.MEDIUM,
            description="CSRF token exposure via cookies",
        ),
        CVEEntry(
            cve_id="CVE-2021-3749",
            library="axios",
            affected_versions=("0.0.1", "0.21.0"),
            max_safe_version="0.21.1",
            cvss_score=7.5,
            severity=Severity.HIGH,
            description="ReDoS in url-parse dependency",
        ),
    ],
    "dompurify": [
        CVEEntry(
            cve_id="CVE-2024-45801",
            library="dompurify",
            affected_versions=("0.0.1", "3.1.5"),
            max_safe_version="3.1.6",
            cvss_score=7.3,
            severity=Severity.HIGH,
            description="XSS bypass via nesting confusion",
        ),
    ],
}

# CDN URL patterns for version extraction
CDN_PATTERNS: dict[str, str] = {
    "cdnjs": r"cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([0-9.]+)",
    "unpkg": r"unpkg\.com/([^@/]+)@([0-9.]+)",
    "jsdelivr": r"cdn\.jsdelivr\.net/(?:npm|gh)/([^@/]+)@([0-9.]+)",
    "google": r"ajax\.googleapis\.com/ajax/libs/([^/]+)/([0-9.]+)",
    "microsoft": r"ajax\.aspnetcdn\.com/ajax/([^/]+)/([0-9.]+)",
    "jquery_cdn": r"code\.jquery\.com/([^/]+)-([0-9.]+)(?:\.min)?\.js",
    "bootstrap_cdn": r"(?:stackpath|maxcdn)\.bootstrapcdn\.com/bootstrap/([0-9.]+)",
}

# JS library comment patterns for version extraction
JS_COMMENT_VERSION_PATTERNS: dict[str, str] = {
    "jquery": r"(?:/\*!?\s*)?jQuery\s+(?:JavaScript Library\s+)?v?([0-9.]+)",
    "angular": r"(?:/\*!?\s*)?(?:AngularJS|Angular)\s+v?([0-9.]+)",
    "react": r"(?:/\*!?\s*)?React\s+v?([0-9.]+)",
    "vue": r"(?:/\*!?\s*)?Vue(?:\.js)?\s+v?([0-9.]+)",
    "lodash": r"(?:/\*!?\s*)?lodash\s+v?([0-9.]+)",
    "bootstrap": r"(?:/\*!?\s*)?Bootstrap\s+v?([0-9.]+)",
    "moment": r"(?:/\*!?\s*)?moment(?:\.js)?\s+v?([0-9.]+)",
    "handlebars": r"(?:/\*!?\s*)?Handlebars(?:\.js)?\s+v?([0-9.]+)",
    "underscore": r"(?:/\*!?\s*)?Underscore(?:\.js)?\s+v?([0-9.]+)",
    "backbone": r"(?:/\*!?\s*)?Backbone(?:\.js)?\s+v?([0-9.]+)",
    "ember": r"(?:/\*!?\s*)?Ember(?:\.js)?\s+v?([0-9.]+)",
    "axios": r"(?:/\*!?\s*)?axios\s+v?([0-9.]+)",
    "dompurify": r"(?:/\*!?\s*)?DOMPurify\s+v?([0-9.]+)",
    "knockout": r"(?:/\*!?\s*)?Knockout(?:\.js)?\s+v?([0-9.]+)",
    "d3": r"(?:/\*!?\s*)?d3(?:\.js)?\s+v?([0-9.]+)",
    "chart": r"(?:/\*!?\s*)?Chart(?:\.js)?\s+v?([0-9.]+)",
    "highcharts": r"(?:/\*!?\s*)?Highcharts\s+(?:JS\s+)?v?([0-9.]+)",
    "three": r"(?:/\*!?\s*)?three(?:\.js)?\s+r?([0-9.]+)",
}


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse version string into comparable tuple."""
    parts = []
    for part in version_str.split("."):
        # Extract numeric portion
        match = re.match(r"(\d+)", part)
        if match:
            parts.append(int(match.group(1)))
        else:
            parts.append(0)
    # Pad to at least 3 components for consistent comparison
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _is_version_vulnerable(version: str, cve: CVEEntry) -> bool:
    """
    Check if a version is vulnerable to a specific CVE.

    Uses simplified comparison: version < max_safe_version is vulnerable.
    """
    try:
        ver_tuple = _parse_version(version)
        safe_tuple = _parse_version(cve.max_safe_version)
        return ver_tuple < safe_tuple
    except (ValueError, AttributeError):
        # If parsing fails, assume vulnerable for safety
        return True


class JSLibraryCVEAnalyzer(BaseAnalyzer):
    """
    Analyzer for JavaScript library CVE detection using novel techniques.

    Implements creative detection methods that bypass typical scanner limitations:
    - Source map analysis for exact version disclosure
    - NPM metadata exposure detection
    - Comment-based fingerprinting
    - Error-triggered version disclosure
    - Prototype pollution vulnerability testing
    - DOM clobbering detection
    - CDN URL version inference
    - Webpack chunk analysis
    - JSONP callback injection testing
    - SRI bypass detection
    """

    analyzer_type = AnalyzerType.JS_LIBRARY_CVE

    # Marker patterns to reduce false positives
    SOURCE_MAP_MARKER = "SecureProbe:SourceMapCheck"
    JSONP_MARKER = "SecureProbe_JSONP_Probe"

    async def analyze(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Analyze page for vulnerable JavaScript libraries using 10 detection methods."""
        findings: list[Finding] = []
        html = page_data.get("html", "")
        scripts = page_data.get("scripts", [])
        network_log = page_data.get("network_log", [])
        headers = page_data.get("headers", {})

        # 1. Source Map Leakage Detection
        findings.extend(self._check_source_map_leakage(url, html, scripts, network_log))

        # 2. NPM Package Metadata Exposure
        findings.extend(self._check_npm_metadata_exposure(url, network_log))

        # 3. JS Comment Fingerprinting
        findings.extend(self._check_comment_fingerprinting(url, html, scripts))

        # 4. Error Message Fingerprinting (passive check in page content)
        findings.extend(self._check_error_fingerprinting(url, html))

        # 5. Prototype Pollution Probing
        findings.extend(self._check_prototype_pollution(url, html, scripts))

        # 6. DOM Clobbering Detection
        findings.extend(self._check_dom_clobbering(url, html))

        # 7. CDN Version Inference
        findings.extend(self._check_cdn_version_inference(url, html, scripts, network_log))

        # 8. Webpack Chunk Analysis
        findings.extend(self._check_webpack_chunks(url, html, scripts, network_log))

        # 9. JSONP Callback Injection Detection
        findings.extend(self._check_jsonp_injection(url, network_log))

        # 10. Subresource Integrity Bypass
        findings.extend(self._check_sri_bypass(url, html, headers))

        return findings

    def _check_source_map_leakage(
        self,
        url: str,
        html: str,
        scripts: list[str],
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Detection Method 1: Source Map Leakage.

        Source maps (.map files) often reveal exact library versions, original source
        code structure, and internal file paths. These are frequently left exposed
        in production.
        """
        findings: list[Finding] = []
        source_map_urls: set[str] = set()

        # Pattern to detect sourceMappingURL references
        source_map_pattern = r"//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)"

        # Check inline scripts and loaded scripts
        all_js_content = html + "\n".join(str(s) for s in scripts if isinstance(s, str))

        for match in re.finditer(source_map_pattern, all_js_content, re.IGNORECASE):
            map_url = match.group(1).strip()
            if map_url:
                # Handle relative URLs
                if not map_url.startswith(("http://", "https://", "data:")):
                    map_url = urljoin(url, map_url)
                if not map_url.startswith("data:"):
                    source_map_urls.add(map_url)

        # Check network log for .map file requests
        for entry in network_log:
            req_url = entry.get("url", "")
            if req_url.endswith(".map") or ".map?" in req_url:
                source_map_urls.add(req_url)

        # Check response headers for SourceMap header
        for entry in network_log:
            resp_headers = entry.get("response_headers", {})
            for header_name, header_value in resp_headers.items():
                if (
                    header_name.lower() in ("sourcemap", "x-sourcemap")
                    and not header_value.startswith("data:")
                ):
                    map_url = urljoin(entry.get("url", url), header_value)
                    source_map_urls.add(map_url)

        if source_map_urls:
            # Check for version info in source map URLs
            detected_libs: dict[str, str] = {}
            for map_url in source_map_urls:
                for lib_name in JS_COMMENT_VERSION_PATTERNS:
                    # Check if library name appears in URL
                    if lib_name.lower() in map_url.lower():
                        # Try to extract version from URL
                        version_match = re.search(r"[/@](\d+\.\d+(?:\.\d+)?)", map_url)
                        if version_match:
                            detected_libs[lib_name] = version_match.group(1)

            evidence_lines = [f"Source map exposed: {smu}" for smu in list(source_map_urls)[:5]]
            evidence = "\n".join(evidence_lines)

            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="JavaScript Source Maps Exposed",
                    description=(
                        f"Found {len(source_map_urls)} exposed source map file(s). "
                        "Source maps reveal original source code, internal file paths, "
                        "and exact library versions. Attackers can use this to identify "
                        "vulnerable dependencies and understand application structure."
                    ),
                    cwe_id="CWE-540",
                    cwe_name="Inclusion of Sensitive Information in Source Code",
                    url=url,
                    evidence=evidence,
                    remediation=(
                        "1. Remove sourceMappingURL comments from production builds. "
                        "2. Configure build tools (webpack/vite) to disable source maps in production. "
                        "3. Block access to .map files via web server configuration. "
                        "4. Use private source map services for debugging."
                    ),
                    cvss_score=5.3,
                    references=[
                        "https://developer.chrome.com/docs/devtools/javascript/source-maps/",
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ],
                    metadata={
                        "source_map_count": len(source_map_urls),
                        "source_maps": list(source_map_urls)[:10],
                        "detected_libraries": detected_libs,
                    },
                )
            )

            # Report CVEs for detected libraries
            for lib_name, version in detected_libs.items():
                findings.extend(self._check_cves_for_library(url, lib_name, version, "source_map"))

        return findings

    def _check_npm_metadata_exposure(
        self,
        url: str,
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Detection Method 2: NPM Package Metadata Exposure.

        Detects exposed package.json, package-lock.json, or node_modules at
        common paths that reveal exact dependency versions.
        """
        findings: list[Finding] = []
        exposed_files: list[str] = []
        detected_packages: dict[str, str] = {}

        # Common paths where package.json might be exposed
        package_json_indicators = [
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "node_modules/",
            ".npmrc",
            "yarn.lock",
            "pnpm-lock.yaml",
        ]

        for entry in network_log:
            req_url = entry.get("url", "")
            response_body = entry.get("response_body", "")

            # Check URL for package metadata files
            for indicator in package_json_indicators:
                if indicator in req_url.lower():
                    exposed_files.append(req_url)

            # Check response content for package.json structure
            if (
                response_body
                and isinstance(response_body, str)
                and '"name":' in response_body
                and '"version":' in response_body
                and ('"dependencies":' in response_body or '"devDependencies":' in response_body)
            ):
                # Attempt to extract dependency versions
                try:
                    import json

                    pkg_data = json.loads(response_body)
                    deps = {
                        **pkg_data.get("dependencies", {}),
                        **pkg_data.get("devDependencies", {}),
                    }
                    for dep_name, dep_version in deps.items():
                        # Normalize version (remove ^, ~, etc.)
                        clean_version = re.sub(r"^[\^~>=<]+", "", str(dep_version))
                        detected_packages[dep_name] = clean_version
                    exposed_files.append(req_url)
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass

        if exposed_files:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="NPM Package Metadata Exposed",
                    description=(
                        f"Found {len(exposed_files)} exposed package metadata file(s). "
                        "These files reveal exact dependency versions, enabling attackers "
                        "to identify vulnerable packages. This also exposes internal "
                        "project structure and development dependencies."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    url=url,
                    evidence=f"Exposed files: {', '.join(exposed_files[:5])}",
                    remediation=(
                        "1. Block access to package.json and related files in web server config. "
                        "2. Ensure build process does not copy these files to public directories. "
                        "3. Use .htaccess or nginx rules to deny access to node_modules/. "
                        "4. Configure CDN/WAF to block requests to package metadata files."
                    ),
                    cvss_score=6.5,
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
                    ],
                    metadata={
                        "exposed_files": exposed_files[:10],
                        "detected_packages": detected_packages,
                    },
                )
            )

            # Check CVEs for detected packages
            for pkg_name, version in detected_packages.items():
                findings.extend(self._check_cves_for_library(url, pkg_name, version, "npm_metadata"))

        return findings

    def _check_comment_fingerprinting(
        self,
        url: str,
        html: str,
        scripts: list[str],
    ) -> list[Finding]:
        """
        Detection Method 3: JS Comment Fingerprinting.

        Extract library versions from license headers and comments in JavaScript
        files. Libraries often include version in their banner comments.
        """
        findings: list[Finding] = []
        detected_versions: dict[str, str] = {}

        # Combine all script content
        all_content = html
        for script in scripts:
            if isinstance(script, str):
                all_content += "\n" + script

        # Look for library version patterns in comments
        for lib_name, pattern in JS_COMMENT_VERSION_PATTERNS.items():
            matches = re.findall(pattern, all_content, re.IGNORECASE | re.MULTILINE)
            if matches:
                # Take the first match as the version
                version = matches[0] if isinstance(matches[0], str) else matches[0][0]
                detected_versions[lib_name] = version

        # Check for CVEs in detected libraries
        for lib_name, version in detected_versions.items():
            lib_findings = self._check_cves_for_library(url, lib_name, version, "comment_fingerprint")
            findings.extend(lib_findings)

        # Report detection summary
        if detected_versions:
            findings.append(
                self._create_finding(
                    severity=Severity.INFO,
                    title="JavaScript Library Versions Detected via Comment Fingerprinting",
                    description=(
                        f"Detected {len(detected_versions)} JavaScript libraries via license "
                        "header/comment analysis. Version information can be used to identify "
                        "known vulnerabilities."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    url=url,
                    evidence="; ".join(f"{k} v{v}" for k, v in detected_versions.items()),
                    remediation=(
                        "Consider minifying JavaScript to remove version-revealing comments. "
                        "Keep all libraries updated to latest secure versions."
                    ),
                    cvss_score=2.0,
                    metadata={"detected_libraries": detected_versions},
                )
            )

        return findings

    def _check_error_fingerprinting(
        self,
        url: str,
        html: str,
    ) -> list[Finding]:
        """
        Detection Method 4: Error Message Fingerprinting.

        Detect JavaScript errors in page content that reveal library versions
        in stack traces or error messages.
        """
        findings: list[Finding] = []
        error_patterns = [
            # Library-specific error patterns with version indicators
            r"(?:TypeError|ReferenceError|SyntaxError).*(?:jQuery|angular|react|vue|lodash)\s*(?:@|v)?(\d+\.\d+(?:\.\d+)?)",
            r"at\s+[^\s]+\s+\((?:[^)]*)/([a-zA-Z]+)(?:@|-)(\d+\.\d+(?:\.\d+)?)",
            r"Uncaught\s+[A-Z][a-z]+Error:.*?([a-zA-Z]+)(?:-|@|/)(\d+\.\d+(?:\.\d+)?)",
            # Webpack/bundler errors revealing versions
            r"(?:webpack|parcel|vite|rollup).*?(?:@|v)(\d+\.\d+(?:\.\d+)?)",
        ]

        detected_from_errors: dict[str, str] = {}

        for pattern in error_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    lib_name = match[0].lower()
                    version = match[1]
                    if lib_name in JS_LIBRARY_CVES:
                        detected_from_errors[lib_name] = version

        if detected_from_errors:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Library Versions Exposed in Error Messages",
                    description=(
                        "JavaScript error messages on the page reveal library versions. "
                        "This indicates unhandled errors in production and provides "
                        "version information useful for exploitation."
                    ),
                    cwe_id="CWE-209",
                    cwe_name="Generation of Error Message Containing Sensitive Information",
                    url=url,
                    evidence="; ".join(f"{k} v{v}" for k, v in detected_from_errors.items()),
                    remediation=(
                        "1. Implement proper error handling to prevent stack traces in production. "
                        "2. Use error boundary components (React) or global error handlers. "
                        "3. Configure source maps to not be served to clients. "
                        "4. Sanitize error messages before displaying."
                    ),
                    cvss_score=4.3,
                    metadata={"detected_from_errors": detected_from_errors},
                )
            )

            # Check CVEs
            for lib_name, version in detected_from_errors.items():
                findings.extend(self._check_cves_for_library(url, lib_name, version, "error_fingerprint"))

        return findings

    def _check_prototype_pollution(
        self,
        url: str,
        html: str,
        scripts: list[str],
    ) -> list[Finding]:
        """
        Detection Method 5: Prototype Pollution Probing.

        Detect potential prototype pollution vulnerabilities by analyzing
        how the application handles __proto__, constructor, and prototype
        in query parameters and JSON payloads.
        """
        findings: list[Finding] = []

        # Check for dangerous patterns in scripts that might be vulnerable
        all_content = html + "\n".join(str(s) for s in scripts if isinstance(s, str))

        # Patterns indicating prototype pollution vulnerability
        vuln_patterns = [
            # Merge/extend operations without proper sanitization
            (r"Object\.assign\s*\(\s*\{\s*\}", "Object.assign with empty target"),
            (r"\.extend\s*\([^)]*\)", "jQuery-style extend"),
            (r"\.merge\s*\([^)]*\)", "Lodash-style merge"),
            (r"for\s*\(\s*(?:var|let|const)\s+\w+\s+in\s+", "for...in loop (potential property iteration)"),
            (r"JSON\.parse\s*\([^)]+\)\s*(?:\.|\[)", "Direct JSON.parse property access"),
            # Dangerous property assignment patterns
            (r"\[\s*['\"]__proto__['\"]\s*\]", "Direct __proto__ access"),
            (r"\[\s*['\"]constructor['\"]\s*\]", "Direct constructor access"),
            (r"\[\s*['\"]prototype['\"]\s*\]", "Direct prototype access"),
        ]

        vulnerable_patterns_found: list[str] = []

        for pattern, description in vuln_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                vulnerable_patterns_found.append(description)

        # Check URL for prototype pollution attempt vectors
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        pollution_params = ["__proto__", "constructor", "prototype"]

        pollution_in_url = False
        for param in pollution_params:
            if param in query_params or f"[{param}]" in parsed_url.query:
                pollution_in_url = True
                break

        if vulnerable_patterns_found:
            findings.append(
                self._create_finding(
                    severity=Severity.HIGH,
                    title="Potential Prototype Pollution Vulnerability Patterns",
                    description=(
                        f"Detected {len(vulnerable_patterns_found)} code patterns that may be "
                        "vulnerable to prototype pollution attacks. Prototype pollution can lead "
                        "to denial of service, security bypasses, or in some cases, remote code "
                        "execution depending on how polluted properties are used."
                    ),
                    cwe_id="CWE-1321",
                    cwe_name="Improperly Controlled Modification of Object Prototype Attributes",
                    url=url,
                    evidence=f"Vulnerable patterns: {'; '.join(vulnerable_patterns_found[:5])}",
                    remediation=(
                        "1. Use Object.create(null) for lookup objects. "
                        "2. Freeze Object.prototype. "
                        "3. Use Map instead of plain objects for user-controlled keys. "
                        "4. Validate and sanitize all keys before object assignment. "
                        "5. Update lodash, jQuery, and other libraries to patched versions."
                    ),
                    cvss_score=7.3,
                    references=[
                        "https://github.com/nicksavers/prototype-pollution",
                        "https://portswigger.net/web-security/prototype-pollution",
                    ],
                    metadata={"patterns_found": vulnerable_patterns_found},
                )
            )

        if pollution_in_url:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Prototype Pollution Vector in URL Parameters",
                    description=(
                        "The URL contains parameters that could be used for prototype pollution "
                        "attacks (__proto__, constructor, prototype). If the application uses "
                        "these parameters to construct objects, it may be vulnerable."
                    ),
                    cwe_id="CWE-1321",
                    cwe_name="Improperly Controlled Modification of Object Prototype Attributes",
                    url=url,
                    evidence=f"Query string: {parsed_url.query[:200]}",
                    remediation=(
                        "1. Filter dangerous property names from user input. "
                        "2. Use hasOwnProperty checks. "
                        "3. Avoid using user input as object keys."
                    ),
                    cvss_score=5.3,
                )
            )

        return findings

    def _check_dom_clobbering(
        self,
        url: str,
        html: str,
    ) -> list[Finding]:
        """
        Detection Method 6: DOM Clobbering Detection.

        Detect if the page is vulnerable to DOM clobbering attacks via
        named form elements or anchor tags that can override global objects.
        """
        findings: list[Finding] = []

        # Patterns that indicate potential DOM clobbering vulnerabilities
        # These are elements with name/id that could clobber important globals
        dangerous_names = [
            "document",
            "window",
            "location",
            "navigator",
            "history",
            "localStorage",
            "sessionStorage",
            "XMLHttpRequest",
            "fetch",
            "eval",
            "Function",
            "Object",
            "Array",
            "String",
            "Number",
            "Boolean",
            "Symbol",
            "Promise",
            "Proxy",
            "Reflect",
            "console",
            "alert",
            "confirm",
            "prompt",
            "open",
            "close",
            "print",
            "self",
            "top",
            "parent",
            "frames",
            "length",
            "name",
        ]

        clobbering_vectors: list[str] = []

        # Check for dangerous id attributes
        id_pattern = r'<(?:form|img|object|embed|a|input|iframe|button)\s+[^>]*id\s*=\s*["\']([^"\']+)["\']'
        name_pattern = r'<(?:form|img|object|embed|a|input|iframe|button)\s+[^>]*name\s*=\s*["\']([^"\']+)["\']'

        for pattern in [id_pattern, name_pattern]:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match.lower() in [n.lower() for n in dangerous_names]:
                    clobbering_vectors.append(match)

        # Check for nested form/input elements that could create deep clobbering
        nested_form_pattern = r'<form\s+[^>]*name\s*=\s*["\'](\w+)["\'][^>]*>.*?<(?:input|img|object)\s+[^>]*name\s*=\s*["\'](\w+)["\']'
        nested_matches = re.findall(nested_form_pattern, html, re.IGNORECASE | re.DOTALL)
        for form_name, element_name in nested_matches:
            clobbering_vectors.append(f"{form_name}.{element_name}")

        if clobbering_vectors:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="DOM Clobbering Vulnerability Detected",
                    description=(
                        f"Found {len(clobbering_vectors)} HTML elements with names/IDs that "
                        "can clobber global JavaScript objects. DOM clobbering can bypass "
                        "security checks, break functionality, or enable XSS in certain contexts."
                    ),
                    cwe_id="CWE-79",
                    cwe_name="Improper Neutralization of Input During Web Page Generation",
                    url=url,
                    evidence=f"Clobberable names: {', '.join(clobbering_vectors[:10])}",
                    remediation=(
                        "1. Avoid using reserved/dangerous names for HTML element IDs and names. "
                        "2. Use document.getElementById() instead of direct global access. "
                        "3. Implement CSP to prevent inline script execution. "
                        "4. Sanitize user-controlled content that becomes element attributes."
                    ),
                    cvss_score=5.4,
                    references=[
                        "https://portswigger.net/web-security/dom-based/dom-clobbering",
                        "https://html.spec.whatwg.org/multipage/window-object.html#named-access-on-the-window-object",
                    ],
                    metadata={"clobbering_vectors": clobbering_vectors[:20]},
                )
            )

        return findings

    def _check_cdn_version_inference(
        self,
        url: str,
        html: str,
        scripts: list[str],
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Detection Method 7: CDN Version Inference.

        Parse CDN URLs (cdnjs, unpkg, jsdelivr, etc.) to extract exact library
        versions, which can be mapped to known CVEs.
        """
        findings: list[Finding] = []
        detected_from_cdn: dict[str, tuple[str, str]] = {}  # lib -> (version, cdn_url)

        # Combine all sources for URL extraction
        all_content = html
        for script in scripts:
            if isinstance(script, str):
                all_content += "\n" + script

        # Also check network log
        cdn_urls = []
        for entry in network_log:
            req_url = entry.get("url", "")
            cdn_urls.append(req_url)

        all_urls = re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', all_content, re.IGNORECASE)
        all_urls.extend(cdn_urls)

        for url_str in all_urls:
            for cdn_name, pattern in CDN_PATTERNS.items():
                match = re.search(pattern, url_str, re.IGNORECASE)
                if match:
                    if cdn_name == "bootstrap_cdn":
                        lib_name = "bootstrap"
                        version = match.group(1)
                    elif cdn_name == "jquery_cdn":
                        lib_name = "jquery"
                        version = match.group(2)
                    else:
                        lib_name = match.group(1).lower()
                        version = match.group(2)

                    # Normalize library names
                    lib_name = lib_name.replace(".js", "").replace("-", "").lower()
                    detected_from_cdn[lib_name] = (version, url_str)

        if detected_from_cdn:
            lib_versions = [f"{lib} v{ver[0]}" for lib, ver in detected_from_cdn.items()]

            findings.append(
                self._create_finding(
                    severity=Severity.INFO,
                    title="JavaScript Libraries Detected via CDN URLs",
                    description=(
                        f"Detected {len(detected_from_cdn)} libraries loaded from CDNs with "
                        "exact version numbers. CDN URLs reveal precise versions which can "
                        "be used to identify vulnerable dependencies."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    url=url,
                    evidence="; ".join(lib_versions),
                    remediation=(
                        "1. Keep CDN-loaded libraries updated to latest secure versions. "
                        "2. Consider using integrity attributes (SRI) for CDN resources. "
                        "3. For sensitive applications, consider self-hosting dependencies."
                    ),
                    cvss_score=2.0,
                    metadata={
                        "cdn_libraries": {
                            lib: {"version": v[0], "url": v[1]} for lib, v in detected_from_cdn.items()
                        }
                    },
                )
            )

            # Check for CVEs
            for lib_name, (version, _) in detected_from_cdn.items():
                findings.extend(self._check_cves_for_library(url, lib_name, version, "cdn_inference"))

        return findings

    def _check_webpack_chunks(
        self,
        url: str,
        html: str,
        scripts: list[str],
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Detection Method 8: Webpack Chunk Analysis.

        Analyze exposed webpack chunks and manifest files to identify bundled
        library versions and internal module structure.
        """
        findings: list[Finding] = []
        webpack_indicators: list[str] = []
        detected_libs: dict[str, str] = {}

        all_content = html + "\n".join(str(s) for s in scripts if isinstance(s, str))

        # Webpack-specific patterns
        webpack_patterns = [
            (r"webpackJsonp\s*\(", "webpackJsonp function call"),
            (r"__webpack_require__\s*\(", "__webpack_require__ function"),
            (r"webpack/runtime/", "webpack runtime module"),
            (r"webpackChunk\w+\s*=", "webpackChunk definition"),
            (r'chunkId\s*:\s*["\'][^"\']+["\']', "chunk ID reference"),
            (r'/\*!\s*webpack[\s\S]*?\*/', "webpack banner comment"),
        ]

        for pattern, description in webpack_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                webpack_indicators.append(description)

        # Look for exposed webpack manifest/stats files
        manifest_patterns = [
            r"manifest\.json",
            r"asset-manifest\.json",
            r"webpack-stats\.json",
            r"chunk-manifest\.json",
            r"stats\.json",
        ]

        exposed_manifests: list[str] = []
        for entry in network_log:
            req_url = entry.get("url", "")
            for pattern in manifest_patterns:
                if re.search(pattern, req_url, re.IGNORECASE):
                    exposed_manifests.append(req_url)

        # Extract version info from webpack chunk comments
        version_in_chunks = re.findall(
            r'/\*!?\s*(\w+(?:\.js)?)\s+(?:v|version\s*)?([\d.]+)',
            all_content,
            re.IGNORECASE,
        )
        for lib, version in version_in_chunks:
            lib_clean = lib.lower().replace(".js", "")
            if lib_clean in JS_LIBRARY_CVES:
                detected_libs[lib_clean] = version

        if webpack_indicators or exposed_manifests:
            description_parts = []
            if webpack_indicators:
                description_parts.append(
                    f"Detected webpack bundler with {len(webpack_indicators)} indicators"
                )
            if exposed_manifests:
                description_parts.append(
                    f"Found {len(exposed_manifests)} exposed manifest file(s)"
                )

            findings.append(
                self._create_finding(
                    severity=Severity.LOW if not exposed_manifests else Severity.MEDIUM,
                    title="Webpack Bundle Information Exposed",
                    description=(
                        f"{'. '.join(description_parts)}. "
                        "Webpack artifacts can reveal internal module structure, "
                        "bundled library versions, and application architecture."
                    ),
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    url=url,
                    evidence=(
                        f"Indicators: {', '.join(webpack_indicators[:5])}; "
                        f"Manifests: {', '.join(exposed_manifests[:3])}"
                    ),
                    remediation=(
                        "1. Configure webpack to minimize bundle exposure in production. "
                        "2. Block access to manifest and stats files via server config. "
                        "3. Use production mode to minimize debug information. "
                        "4. Consider using webpack's optimization.moduleIds: 'deterministic'."
                    ),
                    cvss_score=3.7 if exposed_manifests else 2.0,
                    metadata={
                        "webpack_indicators": webpack_indicators,
                        "exposed_manifests": exposed_manifests,
                        "detected_libraries": detected_libs,
                    },
                )
            )

            # Check CVEs for detected libraries
            for lib_name, version in detected_libs.items():
                findings.extend(self._check_cves_for_library(url, lib_name, version, "webpack_chunk"))

        return findings

    def _check_jsonp_injection(
        self,
        url: str,
        network_log: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Detection Method 9: JSONP Callback Injection.

        Detect JSONP endpoints that may be vulnerable to XSS via callback
        parameter manipulation.
        """
        findings: list[Finding] = []
        jsonp_endpoints: list[dict[str, Any]] = []

        # Common JSONP callback parameter names
        callback_params = [
            "callback",
            "jsonp",
            "cb",
            "jsonpcallback",
            "jsoncallback",
            "_callback",
            "call",
            "func",
            "function",
        ]

        for entry in network_log:
            req_url = entry.get("url", "")
            response_body = entry.get("response_body", "")

            parsed = urlparse(req_url)
            query = parse_qs(parsed.query)

            # Check if URL has callback parameter
            callback_value = None
            callback_param_name = None
            for param in callback_params:
                if param in query:
                    callback_value = query[param][0] if query[param] else None
                    callback_param_name = param
                    break

            # Check if callback is present and response wraps JSON in callback
            if (
                callback_value
                and response_body
                and isinstance(response_body, str)
                and re.match(rf"^\s*{re.escape(callback_value)}\s*\(", response_body)
            ):
                # Analyze if callback is properly sanitized
                is_vulnerable = False
                vulnerability_reason = ""

                # Check for dangerous characters that should be blocked
                dangerous_chars = ["<", ">", '"', "'", "(", ")", ";", "&"]
                if any(c in callback_value for c in dangerous_chars):
                    is_vulnerable = True
                    vulnerability_reason = "Dangerous characters accepted in callback"
                elif len(callback_value) > 50:
                    is_vulnerable = True
                    vulnerability_reason = "Excessive callback length accepted"
                elif not re.match(r"^[\w.$]+$", callback_value):
                    is_vulnerable = True
                    vulnerability_reason = "Non-alphanumeric callback accepted"

                jsonp_endpoints.append(
                    {
                        "url": req_url,
                        "callback_param": callback_param_name,
                        "callback_value": callback_value[:50],
                        "vulnerable": is_vulnerable,
                        "reason": vulnerability_reason,
                    }
                )

        if jsonp_endpoints:
            vulnerable_endpoints = [e for e in jsonp_endpoints if e.get("vulnerable")]
            safe_endpoints = [e for e in jsonp_endpoints if not e.get("vulnerable")]

            if vulnerable_endpoints:
                findings.append(
                    self._create_finding(
                        severity=Severity.HIGH,
                        title="JSONP Endpoint Vulnerable to Callback Injection",
                        description=(
                            f"Found {len(vulnerable_endpoints)} JSONP endpoint(s) that may be "
                            "vulnerable to XSS via callback parameter manipulation. Attackers can "
                            "inject malicious JavaScript that executes in the context of the origin."
                        ),
                        cwe_id="CWE-79",
                        cwe_name="Improper Neutralization of Input During Web Page Generation",
                        url=url,
                        evidence="; ".join(
                            f"{e['url'][:100]} ({e['reason']})" for e in vulnerable_endpoints[:3]
                        ),
                        remediation=(
                            "1. Validate callback parameter against strict whitelist (alphanumeric + underscore only). "
                            "2. Limit callback parameter length (e.g., max 50 chars). "
                            "3. Migrate to CORS-based JSON APIs instead of JSONP. "
                            "4. Set Content-Type: application/json with X-Content-Type-Options: nosniff."
                        ),
                        cvss_score=6.1,
                        references=[
                            "https://owasp.org/www-community/attacks/JSONP_Injection",
                            "https://portswigger.net/web-security/cors/same-origin-policy",
                        ],
                        metadata={"vulnerable_endpoints": vulnerable_endpoints[:10]},
                    )
                )

            if safe_endpoints:
                findings.append(
                    self._create_finding(
                        severity=Severity.INFO,
                        title="JSONP Endpoints Detected",
                        description=(
                            f"Found {len(safe_endpoints)} JSONP endpoint(s). While these appear "
                            "to sanitize callbacks properly, JSONP is a legacy pattern with "
                            "inherent security risks."
                        ),
                        cwe_id="CWE-346",
                        cwe_name="Origin Validation Error",
                        url=url,
                        evidence=f"JSONP endpoints: {len(safe_endpoints)} detected",
                        remediation=(
                            "Consider migrating from JSONP to CORS-enabled JSON APIs. "
                            "JSONP bypasses same-origin policy by design."
                        ),
                        cvss_score=2.0,
                        metadata={"safe_endpoints": [e["url"] for e in safe_endpoints[:5]]},
                    )
                )

        return findings

    def _check_sri_bypass(
        self,
        url: str,
        html: str,
        headers: dict[str, str],
    ) -> list[Finding]:
        """
        Detection Method 10: Subresource Integrity Bypass.

        Detect missing or weak SRI (Subresource Integrity) hashes on external
        scripts and stylesheets, which allows supply-chain attacks.
        """
        findings: list[Finding] = []

        # Find all external script and link tags
        script_pattern = r'<script[^>]+src\s*=\s*["\']([^"\']+)["\'][^>]*>'
        link_pattern = r'<link[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]*>'
        integrity_pattern = r'integrity\s*=\s*["\']([^"\']+)["\']'
        crossorigin_pattern = r'crossorigin\s*(?:=\s*["\']([^"\']*)["\'])?'

        external_resources: list[dict[str, Any]] = []

        # Analyze scripts
        for match in re.finditer(script_pattern, html, re.IGNORECASE):
            full_tag = match.group(0)
            src = match.group(1)

            # Check if external (CDN or different domain)
            if self._is_external_resource(url, src):
                has_integrity = bool(re.search(integrity_pattern, full_tag, re.IGNORECASE))
                has_crossorigin = bool(re.search(crossorigin_pattern, full_tag, re.IGNORECASE))

                integrity_match = re.search(integrity_pattern, full_tag, re.IGNORECASE)
                integrity_value = integrity_match.group(1) if integrity_match else None

                # Check integrity hash strength - SHA-256/384/512 are acceptable
                weak_hash = False
                if integrity_value:
                    strong_prefixes = ("sha256-", "sha384-", "sha512-")
                    weak_hash = not integrity_value.startswith(strong_prefixes)

                external_resources.append(
                    {
                        "type": "script",
                        "url": src,
                        "has_integrity": has_integrity,
                        "has_crossorigin": has_crossorigin,
                        "weak_hash": weak_hash,
                        "integrity": integrity_value[:50] if integrity_value else None,
                    }
                )

        # Analyze stylesheets
        for match in re.finditer(link_pattern, html, re.IGNORECASE):
            full_tag = match.group(0)
            href = match.group(1)

            # Only check external stylesheets
            full_tag_lower = full_tag.lower()
            is_stylesheet = 'rel=' in full_tag_lower and 'stylesheet' in full_tag_lower
            if is_stylesheet and self._is_external_resource(url, href):
                has_integrity = bool(re.search(integrity_pattern, full_tag, re.IGNORECASE))
                has_crossorigin = bool(re.search(crossorigin_pattern, full_tag, re.IGNORECASE))

                external_resources.append(
                    {
                        "type": "stylesheet",
                        "url": href,
                        "has_integrity": has_integrity,
                        "has_crossorigin": has_crossorigin,
                        "weak_hash": False,
                    }
                )

        # Analyze findings
        missing_sri = [r for r in external_resources if not r["has_integrity"]]
        weak_sri = [r for r in external_resources if r.get("weak_hash")]
        missing_crossorigin = [
            r for r in external_resources if r["has_integrity"] and not r["has_crossorigin"]
        ]

        if missing_sri:
            cdn_resources = [r for r in missing_sri if self._is_cdn_url(r["url"])]
            other_external = [r for r in missing_sri if not self._is_cdn_url(r["url"])]

            if cdn_resources:
                findings.append(
                    self._create_finding(
                        severity=Severity.MEDIUM,
                        title="Missing Subresource Integrity on CDN Resources",
                        description=(
                            f"Found {len(cdn_resources)} CDN-loaded resource(s) without SRI hashes. "
                            "Without SRI, if the CDN is compromised, attackers can inject malicious "
                            "code that executes on your users' browsers."
                        ),
                        cwe_id="CWE-353",
                        cwe_name="Missing Support for Integrity Check",
                        url=url,
                        evidence="; ".join(r["url"][:80] for r in cdn_resources[:5]),
                        remediation=(
                            "1. Add integrity attribute with SHA-384 or SHA-512 hash to all CDN resources. "
                            "2. Add crossorigin='anonymous' attribute when using SRI. "
                            "3. Use SRI Hash Generator tools or package manager lock files. "
                            "4. Consider using require-sri-for CSP directive."
                        ),
                        cvss_score=5.3,
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                            "https://www.srihash.org/",
                        ],
                        metadata={
                            "resources_without_sri": [r["url"] for r in cdn_resources[:20]],
                            "total_external_resources": len(external_resources),
                        },
                    )
                )

            if other_external:
                findings.append(
                    self._create_finding(
                        severity=Severity.LOW,
                        title="Missing SRI on External Resources",
                        description=(
                            f"Found {len(other_external)} external resource(s) from third-party "
                            "domains without SRI. While the risk is lower than CDN resources, "
                            "SRI provides defense-in-depth against supply chain attacks."
                        ),
                        cwe_id="CWE-353",
                        cwe_name="Missing Support for Integrity Check",
                        url=url,
                        evidence="; ".join(r["url"][:80] for r in other_external[:3]),
                        remediation="Consider adding SRI hashes for all third-party resources.",
                        cvss_score=3.1,
                    )
                )

        if weak_sri:
            findings.append(
                self._create_finding(
                    severity=Severity.MEDIUM,
                    title="Weak Subresource Integrity Hash Algorithm",
                    description=(
                        f"Found {len(weak_sri)} resource(s) using weak or unknown SRI hash "
                        "algorithms. Use SHA-384 or SHA-512 for robust integrity verification."
                    ),
                    cwe_id="CWE-328",
                    cwe_name="Use of Weak Hash",
                    url=url,
                    evidence="; ".join(f"{r['url'][:50]}: {r.get('integrity', 'unknown')}" for r in weak_sri[:3]),
                    remediation="Upgrade SRI hashes to use SHA-384 or SHA-512 algorithms.",
                    cvss_score=4.3,
                )
            )

        if missing_crossorigin:
            findings.append(
                self._create_finding(
                    severity=Severity.LOW,
                    title="SRI Without CrossOrigin Attribute",
                    description=(
                        f"Found {len(missing_crossorigin)} resource(s) with SRI but missing "
                        "crossorigin attribute. The crossorigin attribute is required for SRI "
                        "validation on cross-origin resources."
                    ),
                    cwe_id="CWE-353",
                    cwe_name="Missing Support for Integrity Check",
                    url=url,
                    evidence="; ".join(r["url"][:80] for r in missing_crossorigin[:3]),
                    remediation="Add crossorigin='anonymous' to all cross-origin resources with SRI.",
                    cvss_score=2.0,
                )
            )

        return findings

    def _is_external_resource(self, page_url: str, resource_url: str) -> bool:
        """Check if a resource URL is external to the page's domain."""
        if resource_url.startswith("//"):
            resource_url = "https:" + resource_url

        if not resource_url.startswith(("http://", "https://")):
            return False  # Relative URL, same origin

        page_parsed = urlparse(page_url)
        resource_parsed = urlparse(resource_url)

        return page_parsed.netloc != resource_parsed.netloc

    def _is_cdn_url(self, resource_url: str) -> bool:
        """Check if URL is from a known CDN."""
        cdn_domains = [
            "cdnjs.cloudflare.com",
            "cdn.jsdelivr.net",
            "unpkg.com",
            "ajax.googleapis.com",
            "ajax.aspnetcdn.com",
            "code.jquery.com",
            "maxcdn.bootstrapcdn.com",
            "stackpath.bootstrapcdn.com",
            "cdn.bootcss.com",
            "lib.baomitu.com",
            "cdn.staticfile.org",
            "cdn.bootcdn.net",
            "fonts.googleapis.com",
            "fonts.gstatic.com",
        ]
        try:
            parsed = urlparse(resource_url)
            return any(cdn in parsed.netloc for cdn in cdn_domains)
        except Exception:
            return False

    def _check_cves_for_library(
        self,
        url: str,
        library_name: str,
        version: str,
        detection_method: str,
    ) -> list[Finding]:
        """Check if a library version has known CVEs."""
        findings: list[Finding] = []

        # Normalize library name
        lib_key = library_name.lower().replace(".js", "").replace("-", "")

        # Special handling for library aliases
        aliases = {
            "angularjs": "angular",
            "jqueryui": "jquery",
            "momentjs": "moment",
            "handlebarjs": "handlebars",
        }
        lib_key = aliases.get(lib_key, lib_key)

        if lib_key not in JS_LIBRARY_CVES:
            return findings

        for cve in JS_LIBRARY_CVES[lib_key]:
            if _is_version_vulnerable(version, cve):
                findings.append(
                    self._create_finding(
                        severity=cve.severity,
                        title=f"Vulnerable {library_name} {version}: {cve.cve_id}",
                        description=(
                            f"{cve.description}. "
                            f"Detected {library_name} version {version} via {detection_method}. "
                            f"This version is vulnerable to {cve.cve_id}. "
                            f"Upgrade to version {cve.max_safe_version} or later."
                        ),
                        cwe_id="CWE-1395",
                        cwe_name="Dependency on Vulnerable Third-Party Component",
                        url=url,
                        evidence=f"{library_name} v{version} < {cve.max_safe_version}",
                        remediation=(
                            f"Upgrade {library_name} to version {cve.max_safe_version} or later. "
                            f"Review changelog for breaking changes. "
                            "Use npm audit or similar tools for ongoing vulnerability detection."
                        ),
                        cvss_score=cve.cvss_score,
                        references=[
                            f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
                            f"https://snyk.io/vuln/search?q={library_name}",
                        ],
                        metadata={
                            "cve_id": cve.cve_id,
                            "library": library_name,
                            "detected_version": version,
                            "safe_version": cve.max_safe_version,
                            "detection_method": detection_method,
                        },
                    )
                )

        return findings
