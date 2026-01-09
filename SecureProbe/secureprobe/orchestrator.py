"""
Scan Orchestrator for SecureProbe.

Manages the scan lifecycle, coordinates analyzers, handles rate limiting,
and aggregates results with deduplication.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path
from typing import Any

import httpx
import structlog
from dotenv import load_dotenv
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "python-sdk"))

# Load environment variables from .env file
load_dotenv()

from secureprobe.analyzers import (
    AccessControlAnalyzer,
    APISecurityAnalyzer,
    APTAttacksAnalyzer,
    BaseAnalyzer,
    BloodyMaryAnalyzer,
    ChaosAttacksAnalyzer,
    ChaosTeenAnalyzer,
    CookieAnalyzer,
    CredentialSprayAnalyzer,
    CryptoAnalyzer,
    EndpointAnalyzer,
    FormAnalyzer,
    HeaderAnalyzer,
    InfoLeakAnalyzer,
    InputValidationAnalyzer,
    JSLibraryCVEAnalyzer,
    MemoryAssaultAnalyzer,
    NovelAttacksAnalyzer,
    SessionSecurityAnalyzer,
    TLSAnalyzer,
)
from secureprobe.models import AnalyzerType, Finding, ScanConfig, ScanMode, ScanResult
from secureprobe.rate_limiter import TokenBucketRateLimiter
from secureprobe.utils import is_same_origin, normalize_url

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
        logger.info(
            "using_remote_browser",
            remote_url=remote_url,
            has_token=bool(remote_token),
        )
        remote_config = RemoteConfig(url=remote_url, token=remote_token)
        return Browser(remote=remote_config)
    else:
        logger.info("using_local_browser")
        return Browser()


class AnalyzerPool:
    """
    Pool for parallel analyzer execution.

    Manages concurrent execution of all enabled analyzers
    with proper error handling and result aggregation.
    """

    def __init__(self, config: ScanConfig) -> None:
        """Initialize analyzer pool with configuration."""
        self.config = config
        self.analyzers: list[BaseAnalyzer] = []
        self._initialize_analyzers()

    def _initialize_analyzers(self) -> None:
        """Initialize enabled analyzers."""
        analyzer_classes: dict[AnalyzerType, type[BaseAnalyzer]] = {
            AnalyzerType.HEADER: HeaderAnalyzer,
            AnalyzerType.COOKIE: CookieAnalyzer,
            AnalyzerType.FORM: FormAnalyzer,
            AnalyzerType.TLS: TLSAnalyzer,
            AnalyzerType.INFO_LEAK: InfoLeakAnalyzer,
            AnalyzerType.ENDPOINT: EndpointAnalyzer,
            AnalyzerType.SESSION_SECURITY: SessionSecurityAnalyzer,
            AnalyzerType.INPUT_VALIDATION: InputValidationAnalyzer,
            AnalyzerType.ACCESS_CONTROL: AccessControlAnalyzer,
            AnalyzerType.CRYPTO_ANALYSIS: CryptoAnalyzer,
            AnalyzerType.API_SECURITY: APISecurityAnalyzer,
            AnalyzerType.CHAOS_ATTACKS: ChaosAttacksAnalyzer,
            AnalyzerType.APT_ATTACKS: APTAttacksAnalyzer,
            AnalyzerType.JS_LIBRARY_CVE: JSLibraryCVEAnalyzer,
            AnalyzerType.NOVEL_ATTACKS: NovelAttacksAnalyzer,
            AnalyzerType.BLOODY_MARY: BloodyMaryAnalyzer,
            AnalyzerType.MEMORY_ASSAULT: MemoryAssaultAnalyzer,
            AnalyzerType.CHAOS_TEEN: ChaosTeenAnalyzer,
            AnalyzerType.CREDENTIAL_SPRAY: CredentialSprayAnalyzer,
        }

        for analyzer_type, analyzer_class in analyzer_classes.items():
            if analyzer_type in self.config.enabled_analyzers:
                self.analyzers.append(analyzer_class(self.config))
                logger.debug("analyzer_initialized", analyzer=analyzer_type.value)

    async def run_all(
        self,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """
        Run all analyzers in parallel.

        Args:
            url: Target URL
            page_data: Page data for analysis

        Returns:
            Combined list of findings from all analyzers
        """
        tasks = [
            self._run_analyzer(analyzer, url, page_data)
            for analyzer in self.analyzers
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        for i, result in enumerate(results):
            analyzer_name = self.analyzers[i].analyzer_type.value if i < len(self.analyzers) else "unknown"
            if isinstance(result, Exception):
                logger.error("analyzer_error", analyzer=analyzer_name, error=str(result))
            elif isinstance(result, list):
                logger.info(
                    "analyzer_findings",
                    analyzer=analyzer_name,
                    finding_count=len(result),
                    url=url,
                )
                findings.extend(result)

        logger.info(
            "all_analyzers_complete",
            total_raw_findings=len(findings),
            url=url,
        )
        return findings

    async def _run_analyzer(
        self,
        analyzer: BaseAnalyzer,
        url: str,
        page_data: dict[str, Any],
    ) -> list[Finding]:
        """Run a single analyzer with error handling."""
        try:
            return await analyzer.analyze(url, page_data)
        except Exception as e:
            logger.error(
                "analyzer_failed",
                analyzer=analyzer.analyzer_type.value,
                error=str(e),
            )
            return []


class ScanOrchestrator:
    """
    Main scan orchestrator.

    Coordinates the entire scan lifecycle:
    1. Authorization verification
    2. Page crawling and data collection
    3. Parallel analyzer execution
    4. Result aggregation with deduplication
    """

    def __init__(self, config: ScanConfig) -> None:
        """
        Initialize scan orchestrator.

        Args:
            config: Scan configuration
        """
        self.config = config
        self.rate_limiter = TokenBucketRateLimiter(rate=config.rate_limit)
        self.analyzer_pool = AnalyzerPool(config)
        self.visited_urls: set[str] = set()
        self.result = ScanResult(target_url=config.target_url)

    async def scan(self) -> ScanResult:
        """
        Execute the security scan.

        Returns:
            Complete scan result with all findings
        """
        logger.info("scan_started", target=self.config.target_url)

        try:
            if not await self._verify_authorization():
                self.result.errors.append("Authorization verification failed")
                self.result.finalize()
                return self.result

            self.result.authorization_verified = True

            await self._scan_url(self.config.target_url, depth=0)

            self.result.finalize()
            logger.info(
                "scan_completed",
                target=self.config.target_url,
                findings=len(self.result.findings),
                duration=f"{self.result.duration_seconds:.2f}s",
            )

        except Exception as e:
            logger.error("scan_error", error=str(e))
            self.result.errors.append(str(e))
            self.result.finalize()

        return self.result

    async def _verify_authorization(self) -> bool:
        """
        Verify authorization to scan the target.

        Checks for robots.txt, security.txt, and performs
        a test request to ensure the target is accessible.

        Returns:
            True if authorized to scan
        """
        logger.info("verifying_authorization", target=self.config.target_url)

        try:
            with _get_browser_instance() as browser:
                page = browser.new_page()

                robots_url = urljoin(self.config.target_url, "/robots.txt")
                try:
                    page.goto(robots_url, timeout=10000)
                    robots_content = page.extract_text()
                    if "Disallow: /" in robots_content and "User-agent: *" in robots_content:
                        logger.warning("robots_disallow_all", url=self.config.target_url)
                except Exception:
                    pass

                page.goto(self.config.target_url, timeout=self.config.timeout * 1000)
                current_url = page.get_current_url()

                if current_url:
                    logger.info("authorization_verified", url=current_url)
                    return True

                page.close()

        except Exception as e:
            logger.error("authorization_check_failed", error=str(e))
            return False

        return True

    async def _scan_url(self, url: str, depth: int) -> None:
        """
        Scan a single URL and optionally crawl links.

        Args:
            url: URL to scan
            depth: Current crawl depth
        """
        if url in self.visited_urls:
            return

        if depth > self.config.max_depth:
            return

        if not is_same_origin(url, self.config.target_url):
            return

        for pattern in self.config.exclude_patterns:
            if pattern in url:
                logger.debug("url_excluded", url=url, pattern=pattern)
                return

        self.visited_urls.add(url)
        self.result.urls_scanned += 1

        logger.info("scanning_url", url=url, depth=depth)

        await self.rate_limiter.acquire()

        try:
            page_data = await self._collect_page_data(url)

            findings = await self.analyzer_pool.run_all(url, page_data)

            added_count = 0
            dedupe_count = 0
            for finding in findings:
                if self.result.add_finding(finding):
                    added_count += 1
                else:
                    dedupe_count += 1

            logger.info(
                "findings_processed",
                url=url,
                raw_findings=len(findings),
                added=added_count,
                deduplicated=dedupe_count,
                total_findings=len(self.result.findings),
            )

            if depth < self.config.max_depth:
                links = self._extract_links(url, page_data.get("html", ""))
                for link in links[:20]:
                    await self._scan_url(link, depth + 1)

        except Exception as e:
            logger.error("url_scan_error", url=url, error=str(e))
            self.result.errors.append(f"Error scanning {url}: {str(e)}")

    async def _collect_page_data(self, url: str) -> dict[str, Any]:
        """
        Collect page data using browser automation and HTTP requests.

        Args:
            url: URL to collect data from

        Returns:
            Dictionary containing HTML, headers, cookies, etc.
        """
        page_data: dict[str, Any] = {
            "html": "",
            "headers": {},
            "cookies": [],
            "forms": [],
            "scripts": [],
            "network_log": [],
            "scan_mode": self.config.scan_mode.value,
            "browser_contexts": [],
        }

        page_data["headers"] = await self._fetch_headers(url)

        try:
            with _get_browser_instance() as browser:
                page = browser.new_page()

                page.enable_network_logging(True)

                page.goto(url, timeout=self.config.timeout * 1000)

                try:
                    page.wait_for_network_idle(idle_time=500, timeout=5000)
                except Exception:
                    pass

                page_data["html"] = page.get_html()
                page_data["cookies"] = self._convert_cookies(page.get_cookies())

                network_log = page.get_network_log()
                page_data["network_log"] = [
                    {
                        "url": getattr(entry, "url", ""),
                        "method": getattr(entry, "method", ""),
                        "status": getattr(entry, "status", 0),
                    }
                    for entry in network_log[:100]
                ]

                try:
                    scripts_result = page.evaluate(
                        """
                        (() => {
                            const scripts = document.querySelectorAll('script');
                            return Array.from(scripts).map(s => s.textContent || '').filter(t => t.length > 0);
                        })()
                        """,
                        return_value=True,
                    )
                    if isinstance(scripts_result, list):
                        page_data["scripts"] = scripts_result
                except Exception:
                    pass

                try:
                    forms_result = page.evaluate(
                        """
                        (() => {
                            const forms = document.querySelectorAll('form');
                            return Array.from(forms).map(form => ({
                                id: form.id || form.name || '',
                                action: form.action || '',
                                method: form.method || 'get',
                                inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(input => ({
                                    name: input.name || '',
                                    type: input.type || '',
                                    autocomplete: input.autocomplete || ''
                                }))
                            }));
                        })()
                        """,
                        return_value=True,
                    )
                    if isinstance(forms_result, list):
                        page_data["forms"] = forms_result
                except Exception:
                    pass

                page.close()

                # Create additional browser contexts for isolation testing
                if self.config.browser_contexts > 1:
                    for i in range(1, self.config.browser_contexts):
                        try:
                            context_page = browser.new_page()
                            context_page.goto(url, timeout=self.config.timeout * 1000)
                            context_cookies = self._convert_cookies(context_page.get_cookies())
                            page_data["browser_contexts"].append({
                                "context_id": i,
                                "cookies": context_cookies,
                            })
                            context_page.close()
                        except Exception as ctx_err:
                            logger.debug(
                                "browser_context_error",
                                context_id=i,
                                error=str(ctx_err),
                            )

        except Exception as e:
            logger.error("page_data_collection_error", url=url, error=str(e))

        return page_data

    async def _fetch_headers(self, url: str) -> dict[str, str]:
        """Fetch HTTP response headers using httpx."""
        headers: dict[str, str] = {}
        try:
            async with httpx.AsyncClient(
                verify=self.config.verify_ssl,
                timeout=self.config.timeout,
                follow_redirects=True,
            ) as client:
                response = await client.head(
                    url,
                    headers={"User-Agent": self.config.user_agent},
                )
                headers = dict(response.headers)
        except Exception as e:
            logger.debug("header_fetch_error", url=url, error=str(e))
            try:
                async with httpx.AsyncClient(
                    verify=self.config.verify_ssl,
                    timeout=self.config.timeout,
                    follow_redirects=True,
                ) as client:
                    response = await client.get(
                        url,
                        headers={"User-Agent": self.config.user_agent},
                    )
                    headers = dict(response.headers)
            except Exception:
                pass
        return headers

    def _convert_cookies(self, cookies: list[Any]) -> list[dict[str, Any]]:
        """Convert cookie objects to dictionaries."""
        result: list[dict[str, Any]] = []
        for cookie in cookies:
            if hasattr(cookie, "__dict__"):
                result.append({
                    "name": getattr(cookie, "name", ""),
                    "value": getattr(cookie, "value", ""),
                    "domain": getattr(cookie, "domain", ""),
                    "path": getattr(cookie, "path", "/"),
                    "secure": getattr(cookie, "secure", False),
                    "httponly": getattr(cookie, "http_only", False),
                    "samesite": str(getattr(cookie, "same_site", "")).lower(),
                    "expires": getattr(cookie, "expires", -1),
                })
            elif isinstance(cookie, dict):
                result.append(cookie)
        return result

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        """Extract links from HTML content."""
        import re

        links: set[str] = set()

        href_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
        matches = re.findall(href_pattern, html, re.IGNORECASE)

        for href in matches:
            if href.startswith("#") or href.startswith("javascript:"):
                continue
            if href.startswith("mailto:") or href.startswith("tel:"):
                continue

            full_url = normalize_url(base_url, href)

            if is_same_origin(full_url, self.config.target_url):
                links.add(full_url)

        return list(links)
