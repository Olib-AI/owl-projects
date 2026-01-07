# DarkWatch: Proactive Dark Web Threat Intelligence Platform

## 1. Executive Summary

**DarkWatch** is a production-grade Open Source Intelligence (OSINT) platform designed to monitor the dark web (Tor network) for data breaches, leaked credentials, and mentions of specific organizations or assets. Leveraging the **Owl Browser's** unique capabilities to handle isolated contexts and native proxy chains, DarkWatch provides a safe, scalable, and automated way to index hidden services (`.onion` sites).

**Key Use Cases:**
*   **Breach Detection:** Automatically detect if corporate emails or passwords appear in dump sites.
*   **Brand Monitoring:** Track mentions of brand names in illicit marketplaces.
*   **Threat Actor Tracking:** Monitor specific forums for planned attacks.
*   **Credential Monitoring:** Detect leaked API keys, private keys, and authentication tokens.
*   **Ransomware Intelligence:** Track ransomware group activities and victim announcements.

**Platform Capabilities:**
*   Automated `.onion` site discovery and indexing
*   Real-time pattern matching for sensitive data (credentials, PII, financial data)
*   AI-powered content analysis and summarization via Owl Browser's built-in VLM
*   Authenticated forum/marketplace crawling with session persistence
*   Evidence preservation with cryptographic chain of custody
*   Integration with SIEM/SOAR platforms for automated response

## 2. System Architecture

Unlike standard web scrapers, a dark web crawler must handle extreme latency, frequent timeouts, and high anonymity requirements.

```mermaid
graph TD
    subgraph "Secure Zone (VPC)"
        Manager[Orchestrator] -->|Jobs| Queue[Redis Stream]
        
        Queue --> Worker1
        Queue --> Worker2
        
        subgraph "Worker Pod 1"
            Worker1[Python Worker]
            Owl1[Owl Browser]
            TorLB1[HAProxy]
            TorPool1["Tor Instance Pool (x10)"]
        end
        
        Worker1 --> Owl1
        Owl1 --> TorLB1
        TorLB1 --> TorPool1
        
        TorPool1 -->|Onion Traffic| DarkWeb((Dark Web))
    end
    
    Worker1 -->|Raw Text| StreamProc[Apache Flink]
    StreamProc -->|Alerts| AlertDB[(PostgreSQL)]
    StreamProc -->|Logs| ClickHouse[(ClickHouse)]
    
    AlertDB --> API[Secure API Gateway]
```

## 3. High-Scale Tor Connectivity

Connecting a single browser to a single Tor instance is insufficient for scale. Tor circuits are slow (300KB/s avg) and often fail. Production deployments require a pool of Tor instances with health monitoring, automatic circuit rotation, and load balancing.

### 3.1. The "Tor Pool" Pattern

We deploy a sidecar container running **multiple Tor instances** (e.g., 10-50 per node) and an **HAProxy** load balancer in front of them.

*   **Round-Robin Rotation:** Every request is routed to a different Tor instance.
*   **Circuit Refreshing:** A background process sends `SIGNAL NEWNYM` to the Tor control ports every 10 minutes to force new circuits.
*   **Health Checking:** Continuous monitoring of circuit establishment and latency.

### 3.2. Tor Pool Manager Implementation

```python
"""
Tor Pool Manager - Production-grade Tor instance management.

This module provides:
- Multiple Tor instance lifecycle management
- Circuit health monitoring and rotation
- Control port management for SIGNAL NEWNYM
- Connection pooling with health checks
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Final

import aiosocks  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# Constants
TOR_CONTROL_PORT_BASE: Final[int] = 9051
TOR_SOCKS_PORT_BASE: Final[int] = 9050
CIRCUIT_ROTATION_INTERVAL: Final[timedelta] = timedelta(minutes=10)
HEALTH_CHECK_INTERVAL: Final[timedelta] = timedelta(seconds=30)
MAX_CIRCUIT_FAILURES: Final[int] = 3


class TorInstanceState(Enum):
    """State machine for Tor instance lifecycle."""
    INITIALIZING = auto()
    HEALTHY = auto()
    DEGRADED = auto()
    ROTATING = auto()
    FAILED = auto()


@dataclass
class TorInstanceMetrics:
    """Metrics for a single Tor instance."""
    requests_served: int = 0
    failures: int = 0
    avg_latency_ms: float = 0.0
    last_circuit_rotation: datetime = field(default_factory=datetime.utcnow)
    last_health_check: datetime = field(default_factory=datetime.utcnow)
    consecutive_failures: int = 0


@dataclass
class TorInstance:
    """Represents a single Tor instance in the pool."""
    instance_id: int
    socks_host: str
    socks_port: int
    control_port: int
    control_password: str
    state: TorInstanceState = TorInstanceState.INITIALIZING
    metrics: TorInstanceMetrics = field(default_factory=TorInstanceMetrics)

    @property
    def is_available(self) -> bool:
        """Check if instance can accept new connections."""
        return self.state in (TorInstanceState.HEALTHY, TorInstanceState.DEGRADED)


class TorPoolManager:
    """
    Manages a pool of Tor instances with health checking and circuit rotation.

    Usage:
        async with TorPoolManager(instance_count=10) as pool:
            instance = await pool.get_healthy_instance()
            proxy_config = pool.get_proxy_config(instance)
    """

    def __init__(
        self,
        instance_count: int = 10,
        base_host: str = "127.0.0.1",
        socks_port_base: int = TOR_SOCKS_PORT_BASE,
        control_port_base: int = TOR_CONTROL_PORT_BASE,
        control_password: str = "darkwatch_tor_control",
    ) -> None:
        self._instance_count = instance_count
        self._base_host = base_host
        self._socks_port_base = socks_port_base
        self._control_port_base = control_port_base
        self._control_password = control_password

        self._instances: list[TorInstance] = []
        self._round_robin_index: int = 0
        self._lock = asyncio.Lock()
        self._health_check_task: asyncio.Task[None] | None = None
        self._rotation_task: asyncio.Task[None] | None = None
        self._running: bool = False

    async def __aenter__(self) -> TorPoolManager:
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.stop()

    async def start(self) -> None:
        """Initialize the Tor pool and start background tasks."""
        logger.info("Starting Tor pool with %d instances", self._instance_count)

        # Initialize instances
        for i in range(self._instance_count):
            instance = TorInstance(
                instance_id=i,
                socks_host=self._base_host,
                socks_port=self._socks_port_base + i,
                control_port=self._control_port_base + i,
                control_password=self._control_password,
            )
            self._instances.append(instance)

        self._running = True

        # Initial health check for all instances
        await self._check_all_instances()

        # Start background tasks
        self._health_check_task = asyncio.create_task(
            self._health_check_loop(),
            name="tor-health-check"
        )
        self._rotation_task = asyncio.create_task(
            self._circuit_rotation_loop(),
            name="tor-circuit-rotation"
        )

        healthy_count = sum(1 for i in self._instances if i.is_available)
        logger.info("Tor pool started: %d/%d instances healthy",
                    healthy_count, self._instance_count)

    async def stop(self) -> None:
        """Gracefully shutdown the pool."""
        self._running = False

        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass

        if self._rotation_task:
            self._rotation_task.cancel()
            try:
                await self._rotation_task
            except asyncio.CancelledError:
                pass

        logger.info("Tor pool stopped")

    async def get_healthy_instance(self) -> TorInstance:
        """
        Get a healthy Tor instance using round-robin selection.

        Raises:
            RuntimeError: If no healthy instances are available.
        """
        async with self._lock:
            available = [i for i in self._instances if i.is_available]

            if not available:
                raise RuntimeError("No healthy Tor instances available")

            # Round-robin selection among healthy instances
            self._round_robin_index = (self._round_robin_index + 1) % len(available)
            instance = available[self._round_robin_index]
            instance.metrics.requests_served += 1

            return instance

    def get_proxy_config(self, instance: TorInstance) -> dict[str, str | int]:
        """Generate proxy configuration for Owl Browser."""
        return {
            "type": "socks5",
            "host": instance.socks_host,
            "port": instance.socks_port,
        }

    async def rotate_circuit(self, instance: TorInstance) -> bool:
        """
        Force circuit rotation for a specific instance via control port.

        Sends SIGNAL NEWNYM to the Tor control port to establish new circuits.
        """
        try:
            instance.state = TorInstanceState.ROTATING

            # Connect to Tor control port
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(instance.socks_host, instance.control_port),
                timeout=10.0
            )

            try:
                # Authenticate
                auth_cmd = f'AUTHENTICATE "{instance.control_password}"\r\n'
                writer.write(auth_cmd.encode())
                await writer.drain()

                response = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if not response.startswith(b"250"):
                    logger.error("Tor auth failed for instance %d: %s",
                                instance.instance_id, response.decode())
                    return False

                # Send NEWNYM signal
                writer.write(b"SIGNAL NEWNYM\r\n")
                await writer.drain()

                response = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if response.startswith(b"250"):
                    instance.metrics.last_circuit_rotation = datetime.utcnow()
                    instance.state = TorInstanceState.HEALTHY
                    logger.debug("Circuit rotated for instance %d", instance.instance_id)
                    return True
                else:
                    logger.warning("NEWNYM failed for instance %d: %s",
                                  instance.instance_id, response.decode())
                    return False

            finally:
                writer.close()
                await writer.wait_closed()

        except asyncio.TimeoutError:
            logger.warning("Timeout rotating circuit for instance %d", instance.instance_id)
            instance.state = TorInstanceState.DEGRADED
            return False
        except Exception as e:
            logger.error("Error rotating circuit for instance %d: %s",
                        instance.instance_id, e)
            instance.state = TorInstanceState.DEGRADED
            return False

    async def _check_instance_health(self, instance: TorInstance) -> bool:
        """
        Verify Tor instance is functional by testing SOCKS5 connectivity.
        """
        try:
            # Test SOCKS5 handshake
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(instance.socks_host, instance.socks_port),
                timeout=10.0
            )

            try:
                # SOCKS5 greeting: version 5, 1 auth method (no auth)
                writer.write(b"\x05\x01\x00")
                await writer.drain()

                response = await asyncio.wait_for(reader.read(2), timeout=5.0)

                if response == b"\x05\x00":
                    instance.state = TorInstanceState.HEALTHY
                    instance.metrics.consecutive_failures = 0
                    instance.metrics.last_health_check = datetime.utcnow()
                    return True
                else:
                    raise ConnectionError(f"Unexpected SOCKS5 response: {response.hex()}")

            finally:
                writer.close()
                await writer.wait_closed()

        except Exception as e:
            instance.metrics.consecutive_failures += 1
            instance.metrics.failures += 1

            if instance.metrics.consecutive_failures >= MAX_CIRCUIT_FAILURES:
                instance.state = TorInstanceState.FAILED
                logger.error("Instance %d marked FAILED after %d consecutive failures",
                            instance.instance_id, instance.metrics.consecutive_failures)
            else:
                instance.state = TorInstanceState.DEGRADED
                logger.warning("Instance %d health check failed: %s",
                              instance.instance_id, e)

            return False

    async def _check_all_instances(self) -> None:
        """Run health checks on all instances concurrently."""
        tasks = [
            self._check_instance_health(instance)
            for instance in self._instances
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _health_check_loop(self) -> None:
        """Background task for periodic health checking."""
        while self._running:
            await asyncio.sleep(HEALTH_CHECK_INTERVAL.total_seconds())
            await self._check_all_instances()

    async def _circuit_rotation_loop(self) -> None:
        """Background task for periodic circuit rotation."""
        while self._running:
            await asyncio.sleep(CIRCUIT_ROTATION_INTERVAL.total_seconds())

            for instance in self._instances:
                if instance.state == TorInstanceState.HEALTHY:
                    await self.rotate_circuit(instance)
                    # Stagger rotations to avoid thundering herd
                    await asyncio.sleep(1.0)

    def get_pool_stats(self) -> dict[str, int | float]:
        """Return aggregate pool statistics."""
        healthy = sum(1 for i in self._instances if i.state == TorInstanceState.HEALTHY)
        degraded = sum(1 for i in self._instances if i.state == TorInstanceState.DEGRADED)
        failed = sum(1 for i in self._instances if i.state == TorInstanceState.FAILED)
        total_requests = sum(i.metrics.requests_served for i in self._instances)
        total_failures = sum(i.metrics.failures for i in self._instances)

        return {
            "total_instances": self._instance_count,
            "healthy": healthy,
            "degraded": degraded,
            "failed": failed,
            "total_requests": total_requests,
            "total_failures": total_failures,
            "failure_rate": total_failures / max(total_requests, 1),
        }
```

### 3.3. HAProxy Configuration for Tor Load Balancing

```haproxy
# /etc/haproxy/haproxy.cfg
# HAProxy configuration for Tor SOCKS5 load balancing

global
    daemon
    maxconn 4096
    log stdout format raw local0

defaults
    mode tcp
    timeout connect 30s
    timeout client 120s
    timeout server 120s
    retries 3
    option redispatch

frontend tor_socks_frontend
    bind *:9050
    default_backend tor_socks_pool

    # Connection rate limiting
    stick-table type ip size 100k expire 30s store conn_rate(10s)
    tcp-request connection track-sc0 src
    tcp-request connection reject if { sc0_conn_rate gt 100 }

backend tor_socks_pool
    balance roundrobin
    option tcp-check

    # Health check: SOCKS5 handshake validation
    tcp-check connect
    tcp-check send-binary 050100
    tcp-check expect binary 0500

    # Tor instances with health checks
    server tor-1 tor-1:9050 check inter 10s fall 3 rise 2
    server tor-2 tor-2:9050 check inter 10s fall 3 rise 2
    server tor-3 tor-3:9050 check inter 10s fall 3 rise 2
    server tor-4 tor-4:9050 check inter 10s fall 3 rise 2
    server tor-5 tor-5:9050 check inter 10s fall 3 rise 2
    server tor-6 tor-6:9050 check inter 10s fall 3 rise 2
    server tor-7 tor-7:9050 check inter 10s fall 3 rise 2
    server tor-8 tor-8:9050 check inter 10s fall 3 rise 2
    server tor-9 tor-9:9050 check inter 10s fall 3 rise 2
    server tor-10 tor-10:9050 check inter 10s fall 3 rise 2

# Stats endpoint for monitoring
listen stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
    stats auth admin:${HAPROXY_STATS_PASSWORD}
```

### 3.4. Tor Instance Docker Configuration

```dockerfile
# Dockerfile.tor-node
# Custom Tor node with control port enabled

FROM alpine:3.19

RUN apk add --no-cache tor

# Tor configuration
RUN mkdir -p /var/lib/tor && chown -R tor:tor /var/lib/tor

COPY torrc /etc/tor/torrc

USER tor
EXPOSE 9050 9051

CMD ["tor", "-f", "/etc/tor/torrc"]
```

```ini
# torrc - Tor configuration file
SocksPort 0.0.0.0:9050
ControlPort 0.0.0.0:9051

# Hashed password for control port (generate with: tor --hash-password "your_password")
HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C

# Circuit settings optimized for dark web crawling
CircuitBuildTimeout 60
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 600

# Disable exit node functionality (we only need client mode)
ExitPolicy reject *:*

# Logging
Log notice stdout

# Data directory
DataDirectory /var/lib/tor
```

## 4. Complete Tor Crawler Implementation

The Tor Crawler is the core component that navigates `.onion` sites, handles dark web-specific challenges (DDOS-Guard, CAPTCHAs, extreme latency), and extracts intelligence using Owl Browser's full SDK capabilities.

### 4.1. Core Crawler Architecture

```python
"""
DarkWatch Tor Crawler - Production-grade dark web crawler.

Features:
- Robust error handling for Tor-specific failures
- CAPTCHA detection and solving (DDOS-Guard, custom challenges)
- Evidence capture (screenshots, video recording)
- Multi-format content extraction (text, HTML, markdown)
- AI-powered content analysis and summarization
- Session persistence for authenticated crawling
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import AsyncIterator, Final, Protocol, TypedDict

from owl_browser import AsyncBrowser, RemoteConfig, ProxyConfig, AsyncPage

logger = logging.getLogger(__name__)

# Constants for Tor-specific timeouts (much higher than clearnet)
TOR_NAVIGATION_TIMEOUT: Final[int] = 120_000  # 2 minutes
TOR_ELEMENT_TIMEOUT: Final[int] = 60_000  # 1 minute
TOR_CAPTCHA_TIMEOUT: Final[int] = 90_000  # 1.5 minutes
MAX_NAVIGATION_RETRIES: Final[int] = 3
CIRCUIT_FAILURE_PATTERNS: Final[tuple[str, ...]] = (
    "NS_ERROR_CONNECTION_REFUSED",
    "NS_ERROR_PROXY_CONNECTION_REFUSED",
    "SOCKS5_HOST_UNREACHABLE",
    "circuit",
)


class CrawlStatus(Enum):
    """Status codes for crawl results."""
    SUCCESS = auto()
    CAPTCHA_FAILED = auto()
    TIMEOUT = auto()
    CIRCUIT_FAILURE = auto()
    BLOCKED = auto()
    NOT_FOUND = auto()
    ERROR = auto()


class ContentFormat(Enum):
    """Supported content extraction formats."""
    TEXT = "text"
    HTML = "html"
    MARKDOWN = "markdown"


@dataclass
class CrawlEvidence:
    """Evidence captured during a crawl."""
    screenshot_base64: str | None = None
    screenshot_path: str | None = None
    video_path: str | None = None
    html_content: str | None = None
    content_hash: str | None = None
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AIAnalysis:
    """AI-generated analysis of page content."""
    summary: str
    detected_entities: list[str]
    threat_indicators: list[str]
    content_category: str
    confidence_score: float


@dataclass
class CrawlResult:
    """Complete result of a crawl operation."""
    url: str
    status: CrawlStatus
    title: str | None = None
    text_content: str | None = None
    markdown_content: str | None = None
    evidence: CrawlEvidence | None = None
    ai_analysis: AIAnalysis | None = None
    error_message: str | None = None
    crawl_duration_ms: int = 0
    tor_instance_id: int | None = None


class TorCrawlerError(Exception):
    """Base exception for Tor crawler errors."""
    pass


class CircuitFailureError(TorCrawlerError):
    """Raised when Tor circuit establishment fails."""
    pass


class CaptchaChallengeError(TorCrawlerError):
    """Raised when CAPTCHA cannot be solved."""
    pass


class DarkWebBlockedError(TorCrawlerError):
    """Raised when access is blocked by the target site."""
    pass


class TorCrawler:
    """
    Production-grade Tor crawler using Owl Browser.

    Handles all aspects of dark web crawling including:
    - Tor proxy management with automatic rotation
    - CAPTCHA detection and solving
    - Evidence capture with chain of custody
    - AI-powered content analysis
    - Robust error handling and retry logic

    Usage:
        async with TorCrawler(tor_pool, browser_url) as crawler:
            result = await crawler.crawl("http://example.onion")
    """

    def __init__(
        self,
        tor_pool: TorPoolManager,
        browser_url: str = "http://owl-browser:8080",
        browser_token: str | None = None,
        evidence_dir: str = "/data/evidence",
        enable_video: bool = False,
        enable_ai_analysis: bool = True,
    ) -> None:
        self._tor_pool = tor_pool
        self._browser_url = browser_url
        self._browser_token = browser_token
        self._evidence_dir = evidence_dir
        self._enable_video = enable_video
        self._enable_ai_analysis = enable_ai_analysis
        self._browser: AsyncBrowser | None = None

    async def __aenter__(self) -> TorCrawler:
        remote_config = RemoteConfig(
            url=self._browser_url,
            token=self._browser_token,
        )
        self._browser = AsyncBrowser(remote=remote_config)
        await self._browser.__aenter__()
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._browser:
            await self._browser.__aexit__(*args)

    async def crawl(
        self,
        url: str,
        extract_formats: list[ContentFormat] | None = None,
        capture_evidence: bool = True,
        solve_captcha: bool = True,
        custom_headers: dict[str, str] | None = None,
    ) -> CrawlResult:
        """
        Crawl a single .onion URL with full evidence capture.

        Args:
            url: The .onion URL to crawl
            extract_formats: Content formats to extract (default: TEXT, MARKDOWN)
            capture_evidence: Whether to capture screenshots/video
            solve_captcha: Whether to attempt CAPTCHA solving
            custom_headers: Additional HTTP headers to send

        Returns:
            CrawlResult with extracted content and evidence
        """
        if extract_formats is None:
            extract_formats = [ContentFormat.TEXT, ContentFormat.MARKDOWN]

        start_time = datetime.now(timezone.utc)
        tor_instance = await self._tor_pool.get_healthy_instance()

        logger.info("Crawling %s via Tor instance %d", url, tor_instance.instance_id)

        try:
            result = await self._execute_crawl(
                url=url,
                tor_instance=tor_instance,
                extract_formats=extract_formats,
                capture_evidence=capture_evidence,
                solve_captcha=solve_captcha,
            )
            result.tor_instance_id = tor_instance.instance_id
            result.crawl_duration_ms = int(
                (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            )
            return result

        except CircuitFailureError as e:
            logger.warning("Circuit failure for %s: %s", url, e)
            # Rotate circuit and retry once
            await self._tor_pool.rotate_circuit(tor_instance)
            return CrawlResult(
                url=url,
                status=CrawlStatus.CIRCUIT_FAILURE,
                error_message=str(e),
                tor_instance_id=tor_instance.instance_id,
            )

        except CaptchaChallengeError as e:
            logger.warning("CAPTCHA failed for %s: %s", url, e)
            return CrawlResult(
                url=url,
                status=CrawlStatus.CAPTCHA_FAILED,
                error_message=str(e),
                tor_instance_id=tor_instance.instance_id,
            )

        except Exception as e:
            logger.error("Crawl error for %s: %s", url, e, exc_info=True)
            return CrawlResult(
                url=url,
                status=CrawlStatus.ERROR,
                error_message=str(e),
                tor_instance_id=tor_instance.instance_id,
            )

    async def _execute_crawl(
        self,
        url: str,
        tor_instance: TorInstance,
        extract_formats: list[ContentFormat],
        capture_evidence: bool,
        solve_captcha: bool,
    ) -> CrawlResult:
        """Execute the actual crawl with Owl Browser."""
        if not self._browser:
            raise RuntimeError("Crawler not initialized")

        # Create isolated page with Tor proxy and stealth mode
        proxy_config = ProxyConfig(
            type="socks5",
            host=tor_instance.socks_host,
            port=tor_instance.socks_port,
            stealth=True,
            timezone_override="UTC",
        )

        # CRITICAL: UTC timezone for all Tor users (anonymity best practice)
        page = await self._browser.new_page(
            proxy=proxy_config,
        )

        try:
            # Start video recording if enabled (for sensitive operations)
            if self._enable_video and capture_evidence:
                await page.start_video_recording(fps=10, codec="h264")

            # Navigate with extended timeout for Tor latency
            await self._navigate_with_retry(page, url)

            # Handle CAPTCHA challenges (DDOS-Guard, custom captchas)
            if solve_captcha:
                await self._handle_captcha(page)

            # Wait for dynamic content to load
            await page.wait_for_network_idle(idle_time=2000, timeout=30000)

            # Extract page metadata
            title = await page.get_title()
            current_url = await page.get_current_url()

            # Extract content in requested formats
            text_content: str | None = None
            markdown_content: str | None = None
            html_content: str | None = None

            if ContentFormat.TEXT in extract_formats:
                text_content = await page.extract_text()

            if ContentFormat.MARKDOWN in extract_formats:
                markdown_content = await page.get_markdown(
                    include_links=True,
                    include_images=False,
                    max_length=500000,
                )

            if ContentFormat.HTML in extract_formats:
                html_content = await page.get_html(clean_level="basic")

            # Capture evidence
            evidence: CrawlEvidence | None = None
            if capture_evidence:
                evidence = await self._capture_evidence(page, url, html_content)

            # AI analysis using Owl Browser's built-in VLM
            ai_analysis: AIAnalysis | None = None
            if self._enable_ai_analysis:
                ai_analysis = await self._perform_ai_analysis(page)

            # Stop video recording
            if self._enable_video and capture_evidence:
                video_path = await page.stop_video_recording()
                if evidence:
                    evidence.video_path = video_path

            return CrawlResult(
                url=current_url,
                status=CrawlStatus.SUCCESS,
                title=title,
                text_content=text_content,
                markdown_content=markdown_content,
                evidence=evidence,
                ai_analysis=ai_analysis,
            )

        finally:
            await page.close()

    async def _navigate_with_retry(
        self,
        page,
        url: str,
        max_retries: int = MAX_NAVIGATION_RETRIES,
    ) -> None:
        """Navigate to URL with retry logic for Tor-specific failures."""
        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=TOR_NAVIGATION_TIMEOUT,
                )
                return

            except Exception as e:
                error_str = str(e).lower()
                last_error = e

                # Check for circuit-level failures
                if any(pattern.lower() in error_str for pattern in CIRCUIT_FAILURE_PATTERNS):
                    raise CircuitFailureError(f"Circuit failure: {e}") from e

                # Retry on timeout
                if "timeout" in error_str:
                    logger.warning(
                        "Navigation timeout for %s (attempt %d/%d)",
                        url, attempt + 1, max_retries
                    )
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    continue

                # Don't retry other errors
                raise

        raise TorCrawlerError(f"Navigation failed after {max_retries} attempts: {last_error}")

    async def _handle_captcha(self, page) -> None:
        """
        Detect and solve CAPTCHA challenges common on dark web sites.

        Handles:
        - DDOS-Guard challenges
        - Simple text CAPTCHAs
        - Image selection CAPTCHAs
        """
        # Check for CAPTCHA presence
        captcha_detected = await page.detect_captcha()

        if not captcha_detected:
            return

        logger.info("CAPTCHA detected, attempting to solve...")

        # Classify the CAPTCHA type
        captcha_info = await page.classify_captcha()
        captcha_type = captcha_info.get("type", "unknown")

        logger.info("CAPTCHA type: %s", captcha_type)

        try:
            match captcha_type:
                case "text":
                    # Text-based CAPTCHA (common on dark web)
                    await page.solve_text_captcha(max_attempts=3)

                case "image" | "image_selection":
                    # Image selection CAPTCHA
                    await page.solve_image_captcha(max_attempts=3, provider="owl-vlm")

                case "ddos_guard" | "cloudflare" | "challenge":
                    # JavaScript challenge - wait for auto-solve
                    await page.solve_captcha(max_attempts=5, provider="owl-vlm")

                case _:
                    # Generic solver
                    await page.solve_captcha(max_attempts=3, provider="owl-vlm")

            # Verify CAPTCHA was solved by checking for redirect
            await page.wait_for_network_idle(idle_time=3000, timeout=30000)

            # Check if still on CAPTCHA page
            if await page.detect_captcha():
                raise CaptchaChallengeError("CAPTCHA still present after solving attempt")

            logger.info("CAPTCHA solved successfully")

        except Exception as e:
            raise CaptchaChallengeError(f"Failed to solve CAPTCHA: {e}") from e

    async def _capture_evidence(
        self,
        page,
        url: str,
        html_content: str | None,
    ) -> CrawlEvidence:
        """Capture forensic evidence of the page state."""
        # Generate unique evidence ID from URL and timestamp
        timestamp = datetime.now(timezone.utc).isoformat()
        evidence_id = hashlib.sha256(f"{url}:{timestamp}".encode()).hexdigest()[:16]

        # Capture full-page screenshot
        screenshot_path = f"{self._evidence_dir}/{evidence_id}_screenshot.png"
        await page.screenshot(path=screenshot_path, mode="fullpage")

        # Also get base64 for immediate processing
        screenshot_base64 = await page.screenshot(mode="fullpage")

        # Calculate content hash for tamper detection
        content_hash: str | None = None
        if html_content:
            content_hash = hashlib.sha256(html_content.encode()).hexdigest()

        return CrawlEvidence(
            screenshot_base64=screenshot_base64,
            screenshot_path=screenshot_path,
            html_content=html_content,
            content_hash=content_hash,
        )

    async def _perform_ai_analysis(self, page) -> AIAnalysis:
        """
        Use Owl Browser's built-in VLM for intelligent content analysis.

        Leverages:
        - page.query_page() for specific questions
        - page.summarize_page() for structured summaries
        - page.ai_extract() for entity extraction
        """
        # Get structured summary
        summary_data = await page.summarize_page(force_refresh=True)
        summary = summary_data.get("summary", "")

        # Extract threat-relevant entities
        entities_response = await page.query_page(
            "List all organization names, person names, email addresses, "
            "cryptocurrency addresses, and domain names mentioned on this page. "
            "Return as a comma-separated list."
        )
        detected_entities = [
            e.strip() for e in entities_response.split(",") if e.strip()
        ]

        # Identify threat indicators
        threat_response = await page.query_page(
            "Identify any indicators of illegal activity, data breaches, "
            "credential dumps, malware, or cybercrime on this page. "
            "List specific findings."
        )
        threat_indicators = [
            t.strip() for t in threat_response.split("\n") if t.strip()
        ]

        # Categorize content
        category_response = await page.query_page(
            "Classify this page into one category: "
            "marketplace, forum, paste_site, leak_site, ransomware, "
            "carding, drugs, weapons, hacking_services, legitimate, other"
        )

        return AIAnalysis(
            summary=summary,
            detected_entities=detected_entities,
            threat_indicators=threat_indicators,
            content_category=category_response.strip().lower(),
            confidence_score=0.85,  # Default confidence
        )


# Example usage
async def main() -> None:
    """Example: Crawl a single .onion site."""
    async with TorPoolManager(instance_count=5) as tor_pool:
        async with TorCrawler(tor_pool, enable_ai_analysis=True) as crawler:
            result = await crawler.crawl(
                "http://example.onion",
                extract_formats=[ContentFormat.TEXT, ContentFormat.MARKDOWN],
                capture_evidence=True,
            )

            if result.status == CrawlStatus.SUCCESS:
                print(f"Title: {result.title}")
                print(f"Content length: {len(result.text_content or '')}")
                if result.ai_analysis:
                    print(f"Category: {result.ai_analysis.content_category}")
                    print(f"Threats: {result.ai_analysis.threat_indicators}")
            else:
                print(f"Crawl failed: {result.status.name} - {result.error_message}")


if __name__ == "__main__":
    asyncio.run(main())
```

### 4.2. Batch Crawling with Concurrency Control

```python
"""
Batch crawler for processing multiple .onion URLs concurrently.
"""

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass

@dataclass
class BatchCrawlConfig:
    """Configuration for batch crawling operations."""
    max_concurrent: int = 10
    delay_between_requests: float = 1.0
    retry_failed: bool = True
    max_retries_per_url: int = 2


class BatchTorCrawler:
    """
    Batch crawler with controlled concurrency for large-scale operations.

    Uses semaphore-based rate limiting to prevent overwhelming Tor circuits.
    """

    def __init__(
        self,
        crawler: TorCrawler,
        config: BatchCrawlConfig | None = None,
    ) -> None:
        self._crawler = crawler
        self._config = config or BatchCrawlConfig()
        self._semaphore = asyncio.Semaphore(self._config.max_concurrent)
        self._results: list[CrawlResult] = []

    async def crawl_batch(
        self,
        urls: list[str],
    ) -> AsyncIterator[CrawlResult]:
        """
        Crawl multiple URLs with controlled concurrency.

        Yields results as they complete (not in order).
        """
        tasks: set[asyncio.Task[CrawlResult]] = set()

        for url in urls:
            # Wait for semaphore slot
            await self._semaphore.acquire()

            task = asyncio.create_task(
                self._crawl_with_release(url),
                name=f"crawl-{url[:50]}"
            )
            tasks.add(task)

            # Stagger requests to avoid burst patterns
            await asyncio.sleep(self._config.delay_between_requests)

        # Yield results as they complete
        while tasks:
            done, tasks = await asyncio.wait(
                tasks,
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                yield task.result()

    async def _crawl_with_release(self, url: str) -> CrawlResult:
        """Crawl a URL and release semaphore when done."""
        try:
            return await self._crawler.crawl(url)
        finally:
            self._semaphore.release()


# Example: Batch crawl with progress tracking
async def batch_crawl_example() -> None:
    urls = [
        "http://site1.onion",
        "http://site2.onion",
        # ... more URLs
    ]

    async with TorPoolManager(instance_count=10) as tor_pool:
        async with TorCrawler(tor_pool) as crawler:
            batch_crawler = BatchTorCrawler(
                crawler,
                config=BatchCrawlConfig(max_concurrent=5)
            )

            processed = 0
            async for result in batch_crawler.crawl_batch(urls):
                processed += 1
                print(f"[{processed}/{len(urls)}] {result.url}: {result.status.name}")
```

## 5. Intelligence Processing Engine

The Intelligence Processing Engine analyzes crawled content in real-time, detecting sensitive data patterns, extracting entities, and generating actionable alerts. This section provides complete implementations for pattern matching, NER, and deduplication.

### 5.1. Stream Processing Architecture

```python
"""
Intelligence Processing Engine - Real-time threat intelligence extraction.

Components:
- Redis Streams consumer for high-throughput processing
- Pattern matchers for credentials, secrets, and PII
- spaCy NER for entity extraction
- SimHash for content deduplication
- Alert generation with severity classification
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Final, Protocol, TypeAlias

import redis.asyncio as redis
import spacy
from simhash import Simhash

logger = logging.getLogger(__name__)

# Type aliases
PatternMatch: TypeAlias = dict[str, str | int | list[str]]


class AlertSeverity(Enum):
    """Alert severity levels aligned with CVSS."""
    CRITICAL = auto()  # Immediate action required
    HIGH = auto()      # Significant threat
    MEDIUM = auto()    # Moderate concern
    LOW = auto()       # Informational
    INFO = auto()      # Context only


class PatternCategory(Enum):
    """Categories of detected patterns."""
    CREDIT_CARD = "credit_card"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    CREDENTIAL = "credential"
    CRYPTO_WALLET = "crypto_wallet"
    PII = "pii"
    CUSTOM = "custom"


@dataclass
class DetectedPattern:
    """A single pattern match result."""
    category: PatternCategory
    pattern_name: str
    matched_value: str
    context: str  # Surrounding text
    line_number: int | None = None
    confidence: float = 1.0
    is_validated: bool = False


@dataclass
class ProcessingResult:
    """Complete processing result for a crawled page."""
    url: str
    patterns_detected: list[DetectedPattern] = field(default_factory=list)
    entities_extracted: dict[str, list[str]] = field(default_factory=dict)
    content_hash: str = ""
    simhash: int = 0
    is_duplicate: bool = False
    similar_urls: list[str] = field(default_factory=list)
    alerts_generated: list[Alert] = field(default_factory=list)
    processed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Alert:
    """Security alert for detected threat."""
    alert_id: str
    severity: AlertSeverity
    category: PatternCategory
    title: str
    description: str
    source_url: str
    matched_patterns: list[DetectedPattern]
    entities: dict[str, list[str]]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
```

### 5.2. Pattern Matchers with Validation

```python
"""
Comprehensive pattern matchers for sensitive data detection.
"""

class PatternMatcher(Protocol):
    """Protocol for pattern matcher implementations."""

    @property
    def category(self) -> PatternCategory: ...

    @property
    def pattern_name(self) -> str: ...

    def find_matches(self, text: str) -> list[DetectedPattern]: ...


class CreditCardMatcher:
    """
    Credit card number detection with Luhn algorithm validation.

    Detects:
    - Visa (4xxx)
    - Mastercard (51-55xx, 2221-2720)
    - American Express (34xx, 37xx)
    - Discover (6011, 65xx)
    """

    PATTERN: Final[re.Pattern[str]] = re.compile(
        r'\b(?:'
        r'4[0-9]{12}(?:[0-9]{3})?|'           # Visa
        r'(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|'  # Mastercard
        r'3[47][0-9]{13}|'                     # Amex
        r'6(?:011|5[0-9]{2})[0-9]{12}'         # Discover
        r')\b',
        re.MULTILINE
    )

    # Pattern with separators
    PATTERN_WITH_SEP: Final[re.Pattern[str]] = re.compile(
        r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        re.MULTILINE
    )

    @property
    def category(self) -> PatternCategory:
        return PatternCategory.CREDIT_CARD

    @property
    def pattern_name(self) -> str:
        return "credit_card_number"

    def find_matches(self, text: str) -> list[DetectedPattern]:
        matches: list[DetectedPattern] = []

        # Find all potential card numbers
        for pattern in [self.PATTERN, self.PATTERN_WITH_SEP]:
            for match in pattern.finditer(text):
                raw_value = match.group()
                # Normalize: remove spaces and dashes
                normalized = re.sub(r'[-\s]', '', raw_value)

                if self._luhn_check(normalized):
                    context = self._extract_context(text, match.start(), match.end())
                    card_type = self._identify_card_type(normalized)

                    matches.append(DetectedPattern(
                        category=self.category,
                        pattern_name=f"{card_type}_card",
                        matched_value=self._mask_card(normalized),
                        context=context,
                        confidence=0.95,
                        is_validated=True,
                    ))

        return matches

    @staticmethod
    def _luhn_check(card_number: str) -> bool:
        """Validate card number using Luhn algorithm."""
        if not card_number.isdigit():
            return False

        digits = [int(d) for d in card_number]
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]

        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(divmod(d * 2, 10))

        return checksum % 10 == 0

    @staticmethod
    def _identify_card_type(number: str) -> str:
        """Identify card type from number prefix."""
        if number.startswith('4'):
            return "visa"
        elif number.startswith(('51', '52', '53', '54', '55')) or \
             (2221 <= int(number[:4]) <= 2720):
            return "mastercard"
        elif number.startswith(('34', '37')):
            return "amex"
        elif number.startswith('6011') or number.startswith('65'):
            return "discover"
        return "unknown"

    @staticmethod
    def _mask_card(number: str) -> str:
        """Mask card number for safe logging."""
        return f"{number[:4]}{'*' * (len(number) - 8)}{number[-4:]}"

    @staticmethod
    def _extract_context(text: str, start: int, end: int, window: int = 50) -> str:
        """Extract surrounding context for the match."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        return text[ctx_start:ctx_end].strip()


class APIKeyMatcher:
    """
    Detect API keys and tokens from various services.

    Supported patterns:
    - AWS Access Keys (AKIA...)
    - AWS Secret Keys
    - Stripe API Keys (sk_live_, pk_live_)
    - GitHub Tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    - Slack Tokens (xoxb-, xoxp-, xoxa-)
    - Google API Keys
    - Generic Bearer Tokens
    """

    PATTERNS: Final[dict[str, re.Pattern[str]]] = {
        "aws_access_key": re.compile(
            r'\b(AKIA[0-9A-Z]{16})\b'
        ),
        "aws_secret_key": re.compile(
            r'(?:aws_secret_access_key|secret_access_key|aws_secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            re.IGNORECASE
        ),
        "stripe_live_key": re.compile(
            r'\b(sk_live_[0-9a-zA-Z]{24,})\b'
        ),
        "stripe_publishable_key": re.compile(
            r'\b(pk_live_[0-9a-zA-Z]{24,})\b'
        ),
        "github_token": re.compile(
            r'\b(gh[pousr]_[A-Za-z0-9_]{36,})\b'
        ),
        "github_oauth": re.compile(
            r'\b(gho_[A-Za-z0-9]{36})\b'
        ),
        "slack_token": re.compile(
            r'\b(xox[bpas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b'
        ),
        "google_api_key": re.compile(
            r'\b(AIza[0-9A-Za-z\-_]{35})\b'
        ),
        "generic_api_key": re.compile(
            r'(?:api_key|apikey|api-key|access_token)\s*[=:]\s*["\']?([a-zA-Z0-9]{32,64})["\']?',
            re.IGNORECASE
        ),
        "jwt_token": re.compile(
            r'\b(eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*)\b'
        ),
        "private_key_header": re.compile(
            r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'
        ),
    }

    @property
    def category(self) -> PatternCategory:
        return PatternCategory.API_KEY

    @property
    def pattern_name(self) -> str:
        return "api_key"

    def find_matches(self, text: str) -> list[DetectedPattern]:
        matches: list[DetectedPattern] = []

        for key_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                # Get the captured group or full match
                value = match.group(1) if match.lastindex else match.group()

                matches.append(DetectedPattern(
                    category=self.category,
                    pattern_name=key_type,
                    matched_value=self._redact_key(value, key_type),
                    context=self._extract_context(text, match.start(), match.end()),
                    confidence=0.90 if "generic" not in key_type else 0.70,
                    is_validated=True,
                ))

        return matches

    @staticmethod
    def _redact_key(value: str, key_type: str) -> str:
        """Redact sensitive portion of the key."""
        if key_type == "private_key_header":
            return value  # Just the header
        if len(value) <= 10:
            return value[:2] + "***"
        return f"{value[:8]}...{value[-4:]}"

    @staticmethod
    def _extract_context(text: str, start: int, end: int, window: int = 30) -> str:
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        return text[ctx_start:ctx_end].strip()


class CredentialMatcher:
    """
    Detect email:password and username:password credential pairs.
    """

    # Email:password patterns
    EMAIL_PASS_PATTERN: Final[re.Pattern[str]] = re.compile(
        r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*[:|]\s*(\S{6,})\b'
    )

    # Username:password in common formats
    USER_PASS_PATTERN: Final[re.Pattern[str]] = re.compile(
        r'^([a-zA-Z0-9_.-]{3,32})\s*[:|]\s*(\S{6,64})$',
        re.MULTILINE
    )

    # Hash patterns (MD5, SHA1, SHA256, bcrypt)
    HASH_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
        "md5": re.compile(r'\b([a-fA-F0-9]{32})\b'),
        "sha1": re.compile(r'\b([a-fA-F0-9]{40})\b'),
        "sha256": re.compile(r'\b([a-fA-F0-9]{64})\b'),
        "bcrypt": re.compile(r'(\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53})'),
    }

    @property
    def category(self) -> PatternCategory:
        return PatternCategory.CREDENTIAL

    @property
    def pattern_name(self) -> str:
        return "credential_pair"

    def find_matches(self, text: str) -> list[DetectedPattern]:
        matches: list[DetectedPattern] = []

        # Email:password pairs
        for match in self.EMAIL_PASS_PATTERN.finditer(text):
            email, password = match.groups()
            matches.append(DetectedPattern(
                category=self.category,
                pattern_name="email_password",
                matched_value=f"{email}:{self._mask_password(password)}",
                context=self._extract_context(text, match.start(), match.end()),
                confidence=0.95,
                is_validated=True,
            ))

        # Username:password pairs
        for match in self.USER_PASS_PATTERN.finditer(text):
            username, password = match.groups()
            # Skip if it looks like a hash
            if not self._is_likely_hash(password):
                matches.append(DetectedPattern(
                    category=self.category,
                    pattern_name="username_password",
                    matched_value=f"{username}:{self._mask_password(password)}",
                    context=self._extract_context(text, match.start(), match.end()),
                    confidence=0.80,
                    is_validated=True,
                ))

        return matches

    @staticmethod
    def _mask_password(password: str) -> str:
        """Mask password for safe storage."""
        if len(password) <= 4:
            return "****"
        return f"{password[0]}{'*' * (len(password) - 2)}{password[-1]}"

    def _is_likely_hash(self, value: str) -> bool:
        """Check if value looks like a password hash."""
        for pattern in self.HASH_PATTERNS.values():
            if pattern.fullmatch(value):
                return True
        return False

    @staticmethod
    def _extract_context(text: str, start: int, end: int, window: int = 20) -> str:
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        return text[ctx_start:ctx_end].strip()


class CryptoWalletMatcher:
    """
    Detect cryptocurrency wallet addresses.

    Supported:
    - Bitcoin (1..., 3..., bc1...)
    - Ethereum (0x...)
    - Monero (4...)
    - Litecoin (L..., M..., ltc1...)
    """

    PATTERNS: Final[dict[str, re.Pattern[str]]] = {
        "bitcoin_legacy": re.compile(r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34})\b'),
        "bitcoin_segwit": re.compile(r'\b(3[a-km-zA-HJ-NP-Z1-9]{25,34})\b'),
        "bitcoin_bech32": re.compile(r'\b(bc1[a-z0-9]{39,59})\b'),
        "ethereum": re.compile(r'\b(0x[a-fA-F0-9]{40})\b'),
        "monero": re.compile(r'\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b'),
        "litecoin_legacy": re.compile(r'\b([LM][a-km-zA-HJ-NP-Z1-9]{26,33})\b'),
        "litecoin_bech32": re.compile(r'\b(ltc1[a-z0-9]{39,59})\b'),
    }

    @property
    def category(self) -> PatternCategory:
        return PatternCategory.CRYPTO_WALLET

    @property
    def pattern_name(self) -> str:
        return "crypto_wallet"

    def find_matches(self, text: str) -> list[DetectedPattern]:
        matches: list[DetectedPattern] = []

        for wallet_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                address = match.group(1)
                matches.append(DetectedPattern(
                    category=self.category,
                    pattern_name=wallet_type,
                    matched_value=address,
                    context=self._extract_context(text, match.start(), match.end()),
                    confidence=0.85,
                    is_validated=False,  # Would need blockchain validation
                ))

        return matches

    @staticmethod
    def _extract_context(text: str, start: int, end: int, window: int = 30) -> str:
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        return text[ctx_start:ctx_end].strip()
```

### 5.3. Named Entity Recognition (NER)

```python
"""
Named Entity Recognition using spaCy for threat intelligence extraction.
"""

class EntityExtractor:
    """
    Extract named entities relevant to threat intelligence.

    Uses spaCy's transformer-based model for high accuracy on:
    - Organizations (ORG) - Company names, threat groups
    - Persons (PERSON) - Threat actors, victims
    - Locations (GPE, LOC) - Geographic context
    - Products (PRODUCT) - Software, hardware targets
    """

    def __init__(self, model_name: str = "en_core_web_trf") -> None:
        """
        Initialize with spaCy model.

        Args:
            model_name: spaCy model to use. Options:
                - en_core_web_trf: Transformer (highest accuracy, slower)
                - en_core_web_lg: Large (good balance)
                - en_core_web_sm: Small (fastest, lower accuracy)
        """
        self._nlp = spacy.load(model_name)

        # Disable unused pipeline components for performance
        self._nlp.disable_pipes("tagger", "parser", "attribute_ruler", "lemmatizer")

    def extract_entities(
        self,
        text: str,
        entity_types: list[str] | None = None,
    ) -> dict[str, list[str]]:
        """
        Extract named entities from text.

        Args:
            text: Input text to analyze
            entity_types: Entity types to extract (default: ORG, PERSON, GPE)

        Returns:
            Dictionary mapping entity types to lists of unique entities
        """
        if entity_types is None:
            entity_types = ["ORG", "PERSON", "GPE", "PRODUCT"]

        # Process text (handle large documents in chunks)
        doc = self._nlp(text[:1_000_000])  # Limit to 1M chars

        entities: dict[str, set[str]] = {etype: set() for etype in entity_types}

        for ent in doc.ents:
            if ent.label_ in entity_types:
                # Normalize entity text
                normalized = ent.text.strip()
                if len(normalized) >= 2:  # Skip single chars
                    entities[ent.label_].add(normalized)

        # Convert sets to sorted lists
        return {k: sorted(v) for k, v in entities.items()}

    def extract_with_context(
        self,
        text: str,
        entity_types: list[str] | None = None,
        context_window: int = 50,
    ) -> list[dict[str, str]]:
        """
        Extract entities with surrounding context.

        Returns list of dicts with entity, type, and context.
        """
        if entity_types is None:
            entity_types = ["ORG", "PERSON"]

        doc = self._nlp(text[:1_000_000])
        results: list[dict[str, str]] = []

        for ent in doc.ents:
            if ent.label_ in entity_types:
                # Extract context
                start = max(0, ent.start_char - context_window)
                end = min(len(text), ent.end_char + context_window)
                context = text[start:end].strip()

                results.append({
                    "entity": ent.text,
                    "type": ent.label_,
                    "context": context,
                })

        return results
```

### 5.4. Content Deduplication with SimHash

```python
"""
SimHash-based near-duplicate detection for dark web content.
"""

class ContentDeduplicator:
    """
    Detect near-duplicate content using SimHash.

    SimHash creates locality-sensitive hashes where similar documents
    produce similar hashes. This allows efficient detection of mirrors
    and slightly modified copies of the same content.
    """

    def __init__(
        self,
        similarity_threshold: int = 3,  # Max Hamming distance for duplicates
        hash_bits: int = 64,
    ) -> None:
        self._threshold = similarity_threshold
        self._hash_bits = hash_bits
        self._known_hashes: dict[int, list[str]] = {}  # hash -> [urls]

    def compute_simhash(self, text: str) -> int:
        """Compute SimHash for text content."""
        # Tokenize into shingles (3-grams)
        tokens = self._get_shingles(text, n=3)

        if not tokens:
            return 0

        return Simhash(tokens, f=self._hash_bits).value

    def is_duplicate(self, text: str, source_url: str) -> tuple[bool, list[str]]:
        """
        Check if content is a near-duplicate of known content.

        Returns:
            Tuple of (is_duplicate, list of similar URLs)
        """
        content_hash = self.compute_simhash(text)

        if content_hash == 0:
            return False, []

        similar_urls: list[str] = []

        # Check against known hashes
        for known_hash, urls in self._known_hashes.items():
            distance = self._hamming_distance(content_hash, known_hash)
            if distance <= self._threshold:
                similar_urls.extend(urls)

        # Store this hash
        if content_hash not in self._known_hashes:
            self._known_hashes[content_hash] = []
        self._known_hashes[content_hash].append(source_url)

        is_dup = len(similar_urls) > 0
        return is_dup, similar_urls

    @staticmethod
    def _get_shingles(text: str, n: int = 3) -> list[str]:
        """Generate n-gram shingles from text."""
        # Normalize text
        text = text.lower()
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'[^\w\s]', '', text)

        words = text.split()
        if len(words) < n:
            return words

        return [' '.join(words[i:i+n]) for i in range(len(words) - n + 1)]

    @staticmethod
    def _hamming_distance(hash1: int, hash2: int) -> int:
        """Calculate Hamming distance between two hashes."""
        xor = hash1 ^ hash2
        return bin(xor).count('1')

    def get_stats(self) -> dict[str, int]:
        """Return deduplication statistics."""
        total_urls = sum(len(urls) for urls in self._known_hashes.values())
        unique_hashes = len(self._known_hashes)

        return {
            "total_urls_processed": total_urls,
            "unique_content_hashes": unique_hashes,
            "duplicate_rate": (total_urls - unique_hashes) / max(total_urls, 1),
        }
```

### 5.5. Integrated Processing Pipeline

```python
"""
Complete processing pipeline integrating all components.
"""

class IntelligenceProcessor:
    """
    Main processing pipeline for threat intelligence extraction.

    Orchestrates:
    - Pattern matching (credentials, API keys, etc.)
    - Entity extraction (organizations, persons)
    - Deduplication
    - Alert generation
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        alert_threshold: AlertSeverity = AlertSeverity.MEDIUM,
    ) -> None:
        self._redis = redis.from_url(redis_url)
        self._alert_threshold = alert_threshold

        # Initialize components
        self._matchers: list[PatternMatcher] = [
            CreditCardMatcher(),
            APIKeyMatcher(),
            CredentialMatcher(),
            CryptoWalletMatcher(),
        ]
        self._entity_extractor = EntityExtractor()
        self._deduplicator = ContentDeduplicator()

    async def process(self, crawl_result: CrawlResult) -> ProcessingResult:
        """
        Process a crawl result through the intelligence pipeline.

        Args:
            crawl_result: Result from TorCrawler

        Returns:
            ProcessingResult with all detected patterns and entities
        """
        text_content = crawl_result.text_content or ""

        # Deduplication check
        is_duplicate, similar_urls = self._deduplicator.is_duplicate(
            text_content,
            crawl_result.url,
        )

        if is_duplicate:
            logger.info("Duplicate content detected for %s", crawl_result.url)
            return ProcessingResult(
                url=crawl_result.url,
                is_duplicate=True,
                similar_urls=similar_urls,
                simhash=self._deduplicator.compute_simhash(text_content),
            )

        # Pattern matching
        all_patterns: list[DetectedPattern] = []
        for matcher in self._matchers:
            patterns = matcher.find_matches(text_content)
            all_patterns.extend(patterns)

        # Entity extraction
        entities = self._entity_extractor.extract_entities(text_content)

        # Content hash for evidence integrity
        content_hash = hashlib.sha256(text_content.encode()).hexdigest()

        # Generate alerts
        alerts = self._generate_alerts(crawl_result.url, all_patterns, entities)

        result = ProcessingResult(
            url=crawl_result.url,
            patterns_detected=all_patterns,
            entities_extracted=entities,
            content_hash=content_hash,
            simhash=self._deduplicator.compute_simhash(text_content),
            is_duplicate=False,
            alerts_generated=alerts,
        )

        # Publish alerts to Redis
        for alert in alerts:
            await self._publish_alert(alert)

        return result

    def _generate_alerts(
        self,
        url: str,
        patterns: list[DetectedPattern],
        entities: dict[str, list[str]],
    ) -> list[Alert]:
        """Generate alerts based on detected patterns."""
        alerts: list[Alert] = []

        # Group patterns by category
        by_category: dict[PatternCategory, list[DetectedPattern]] = {}
        for pattern in patterns:
            if pattern.category not in by_category:
                by_category[pattern.category] = []
            by_category[pattern.category].append(pattern)

        # Create alerts for each category with significant findings
        for category, category_patterns in by_category.items():
            severity = self._determine_severity(category, len(category_patterns))

            if severity.value <= self._alert_threshold.value:
                alert = Alert(
                    alert_id=hashlib.sha256(
                        f"{url}:{category.value}:{datetime.now(timezone.utc).isoformat()}".encode()
                    ).hexdigest()[:16],
                    severity=severity,
                    category=category,
                    title=f"{category.value.upper()} detected on dark web",
                    description=f"Found {len(category_patterns)} {category.value} patterns",
                    source_url=url,
                    matched_patterns=category_patterns,
                    entities=entities,
                )
                alerts.append(alert)

        return alerts

    @staticmethod
    def _determine_severity(
        category: PatternCategory,
        count: int,
    ) -> AlertSeverity:
        """Determine alert severity based on pattern category and count."""
        severity_map: dict[PatternCategory, AlertSeverity] = {
            PatternCategory.PRIVATE_KEY: AlertSeverity.CRITICAL,
            PatternCategory.API_KEY: AlertSeverity.HIGH,
            PatternCategory.CREDENTIAL: AlertSeverity.HIGH,
            PatternCategory.CREDIT_CARD: AlertSeverity.CRITICAL,
            PatternCategory.CRYPTO_WALLET: AlertSeverity.MEDIUM,
            PatternCategory.PII: AlertSeverity.MEDIUM,
        }

        base_severity = severity_map.get(category, AlertSeverity.LOW)

        # Escalate based on volume
        if count > 100:
            if base_severity == AlertSeverity.HIGH:
                return AlertSeverity.CRITICAL
            elif base_severity == AlertSeverity.MEDIUM:
                return AlertSeverity.HIGH

        return base_severity

    async def _publish_alert(self, alert: Alert) -> None:
        """Publish alert to Redis stream for downstream consumers."""
        await self._redis.xadd(
            "darkwatch:alerts",
            {
                "alert_id": alert.alert_id,
                "severity": alert.severity.name,
                "category": alert.category.value,
                "title": alert.title,
                "source_url": alert.source_url,
                "created_at": alert.created_at.isoformat(),
            },
            maxlen=100000,
        )
```

## 6. Forum and Marketplace Crawling

Dark web forums and marketplaces require authenticated access with persistent sessions. This section covers login automation, session management, and content extraction patterns.

### 6.1. Authenticated Crawler Implementation

```python
"""
Forum and Marketplace Crawler with authentication support.

Features:
- Login flow automation with CAPTCHA solving
- Session persistence using browser profiles
- 2FA/TOTP handling
- Pagination and infinite scroll handling
- User/seller profile extraction
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

import pyotp
from owl_browser import AsyncBrowser, RemoteConfig, ProxyConfig, AsyncPage

logger = logging.getLogger(__name__)

# Forum-specific timeouts (even higher due to authentication complexity)
LOGIN_TIMEOUT: Final[int] = 180_000  # 3 minutes for full login flow
PAGE_LOAD_TIMEOUT: Final[int] = 120_000  # 2 minutes


@dataclass
class ForumCredentials:
    """Credentials for forum authentication."""
    username: str
    password: str
    totp_secret: str | None = None  # Base32 encoded TOTP secret
    backup_codes: list[str] = field(default_factory=list)
    pgp_private_key: str | None = None  # For PGP-based auth


@dataclass
class ForumProfile:
    """Stored session profile for a forum."""
    forum_id: str
    profile_path: str
    last_login: datetime
    cookies_valid_until: datetime | None = None
    login_count: int = 0


@dataclass
class UserProfile:
    """Extracted user/seller profile from a forum."""
    username: str
    user_id: str | None = None
    registration_date: str | None = None
    reputation_score: float | None = None
    total_posts: int = 0
    total_sales: int = 0
    pgp_public_key: str | None = None
    contact_methods: dict[str, str] = field(default_factory=dict)
    raw_html: str | None = None


class ForumCrawler:
    """
    Specialized crawler for authenticated forum access.

    Handles the complete authentication lifecycle including:
    - Initial login with CAPTCHA solving
    - Session persistence via browser profiles
    - Automatic session refresh
    - 2FA/TOTP code generation
    """

    def __init__(
        self,
        browser: AsyncBrowser,
        tor_pool: TorPoolManager,
        profiles_dir: str = "/data/profiles",
    ) -> None:
        self._browser = browser
        self._tor_pool = tor_pool
        self._profiles_dir = Path(profiles_dir)
        self._profiles_dir.mkdir(parents=True, exist_ok=True)
        self._active_sessions: dict[str, ForumProfile] = {}

    async def login(
        self,
        forum_id: str,
        login_url: str,
        credentials: ForumCredentials,
        selectors: ForumSelectors,
    ) -> bool:
        """
        Perform full login flow for a forum.

        Args:
            forum_id: Unique identifier for the forum
            login_url: URL of the login page
            credentials: Authentication credentials
            selectors: CSS/NL selectors for form elements

        Returns:
            True if login successful, False otherwise
        """
        tor_instance = await self._tor_pool.get_healthy_instance()
        proxy_config = ProxyConfig(
            type="socks5",
            host=tor_instance.socks_host,
            port=tor_instance.socks_port,
        )

        # Check for existing valid session
        profile_path = self._profiles_dir / f"{forum_id}.profile"
        if profile_path.exists():
            logger.info("Loading existing profile for %s", forum_id)
            page = await self._browser.new_page(
                proxy=proxy_config,
                profile_path=str(profile_path),
                stealth=True,
                timezone_override="UTC",
            )

            try:
                # Test if session is still valid
                await page.goto(login_url, timeout=PAGE_LOAD_TIMEOUT)
                if await self._is_logged_in(page, selectors):
                    logger.info("Existing session valid for %s", forum_id)
                    await page.close()
                    return True
            except Exception as e:
                logger.warning("Session validation failed: %s", e)
            finally:
                await page.close()

        # Perform fresh login
        page = await self._browser.new_page(
            proxy=proxy_config,
            stealth=True,
            timezone_override="UTC",
        )

        try:
            logger.info("Performing fresh login to %s", forum_id)

            # Navigate to login page
            await page.goto(login_url, timeout=PAGE_LOAD_TIMEOUT)

            # Handle pre-login CAPTCHA if present
            if await page.detect_captcha():
                logger.info("Solving pre-login CAPTCHA")
                await page.solve_captcha(max_attempts=5)

            # Fill username
            await page.type(selectors.username_field, credentials.username)
            await asyncio.sleep(0.5)  # Human-like delay

            # Fill password
            await page.type(selectors.password_field, credentials.password)
            await asyncio.sleep(0.3)

            # Handle CAPTCHA on login form if present
            if await page.detect_captcha():
                logger.info("Solving login form CAPTCHA")
                await page.solve_captcha(max_attempts=3)

            # Submit login
            await page.click(selectors.submit_button)

            # Wait for navigation
            await page.wait_for_network_idle(idle_time=3000, timeout=30000)

            # Handle 2FA if required
            if credentials.totp_secret and await self._is_2fa_page(page, selectors):
                await self._handle_2fa(page, credentials, selectors)

            # Verify login success
            if await self._is_logged_in(page, selectors):
                # Save session profile
                await page.save_profile(str(profile_path))

                self._active_sessions[forum_id] = ForumProfile(
                    forum_id=forum_id,
                    profile_path=str(profile_path),
                    last_login=datetime.now(timezone.utc),
                    login_count=1,
                )

                logger.info("Login successful for %s", forum_id)
                return True
            else:
                logger.error("Login failed for %s - not logged in after submit", forum_id)
                return False

        except Exception as e:
            logger.error("Login error for %s: %s", forum_id, e, exc_info=True)
            return False

        finally:
            await page.close()

    async def _handle_2fa(
        self,
        page,
        credentials: ForumCredentials,
        selectors: ForumSelectors,
    ) -> None:
        """Handle 2FA/TOTP challenge."""
        if not credentials.totp_secret:
            raise ValueError("2FA required but no TOTP secret provided")

        logger.info("Handling 2FA challenge")

        # Generate TOTP code
        totp = pyotp.TOTP(credentials.totp_secret)
        code = totp.now()

        # Enter code
        await page.type(selectors.totp_field, code)
        await asyncio.sleep(0.3)

        # Submit
        await page.click(selectors.totp_submit)
        await page.wait_for_network_idle(idle_time=2000, timeout=30000)

    async def _is_logged_in(self, page, selectors: ForumSelectors) -> bool:
        """Check if currently logged in."""
        try:
            # Look for logout link or user menu
            if selectors.logged_in_indicator:
                await page.wait_for_selector(
                    selectors.logged_in_indicator,
                    timeout=5000
                )
                return True
        except Exception:
            pass
        return False

    async def _is_2fa_page(self, page, selectors: ForumSelectors) -> bool:
        """Check if on 2FA input page."""
        try:
            if selectors.totp_field:
                await page.wait_for_selector(selectors.totp_field, timeout=3000)
                return True
        except Exception:
            pass
        return False

    async def crawl_with_session(
        self,
        forum_id: str,
        url: str,
    ) -> CrawlResult:
        """
        Crawl a URL using an authenticated session.

        Requires prior successful login.
        """
        if forum_id not in self._active_sessions:
            raise ValueError(f"No active session for {forum_id}")

        profile = self._active_sessions[forum_id]
        tor_instance = await self._tor_pool.get_healthy_instance()

        page = await self._browser.new_page(
            proxy=ProxyConfig(
                type="socks5",
                host=tor_instance.socks_host,
                port=tor_instance.socks_port,
            ),
            profile_path=profile.profile_path,
            stealth=True,
            timezone_override="UTC",
        )

        try:
            await page.goto(url, timeout=PAGE_LOAD_TIMEOUT)
            await page.wait_for_network_idle(idle_time=2000, timeout=30000)

            # Extract content
            text_content = await page.extract_text()
            html_content = await page.get_html(clean_level="basic")
            screenshot = await page.screenshot(mode="fullpage")

            # Update profile with fresh cookies
            await page.save_profile(profile.profile_path)

            return CrawlResult(
                url=url,
                status=CrawlStatus.SUCCESS,
                title=await page.get_title(),
                text_content=text_content,
                evidence=CrawlEvidence(
                    screenshot_base64=screenshot,
                    html_content=html_content,
                ),
            )

        finally:
            await page.close()

    async def extract_user_profile(
        self,
        forum_id: str,
        profile_url: str,
    ) -> UserProfile:
        """
        Extract detailed user/seller profile information.

        Uses AI extraction for unstructured profile pages.
        """
        result = await self.crawl_with_session(forum_id, profile_url)

        if result.status != CrawlStatus.SUCCESS:
            raise TorCrawlerError(f"Failed to load profile: {result.error_message}")

        # Use AI to extract structured data
        page = await self._get_page_for_analysis(forum_id, profile_url)

        try:
            # Extract using natural language queries
            username = await page.ai_extract("the username or handle of this user")
            reputation = await page.query_page(
                "What is the reputation score or feedback rating? Return just the number."
            )
            registration = await page.ai_extract("when did this user register or join")
            pgp_key = await page.ai_extract(
                "the PGP public key if displayed, or 'none' if not present"
            )

            return UserProfile(
                username=username,
                reputation_score=self._parse_reputation(reputation),
                registration_date=registration,
                pgp_public_key=pgp_key if pgp_key != "none" else None,
                raw_html=result.evidence.html_content if result.evidence else None,
            )

        finally:
            await page.close()

    @staticmethod
    def _parse_reputation(rep_str: str) -> float | None:
        """Parse reputation score from string."""
        import re
        match = re.search(r'[\d.]+', rep_str)
        if match:
            try:
                return float(match.group())
            except ValueError:
                pass
        return None


@dataclass
class ForumSelectors:
    """Selectors for forum authentication elements."""
    username_field: str = "username input"
    password_field: str = "password input"
    submit_button: str = "login button"
    totp_field: str | None = "2fa code input"
    totp_submit: str | None = "verify button"
    logged_in_indicator: str | None = "logout link"
    captcha_image: str | None = None
```

### 6.2. Pagination and Infinite Scroll Handling

```python
"""
Pagination handling for forum thread and listing pages.
"""

class PaginatedCrawler:
    """
    Handle pagination patterns common on dark web forums.

    Supports:
    - Traditional numbered pagination
    - "Load more" buttons
    - Infinite scroll
    """

    def __init__(self, forum_crawler: ForumCrawler) -> None:
        self._crawler = forum_crawler

    async def crawl_all_pages(
        self,
        forum_id: str,
        start_url: str,
        max_pages: int = 50,
        pagination_type: str = "numbered",
    ) -> AsyncIterator[CrawlResult]:
        """
        Crawl through all pages of a paginated listing.

        Args:
            forum_id: Forum identifier
            start_url: First page URL
            max_pages: Maximum pages to crawl
            pagination_type: "numbered", "load_more", or "infinite_scroll"
        """
        if pagination_type == "infinite_scroll":
            async for result in self._crawl_infinite_scroll(forum_id, start_url, max_pages):
                yield result
        else:
            async for result in self._crawl_numbered_pages(forum_id, start_url, max_pages):
                yield result

    async def _crawl_numbered_pages(
        self,
        forum_id: str,
        start_url: str,
        max_pages: int,
    ) -> AsyncIterator[CrawlResult]:
        """Crawl traditional numbered pagination."""
        current_url = start_url
        pages_crawled = 0

        while current_url and pages_crawled < max_pages:
            result = await self._crawler.crawl_with_session(forum_id, current_url)
            yield result

            pages_crawled += 1

            # Find next page link using AI
            page = await self._crawler._get_page_for_analysis(forum_id, current_url)
            try:
                next_link = await page.query_page(
                    "What is the URL of the 'next page' or 'page " +
                    str(pages_crawled + 1) + "' link? Return only the URL or 'none'."
                )
                if next_link and next_link.lower() != "none":
                    current_url = next_link
                else:
                    break
            finally:
                await page.close()

    async def _crawl_infinite_scroll(
        self,
        forum_id: str,
        url: str,
        max_scrolls: int,
    ) -> AsyncIterator[CrawlResult]:
        """Handle infinite scroll pages."""
        profile = self._crawler._active_sessions[forum_id]
        tor_instance = await self._crawler._tor_pool.get_healthy_instance()

        page = await self._crawler._browser.new_page(
            proxy=ProxyConfig(
                type="socks5",
                host=tor_instance.socks_host,
                port=tor_instance.socks_port,
            ),
            profile_path=profile.profile_path,
            stealth=True,
            timezone_override="UTC",
        )

        try:
            await page.goto(url, timeout=PAGE_LOAD_TIMEOUT)
            await page.wait_for_network_idle(idle_time=2000, timeout=30000)

            previous_height = 0
            scroll_count = 0

            while scroll_count < max_scrolls:
                # Scroll to bottom
                await page.scroll_to_bottom()
                await page.wait_for_network_idle(idle_time=3000, timeout=30000)

                # Check if new content loaded
                current_height = await page.expression(
                    "document.body.scrollHeight"
                )

                if current_height == previous_height:
                    # No new content, we've reached the end
                    break

                previous_height = current_height
                scroll_count += 1

                # Yield intermediate result
                yield CrawlResult(
                    url=f"{url}#scroll_{scroll_count}",
                    status=CrawlStatus.SUCCESS,
                    text_content=await page.extract_text(),
                )

            # Final full page capture
            yield CrawlResult(
                url=url,
                status=CrawlStatus.SUCCESS,
                title=await page.get_title(),
                text_content=await page.extract_text(),
                evidence=CrawlEvidence(
                    screenshot_base64=await page.screenshot(mode="fullpage"),
                    html_content=await page.get_html(clean_level="basic"),
                ),
            )

        finally:
            await page.close()
```

## 7. Evidence Storage and Chain of Custody

Forensic evidence must be preserved with cryptographic integrity guarantees. This section covers secure evidence storage, tamper detection, and database schemas.

### 7.1. Evidence Storage Implementation

```python
"""
Evidence storage with cryptographic chain of custody.

Features:
- AES-256-GCM encryption for evidence files
- SHA-256 hash chain for tamper detection
- Metadata preservation
- S3-compatible storage backend
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import aioboto3

logger = logging.getLogger(__name__)

# Evidence retention periods
RETENTION_HOT: Final[int] = 30  # Days in hot storage
RETENTION_WARM: Final[int] = 365  # Days in warm storage
RETENTION_COLD: Final[int] = 2555  # 7 years in cold storage


@dataclass
class EvidenceMetadata:
    """Metadata for stored evidence."""
    evidence_id: str
    source_url: str
    capture_timestamp: datetime
    content_type: str  # screenshot, html, video
    file_size_bytes: int
    content_hash_sha256: str
    previous_hash: str | None  # For hash chain
    encryption_nonce: str  # Base64 encoded
    storage_path: str
    collector_id: str
    chain_of_custody: list[dict[str, str]] = field(default_factory=list)


class EvidenceStore:
    """
    Secure evidence storage with chain of custody.

    All evidence is:
    1. Hashed before encryption (content integrity)
    2. Encrypted with AES-256-GCM
    3. Linked to previous evidence via hash chain
    4. Stored in S3-compatible storage with versioning
    """

    def __init__(
        self,
        encryption_key: bytes,  # 32 bytes for AES-256
        s3_endpoint: str = "http://minio:9000",
        s3_bucket: str = "darkwatch-evidence",
        s3_access_key: str | None = None,
        s3_secret_key: str | None = None,
    ) -> None:
        if len(encryption_key) != 32:
            raise ValueError("Encryption key must be 32 bytes for AES-256")

        self._cipher = AESGCM(encryption_key)
        self._s3_endpoint = s3_endpoint
        self._s3_bucket = s3_bucket
        self._s3_access_key = s3_access_key or os.environ.get("AWS_ACCESS_KEY_ID")
        self._s3_secret_key = s3_secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
        self._last_hash: str | None = None

    async def store_evidence(
        self,
        evidence_id: str,
        content: bytes,
        source_url: str,
        content_type: str,
        collector_id: str,
    ) -> EvidenceMetadata:
        """
        Store evidence with encryption and chain of custody.

        Args:
            evidence_id: Unique identifier for this evidence
            content: Raw evidence bytes (screenshot, HTML, etc.)
            source_url: URL where evidence was captured
            content_type: Type of evidence (screenshot, html, video)
            collector_id: Identifier of the collection system

        Returns:
            EvidenceMetadata with storage details
        """
        capture_time = datetime.now(timezone.utc)

        # Calculate content hash BEFORE encryption
        content_hash = hashlib.sha256(content).hexdigest()

        # Generate random nonce for AES-GCM
        nonce = os.urandom(12)

        # Encrypt content
        encrypted = self._cipher.encrypt(nonce, content, None)

        # Build hash chain
        chain_input = f"{content_hash}:{self._last_hash or 'genesis'}"
        chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()

        # Storage path with date partitioning
        date_path = capture_time.strftime("%Y/%m/%d")
        storage_path = f"{date_path}/{evidence_id}"

        # Store in S3
        async with aioboto3.Session().client(
            "s3",
            endpoint_url=self._s3_endpoint,
            aws_access_key_id=self._s3_access_key,
            aws_secret_access_key=self._s3_secret_key,
        ) as s3:
            await s3.put_object(
                Bucket=self._s3_bucket,
                Key=storage_path,
                Body=encrypted,
                ContentType="application/octet-stream",
                Metadata={
                    "evidence-id": evidence_id,
                    "content-hash": content_hash,
                    "chain-hash": chain_hash,
                    "source-url": source_url,
                    "capture-time": capture_time.isoformat(),
                },
            )

        # Update chain
        self._last_hash = chain_hash

        metadata = EvidenceMetadata(
            evidence_id=evidence_id,
            source_url=source_url,
            capture_timestamp=capture_time,
            content_type=content_type,
            file_size_bytes=len(content),
            content_hash_sha256=content_hash,
            previous_hash=self._last_hash,
            encryption_nonce=base64.b64encode(nonce).decode(),
            storage_path=storage_path,
            collector_id=collector_id,
            chain_of_custody=[
                {
                    "action": "captured",
                    "timestamp": capture_time.isoformat(),
                    "actor": collector_id,
                    "hash": chain_hash,
                }
            ],
        )

        return metadata

    async def retrieve_evidence(
        self,
        metadata: EvidenceMetadata,
    ) -> bytes:
        """
        Retrieve and decrypt evidence with integrity verification.

        Raises:
            ValueError: If content hash doesn't match (tampered)
        """
        async with aioboto3.Session().client(
            "s3",
            endpoint_url=self._s3_endpoint,
            aws_access_key_id=self._s3_access_key,
            aws_secret_access_key=self._s3_secret_key,
        ) as s3:
            response = await s3.get_object(
                Bucket=self._s3_bucket,
                Key=metadata.storage_path,
            )
            encrypted = await response["Body"].read()

        # Decrypt
        nonce = base64.b64decode(metadata.encryption_nonce)
        content = self._cipher.decrypt(nonce, encrypted, None)

        # Verify integrity
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != metadata.content_hash_sha256:
            raise ValueError(
                f"Evidence integrity check failed! "
                f"Expected {metadata.content_hash_sha256}, got {actual_hash}"
            )

        # Log chain of custody access
        metadata.chain_of_custody.append({
            "action": "retrieved",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": "system",
            "verified_hash": actual_hash,
        })

        return content

    async def verify_chain(
        self,
        evidence_list: list[EvidenceMetadata],
    ) -> bool:
        """
        Verify the integrity of the hash chain.

        Returns True if chain is intact, False if tampered.
        """
        previous_hash: str | None = None

        for metadata in sorted(evidence_list, key=lambda x: x.capture_timestamp):
            # Recalculate chain hash
            chain_input = f"{metadata.content_hash_sha256}:{previous_hash or 'genesis'}"
            expected_chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()

            if metadata.previous_hash != previous_hash:
                logger.error(
                    "Chain broken at %s: previous_hash mismatch",
                    metadata.evidence_id
                )
                return False

            previous_hash = expected_chain_hash

        return True
```

### 7.2. PostgreSQL Schema for Alerts

```sql
-- PostgreSQL schema for DarkWatch alerts and intelligence

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Enum types
CREATE TYPE alert_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE pattern_category AS ENUM (
    'credit_card', 'api_key', 'private_key',
    'credential', 'crypto_wallet', 'pii', 'custom'
);
CREATE TYPE crawl_status AS ENUM (
    'success', 'captcha_failed', 'timeout',
    'circuit_failure', 'blocked', 'not_found', 'error'
);

-- Main alerts table
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(32) UNIQUE NOT NULL,
    severity alert_severity NOT NULL,
    category pattern_category NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    source_url TEXT NOT NULL,
    source_domain VARCHAR(255),
    matched_patterns JSONB NOT NULL DEFAULT '[]',
    entities JSONB NOT NULL DEFAULT '{}',
    evidence_id UUID REFERENCES evidence(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by VARCHAR(255),
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,

    -- Partitioning key
    created_date DATE GENERATED ALWAYS AS (DATE(created_at)) STORED
) PARTITION BY RANGE (created_date);

-- Create monthly partitions
CREATE TABLE alerts_2024_01 PARTITION OF alerts
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
CREATE TABLE alerts_2024_02 PARTITION OF alerts
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
-- Continue for each month...

-- Evidence metadata table
CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    evidence_id VARCHAR(64) UNIQUE NOT NULL,
    source_url TEXT NOT NULL,
    capture_timestamp TIMESTAMPTZ NOT NULL,
    content_type VARCHAR(50) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    content_hash_sha256 VARCHAR(64) NOT NULL,
    chain_hash VARCHAR(64),
    previous_hash VARCHAR(64),
    storage_path TEXT NOT NULL,
    collector_id VARCHAR(255) NOT NULL,
    chain_of_custody JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Crawl jobs table
CREATE TABLE crawl_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id VARCHAR(64) UNIQUE NOT NULL,
    target_url TEXT NOT NULL,
    status crawl_status NOT NULL DEFAULT 'success',
    tor_instance_id INTEGER,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    content_hash VARCHAR(64),
    simhash BIGINT,
    is_duplicate BOOLEAN DEFAULT FALSE,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Detected patterns table (for detailed analysis)
CREATE TABLE detected_patterns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id),
    category pattern_category NOT NULL,
    pattern_name VARCHAR(100) NOT NULL,
    matched_value_hash VARCHAR(64) NOT NULL,  -- Hashed for security
    context TEXT,
    confidence DECIMAL(3,2) NOT NULL,
    is_validated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Entity mentions table
CREATE TABLE entity_mentions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id),
    entity_type VARCHAR(50) NOT NULL,  -- ORG, PERSON, GPE, etc.
    entity_value TEXT NOT NULL,
    context TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Monitored keywords/assets
CREATE TABLE watch_list (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL,
    keyword TEXT NOT NULL,
    keyword_type VARCHAR(50) NOT NULL,  -- domain, email, brand, executive
    is_active BOOLEAN DEFAULT TRUE,
    alert_threshold alert_severity DEFAULT 'medium',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255)
);

-- Indexes for performance
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_category ON alerts(category);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX idx_alerts_source_domain ON alerts(source_domain);
CREATE INDEX idx_alerts_patterns ON alerts USING GIN(matched_patterns);
CREATE INDEX idx_alerts_entities ON alerts USING GIN(entities);

CREATE INDEX idx_evidence_source_url ON evidence(source_url);
CREATE INDEX idx_evidence_content_hash ON evidence(content_hash_sha256);
CREATE INDEX idx_evidence_capture ON evidence(capture_timestamp DESC);

CREATE INDEX idx_crawl_jobs_status ON crawl_jobs(status);
CREATE INDEX idx_crawl_jobs_started ON crawl_jobs(started_at DESC);
CREATE INDEX idx_crawl_jobs_simhash ON crawl_jobs(simhash);

CREATE INDEX idx_watch_list_keyword ON watch_list(keyword);
CREATE INDEX idx_watch_list_org ON watch_list(organization_id);
```

### 7.3. ClickHouse Schema for Analytics

```sql
-- ClickHouse schema for high-volume analytics

-- Crawl events (append-only, time-series)
CREATE TABLE crawl_events (
    event_id UUID,
    event_time DateTime64(3) DEFAULT now64(3),
    event_date Date DEFAULT toDate(event_time),

    -- Crawl details
    job_id String,
    target_url String,
    target_domain String,
    status Enum8(
        'success' = 1, 'captcha_failed' = 2, 'timeout' = 3,
        'circuit_failure' = 4, 'blocked' = 5, 'not_found' = 6, 'error' = 7
    ),

    -- Performance metrics
    duration_ms UInt32,
    tor_instance_id UInt16,
    content_size_bytes UInt32,

    -- Content analysis
    patterns_found UInt16,
    entities_found UInt16,
    is_duplicate UInt8,
    simhash UInt64,
    content_category LowCardinality(String),

    -- AI analysis
    threat_score Float32,

    -- Error tracking
    error_type LowCardinality(String),
    error_message String

) ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, target_domain, event_time)
TTL event_date + INTERVAL 2 YEAR;

-- Alert aggregations (materialized view)
CREATE MATERIALIZED VIEW alert_hourly_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, severity, category)
AS SELECT
    toStartOfHour(event_time) AS hour,
    status,
    count() AS total_crawls,
    countIf(patterns_found > 0) AS crawls_with_patterns,
    sum(patterns_found) AS total_patterns,
    avg(duration_ms) AS avg_duration_ms,
    quantile(0.95)(duration_ms) AS p95_duration_ms
FROM crawl_events
GROUP BY hour, status;

-- Domain statistics
CREATE MATERIALIZED VIEW domain_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, target_domain)
AS SELECT
    toDate(event_time) AS date,
    target_domain,
    count() AS crawl_count,
    countIf(status = 'success') AS success_count,
    countIf(is_duplicate = 1) AS duplicate_count,
    sum(patterns_found) AS total_patterns,
    avg(threat_score) AS avg_threat_score
FROM crawl_events
GROUP BY date, target_domain;

-- Pattern detection trends
CREATE TABLE pattern_detections (
    detection_time DateTime64(3) DEFAULT now64(3),
    detection_date Date DEFAULT toDate(detection_time),

    alert_id String,
    source_url String,
    source_domain String,

    category LowCardinality(String),
    pattern_name LowCardinality(String),
    confidence Float32,

    -- Denormalized for fast queries
    organization_id Nullable(UUID),
    matched_keyword Nullable(String)

) ENGINE = MergeTree()
PARTITION BY toYYYYMM(detection_date)
ORDER BY (detection_date, category, pattern_name, detection_time)
TTL detection_date + INTERVAL 3 YEAR;

-- Useful queries
-- Top threat actors by volume
-- SELECT
--     source_domain,
--     count() as detection_count,
--     uniq(category) as unique_categories
-- FROM pattern_detections
-- WHERE detection_date >= today() - 30
-- GROUP BY source_domain
-- ORDER BY detection_count DESC
-- LIMIT 20;
```

## 8. Security Infrastructure

Running a dark web scanner carries significant operational security (OpSec) risks. The infrastructure must be properly isolated and hardened.

### 8.1. Network Isolation Principles

*   **VPC Peering:** None. The crawler VPC should have NO peering connection to production VPCs.
*   **Egress Filtering:** Block all outbound traffic except port 9050 (Tor) and port 443 (S3/API).
*   **No Direct Internet:** All traffic must route through Tor. No clearnet access from crawler nodes.
*   **Separate AWS Account:** Use a dedicated AWS account with no cross-account roles to production.

### 8.2. Complete Docker Compose Deployment

```yaml
# docker-compose.yml - Full DarkWatch deployment
version: '3.8'

networks:
  # Isolated network for Tor traffic only
  tor-net:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.28.0.0/16

  # Management network for API/monitoring
  mgmt-net:
    driver: bridge

  # Database network
  data-net:
    driver: bridge
    internal: true

volumes:
  tor-data:
  postgres-data:
  redis-data:
  minio-data:
  evidence-data:

secrets:
  postgres_password:
    file: ./secrets/postgres_password.txt
  redis_password:
    file: ./secrets/redis_password.txt
  evidence_key:
    file: ./secrets/evidence_encryption_key.txt
  minio_secret:
    file: ./secrets/minio_secret_key.txt

services:
  # ============================================
  # TOR POOL (10 instances)
  # ============================================
  tor-1:
    build:
      context: ./docker/tor
      dockerfile: Dockerfile.tor-node
    environment:
      - TOR_INSTANCE_ID=1
    volumes:
      - tor-data:/var/lib/tor
    networks:
      tor-net:
        ipv4_address: 172.28.1.1
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "9050"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
    restart: unless-stopped

  tor-2:
    build:
      context: ./docker/tor
      dockerfile: Dockerfile.tor-node
    environment:
      - TOR_INSTANCE_ID=2
    networks:
      tor-net:
        ipv4_address: 172.28.1.2
    restart: unless-stopped

  # ... (tor-3 through tor-10 follow same pattern)

  # ============================================
  # HAPROXY LOAD BALANCER
  # ============================================
  haproxy:
    image: haproxy:2.9-alpine
    volumes:
      - ./config/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    ports:
      - "8404:8404"  # Stats (internal only)
    networks:
      - tor-net
    depends_on:
      - tor-1
      - tor-2
    healthcheck:
      test: ["CMD", "haproxy", "-c", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
      interval: 30s
      timeout: 5s
      retries: 3
    restart: unless-stopped

  # ============================================
  # OWL BROWSER NODES
  # ============================================
  owl-browser-1:
    image: olib/owl-browser:latest
    environment:
      - ENABLE_STEALTH=true
      - PROXY_HOST=haproxy
      - PROXY_PORT=9050
      - TIMEZONE=UTC
      - MAX_CONCURRENT_PAGES=5
    volumes:
      - evidence-data:/data/evidence
    networks:
      - tor-net
      - mgmt-net
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2'
    restart: unless-stopped

  owl-browser-2:
    image: olib/owl-browser:latest
    environment:
      - ENABLE_STEALTH=true
      - PROXY_HOST=haproxy
      - PROXY_PORT=9050
      - TIMEZONE=UTC
      - MAX_CONCURRENT_PAGES=5
    volumes:
      - evidence-data:/data/evidence
    networks:
      - tor-net
      - mgmt-net
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2'
    restart: unless-stopped

  # ============================================
  # APPLICATION WORKERS
  # ============================================
  crawler-worker:
    build:
      context: .
      dockerfile: Dockerfile.worker
    environment:
      - BROWSER_URLS=http://owl-browser-1:8080,http://owl-browser-2:8080
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
      - POSTGRES_URL=postgresql://darkwatch:${POSTGRES_PASSWORD}@postgres:5432/darkwatch
      - EVIDENCE_BUCKET=darkwatch-evidence
      - MINIO_ENDPOINT=http://minio:9000
      - LOG_LEVEL=INFO
    secrets:
      - evidence_key
    networks:
      - mgmt-net
      - data-net
    depends_on:
      - owl-browser-1
      - redis
      - postgres
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 1G
          cpus: '1'
    restart: unless-stopped

  processor-worker:
    build:
      context: .
      dockerfile: Dockerfile.processor
    environment:
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
      - POSTGRES_URL=postgresql://darkwatch:${POSTGRES_PASSWORD}@postgres:5432/darkwatch
      - CLICKHOUSE_URL=http://clickhouse:8123
      - SPACY_MODEL=en_core_web_trf
    networks:
      - data-net
    depends_on:
      - redis
      - postgres
      - clickhouse
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 4G  # NER models need memory
          cpus: '2'
    restart: unless-stopped

  # ============================================
  # DATA STORES
  # ============================================
  redis:
    image: redis:7-alpine
    command: >
      redis-server
      --requirepass ${REDIS_PASSWORD}
      --maxmemory 512mb
      --maxmemory-policy allkeys-lru
      --appendonly yes
    volumes:
      - redis-data:/data
    networks:
      - data-net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=darkwatch
      - POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
      - POSTGRES_DB=darkwatch
    secrets:
      - postgres_password
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./sql/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    networks:
      - data-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U darkwatch"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  clickhouse:
    image: clickhouse/clickhouse-server:24-alpine
    volumes:
      - ./config/clickhouse:/etc/clickhouse-server/config.d:ro
    networks:
      - data-net
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
    restart: unless-stopped

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      - MINIO_ROOT_USER=darkwatch
      - MINIO_ROOT_PASSWORD_FILE=/run/secrets/minio_secret
    secrets:
      - minio_secret
    volumes:
      - minio-data:/data
    networks:
      - data-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped

  # ============================================
  # MONITORING
  # ============================================
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    networks:
      - mgmt-net
      - data-net
    ports:
      - "9090:9090"
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - ./config/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    networks:
      - mgmt-net
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
    restart: unless-stopped
```

### 8.3. Kubernetes Deployment

```yaml
# kubernetes/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: darkwatch
  labels:
    name: darkwatch
    pod-security.kubernetes.io/enforce: restricted

---
# kubernetes/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: darkwatch-isolation
  namespace: darkwatch
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Only allow internal traffic
    - from:
        - namespaceSelector:
            matchLabels:
              name: darkwatch
  egress:
    # Allow DNS
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
    # Allow internal traffic
    - to:
        - namespaceSelector:
            matchLabels:
              name: darkwatch
    # Block all other egress (Tor handles external)

---
# kubernetes/tor-pool.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: tor-pool
  namespace: darkwatch
spec:
  serviceName: tor-pool
  replicas: 10
  selector:
    matchLabels:
      app: tor
  template:
    metadata:
      labels:
        app: tor
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: tor
          image: darkwatch/tor-node:latest
          ports:
            - containerPort: 9050
              name: socks
            - containerPort: 9051
              name: control
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "256Mi"
              cpu: "500m"
          livenessProbe:
            tcpSocket:
              port: 9050
            initialDelaySeconds: 60
            periodSeconds: 30
          readinessProbe:
            tcpSocket:
              port: 9050
            initialDelaySeconds: 30
            periodSeconds: 10
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: tor-data
              mountPath: /var/lib/tor
  volumeClaimTemplates:
    - metadata:
        name: tor-data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi

---
# kubernetes/owl-browser.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: owl-browser
  namespace: darkwatch
spec:
  replicas: 3
  selector:
    matchLabels:
      app: owl-browser
  template:
    metadata:
      labels:
        app: owl-browser
    spec:
      containers:
        - name: owl-browser
          image: olib/owl-browser:latest
          ports:
            - containerPort: 8080
          env:
            - name: ENABLE_STEALTH
              value: "true"
            - name: TIMEZONE
              value: "UTC"
            - name: PROXY_HOST
              value: "haproxy"
            - name: PROXY_PORT
              value: "9050"
          resources:
            requests:
              memory: "1Gi"
              cpu: "500m"
            limits:
              memory: "2Gi"
              cpu: "2"
          volumeMounts:
            - name: evidence
              mountPath: /data/evidence
      volumes:
        - name: evidence
          persistentVolumeClaim:
            claimName: evidence-pvc
```

### 8.4. Secrets Management

```python
"""
Secrets management for DarkWatch using HashiCorp Vault or AWS Secrets Manager.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from functools import lru_cache

import boto3
import hvac


class SecretsProvider(ABC):
    """Abstract base for secrets providers."""

    @abstractmethod
    def get_secret(self, key: str) -> str: ...


class VaultSecretsProvider(SecretsProvider):
    """HashiCorp Vault secrets provider."""

    def __init__(
        self,
        vault_addr: str | None = None,
        vault_token: str | None = None,
        mount_point: str = "darkwatch",
    ) -> None:
        self._client = hvac.Client(
            url=vault_addr or os.environ["VAULT_ADDR"],
            token=vault_token or os.environ["VAULT_TOKEN"],
        )
        self._mount_point = mount_point

    @lru_cache(maxsize=100)
    def get_secret(self, key: str) -> str:
        secret = self._client.secrets.kv.v2.read_secret_version(
            path=key,
            mount_point=self._mount_point,
        )
        return secret["data"]["data"]["value"]


class AWSSecretsProvider(SecretsProvider):
    """AWS Secrets Manager provider."""

    def __init__(self, region: str = "us-east-1") -> None:
        self._client = boto3.client("secretsmanager", region_name=region)

    @lru_cache(maxsize=100)
    def get_secret(self, key: str) -> str:
        response = self._client.get_secret_value(SecretId=f"darkwatch/{key}")
        return response["SecretString"]


# Usage
secrets = VaultSecretsProvider()
evidence_key = secrets.get_secret("evidence_encryption_key")
postgres_password = secrets.get_secret("postgres_password")
```

## 9. Monitoring and Alerting

Comprehensive monitoring is critical for maintaining crawler health and detecting operational issues.

### 9.1. Prometheus Metrics

```python
"""
Prometheus metrics for DarkWatch monitoring.
"""

from prometheus_client import Counter, Gauge, Histogram, Info

# Crawl metrics
CRAWL_TOTAL = Counter(
    "darkwatch_crawls_total",
    "Total number of crawl attempts",
    ["status", "tor_instance"]
)

CRAWL_DURATION = Histogram(
    "darkwatch_crawl_duration_seconds",
    "Crawl duration in seconds",
    ["status"],
    buckets=[1, 5, 10, 30, 60, 120, 300]
)

# Tor pool metrics
TOR_INSTANCES_HEALTHY = Gauge(
    "darkwatch_tor_instances_healthy",
    "Number of healthy Tor instances"
)

TOR_INSTANCES_TOTAL = Gauge(
    "darkwatch_tor_instances_total",
    "Total number of Tor instances"
)

TOR_CIRCUIT_ROTATIONS = Counter(
    "darkwatch_tor_circuit_rotations_total",
    "Total circuit rotations",
    ["instance_id", "reason"]
)

# Pattern detection metrics
PATTERNS_DETECTED = Counter(
    "darkwatch_patterns_detected_total",
    "Total patterns detected",
    ["category", "pattern_name"]
)

ALERTS_GENERATED = Counter(
    "darkwatch_alerts_generated_total",
    "Total alerts generated",
    ["severity", "category"]
)

# Processing metrics
PROCESSING_QUEUE_SIZE = Gauge(
    "darkwatch_processing_queue_size",
    "Number of items in processing queue"
)

DEDUPLICATION_RATE = Gauge(
    "darkwatch_deduplication_rate",
    "Rate of duplicate content detection"
)

# Evidence metrics
EVIDENCE_STORED = Counter(
    "darkwatch_evidence_stored_total",
    "Total evidence files stored",
    ["content_type"]
)

EVIDENCE_SIZE_BYTES = Histogram(
    "darkwatch_evidence_size_bytes",
    "Size of stored evidence files",
    buckets=[1024, 10240, 102400, 1048576, 10485760]
)
```

### 9.2. Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "title": "DarkWatch Operations",
    "panels": [
      {
        "title": "Crawl Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(rate(darkwatch_crawls_total{status='success'}[5m])) / sum(rate(darkwatch_crawls_total[5m])) * 100"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "thresholds": {
              "steps": [
                {"color": "red", "value": 0},
                {"color": "yellow", "value": 70},
                {"color": "green", "value": 90}
              ]
            }
          }
        }
      },
      {
        "title": "Tor Pool Health",
        "type": "gauge",
        "targets": [
          {
            "expr": "darkwatch_tor_instances_healthy / darkwatch_tor_instances_total * 100"
          }
        ]
      },
      {
        "title": "Alerts by Severity (24h)",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum by (severity) (increase(darkwatch_alerts_generated_total[24h]))"
          }
        ]
      },
      {
        "title": "Crawl Duration (p95)",
        "type": "timeseries",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(darkwatch_crawl_duration_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "Pattern Detections",
        "type": "timeseries",
        "targets": [
          {
            "expr": "sum by (category) (rate(darkwatch_patterns_detected_total[1h]))"
          }
        ]
      }
    ]
  }
}
```

### 9.3. SIEM Integration

```python
"""
SIEM integration for DarkWatch alerts.

Supports:
- Splunk HEC
- Elastic SIEM
- Microsoft Sentinel
- Generic Syslog
"""

from __future__ import annotations

import json
import logging
import socket
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import aiohttp

logger = logging.getLogger(__name__)


class SIEMExporter(ABC):
    """Base class for SIEM exporters."""

    @abstractmethod
    async def export_alert(self, alert: Alert) -> bool: ...


class SplunkHECExporter(SIEMExporter):
    """Export alerts to Splunk via HTTP Event Collector."""

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        source: str = "darkwatch",
        sourcetype: str = "darkwatch:alert",
    ) -> None:
        self._hec_url = hec_url
        self._hec_token = hec_token
        self._source = source
        self._sourcetype = sourcetype

    async def export_alert(self, alert: Alert) -> bool:
        event = {
            "time": alert.created_at.timestamp(),
            "source": self._source,
            "sourcetype": self._sourcetype,
            "event": {
                "alert_id": alert.alert_id,
                "severity": alert.severity.name,
                "category": alert.category.value,
                "title": alert.title,
                "description": alert.description,
                "source_url": alert.source_url,
                "patterns": [
                    {
                        "name": p.pattern_name,
                        "category": p.category.value,
                        "confidence": p.confidence,
                    }
                    for p in alert.matched_patterns
                ],
                "entities": alert.entities,
            },
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self._hec_url,
                headers={
                    "Authorization": f"Splunk {self._hec_token}",
                    "Content-Type": "application/json",
                },
                json=event,
            ) as response:
                if response.status != 200:
                    logger.error("Splunk HEC export failed: %s", await response.text())
                    return False
                return True


class ElasticSIEMExporter(SIEMExporter):
    """Export alerts to Elastic SIEM."""

    def __init__(
        self,
        es_url: str,
        api_key: str,
        index: str = "darkwatch-alerts",
    ) -> None:
        self._es_url = es_url
        self._api_key = api_key
        self._index = index

    async def export_alert(self, alert: Alert) -> bool:
        doc = {
            "@timestamp": alert.created_at.isoformat(),
            "event": {
                "kind": "alert",
                "category": ["threat"],
                "type": ["indicator"],
                "severity": self._map_severity(alert.severity),
            },
            "darkwatch": {
                "alert_id": alert.alert_id,
                "category": alert.category.value,
                "title": alert.title,
                "source_url": alert.source_url,
            },
            "threat": {
                "indicator": {
                    "type": alert.category.value,
                    "description": alert.description,
                },
            },
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self._es_url}/{self._index}/_doc",
                headers={
                    "Authorization": f"ApiKey {self._api_key}",
                    "Content-Type": "application/json",
                },
                json=doc,
            ) as response:
                return response.status in (200, 201)

    @staticmethod
    def _map_severity(severity: AlertSeverity) -> int:
        """Map to ECS severity (0-100)."""
        mapping = {
            AlertSeverity.CRITICAL: 90,
            AlertSeverity.HIGH: 70,
            AlertSeverity.MEDIUM: 50,
            AlertSeverity.LOW: 30,
            AlertSeverity.INFO: 10,
        }
        return mapping.get(severity, 50)
```

## 10. Operational Security (OpSec) Best Practices

### 10.1. Entry/Exit Node Considerations

```markdown
## Tor Circuit Security

### Entry Node (Guard) Rotation
- **DO NOT** frequently rotate entry guards. Tor chooses persistent guards for a reason.
- Entry guard rotation increases exposure to malicious nodes.
- Let Tor manage guard selection automatically (persists for ~2-3 months).

### Exit Node Concerns
- DarkWatch only accesses .onion sites (no exit nodes used).
- All traffic stays within the Tor network.
- No exit node fingerprinting risk for onion-only operations.

### Circuit Rotation Strategy
- Rotate circuits every 10 minutes for fresh paths.
- Rotate immediately on circuit failure.
- Use `SIGNAL NEWNYM` via control port.
- Stagger rotations across instances to avoid burst patterns.
```

### 10.2. Traffic Pattern Obfuscation

```python
"""
Traffic pattern obfuscation to prevent timing analysis.
"""

import asyncio
import random
from typing import Final

# Jitter ranges (seconds)
MIN_REQUEST_DELAY: Final[float] = 0.5
MAX_REQUEST_DELAY: Final[float] = 3.0
MIN_PAGE_DWELL: Final[float] = 2.0
MAX_PAGE_DWELL: Final[float] = 10.0


async def obfuscated_delay() -> None:
    """Add random delay between requests."""
    delay = random.uniform(MIN_REQUEST_DELAY, MAX_REQUEST_DELAY)
    await asyncio.sleep(delay)


async def simulate_reading_time(content_length: int) -> None:
    """
    Simulate human reading time based on content length.

    Average reading speed: 200-250 words per minute.
    """
    words = content_length / 5  # Approximate words
    reading_time = words / 225  # Minutes at 225 wpm
    reading_seconds = reading_time * 60

    # Add variability and cap
    actual_delay = min(
        random.uniform(reading_seconds * 0.5, reading_seconds * 1.5),
        MAX_PAGE_DWELL
    )
    actual_delay = max(actual_delay, MIN_PAGE_DWELL)

    await asyncio.sleep(actual_delay)


class TrafficShaper:
    """
    Shape traffic patterns to appear more human-like.

    Implements:
    - Variable request intervals
    - Session duration limits
    - Activity windows
    """

    def __init__(
        self,
        requests_per_session: tuple[int, int] = (5, 15),
        session_duration: tuple[int, int] = (300, 900),  # 5-15 minutes
    ) -> None:
        self._requests_per_session = requests_per_session
        self._session_duration = session_duration
        self._session_start: float | None = None
        self._request_count: int = 0

    def should_end_session(self) -> bool:
        """Check if current session should end."""
        import time

        if self._session_start is None:
            return False

        elapsed = time.time() - self._session_start
        max_duration = random.randint(*self._session_duration)

        if elapsed > max_duration:
            return True

        max_requests = random.randint(*self._requests_per_session)
        if self._request_count >= max_requests:
            return True

        return False

    def start_session(self) -> None:
        """Start a new session."""
        import time
        self._session_start = time.time()
        self._request_count = 0

    def record_request(self) -> None:
        """Record a request in the current session."""
        self._request_count += 1
```

### 10.3. Logging Sanitization

```python
"""
Log sanitization to prevent sensitive data leakage.
"""

import logging
import re
from typing import Final

# Patterns to redact
REDACTION_PATTERNS: Final[list[tuple[str, str]]] = [
    # Onion URLs - keep domain, redact path
    (r'(https?://[a-z2-7]{56}\.onion)/[^\s]*', r'\1/[REDACTED]'),

    # Credentials
    (r'(password|passwd|pwd|secret|token|key)[=:]\s*\S+', r'\1=[REDACTED]'),

    # IP addresses
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REDACTED]'),

    # Email addresses
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]'),

    # Credit card numbers
    (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', '[CC_REDACTED]'),

    # API keys
    (r'\b(sk_live_|pk_live_|AKIA)[A-Za-z0-9]+', '[API_KEY_REDACTED]'),
]


class SanitizingFormatter(logging.Formatter):
    """Log formatter that redacts sensitive information."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)

        for pattern, replacement in REDACTION_PATTERNS:
            message = re.sub(pattern, replacement, message, flags=re.IGNORECASE)

        return message


def configure_sanitized_logging() -> None:
    """Configure logging with sanitization."""
    handler = logging.StreamHandler()
    handler.setFormatter(SanitizingFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))

    logging.root.handlers = [handler]
    logging.root.setLevel(logging.INFO)
```

### 10.4. Instance Rotation Strategy

```python
"""
Crawler instance rotation to prevent fingerprinting.
"""

from datetime import datetime, timedelta
import random


class InstanceRotationPolicy:
    """
    Manage crawler instance rotation to prevent behavioral fingerprinting.

    Strategies:
    - Time-based rotation (every N hours)
    - Request-based rotation (every N requests)
    - Random rotation within windows
    """

    def __init__(
        self,
        max_instance_lifetime: timedelta = timedelta(hours=4),
        max_requests_per_instance: int = 500,
        rotation_jitter: float = 0.3,  # +/- 30% variance
    ) -> None:
        self._max_lifetime = max_instance_lifetime
        self._max_requests = max_requests_per_instance
        self._jitter = rotation_jitter
        self._instance_births: dict[str, datetime] = {}
        self._instance_requests: dict[str, int] = {}

    def register_instance(self, instance_id: str) -> None:
        """Register a new instance."""
        self._instance_births[instance_id] = datetime.utcnow()
        self._instance_requests[instance_id] = 0

    def record_request(self, instance_id: str) -> None:
        """Record a request for an instance."""
        self._instance_requests[instance_id] = (
            self._instance_requests.get(instance_id, 0) + 1
        )

    def should_rotate(self, instance_id: str) -> bool:
        """Check if instance should be rotated."""
        if instance_id not in self._instance_births:
            return True

        # Time-based check with jitter
        birth = self._instance_births[instance_id]
        jittered_lifetime = self._max_lifetime * (
            1 + random.uniform(-self._jitter, self._jitter)
        )
        if datetime.utcnow() - birth > jittered_lifetime:
            return True

        # Request-based check with jitter
        requests = self._instance_requests.get(instance_id, 0)
        jittered_max = int(self._max_requests * (
            1 + random.uniform(-self._jitter, self._jitter)
        ))
        if requests >= jittered_max:
            return True

        return False

    def rotate_instance(self, instance_id: str) -> None:
        """Mark instance as rotated (remove from tracking)."""
        self._instance_births.pop(instance_id, None)
        self._instance_requests.pop(instance_id, None)
```

## 11. Future Roadmap

1.  **Image Analysis Pipeline:** Using Owl Browser's VLM to detect logos, ID cards, and sensitive images in dumps.

2.  **Automated Threat Actor Profiling:** Build behavioral profiles of sellers and threat actors using ML clustering.

3.  **Distributed Entry Points:** Use residential proxies before Tor entry to obfuscate crawler origin.

4.  **Real-time Collaboration Feed:** Share anonymized IOCs with threat intelligence sharing platforms (MISP, OpenCTI).

5.  **Natural Language Interaction:** Use the LLM to interact with forum users for deeper intelligence gathering (requires careful legal review).

6.  **Ransomware Negotiation Monitoring:** Passive monitoring of ransom negotiation chats for victim intelligence.

---

## Appendix A: Owl Browser SDK Quick Reference

| Method | Use Case |
|--------|----------|
| `page.goto(url)` | Navigate to .onion URL |
| `page.detect_captcha()` | Check for CAPTCHA presence |
| `page.solve_captcha()` | Solve CAPTCHAs automatically |
| `page.extract_text()` | Get page text content |
| `page.get_html()` | Get page HTML |
| `page.get_markdown()` | Get content as Markdown |
| `page.screenshot()` | Capture evidence |
| `page.start_video_recording()` | Record session |
| `page.query_page(query)` | AI-powered content queries |
| `page.summarize_page()` | Get AI summary |
| `page.save_profile()` | Persist session state |
| `page.load_profile()` | Restore session state |
| `page.type(selector, text)` | Type into form fields |
| `page.click(selector)` | Click elements (NL supported) |
| `page.scroll_to_bottom()` | Handle infinite scroll |
| `page.wait_for_network_idle()` | Wait for page load |

---

*DarkWatch Documentation - Version 2.0*
*Last Updated: 2024*

---

## Disclaimer

This project documentation was generated by generative AI. While the architectural concepts and implementation patterns are based on real-world best practices, some features, configurations, or code examples may require adjustments for production use. Please review and test thoroughly before deploying.