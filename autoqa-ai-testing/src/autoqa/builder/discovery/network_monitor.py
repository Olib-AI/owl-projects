"""Monitors network activity during page interactions.

This module provides network request monitoring to understand
API calls, resource loading, and network timing during test execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from owl_browser import OwlBrowser

logger = structlog.get_logger(__name__)


class RequestType(StrEnum):
    """Type of network request."""

    XHR = "xhr"
    """XMLHttpRequest."""

    FETCH = "fetch"
    """Fetch API request."""

    DOCUMENT = "document"
    """HTML document request."""

    SCRIPT = "script"
    """JavaScript file."""

    STYLESHEET = "stylesheet"
    """CSS stylesheet."""

    IMAGE = "image"
    """Image resource."""

    FONT = "font"
    """Font file."""

    WEBSOCKET = "websocket"
    """WebSocket connection."""

    OTHER = "other"
    """Other request type."""


@dataclass
class NetworkRequest:
    """Information about a single network request."""

    url: str
    """Request URL."""

    method: str
    """HTTP method (GET, POST, etc.)."""

    request_type: RequestType
    """Type of request."""

    status: int | None = None
    """HTTP response status code."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    """When request was initiated."""

    duration_ms: float | None = None
    """Request duration in milliseconds."""

    response_size: int | None = None
    """Response body size in bytes."""

    request_headers: dict[str, str] = field(default_factory=dict)
    """Request headers."""

    response_headers: dict[str, str] = field(default_factory=dict)
    """Response headers."""

    request_body: str | None = None
    """Request body (for POST, PUT, etc.)."""

    initiator: str | None = None
    """What initiated this request."""

    error_message: str | None = None
    """Error message if request failed."""


@dataclass
class NetworkAnalysis:
    """Analysis of network activity during a time period."""

    total_requests: int
    """Total number of requests."""

    api_calls: list[NetworkRequest]
    """XHR/fetch requests to API endpoints."""

    resource_loads: list[NetworkRequest]
    """Scripts, styles, images, fonts."""

    failed_requests: list[NetworkRequest]
    """Requests that failed (4xx, 5xx, or network error)."""

    is_idle: bool
    """Whether network is currently idle."""

    total_transfer_size: int
    """Total bytes transferred."""

    api_endpoints: list[str]
    """Unique API endpoints discovered."""

    avg_response_time_ms: float
    """Average response time in milliseconds."""


class NetworkMonitor:
    """
    Monitors network requests during interactions.

    Captures network activity to understand:
    - API calls triggered by interactions
    - Resource loading patterns
    - Network errors and failures
    - Timing information
    """

    def __init__(self) -> None:
        """Initialize the network monitor."""
        self._requests: list[NetworkRequest] = []
        self._monitoring = False
        self._log = logger.bind(component="network_monitor")

    async def start_monitoring(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> None:
        """
        Start capturing network requests.

        Args:
            browser: Browser instance
            context_id: Browser context ID
        """
        self._requests = []
        self._monitoring = True
        self._log.debug("Network monitoring started", context_id=context_id)

        # Note: The actual network logging is typically handled by the browser SDK.
        # This method prepares the monitor to collect data.
        # Browser SDK integration would go here when available.

    async def stop_monitoring(self) -> list[NetworkRequest]:
        """
        Stop monitoring and return captured requests.

        Returns:
            List of captured network requests
        """
        self._monitoring = False
        self._log.debug(
            "Network monitoring stopped",
            requests_captured=len(self._requests),
        )
        return list(self._requests)

    async def wait_for_network_idle(
        self,
        browser: OwlBrowser,
        context_id: str,
        timeout_ms: int = 5000,
        idle_time_ms: int = 500,
    ) -> bool:
        """
        Wait for network to become idle.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            timeout_ms: Maximum wait time in milliseconds
            idle_time_ms: How long network must be idle

        Returns:
            True if network became idle, False if timed out
        """
        try:
            await browser.wait_for_network_idle(
                context_id=context_id,
                idle_time=idle_time_ms,
                timeout=timeout_ms,
            )
            return True
        except Exception as e:
            self._log.debug(
                "Wait for network idle timed out",
                timeout_ms=timeout_ms,
                error=str(e),
            )
            return False

    async def capture_requests_during(
        self,
        browser: OwlBrowser,
        context_id: str,
        action_fn: Any,
        wait_after_ms: int = 1000,
    ) -> list[NetworkRequest]:
        """
        Capture network requests during an action.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            action_fn: Async function that performs the action
            wait_after_ms: Time to wait after action for requests to complete

        Returns:
            List of network requests captured during action
        """
        import asyncio

        await self.start_monitoring(browser, context_id)

        try:
            # Perform the action
            await action_fn()

            # Wait for requests to complete
            await asyncio.sleep(wait_after_ms / 1000)

            # Try to wait for idle
            await self.wait_for_network_idle(
                browser, context_id, timeout_ms=2000, idle_time_ms=200
            )

        finally:
            requests = await self.stop_monitoring()

        return requests

    def analyze_requests(
        self,
        requests: list[NetworkRequest],
    ) -> NetworkAnalysis:
        """
        Analyze captured network requests.

        Args:
            requests: List of network requests to analyze

        Returns:
            Analysis of the requests
        """
        # Separate API calls from resource loads
        api_calls = [
            r for r in requests
            if r.request_type in (RequestType.XHR, RequestType.FETCH)
        ]

        resource_loads = [
            r for r in requests
            if r.request_type not in (RequestType.XHR, RequestType.FETCH)
        ]

        # Find failed requests
        failed = [
            r for r in requests
            if (r.status and r.status >= 400) or r.error_message
        ]

        # Calculate total transfer size
        total_size = sum(r.response_size or 0 for r in requests)

        # Get unique API endpoints
        api_endpoints = list({
            self._extract_endpoint(r.url)
            for r in api_calls
        })

        # Calculate average response time
        valid_durations = [r.duration_ms for r in requests if r.duration_ms]
        avg_response_time = (
            sum(valid_durations) / len(valid_durations)
            if valid_durations else 0.0
        )

        return NetworkAnalysis(
            total_requests=len(requests),
            api_calls=api_calls,
            resource_loads=resource_loads,
            failed_requests=failed,
            is_idle=True,
            total_transfer_size=total_size,
            api_endpoints=api_endpoints,
            avg_response_time_ms=avg_response_time,
        )

    def _extract_endpoint(self, url: str) -> str:
        """Extract API endpoint path from URL."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.path

    def add_request(self, request: NetworkRequest) -> None:
        """
        Add a request to the captured list.

        Args:
            request: Network request to add
        """
        if self._monitoring:
            self._requests.append(request)

    async def get_pending_requests(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> list[str]:
        """
        Get URLs of currently pending requests.

        Args:
            browser: Browser instance
            context_id: Browser context ID

        Returns:
            List of pending request URLs
        """
        # This would require browser SDK support for pending request tracking
        # For now, return empty list
        return []

    def classify_request_type(
        self,
        url: str,
        resource_type: str | None = None,
    ) -> RequestType:
        """
        Classify a request based on URL and resource type.

        Args:
            url: Request URL
            resource_type: Browser-reported resource type

        Returns:
            Classified request type
        """
        url_lower = url.lower()

        # Check resource type hint first
        if resource_type:
            type_map = {
                "xhr": RequestType.XHR,
                "fetch": RequestType.FETCH,
                "document": RequestType.DOCUMENT,
                "script": RequestType.SCRIPT,
                "stylesheet": RequestType.STYLESHEET,
                "image": RequestType.IMAGE,
                "font": RequestType.FONT,
                "websocket": RequestType.WEBSOCKET,
            }
            if resource_type.lower() in type_map:
                return type_map[resource_type.lower()]

        # Classify by URL extension
        if any(ext in url_lower for ext in [".js", ".mjs"]):
            return RequestType.SCRIPT
        if any(ext in url_lower for ext in [".css"]):
            return RequestType.STYLESHEET
        if any(ext in url_lower for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"]):
            return RequestType.IMAGE
        if any(ext in url_lower for ext in [".woff", ".woff2", ".ttf", ".eot"]):
            return RequestType.FONT
        if "api" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower:
            return RequestType.FETCH
        if url_lower.endswith(".html") or url_lower.endswith("/"):
            return RequestType.DOCUMENT

        return RequestType.OTHER


# Convenience function
async def wait_for_idle(
    browser: OwlBrowser,
    context_id: str,
    timeout_ms: int = 5000,
) -> bool:
    """Wait for network idle using default monitor."""
    monitor = NetworkMonitor()
    return await monitor.wait_for_network_idle(browser, context_id, timeout_ms)
