# TrendScope: Cross-Platform Social Media Intelligence Engine

## 1. Executive Summary

**TrendScope** is an enterprise-grade analytics platform designed to surface emerging trends, sentiment, and influencer networks across "walled garden" social media platforms (Twitter/X, TikTok, LinkedIn, Instagram).

In an era where official APIs are prohibitively expensive (e.g., X Enterprise API costs \$42,000/month) or severely restricted, TrendScope provides a democratized alternative. It uses the **Owl Browser** to navigate these complex, dynamic Single Page Applications (SPAs) just like a human user, extracting public data for research, marketing, and sociological analysis.

## 2. System Architecture

The platform is built on a **Lambda Architecture**, processing data in both batch (historical analysis) and speed (real-time monitoring) layers.

```mermaid
graph TD
    User[Analyst] -->|Campaign Config| API[GraphQL API]
    API -->|Jobs| Queue[RabbitMQ]
    
    subgraph "Scraping Grid"
        Queue --> Orchestrator[Task Orchestrator]
        Orchestrator -->|Spawn| BrowserPod[Owl Browser Pod]
        
        BrowserPod -->|Proxy| Resid[Residential Proxy Gateway]
        Resid --> Social[Social Platforms]
        
        BrowserPod -->|Raw JSON/Images| Kafka[Apache Kafka]
    end
    
    subgraph "Processing Layer"
        Kafka --> Spark[Spark Streaming]
        
        Spark -->|Text| NLP[RoBERTa Model]
        Spark -->|Images| VLM[Clip Model]
    end
    
    subgraph "Storage Layer"
        NLP --> Timescale[TimescaleDB (Metrics)]
        VLM --> VectorDB[Milvus (Visual Search)]
        Spark --> DataLake[S3 (Raw Archives)]
    end
    
    Timescale --> Dashboard[Grafana / Custom UI]
```

## 3. High-Scale Scraping: The Grid

Scraping social media at scale (1M+ posts/day) requires a sophisticated "Browser Grid". We replace Selenium Grid with a custom Kubernetes-based orchestrator.

### 3.1. Session Management (The "Account Farm")
Platforms like LinkedIn and Instagram require login. We manage a pool of "Research Accounts".

*   **Cookie Preservation:** Sessions are serialized to encrypted S3 objects.
*   **Health Checks:** A background service verifies if an account is "shadowbanned" or locked. If locked, it triggers an automated "Unlock Flow" using SMS verification APIs.
*   **Rotation Logic:** Use Account A for 50 requests, then switch to Account B to mimic human rest periods.

### 3.2. Proxy Strategy
*   **Residential Proxies:** Mandatory. We use a rotating pool of 10k+ residential IPs (BrightData/Smartproxy).
*   **Sticky Sessions:** For logged-in accounts, we bind `IP_X` to `Account_Y` for 24 hours to prevent "Suspicious Login" alerts.

### 3.3. Session & Account Management (Full Implementation)

Managing authenticated sessions across multiple accounts requires careful orchestration. The following implementation provides a complete account pool manager with health monitoring.

```python
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any

from owl_browser import Browser, RemoteConfig, ProxyConfig

if TYPE_CHECKING:
    from owl_browser import Page


class AccountStatus(Enum):
    """Account health status enumeration."""
    HEALTHY = auto()
    RATE_LIMITED = auto()
    SHADOWBANNED = auto()
    LOCKED = auto()
    REQUIRES_VERIFICATION = auto()
    SUSPENDED = auto()
    UNKNOWN = auto()


class Platform(Enum):
    """Supported social media platforms."""
    TWITTER = "twitter"
    TIKTOK = "tiktok"
    LINKEDIN = "linkedin"
    INSTAGRAM = "instagram"


@dataclass
class AccountCredentials:
    """Encrypted account credentials storage."""
    platform: Platform
    username: str
    email: str
    _encrypted_password: bytes = field(repr=False)
    phone_number: str | None = None
    backup_codes: list[str] = field(default_factory=list, repr=False)
    created_at: datetime = field(default_factory=datetime.now)

    def get_password(self, encryption_key: bytes) -> str:
        """Decrypt and return password. Implementation depends on crypto library."""
        # In production, use cryptography.fernet or similar
        raise NotImplementedError("Implement with your encryption library")


@dataclass
class AccountSession:
    """Represents an authenticated browser session."""
    account_id: str
    platform: Platform
    profile_path: Path
    proxy_binding: str | None  # IP address bound to this session
    status: AccountStatus = AccountStatus.UNKNOWN
    last_used: datetime = field(default_factory=datetime.now)
    request_count: int = 0
    daily_request_count: int = 0
    last_health_check: datetime | None = None
    cooldown_until: datetime | None = None
    error_count: int = 0

    @property
    def is_available(self) -> bool:
        """Check if account is available for use."""
        if self.status in (
            AccountStatus.LOCKED,
            AccountStatus.SUSPENDED,
            AccountStatus.REQUIRES_VERIFICATION,
        ):
            return False
        if self.cooldown_until and datetime.now() < self.cooldown_until:
            return False
        return True

    @property
    def needs_health_check(self) -> bool:
        """Check if account needs health verification."""
        if self.last_health_check is None:
            return True
        return datetime.now() - self.last_health_check > timedelta(hours=1)


class AccountPoolManager:
    """Production-grade account pool manager with rotation and health monitoring.

    Features:
    - Multi-platform account management
    - Automatic session persistence with save_profile/load_profile
    - Health monitoring and shadowban detection
    - Request rate limiting per account
    - Automatic cooldown and rotation
    """

    # Platform-specific rate limits (requests per hour)
    RATE_LIMITS: dict[Platform, int] = {
        Platform.TWITTER: 100,
        Platform.TIKTOK: 80,
        Platform.LINKEDIN: 50,  # Most aggressive limits
        Platform.INSTAGRAM: 60,
    }

    # Cooldown duration after rate limit hit
    COOLDOWN_MINUTES: dict[Platform, int] = {
        Platform.TWITTER: 15,
        Platform.TIKTOK: 20,
        Platform.LINKEDIN: 60,
        Platform.INSTAGRAM: 30,
    }

    def __init__(
        self,
        browser: Browser,
        profiles_directory: Path,
        proxy_pool: list[ProxyConfig],
    ) -> None:
        self._browser = browser
        self._profiles_dir = profiles_directory
        self._proxy_pool = proxy_pool
        self._sessions: dict[str, AccountSession] = {}
        self._proxy_bindings: dict[str, str] = {}  # proxy_url -> account_id
        self._lock = asyncio.Lock()

    async def register_account(
        self,
        credentials: AccountCredentials,
        proxy: ProxyConfig | None = None,
    ) -> str:
        """Register a new account and perform initial login.

        Args:
            credentials: Account credentials object.
            proxy: Optional proxy to bind to this account.

        Returns:
            Unique account ID for future reference.

        Raises:
            LoginError: If initial authentication fails.
        """
        account_id = self._generate_account_id(credentials)
        profile_path = self._profiles_dir / f"{account_id}.owlprofile"

        # Perform initial login based on platform
        page = self._browser.new_page(proxy=proxy)

        try:
            login_success = await self._perform_login(
                page, credentials, profile_path
            )

            if not login_success:
                raise PermissionError(
                    f"Failed to authenticate {credentials.username} on {credentials.platform.value}"
                )

            # Create session record
            session = AccountSession(
                account_id=account_id,
                platform=credentials.platform,
                profile_path=profile_path,
                proxy_binding=proxy.url if proxy else None,
                status=AccountStatus.HEALTHY,
                last_health_check=datetime.now(),
            )

            async with self._lock:
                self._sessions[account_id] = session
                if proxy:
                    self._proxy_bindings[proxy.url] = account_id

            return account_id

        finally:
            await page.close()

    async def get_available_session(
        self,
        platform: Platform,
        preferred_proxy: ProxyConfig | None = None,
    ) -> tuple[AccountSession, ProxyConfig | None]:
        """Get an available session for the specified platform.

        Implements round-robin selection with health awareness.

        Args:
            platform: Target platform.
            preferred_proxy: Optional preferred proxy (for geo-targeting).

        Returns:
            Tuple of (session, proxy_config) for the request.

        Raises:
            NoAvailableSessionError: If no healthy sessions available.
        """
        async with self._lock:
            # Filter sessions by platform and availability
            available = [
                s for s in self._sessions.values()
                if s.platform == platform and s.is_available
            ]

            if not available:
                raise RuntimeError(
                    f"No available sessions for {platform.value}. "
                    "All accounts may be rate-limited or locked."
                )

            # Sort by least recently used
            available.sort(key=lambda s: s.last_used)

            # Select session with proxy preference
            selected = available[0]
            if preferred_proxy:
                for session in available:
                    if session.proxy_binding == preferred_proxy.url:
                        selected = session
                        break

            # Find matching proxy
            proxy = None
            if selected.proxy_binding:
                proxy = next(
                    (p for p in self._proxy_pool if p.url == selected.proxy_binding),
                    None
                )

            # Update usage stats
            selected.last_used = datetime.now()
            selected.request_count += 1
            selected.daily_request_count += 1

            # Check if approaching rate limit
            hourly_limit = self.RATE_LIMITS[platform]
            if selected.request_count >= hourly_limit * 0.8:
                # Preemptive cooldown at 80% capacity
                cooldown_mins = self.COOLDOWN_MINUTES[platform] // 2
                selected.cooldown_until = datetime.now() + timedelta(minutes=cooldown_mins)
                selected.request_count = 0

            return selected, proxy

    async def check_account_health(
        self,
        account_id: str,
    ) -> AccountStatus:
        """Perform health check on an account to detect shadowban or locks.

        Args:
            account_id: The account to check.

        Returns:
            Updated AccountStatus after health check.
        """
        async with self._lock:
            session = self._sessions.get(account_id)
            if not session:
                raise KeyError(f"Account {account_id} not found")

        proxy = None
        if session.proxy_binding:
            proxy = next(
                (p for p in self._proxy_pool if p.url == session.proxy_binding),
                None
            )

        page = self._browser.new_page(proxy=proxy)

        try:
            # Load saved profile
            await page.load_profile(str(session.profile_path))

            # Navigate to platform-specific health check URL
            health_url = self._get_health_check_url(session.platform)
            await page.goto(health_url, wait_until="networkidle", timeout=20000)

            # Use AI to analyze page state
            health_analysis = await page.query_page(
                "Analyze this page for signs of: "
                "1) Account suspension or ban message "
                "2) Rate limiting or 'try again later' warnings "
                "3) Verification or security challenge required "
                "4) Shadowban indicators (no engagement, limited visibility) "
                "5) Normal logged-in state. "
                "Return the most likely status."
            )

            # Parse AI response to determine status
            status = self._parse_health_status(health_analysis)

            async with self._lock:
                session.status = status
                session.last_health_check = datetime.now()

                # Apply appropriate action based on status
                if status == AccountStatus.RATE_LIMITED:
                    cooldown = self.COOLDOWN_MINUTES[session.platform]
                    session.cooldown_until = datetime.now() + timedelta(minutes=cooldown)
                elif status == AccountStatus.SHADOWBANNED:
                    # Extended cooldown for shadowban
                    session.cooldown_until = datetime.now() + timedelta(hours=24)

            return status

        finally:
            await page.close()

    async def refresh_session(
        self,
        account_id: str,
    ) -> bool:
        """Refresh an expired or stale session by re-authenticating.

        Args:
            account_id: Account to refresh.

        Returns:
            True if refresh successful.
        """
        async with self._lock:
            session = self._sessions.get(account_id)
            if not session:
                return False

        proxy = None
        if session.proxy_binding:
            proxy = next(
                (p for p in self._proxy_pool if p.url == session.proxy_binding),
                None
            )

        page = self._browser.new_page(proxy=proxy)

        try:
            # Load existing profile
            await page.load_profile(str(session.profile_path))

            # Navigate to verify session
            test_url = self._get_health_check_url(session.platform)
            await page.goto(test_url, wait_until="networkidle", timeout=20000)

            # Check if still logged in
            logged_in = await page.query_page(
                "Is this page showing a logged-in user state (not a login page)?"
            )

            if "yes" in logged_in.lower():
                # Update session cookies
                await page.update_profile_cookies()
                await page.save_profile(str(session.profile_path))

                async with self._lock:
                    session.status = AccountStatus.HEALTHY
                    session.error_count = 0

                return True

            return False

        finally:
            await page.close()

    async def report_error(
        self,
        account_id: str,
        error_type: str,
    ) -> None:
        """Report an error encountered while using an account.

        Args:
            account_id: Account that encountered error.
            error_type: Type of error (e.g., 'rate_limit', 'captcha', 'block').
        """
        async with self._lock:
            session = self._sessions.get(account_id)
            if not session:
                return

            session.error_count += 1

            if error_type == "rate_limit":
                session.status = AccountStatus.RATE_LIMITED
                cooldown = self.COOLDOWN_MINUTES[session.platform]
                session.cooldown_until = datetime.now() + timedelta(minutes=cooldown)
            elif error_type == "block" or session.error_count >= 3:
                session.status = AccountStatus.LOCKED
                # Trigger immediate health check
                session.last_health_check = None

    async def get_pool_stats(self) -> dict[str, Any]:
        """Get current pool statistics for monitoring."""
        async with self._lock:
            stats: dict[str, Any] = {
                "total_accounts": len(self._sessions),
                "by_platform": {},
                "by_status": {},
            }

            for session in self._sessions.values():
                # By platform
                platform_key = session.platform.value
                if platform_key not in stats["by_platform"]:
                    stats["by_platform"][platform_key] = {
                        "total": 0,
                        "available": 0,
                        "total_requests": 0,
                    }
                stats["by_platform"][platform_key]["total"] += 1
                if session.is_available:
                    stats["by_platform"][platform_key]["available"] += 1
                stats["by_platform"][platform_key]["total_requests"] += session.request_count

                # By status
                status_key = session.status.name
                stats["by_status"][status_key] = stats["by_status"].get(status_key, 0) + 1

            return stats

    async def _perform_login(
        self,
        page: Page,
        credentials: AccountCredentials,
        profile_path: Path,
    ) -> bool:
        """Platform-specific login implementation."""
        login_urls = {
            Platform.TWITTER: "https://twitter.com/i/flow/login",
            Platform.TIKTOK: "https://www.tiktok.com/login",
            Platform.LINKEDIN: "https://www.linkedin.com/login",
            Platform.INSTAGRAM: "https://www.instagram.com/accounts/login/",
        }

        await page.goto(
            login_urls[credentials.platform],
            wait_until="networkidle",
            timeout=20000
        )

        # Platform-specific login flows
        if credentials.platform == Platform.TWITTER:
            await page.type("username input", credentials.username)
            await page.click("Next button")
            await page.wait_for_network_idle(idle_time=1500, timeout=10000)
            # Twitter may ask for email verification
            email_check = await page.query_page("Is there an email verification step?")
            if "yes" in email_check.lower():
                await page.type("email input", credentials.email)
                await page.click("Next button")
                await page.wait_for_network_idle(idle_time=1500, timeout=10000)
            await page.type("password input", "PLACEHOLDER")  # Use actual decrypted password
            await page.click("Log in button")

        elif credentials.platform == Platform.INSTAGRAM:
            await page.type("username input", credentials.username)
            await page.type("password input", "PLACEHOLDER")
            await page.click("Log in button")

        elif credentials.platform == Platform.LINKEDIN:
            await page.type("username input", credentials.email)
            await page.type("password input", "PLACEHOLDER")
            await page.click("Sign in button")

        elif credentials.platform == Platform.TIKTOK:
            # TikTok login is more complex, often requires phone/email selection
            await page.click("Use phone / email / username")
            await page.wait(1000)
            await page.click("Log in with email or username")
            await page.type("email or username input", credentials.username)
            await page.type("password input", "PLACEHOLDER")
            await page.click("Log in button")

        await page.wait_for_network_idle(idle_time=3000, timeout=30000)

        # Handle CAPTCHA if present
        if await page.detect_captcha():
            solved = await page.solve_captcha(max_attempts=3)
            if not solved:
                return False
            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

        # Verify login success
        current_url = await page.get_current_url()
        success_indicators = {
            Platform.TWITTER: ["home", "compose"],
            Platform.TIKTOK: ["foryou", "following", "@"],
            Platform.LINKEDIN: ["feed", "mynetwork"],
            Platform.INSTAGRAM: ["/", "explore"],
        }

        for indicator in success_indicators[credentials.platform]:
            if indicator in current_url:
                await page.save_profile(str(profile_path))
                return True

        return False

    def _generate_account_id(self, credentials: AccountCredentials) -> str:
        """Generate unique account ID from credentials."""
        unique_string = f"{credentials.platform.value}:{credentials.username}:{credentials.email}"
        return hashlib.sha256(unique_string.encode()).hexdigest()[:16]

    def _get_health_check_url(self, platform: Platform) -> str:
        """Get platform-specific health check URL."""
        urls = {
            Platform.TWITTER: "https://twitter.com/home",
            Platform.TIKTOK: "https://www.tiktok.com/foryou",
            Platform.LINKEDIN: "https://www.linkedin.com/feed/",
            Platform.INSTAGRAM: "https://www.instagram.com/",
        }
        return urls[platform]

    def _parse_health_status(self, analysis: str) -> AccountStatus:
        """Parse AI health analysis into AccountStatus."""
        analysis_lower = analysis.lower()

        if "suspend" in analysis_lower or "ban" in analysis_lower:
            return AccountStatus.SUSPENDED
        if "rate limit" in analysis_lower or "try again" in analysis_lower:
            return AccountStatus.RATE_LIMITED
        if "verify" in analysis_lower or "challenge" in analysis_lower:
            return AccountStatus.REQUIRES_VERIFICATION
        if "shadowban" in analysis_lower or "limited visibility" in analysis_lower:
            return AccountStatus.SHADOWBANNED
        if "locked" in analysis_lower:
            return AccountStatus.LOCKED
        if "normal" in analysis_lower or "logged in" in analysis_lower:
            return AccountStatus.HEALTHY

        return AccountStatus.UNKNOWN
```

### 3.4. Proxy & Stealth Strategy (Full Implementation)

Effective anti-detection requires coordinated proxy management, fingerprint randomization, and behavioral mimicry.

```python
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any
from collections.abc import Callable, Awaitable

from owl_browser import Browser, RemoteConfig, ProxyConfig

if TYPE_CHECKING:
    from owl_browser import Page


class ProxyType(Enum):
    """Proxy protocol types."""
    HTTP = "http"
    HTTPS = "https"
    SOCKS5 = "socks5"
    SOCKS5H = "socks5h"  # Remote DNS resolution


class ProxyTier(Enum):
    """Proxy quality tiers affecting rotation strategy."""
    RESIDENTIAL = "residential"  # Real ISP IPs, highest quality
    MOBILE = "mobile"  # Mobile carrier IPs, very high quality
    ISP = "isp"  # Static residential IPs
    DATACENTER = "datacenter"  # Datacenter IPs, lowest quality for social media


@dataclass
class ProxyEndpoint:
    """Represents a single proxy endpoint with metadata."""
    url: str
    proxy_type: ProxyType
    tier: ProxyTier
    country: str
    city: str | None = None
    isp: str | None = None
    # Usage tracking
    request_count: int = 0
    error_count: int = 0
    last_used: datetime | None = None
    blocked_until: datetime | None = None
    # Performance metrics
    avg_response_time_ms: float = 0.0
    success_rate: float = 1.0

    @property
    def is_available(self) -> bool:
        """Check if proxy is available for use."""
        if self.blocked_until and datetime.now() < self.blocked_until:
            return False
        if self.success_rate < 0.5:  # Block if success rate drops below 50%
            return False
        return True

    def to_proxy_config(self) -> ProxyConfig:
        """Convert to Owl Browser ProxyConfig."""
        return ProxyConfig(
            url=self.url,
            type=self.proxy_type.value,
        )


@dataclass
class StealthProfile:
    """Browser fingerprint and behavioral profile for stealth."""
    # Viewport and screen
    viewport_width: int
    viewport_height: int
    screen_width: int
    screen_height: int
    device_pixel_ratio: float
    # Platform info
    platform: str  # e.g., "Win32", "MacIntel", "Linux x86_64"
    user_agent: str
    # Timezone (should match proxy location)
    timezone: str
    timezone_offset: int  # Minutes from UTC
    # Language
    languages: list[str]
    # Hardware
    hardware_concurrency: int
    device_memory: int  # GB
    # Behavioral
    typing_speed_wpm: int  # Words per minute
    mouse_movement_style: str  # "smooth", "jerky", "fast"


class ProxyPoolManager:
    """Advanced proxy pool manager with geo-targeting and rotation strategies.

    Features:
    - Multi-tier proxy support (residential, mobile, datacenter)
    - Geo-targeted proxy selection
    - Sticky sessions for authenticated contexts
    - Automatic health monitoring and rotation
    - Load balancing across proxy pool
    """

    # Cooldown after proxy error (minutes)
    ERROR_COOLDOWN_MINUTES = 10
    # Maximum errors before proxy is marked as bad
    MAX_ERRORS = 5

    def __init__(
        self,
        proxies: list[ProxyEndpoint],
        default_sticky_duration_hours: int = 24,
    ) -> None:
        self._proxies = {p.url: p for p in proxies}
        self._sticky_bindings: dict[str, tuple[str, datetime]] = {}  # account_id -> (proxy_url, expires)
        self._sticky_duration = timedelta(hours=default_sticky_duration_hours)
        self._lock = asyncio.Lock()

    async def get_proxy(
        self,
        country: str | None = None,
        tier: ProxyTier = ProxyTier.RESIDENTIAL,
        account_id: str | None = None,
    ) -> ProxyEndpoint | None:
        """Get an available proxy matching criteria.

        Args:
            country: Required country code (e.g., "US", "GB").
            tier: Minimum proxy tier required.
            account_id: If provided, returns sticky proxy for this account.

        Returns:
            ProxyEndpoint or None if no matching proxy available.
        """
        async with self._lock:
            # Check for existing sticky binding
            if account_id and account_id in self._sticky_bindings:
                proxy_url, expires = self._sticky_bindings[account_id]
                if datetime.now() < expires:
                    proxy = self._proxies.get(proxy_url)
                    if proxy and proxy.is_available:
                        return proxy
                # Expired or unavailable, remove binding
                del self._sticky_bindings[account_id]

            # Filter available proxies
            candidates = [
                p for p in self._proxies.values()
                if p.is_available
                and (country is None or p.country == country)
                and self._tier_rank(p.tier) >= self._tier_rank(tier)
            ]

            if not candidates:
                return None

            # Sort by success rate and usage (prefer less used, higher success)
            candidates.sort(
                key=lambda p: (p.success_rate, -p.request_count),
                reverse=True
            )

            selected = candidates[0]

            # Create sticky binding if account specified
            if account_id:
                self._sticky_bindings[account_id] = (
                    selected.url,
                    datetime.now() + self._sticky_duration
                )

            # Update usage
            selected.request_count += 1
            selected.last_used = datetime.now()

            return selected

    async def report_success(
        self,
        proxy_url: str,
        response_time_ms: float,
    ) -> None:
        """Report successful request through proxy."""
        async with self._lock:
            proxy = self._proxies.get(proxy_url)
            if proxy:
                # Update running average response time
                alpha = 0.1  # Exponential moving average factor
                proxy.avg_response_time_ms = (
                    alpha * response_time_ms +
                    (1 - alpha) * proxy.avg_response_time_ms
                )
                # Update success rate
                total = proxy.request_count
                proxy.success_rate = (
                    (proxy.success_rate * (total - 1) + 1.0) / total
                    if total > 0 else 1.0
                )

    async def report_error(
        self,
        proxy_url: str,
        error_type: str,
    ) -> None:
        """Report error through proxy.

        Args:
            proxy_url: The proxy that failed.
            error_type: Type of error ("block", "timeout", "captcha", etc.)
        """
        async with self._lock:
            proxy = self._proxies.get(proxy_url)
            if not proxy:
                return

            proxy.error_count += 1

            # Update success rate
            total = proxy.request_count
            proxy.success_rate = (
                (proxy.success_rate * (total - 1)) / total
                if total > 0 else 0.0
            )

            # Apply cooldown based on error type
            if error_type == "block":
                # Longer cooldown for blocks
                proxy.blocked_until = datetime.now() + timedelta(hours=1)
            elif proxy.error_count >= self.MAX_ERRORS:
                # Extended block for repeated errors
                proxy.blocked_until = datetime.now() + timedelta(hours=24)
            else:
                proxy.blocked_until = datetime.now() + timedelta(
                    minutes=self.ERROR_COOLDOWN_MINUTES
                )

    async def rotate_proxy(
        self,
        account_id: str,
        country: str | None = None,
    ) -> ProxyEndpoint | None:
        """Force rotation to a new proxy for an account.

        Args:
            account_id: Account requiring new proxy.
            country: Optional geo-restriction.

        Returns:
            New proxy endpoint.
        """
        async with self._lock:
            # Clear existing binding
            old_binding = self._sticky_bindings.pop(account_id, None)
            old_proxy_url = old_binding[0] if old_binding else None

        # Get new proxy (will create new sticky binding)
        new_proxy = await self.get_proxy(
            country=country,
            account_id=account_id,
        )

        # Ensure we didn't get the same proxy
        if new_proxy and old_proxy_url and new_proxy.url == old_proxy_url:
            # Try again with explicit exclusion
            async with self._lock:
                candidates = [
                    p for p in self._proxies.values()
                    if p.is_available
                    and p.url != old_proxy_url
                    and (country is None or p.country == country)
                ]
                if candidates:
                    new_proxy = random.choice(candidates)
                    self._sticky_bindings[account_id] = (
                        new_proxy.url,
                        datetime.now() + self._sticky_duration
                    )

        return new_proxy

    def _tier_rank(self, tier: ProxyTier) -> int:
        """Return numeric rank for tier comparison."""
        ranks = {
            ProxyTier.DATACENTER: 1,
            ProxyTier.ISP: 2,
            ProxyTier.RESIDENTIAL: 3,
            ProxyTier.MOBILE: 4,
        }
        return ranks.get(tier, 0)

    async def get_pool_stats(self) -> dict[str, Any]:
        """Get proxy pool statistics."""
        async with self._lock:
            available = [p for p in self._proxies.values() if p.is_available]
            blocked = [p for p in self._proxies.values() if not p.is_available]

            by_country: dict[str, int] = {}
            by_tier: dict[str, int] = {}

            for proxy in self._proxies.values():
                by_country[proxy.country] = by_country.get(proxy.country, 0) + 1
                by_tier[proxy.tier.value] = by_tier.get(proxy.tier.value, 0) + 1

            return {
                "total": len(self._proxies),
                "available": len(available),
                "blocked": len(blocked),
                "sticky_bindings": len(self._sticky_bindings),
                "by_country": by_country,
                "by_tier": by_tier,
                "avg_success_rate": sum(p.success_rate for p in self._proxies.values()) / len(self._proxies) if self._proxies else 0,
            }


class StealthEngine:
    """Browser stealth configuration and behavioral mimicry engine.

    Coordinates fingerprint management and human-like behavior patterns
    to avoid detection by anti-bot systems.
    """

    # Common viewport sizes (width, height)
    COMMON_VIEWPORTS = [
        (1920, 1080),
        (1366, 768),
        (1536, 864),
        (1440, 900),
        (1280, 720),
        (2560, 1440),
    ]

    # Common user agents (rotate these regularly)
    CHROME_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    ]

    def __init__(self, browser: Browser) -> None:
        self._browser = browser
        self._profiles: dict[str, StealthProfile] = {}

    def generate_profile(
        self,
        account_id: str,
        proxy_country: str = "US",
    ) -> StealthProfile:
        """Generate a consistent stealth profile for an account.

        The profile is deterministically generated from account_id
        for consistency across sessions.

        Args:
            account_id: Unique account identifier.
            proxy_country: Country code for timezone/locale matching.

        Returns:
            StealthProfile with randomized but consistent fingerprint.
        """
        # Use account_id as seed for deterministic randomization
        seed = int(account_id[:8], 16) if account_id else random.randint(0, 2**32)
        rng = random.Random(seed)

        # Select viewport
        viewport = rng.choice(self.COMMON_VIEWPORTS)

        # Select platform-matched user agent and platform string
        platforms = [
            ("Win32", "Windows NT 10.0"),
            ("MacIntel", "Macintosh; Intel Mac OS X 10_15_7"),
        ]
        platform_choice = rng.choice(platforms)

        # Match user agent to platform
        if "Win" in platform_choice[0]:
            user_agent = rng.choice([ua for ua in self.CHROME_USER_AGENTS if "Windows" in ua])
        else:
            user_agent = rng.choice([ua for ua in self.CHROME_USER_AGENTS if "Mac" in ua])

        # Timezone based on proxy country
        timezones = {
            "US": [("America/New_York", -300), ("America/Chicago", -360), ("America/Los_Angeles", -480)],
            "GB": [("Europe/London", 0)],
            "DE": [("Europe/Berlin", 60)],
            "JP": [("Asia/Tokyo", 540)],
        }
        tz_options = timezones.get(proxy_country, [("America/New_York", -300)])
        timezone, offset = rng.choice(tz_options)

        profile = StealthProfile(
            viewport_width=viewport[0],
            viewport_height=viewport[1],
            screen_width=viewport[0] + rng.randint(0, 200),
            screen_height=viewport[1] + rng.randint(0, 100),
            device_pixel_ratio=rng.choice([1.0, 1.25, 1.5, 2.0]),
            platform=platform_choice[0],
            user_agent=user_agent,
            timezone=timezone,
            timezone_offset=offset,
            languages=["en-US", "en"] if proxy_country == "US" else ["en-GB", "en"],
            hardware_concurrency=rng.choice([4, 8, 12, 16]),
            device_memory=rng.choice([4, 8, 16]),
            typing_speed_wpm=rng.randint(30, 80),
            mouse_movement_style=rng.choice(["smooth", "natural", "fast"]),
        )

        self._profiles[account_id] = profile
        return profile

    async def apply_profile(
        self,
        page: Page,
        profile: StealthProfile,
    ) -> None:
        """Apply stealth profile to a page context.

        Args:
            page: Owl Browser page to configure.
            profile: StealthProfile to apply.
        """
        # Set viewport
        await page.set_viewport(
            width=profile.viewport_width,
            height=profile.viewport_height
        )

        # Apply fingerprint overrides via JavaScript injection
        fingerprint_script = f"""
        Object.defineProperty(navigator, 'platform', {{
            get: () => '{profile.platform}'
        }});
        Object.defineProperty(navigator, 'hardwareConcurrency', {{
            get: () => {profile.hardware_concurrency}
        }});
        Object.defineProperty(navigator, 'deviceMemory', {{
            get: () => {profile.device_memory}
        }});
        Object.defineProperty(navigator, 'languages', {{
            get: () => {profile.languages}
        }});
        Object.defineProperty(screen, 'width', {{
            get: () => {profile.screen_width}
        }});
        Object.defineProperty(screen, 'height', {{
            get: () => {profile.screen_height}
        }});
        Object.defineProperty(window, 'devicePixelRatio', {{
            get: () => {profile.device_pixel_ratio}
        }});
        """

        await page.evaluate(fingerprint_script)

    async def human_type(
        self,
        page: Page,
        selector: str,
        text: str,
        profile: StealthProfile,
    ) -> None:
        """Type text with human-like timing variations.

        Args:
            page: Target page.
            selector: Input selector.
            text: Text to type.
            profile: StealthProfile for typing speed.
        """
        # Calculate base delay from WPM
        # Average word length ~5 chars, so chars per minute = WPM * 5
        cpm = profile.typing_speed_wpm * 5
        base_delay_ms = 60000 / cpm  # Milliseconds per character

        for char in text:
            # Add variation to delay
            variation = random.uniform(0.5, 1.5)
            delay = base_delay_ms * variation

            # Occasional longer pauses (thinking)
            if random.random() < 0.05:
                delay += random.uniform(200, 500)

            await page.type(selector, char)
            await page.wait(int(delay))

    async def human_scroll(
        self,
        page: Page,
        target_y: int,
        profile: StealthProfile,
    ) -> None:
        """Scroll to position with human-like behavior.

        Args:
            page: Target page.
            target_y: Target scroll position.
            profile: StealthProfile for movement style.
        """
        # Get current scroll position
        current_y = await page.expression("window.scrollY")
        distance = target_y - current_y

        if abs(distance) < 100:
            await page.scroll_to(x=0, y=target_y)
            return

        # Human scrolling: variable speed, occasional pauses
        steps = random.randint(5, 15)
        for i in range(steps):
            progress = (i + 1) / steps
            # Ease-out curve for natural deceleration
            eased_progress = 1 - (1 - progress) ** 2

            intermediate_y = int(current_y + distance * eased_progress)
            await page.scroll_to(x=0, y=intermediate_y)

            # Variable delay between scroll steps
            delay = random.uniform(30, 100)
            if profile.mouse_movement_style == "smooth":
                delay *= 1.5
            elif profile.mouse_movement_style == "fast":
                delay *= 0.7

            await page.wait(int(delay))

            # Occasional pause to "read"
            if random.random() < 0.1:
                await page.wait(random.randint(500, 1500))

    async def random_mouse_movement(
        self,
        page: Page,
    ) -> None:
        """Perform random mouse movements to simulate human presence."""
        viewport = await page.get_viewport()
        width = viewport.get("width", 1920)
        height = viewport.get("height", 1080)

        # Generate random path
        start_x = random.randint(100, width - 100)
        start_y = random.randint(100, height - 100)
        end_x = random.randint(100, width - 100)
        end_y = random.randint(100, height - 100)

        await page.mouse_move(
            start_x=start_x,
            start_y=start_y,
            end_x=end_x,
            end_y=end_y,
            steps=random.randint(10, 30),
        )
```

## 4. Technical Implementation

### 4.1. Intelligent Infinite Scroll
We use a robust scrolling pattern that detects "skeletons" and loading spinners.

```python
async def scrape_feed_robust(page, max_posts=1000):
    posts = []
    
    while len(posts) < max_posts:
        # 1. Scroll and Wait for stabilization
        await page.scroll_by(0, 1000)
        
        # Custom waiter: waits for network idle OR for specific skeleton elements to disappear
        try:
            await page.wait_for_function(
                "() => document.querySelectorAll('.loading-spinner').length === 0", 
                timeout=5000
            )
        except:
            print("Warning: Loader didn't vanish, checking for content...")

        # 2. Extract using semantic templates
        batch = await page.extract_json(template={
            "items": [{
                "id": "attribute: data-testid='tweet-id'",
                "text": "text content of post",
                "media": "img src"
            }]
        })
        
        # 3. Deduplicate in memory
        new_items = [p for p in batch['items'] if p['id'] not in seen_ids]
        posts.extend(new_items)
        
        # 4. Check for "Rate Limit" or "Login Wall" modals
        if await page.query_page("Is there a login popup blocking the view?"):
            print("Login wall detected. Refreshing context...")
            # Logic to swap proxy/context
            break
```

### 4.2. Multi-Modal Analysis (Video & Image)
Text is only half the story. TrendScope analyzes memes and videos.

*   **Video Fingerprinting:** We extract keyframes from TikToks/Reels.
*   **VLM Analysis:** `page.query_page()` converts visual content into searchable text tags.
    *   *Input:* Video of a person dancing with a soda can.
    *   *Output Tags:* `[dancing, happy, soda, brand:coca-cola, viral_audio:track_id]`

### 4.3. Platform-Specific Scrapers

Each social platform requires tailored extraction logic due to unique DOM structures, authentication requirements, and rate limiting behaviors.

#### 4.3.1. Twitter/X Scraper

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from owl_browser import Browser, RemoteConfig, ProxyConfig

if TYPE_CHECKING:
    from owl_browser import Page


@dataclass(slots=True)
class Tweet:
    """Structured representation of a Twitter post."""
    tweet_id: str
    author_handle: str
    author_display_name: str
    content: str
    timestamp: datetime
    likes: int
    retweets: int
    replies: int
    media_urls: list[str] = field(default_factory=list)
    hashtags: list[str] = field(default_factory=list)
    mentions: list[str] = field(default_factory=list)
    is_retweet: bool = False
    quoted_tweet_id: str | None = None


class TwitterScraper:
    """Production-grade Twitter/X feed and profile scraper.

    Uses Owl Browser SDK for stealth navigation and AI-powered extraction.
    Handles infinite scroll, rate detection, and login walls.
    """

    FEED_SCROLL_INCREMENT: int = 800
    MAX_SCROLL_ATTEMPTS: int = 50
    NETWORK_IDLE_TIMEOUT: int = 3000

    def __init__(
        self,
        browser: Browser,
        proxy_config: ProxyConfig | None = None,
    ) -> None:
        self._browser = browser
        self._proxy_config = proxy_config
        self._seen_ids: set[str] = set()

    async def scrape_user_feed(
        self,
        username: str,
        max_tweets: int = 100,
        include_replies: bool = False,
    ) -> list[Tweet]:
        """Scrape tweets from a user's profile timeline.

        Args:
            username: Twitter handle without @ prefix.
            max_tweets: Maximum number of tweets to collect.
            include_replies: Whether to include reply tweets.

        Returns:
            List of Tweet objects with full metadata.

        Raises:
            ElementNotFoundError: If profile page structure is unrecognized.
            FirewallError: If rate limited or blocked.
        """
        page = self._browser.new_page(proxy=self._proxy_config)
        tweets: list[Tweet] = []

        try:
            # Navigate to user profile
            url = f"https://twitter.com/{username}"
            if not include_replies:
                url = f"https://twitter.com/{username}/with_replies"

            await page.goto(url, wait_until="networkidle", timeout=15000)

            # Wait for initial content to render
            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Check for account suspension or non-existence
            suspension_check = await page.query_page(
                "Is this account suspended or does not exist?"
            )
            if "yes" in suspension_check.lower():
                return []

            scroll_attempts = 0
            while len(tweets) < max_tweets and scroll_attempts < self.MAX_SCROLL_ATTEMPTS:
                # Extract current batch using semantic template
                batch_data = await page.extract_json(template={
                    "tweets": [{
                        "id": "data-tweet-id or article data attribute",
                        "author_handle": "username starting with @",
                        "author_name": "display name of author",
                        "text": "main tweet text content",
                        "timestamp": "time element datetime attribute",
                        "likes": "like count number",
                        "retweets": "retweet count number",
                        "replies": "reply count number",
                        "images": ["image URLs in tweet"],
                        "is_retweet": "boolean if this is a retweet"
                    }]
                })

                # Process and deduplicate
                for raw in batch_data.get("tweets", []):
                    if raw["id"] and raw["id"] not in self._seen_ids:
                        self._seen_ids.add(raw["id"])
                        tweet = self._parse_tweet(raw)
                        tweets.append(tweet)

                # Scroll for more content
                await page.scroll_by(x=0, y=self.FEED_SCROLL_INCREMENT)

                # Wait for new content with spinner detection
                try:
                    await page.wait_for_function(
                        "() => !document.querySelector('[data-testid=\"cellInnerDiv\"] [role=\"progressbar\"]')",
                        timeout=self.NETWORK_IDLE_TIMEOUT
                    )
                except TimeoutError:
                    pass  # Continue anyway, content may have loaded

                # Detect rate limiting modal
                rate_limit_check = await page.query_page(
                    "Is there a rate limit warning or 'Something went wrong' message visible?"
                )
                if "yes" in rate_limit_check.lower():
                    break

                scroll_attempts += 1

            return tweets[:max_tweets]

        finally:
            await page.close()

    async def scrape_tweet_details(
        self,
        tweet_id: str,
        include_replies: bool = True,
        max_replies: int = 50,
    ) -> dict:
        """Extract full details from a single tweet including reply thread.

        Args:
            tweet_id: The numeric tweet ID.
            include_replies: Whether to scrape reply thread.
            max_replies: Maximum replies to collect.

        Returns:
            Dictionary with tweet data and optional replies array.
        """
        page = self._browser.new_page(proxy=self._proxy_config)

        try:
            await page.goto(
                f"https://twitter.com/i/status/{tweet_id}",
                wait_until="networkidle",
                timeout=15000
            )

            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Extract main tweet with AI
            main_tweet = await page.ai_extract(
                "Extract the main tweet: author handle, display name, full text, "
                "timestamp, like count, retweet count, reply count, quote count, "
                "and all media URLs (images/videos)"
            )

            replies: list[dict] = []
            if include_replies:
                scroll_count = 0
                while len(replies) < max_replies and scroll_count < 20:
                    reply_batch = await page.extract_json(template={
                        "replies": [{
                            "id": "reply tweet id",
                            "author": "reply author handle",
                            "text": "reply text content",
                            "likes": "reply like count"
                        }]
                    })

                    for r in reply_batch.get("replies", []):
                        if r["id"] not in self._seen_ids:
                            self._seen_ids.add(r["id"])
                            replies.append(r)

                    await page.scroll_by(x=0, y=600)
                    await page.wait_for_network_idle(idle_time=1500, timeout=5000)
                    scroll_count += 1

            return {
                "tweet": main_tweet,
                "replies": replies[:max_replies]
            }

        finally:
            await page.close()

    async def search_hashtag(
        self,
        hashtag: str,
        max_tweets: int = 200,
        search_type: str = "latest",
    ) -> list[Tweet]:
        """Search for tweets containing a specific hashtag.

        Args:
            hashtag: Hashtag without # prefix.
            max_tweets: Maximum tweets to collect.
            search_type: One of 'latest', 'top', 'people', 'photos', 'videos'.

        Returns:
            List of Tweet objects matching the hashtag.
        """
        page = self._browser.new_page(proxy=self._proxy_config)
        tweets: list[Tweet] = []

        try:
            search_url = f"https://twitter.com/search?q=%23{hashtag}&src=typed_query"
            if search_type == "latest":
                search_url += "&f=live"
            elif search_type == "photos":
                search_url += "&f=image"
            elif search_type == "videos":
                search_url += "&f=video"

            await page.goto(search_url, wait_until="networkidle", timeout=15000)
            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            scroll_attempts = 0
            while len(tweets) < max_tweets and scroll_attempts < self.MAX_SCROLL_ATTEMPTS:
                batch_data = await page.extract_json(template={
                    "tweets": [{
                        "id": "tweet identifier",
                        "author_handle": "author username",
                        "author_name": "author display name",
                        "text": "tweet text content",
                        "timestamp": "tweet time",
                        "engagement": "likes, retweets, replies counts"
                    }]
                })

                for raw in batch_data.get("tweets", []):
                    if raw.get("id") and raw["id"] not in self._seen_ids:
                        self._seen_ids.add(raw["id"])
                        tweet = self._parse_tweet(raw)
                        tweets.append(tweet)

                await page.scroll_by(x=0, y=self.FEED_SCROLL_INCREMENT)
                await page.wait_for_network_idle(idle_time=1500, timeout=5000)
                scroll_attempts += 1

            return tweets[:max_tweets]

        finally:
            await page.close()

    def _parse_tweet(self, raw: dict) -> Tweet:
        """Parse raw extraction data into Tweet dataclass."""
        import re

        text = raw.get("text", "")
        hashtags = re.findall(r"#(\w+)", text)
        mentions = re.findall(r"@(\w+)", text)

        return Tweet(
            tweet_id=raw.get("id", ""),
            author_handle=raw.get("author_handle", "").lstrip("@"),
            author_display_name=raw.get("author_name", ""),
            content=text,
            timestamp=datetime.now(),  # Parse from raw timestamp
            likes=int(raw.get("likes", 0) or 0),
            retweets=int(raw.get("retweets", 0) or 0),
            replies=int(raw.get("replies", 0) or 0),
            media_urls=raw.get("images", []),
            hashtags=hashtags,
            mentions=mentions,
            is_retweet=bool(raw.get("is_retweet")),
        )
```

#### 4.3.2. TikTok Scraper

```python
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from owl_browser import Browser, RemoteConfig, ProxyConfig

if TYPE_CHECKING:
    from owl_browser import Page


@dataclass(slots=True)
class TikTokVideo:
    """Structured representation of a TikTok video."""
    video_id: str
    author_username: str
    author_nickname: str
    description: str
    sound_name: str
    sound_author: str
    likes: int
    comments: int
    shares: int
    views: int
    hashtags: list[str] = field(default_factory=list)
    video_url: str | None = None
    thumbnail_url: str | None = None
    duration_seconds: int = 0
    created_at: datetime | None = None


class TikTokScraper:
    """Production TikTok scraper for videos, profiles, and trending content.

    Handles TikTok's aggressive anti-bot measures through Owl Browser's
    stealth capabilities and residential proxy rotation.
    """

    SCROLL_INCREMENT: int = 600
    MAX_SCROLL_ATTEMPTS: int = 40

    def __init__(
        self,
        browser: Browser,
        proxy_config: ProxyConfig | None = None,
    ) -> None:
        self._browser = browser
        self._proxy_config = proxy_config
        self._seen_ids: set[str] = set()

    async def scrape_user_videos(
        self,
        username: str,
        max_videos: int = 50,
    ) -> list[TikTokVideo]:
        """Scrape videos from a TikTok user's profile.

        Args:
            username: TikTok username without @ prefix.
            max_videos: Maximum number of videos to collect.

        Returns:
            List of TikTokVideo objects with metadata.
        """
        page = self._browser.new_page(proxy=self._proxy_config)
        videos: list[TikTokVideo] = []

        try:
            await page.goto(
                f"https://www.tiktok.com/@{username}",
                wait_until="networkidle",
                timeout=20000
            )

            # TikTok often shows CAPTCHA - handle it
            captcha_detected = await page.detect_captcha()
            if captcha_detected:
                await page.solve_captcha(max_attempts=3)
                await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Wait for video grid to load
            await page.wait_for_selector(
                "[data-e2e='user-post-item']",
                timeout=10000
            )

            # Extract profile metadata first
            profile_info = await page.ai_extract(
                "Extract profile info: follower count, following count, "
                "total likes, bio description, verified status"
            )

            scroll_attempts = 0
            while len(videos) < max_videos and scroll_attempts < self.MAX_SCROLL_ATTEMPTS:
                # Extract video cards from grid
                batch_data = await page.extract_json(template={
                    "videos": [{
                        "id": "video ID from href or data attribute",
                        "description": "video caption text",
                        "views": "view count",
                        "thumbnail": "thumbnail image URL"
                    }]
                })

                for raw in batch_data.get("videos", []):
                    video_id = raw.get("id", "")
                    if video_id and video_id not in self._seen_ids:
                        self._seen_ids.add(video_id)
                        video = TikTokVideo(
                            video_id=video_id,
                            author_username=username,
                            author_nickname="",
                            description=raw.get("description", ""),
                            sound_name="",
                            sound_author="",
                            likes=0,
                            comments=0,
                            shares=0,
                            views=self._parse_count(raw.get("views", "0")),
                            hashtags=re.findall(r"#(\w+)", raw.get("description", "")),
                            thumbnail_url=raw.get("thumbnail"),
                        )
                        videos.append(video)

                await page.scroll_by(x=0, y=self.SCROLL_INCREMENT)
                await page.wait_for_network_idle(idle_time=1500, timeout=5000)
                scroll_attempts += 1

            return videos[:max_videos]

        finally:
            await page.close()

    async def scrape_video_details(
        self,
        video_url: str,
        include_comments: bool = True,
        max_comments: int = 100,
    ) -> dict:
        """Extract full metadata and comments from a single TikTok video.

        Args:
            video_url: Full TikTok video URL.
            include_comments: Whether to scrape comments.
            max_comments: Maximum comments to collect.

        Returns:
            Dictionary with video metadata and comments array.
        """
        page = self._browser.new_page(proxy=self._proxy_config)

        try:
            await page.goto(video_url, wait_until="networkidle", timeout=20000)

            # Handle potential CAPTCHA
            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=3)
                await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Use AI to extract comprehensive video metadata
            video_data = await page.ai_extract(
                "Extract all video metadata: author username, author nickname, "
                "video description/caption, sound name, sound author, "
                "like count, comment count, share count, save count, "
                "all hashtags, and video duration"
            )

            # Analyze video content using VLM
            visual_analysis = await page.query_page(
                "Describe what is happening in this video. Include: "
                "main subjects, actions, objects, text overlays, brands visible, "
                "emotional tone, and content category (dance, comedy, tutorial, etc.)"
            )
            video_data["visual_analysis"] = visual_analysis

            comments: list[dict] = []
            if include_comments:
                # Click to expand comments if needed
                try:
                    await page.click("comments button or icon")
                    await page.wait_for_network_idle(idle_time=1500, timeout=5000)
                except Exception:
                    pass  # Comments may already be visible

                scroll_count = 0
                while len(comments) < max_comments and scroll_count < 30:
                    comment_batch = await page.extract_json(template={
                        "comments": [{
                            "id": "comment identifier",
                            "author": "commenter username",
                            "text": "comment text",
                            "likes": "comment like count",
                            "replies_count": "number of replies",
                            "timestamp": "when posted"
                        }]
                    })

                    for c in comment_batch.get("comments", []):
                        if c.get("id") and c["id"] not in self._seen_ids:
                            self._seen_ids.add(c["id"])
                            comments.append(c)

                    # Scroll within comments section
                    await page.scroll_by(x=0, y=400)
                    await page.wait_for_network_idle(idle_time=1000, timeout=3000)
                    scroll_count += 1

            return {
                "video": video_data,
                "comments": comments[:max_comments]
            }

        finally:
            await page.close()

    async def scrape_trending(
        self,
        max_videos: int = 30,
    ) -> list[TikTokVideo]:
        """Scrape videos from TikTok's Discover/Trending page.

        Args:
            max_videos: Maximum trending videos to collect.

        Returns:
            List of trending TikTokVideo objects.
        """
        page = self._browser.new_page(proxy=self._proxy_config)
        videos: list[TikTokVideo] = []

        try:
            await page.goto(
                "https://www.tiktok.com/explore",
                wait_until="networkidle",
                timeout=20000
            )

            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=3)

            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Extract trending hashtags and sounds
            trending_meta = await page.ai_extract(
                "Extract trending hashtags and trending sounds visible on the page"
            )

            scroll_attempts = 0
            while len(videos) < max_videos and scroll_attempts < 20:
                batch_data = await page.extract_json(template={
                    "videos": [{
                        "id": "video identifier",
                        "author": "creator username",
                        "description": "video caption",
                        "views": "view count",
                        "likes": "like count"
                    }]
                })

                for raw in batch_data.get("videos", []):
                    if raw.get("id") and raw["id"] not in self._seen_ids:
                        self._seen_ids.add(raw["id"])
                        video = TikTokVideo(
                            video_id=raw["id"],
                            author_username=raw.get("author", ""),
                            author_nickname="",
                            description=raw.get("description", ""),
                            sound_name="",
                            sound_author="",
                            likes=self._parse_count(raw.get("likes", "0")),
                            comments=0,
                            shares=0,
                            views=self._parse_count(raw.get("views", "0")),
                            hashtags=re.findall(r"#(\w+)", raw.get("description", "")),
                        )
                        videos.append(video)

                await page.scroll_by(x=0, y=self.SCROLL_INCREMENT)
                await page.wait_for_network_idle(idle_time=1500, timeout=5000)
                scroll_attempts += 1

            return videos[:max_videos]

        finally:
            await page.close()

    def _parse_count(self, count_str: str) -> int:
        """Parse TikTok's abbreviated counts (e.g., '1.2M' -> 1200000)."""
        if not count_str:
            return 0

        count_str = str(count_str).strip().upper()
        multipliers = {"K": 1_000, "M": 1_000_000, "B": 1_000_000_000}

        for suffix, multiplier in multipliers.items():
            if suffix in count_str:
                try:
                    return int(float(count_str.replace(suffix, "")) * multiplier)
                except ValueError:
                    return 0

        try:
            return int(count_str.replace(",", ""))
        except ValueError:
            return 0
```

#### 4.3.3. LinkedIn Scraper (Authenticated)

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from owl_browser import Browser, RemoteConfig, ProxyConfig

if TYPE_CHECKING:
    from owl_browser import Page


@dataclass(slots=True)
class LinkedInPost:
    """Structured representation of a LinkedIn post."""
    post_id: str
    author_name: str
    author_headline: str
    author_profile_url: str
    content: str
    likes: int
    comments: int
    reposts: int
    timestamp: str
    post_type: Literal["text", "image", "video", "article", "poll", "document"]
    media_urls: list[str] = field(default_factory=list)
    hashtags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class LinkedInProfile:
    """Structured representation of a LinkedIn profile."""
    profile_url: str
    full_name: str
    headline: str
    location: str
    about: str
    follower_count: int
    connection_count: int
    experience: list[dict] = field(default_factory=list)
    education: list[dict] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)


class LinkedInScraper:
    """Production LinkedIn scraper requiring authenticated sessions.

    LinkedIn has aggressive anti-scraping measures. This scraper:
    - Requires pre-authenticated profile sessions
    - Implements human-like delays between actions
    - Uses profile persistence for session management
    """

    SCROLL_INCREMENT: int = 500
    ACTION_DELAY_MS: int = 2000  # Minimum delay between actions

    def __init__(
        self,
        browser: Browser,
        profile_path: str,
        proxy_config: ProxyConfig | None = None,
    ) -> None:
        """Initialize LinkedIn scraper with authenticated profile.

        Args:
            browser: Owl Browser instance.
            profile_path: Path to saved authenticated browser profile.
            proxy_config: Optional proxy configuration.
        """
        self._browser = browser
        self._profile_path = profile_path
        self._proxy_config = proxy_config
        self._seen_ids: set[str] = set()

    async def login(
        self,
        email: str,
        password: str,
        profile_save_path: str,
    ) -> bool:
        """Perform LinkedIn login and save session profile.

        Args:
            email: LinkedIn account email.
            password: LinkedIn account password.
            profile_save_path: Path to save authenticated profile.

        Returns:
            True if login successful, False otherwise.
        """
        page = self._browser.new_page(proxy=self._proxy_config)

        try:
            await page.goto(
                "https://www.linkedin.com/login",
                wait_until="networkidle",
                timeout=15000
            )

            # Type credentials with human-like delays
            await page.type("username input field", email)
            await page.wait(500)
            await page.type("password input field", password)
            await page.wait(500)

            # Click sign in
            await page.click("Sign in button")

            # Wait for navigation
            await page.wait_for_network_idle(idle_time=3000, timeout=30000)

            # Check for CAPTCHA or verification
            if await page.detect_captcha():
                solved = await page.solve_captcha(max_attempts=3)
                if not solved:
                    return False
                await page.wait_for_network_idle(idle_time=3000, timeout=15000)

            # Check for 2FA or verification challenges
            challenge_check = await page.query_page(
                "Is there a verification challenge, security check, or 2FA prompt?"
            )
            if "yes" in challenge_check.lower():
                # Cannot proceed without manual intervention
                return False

            # Verify successful login by checking for feed
            current_url = await page.get_current_url()
            if "feed" in current_url or "mynetwork" in current_url:
                # Save authenticated profile
                await page.save_profile(profile_save_path)
                self._profile_path = profile_save_path
                return True

            return False

        finally:
            await page.close()

    async def scrape_feed(
        self,
        max_posts: int = 50,
    ) -> list[LinkedInPost]:
        """Scrape posts from the authenticated user's feed.

        Args:
            max_posts: Maximum number of posts to collect.

        Returns:
            List of LinkedInPost objects.
        """
        page = self._browser.new_page(
            proxy=self._proxy_config,
            profile_path=self._profile_path
        )
        posts: list[LinkedInPost] = []

        try:
            # Load profile to restore session
            await page.load_profile(self._profile_path)

            await page.goto(
                "https://www.linkedin.com/feed/",
                wait_until="networkidle",
                timeout=20000
            )

            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Verify we're logged in
            login_check = await page.query_page(
                "Is this a logged-in LinkedIn feed showing posts?"
            )
            if "no" in login_check.lower():
                raise PermissionError("LinkedIn session expired or invalid")

            scroll_attempts = 0
            while len(posts) < max_posts and scroll_attempts < 30:
                # Extract posts using semantic template
                batch_data = await page.extract_json(template={
                    "posts": [{
                        "id": "post URN or unique identifier",
                        "author_name": "post author full name",
                        "author_headline": "author job title/headline",
                        "author_url": "link to author profile",
                        "content": "post text content",
                        "likes": "reaction count",
                        "comments": "comment count",
                        "reposts": "repost/share count",
                        "timestamp": "when posted (e.g., 2h, 1d)",
                        "post_type": "text, image, video, article, poll",
                        "media": ["image or video URLs"]
                    }]
                })

                for raw in batch_data.get("posts", []):
                    post_id = raw.get("id", "")
                    if post_id and post_id not in self._seen_ids:
                        self._seen_ids.add(post_id)
                        post = self._parse_post(raw)
                        posts.append(post)

                # Human-like scroll with delay
                await page.scroll_by(x=0, y=self.SCROLL_INCREMENT)
                await page.wait(self.ACTION_DELAY_MS)
                await page.wait_for_network_idle(idle_time=1500, timeout=5000)
                scroll_attempts += 1

            # Update profile cookies before closing
            await page.update_profile_cookies()

            return posts[:max_posts]

        finally:
            await page.close()

    async def scrape_profile(
        self,
        profile_url: str,
    ) -> LinkedInProfile:
        """Scrape detailed information from a LinkedIn profile.

        Args:
            profile_url: Full LinkedIn profile URL.

        Returns:
            LinkedInProfile object with comprehensive data.
        """
        page = self._browser.new_page(
            proxy=self._proxy_config,
            profile_path=self._profile_path
        )

        try:
            await page.load_profile(self._profile_path)

            await page.goto(profile_url, wait_until="networkidle", timeout=20000)
            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Use AI to extract comprehensive profile data
            profile_data = await page.ai_extract(
                "Extract complete LinkedIn profile: full name, headline, "
                "location, about/summary section, follower count, "
                "connection count (500+ counts as 500)"
            )

            # Scroll to load experience section
            await page.scroll_to_element("Experience section")
            await page.wait_for_network_idle(idle_time=1500, timeout=5000)

            experience_data = await page.extract_json(template={
                "experience": [{
                    "title": "job title",
                    "company": "company name",
                    "duration": "employment duration",
                    "location": "job location",
                    "description": "role description"
                }]
            })

            # Scroll to education
            await page.scroll_to_element("Education section")
            await page.wait_for_network_idle(idle_time=1500, timeout=5000)

            education_data = await page.extract_json(template={
                "education": [{
                    "school": "institution name",
                    "degree": "degree type and field",
                    "years": "attendance years"
                }]
            })

            # Extract skills if visible
            skills_data = await page.ai_extract(
                "List all visible skills from the Skills section"
            )

            return LinkedInProfile(
                profile_url=profile_url,
                full_name=profile_data.get("full_name", ""),
                headline=profile_data.get("headline", ""),
                location=profile_data.get("location", ""),
                about=profile_data.get("about", ""),
                follower_count=int(profile_data.get("follower_count", 0) or 0),
                connection_count=int(profile_data.get("connection_count", 0) or 0),
                experience=experience_data.get("experience", []),
                education=education_data.get("education", []),
                skills=skills_data if isinstance(skills_data, list) else [],
            )

        finally:
            await page.close()

    async def scrape_company_page(
        self,
        company_url: str,
        include_posts: bool = True,
        max_posts: int = 20,
    ) -> dict:
        """Scrape a LinkedIn company page.

        Args:
            company_url: LinkedIn company page URL.
            include_posts: Whether to scrape recent company posts.
            max_posts: Maximum company posts to collect.

        Returns:
            Dictionary with company info and optional posts.
        """
        page = self._browser.new_page(
            proxy=self._proxy_config,
            profile_path=self._profile_path
        )

        try:
            await page.load_profile(self._profile_path)

            await page.goto(company_url, wait_until="networkidle", timeout=20000)
            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Extract company overview
            company_info = await page.ai_extract(
                "Extract company information: name, industry, company size, "
                "headquarters location, founded year, specialties, "
                "follower count, employee count on LinkedIn, website URL"
            )

            posts: list[dict] = []
            if include_posts:
                # Navigate to posts tab
                try:
                    await page.click("Posts tab")
                    await page.wait_for_network_idle(idle_time=2000, timeout=10000)
                except Exception:
                    pass  # May already be on posts or tab not visible

                scroll_count = 0
                while len(posts) < max_posts and scroll_count < 15:
                    post_batch = await page.extract_json(template={
                        "posts": [{
                            "content": "post text",
                            "likes": "reaction count",
                            "comments": "comment count",
                            "timestamp": "post time"
                        }]
                    })

                    posts.extend(post_batch.get("posts", []))

                    await page.scroll_by(x=0, y=self.SCROLL_INCREMENT)
                    await page.wait(self.ACTION_DELAY_MS)
                    scroll_count += 1

            return {
                "company": company_info,
                "posts": posts[:max_posts]
            }

        finally:
            await page.close()

    def _parse_post(self, raw: dict) -> LinkedInPost:
        """Parse raw extraction data into LinkedInPost dataclass."""
        import re

        content = raw.get("content", "")
        hashtags = re.findall(r"#(\w+)", content)

        post_type_map = {
            "text": "text",
            "image": "image",
            "video": "video",
            "article": "article",
            "poll": "poll",
            "document": "document",
        }
        raw_type = raw.get("post_type", "text").lower()
        post_type = post_type_map.get(raw_type, "text")

        return LinkedInPost(
            post_id=raw.get("id", ""),
            author_name=raw.get("author_name", ""),
            author_headline=raw.get("author_headline", ""),
            author_profile_url=raw.get("author_url", ""),
            content=content,
            likes=int(raw.get("likes", 0) or 0),
            comments=int(raw.get("comments", 0) or 0),
            reposts=int(raw.get("reposts", 0) or 0),
            timestamp=raw.get("timestamp", ""),
            post_type=post_type,
            media_urls=raw.get("media", []),
            hashtags=hashtags,
        )
```

#### 4.3.4. Instagram Scraper

```python
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from owl_browser import Browser, RemoteConfig, ProxyConfig

if TYPE_CHECKING:
    from owl_browser import Page


@dataclass(slots=True)
class InstagramPost:
    """Structured representation of an Instagram post."""
    post_id: str
    shortcode: str
    author_username: str
    caption: str
    likes: int
    comments: int
    post_type: Literal["image", "video", "carousel", "reel"]
    media_urls: list[str] = field(default_factory=list)
    hashtags: list[str] = field(default_factory=list)
    mentions: list[str] = field(default_factory=list)
    location: str | None = None
    timestamp: datetime | None = None


@dataclass(slots=True)
class InstagramProfile:
    """Structured representation of an Instagram profile."""
    username: str
    full_name: str
    bio: str
    external_url: str | None
    follower_count: int
    following_count: int
    post_count: int
    is_verified: bool
    is_private: bool
    profile_pic_url: str | None = None


class InstagramScraper:
    """Production Instagram scraper for posts, stories, reels, and profiles.

    Instagram requires careful handling due to:
    - Aggressive rate limiting
    - Login walls after limited browsing
    - Dynamic content loading
    """

    SCROLL_INCREMENT: int = 600
    MAX_SCROLL_ATTEMPTS: int = 35

    def __init__(
        self,
        browser: Browser,
        proxy_config: ProxyConfig | None = None,
        profile_path: str | None = None,
    ) -> None:
        self._browser = browser
        self._proxy_config = proxy_config
        self._profile_path = profile_path
        self._seen_ids: set[str] = set()

    async def login(
        self,
        username: str,
        password: str,
        profile_save_path: str,
    ) -> bool:
        """Perform Instagram login and save session.

        Args:
            username: Instagram username.
            password: Instagram password.
            profile_save_path: Path to save authenticated profile.

        Returns:
            True if login successful.
        """
        page = self._browser.new_page(proxy=self._proxy_config)

        try:
            await page.goto(
                "https://www.instagram.com/accounts/login/",
                wait_until="networkidle",
                timeout=20000
            )

            # Handle cookie consent if present
            try:
                await page.click("Accept cookies button")
                await page.wait(1000)
            except Exception:
                pass

            # Wait for login form
            await page.wait_for_selector("username input", timeout=10000)

            # Enter credentials
            await page.type("username input", username)
            await page.wait(500)
            await page.type("password input", password)
            await page.wait(500)

            # Submit login
            await page.click("Log in button")

            await page.wait_for_network_idle(idle_time=3000, timeout=30000)

            # Handle CAPTCHA if present
            if await page.detect_captcha():
                solved = await page.solve_captcha(max_attempts=3)
                if not solved:
                    return False

            # Check for "Save Login Info" prompt and dismiss
            save_info_check = await page.query_page(
                "Is there a 'Save Your Login Info' or 'Turn on Notifications' prompt?"
            )
            if "yes" in save_info_check.lower():
                await page.click("Not Now button")
                await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Verify login success
            current_url = await page.get_current_url()
            if "login" not in current_url and "challenge" not in current_url:
                await page.save_profile(profile_save_path)
                self._profile_path = profile_save_path
                return True

            return False

        finally:
            await page.close()

    async def scrape_user_posts(
        self,
        username: str,
        max_posts: int = 50,
    ) -> list[InstagramPost]:
        """Scrape posts from an Instagram user's profile grid.

        Args:
            username: Instagram username.
            max_posts: Maximum posts to collect.

        Returns:
            List of InstagramPost objects.
        """
        page = self._browser.new_page(
            proxy=self._proxy_config,
            profile_path=self._profile_path
        )
        posts: list[InstagramPost] = []

        try:
            if self._profile_path:
                await page.load_profile(self._profile_path)

            await page.goto(
                f"https://www.instagram.com/{username}/",
                wait_until="networkidle",
                timeout=20000
            )

            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Check for private account
            private_check = await page.query_page(
                "Is this account private and showing 'This Account is Private'?"
            )
            if "yes" in private_check.lower():
                return []  # Cannot scrape private accounts without following

            # Check for login wall
            login_wall = await page.query_page(
                "Is there a login popup or 'Log in to continue' message?"
            )
            if "yes" in login_wall.lower():
                if not self._profile_path:
                    return []  # Need authentication
                # Try to dismiss
                await page.press_key("Escape")
                await page.wait(500)

            scroll_attempts = 0
            while len(posts) < max_posts and scroll_attempts < self.MAX_SCROLL_ATTEMPTS:
                # Extract post grid items
                batch_data = await page.extract_json(template={
                    "posts": [{
                        "shortcode": "post shortcode from href (e.g., /p/ABC123/)",
                        "thumbnail": "post thumbnail image URL",
                        "type": "image, video, or carousel indicator",
                        "likes_or_views": "like or view count if visible"
                    }]
                })

                for raw in batch_data.get("posts", []):
                    shortcode = raw.get("shortcode", "")
                    if shortcode and shortcode not in self._seen_ids:
                        self._seen_ids.add(shortcode)
                        post = InstagramPost(
                            post_id=shortcode,
                            shortcode=shortcode,
                            author_username=username,
                            caption="",  # Need to visit post for full caption
                            likes=0,
                            comments=0,
                            post_type=self._determine_post_type(raw.get("type", "")),
                            media_urls=[raw.get("thumbnail", "")],
                        )
                        posts.append(post)

                await page.scroll_by(x=0, y=self.SCROLL_INCREMENT)

                # Wait for lazy-loaded images
                try:
                    await page.wait_for_function(
                        "() => !document.querySelector('svg[aria-label=\"Loading...\"]')",
                        timeout=3000
                    )
                except TimeoutError:
                    pass

                await page.wait_for_network_idle(idle_time=1500, timeout=5000)
                scroll_attempts += 1

            return posts[:max_posts]

        finally:
            await page.close()

    async def scrape_post_details(
        self,
        shortcode: str,
        include_comments: bool = True,
        max_comments: int = 50,
    ) -> dict:
        """Scrape full details from a single Instagram post.

        Args:
            shortcode: Instagram post shortcode.
            include_comments: Whether to scrape comments.
            max_comments: Maximum comments to collect.

        Returns:
            Dictionary with post data and comments.
        """
        page = self._browser.new_page(
            proxy=self._proxy_config,
            profile_path=self._profile_path
        )

        try:
            if self._profile_path:
                await page.load_profile(self._profile_path)

            await page.goto(
                f"https://www.instagram.com/p/{shortcode}/",
                wait_until="networkidle",
                timeout=20000
            )

            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Extract comprehensive post data using AI
            post_data = await page.ai_extract(
                "Extract Instagram post details: author username, full caption text, "
                "like count, comment count, post date, location tag if any, "
                "all hashtags, all @mentions, and whether it's image/video/carousel/reel"
            )

            # Get all media URLs for carousels
            media_urls: list[str] = []
            is_carousel = await page.query_page(
                "Is this a carousel post with multiple images/videos (has navigation arrows)?"
            )

            if "yes" in is_carousel.lower():
                # Navigate through carousel
                for _ in range(10):  # Max 10 slides
                    media_batch = await page.extract_json(template={
                        "media": ["current visible image or video URL"]
                    })
                    media_urls.extend(media_batch.get("media", []))

                    # Try to go to next slide
                    try:
                        await page.click("Next button or right arrow")
                        await page.wait(800)
                    except Exception:
                        break  # No more slides
            else:
                # Single media post
                media_batch = await page.extract_json(template={
                    "media": ["image or video URL"]
                })
                media_urls = media_batch.get("media", [])

            # Visual content analysis
            visual_analysis = await page.query_page(
                "Describe the visual content: subjects, objects, scene, "
                "colors, mood, any visible text, brands, or products"
            )
            post_data["visual_analysis"] = visual_analysis

            comments: list[dict] = []
            if include_comments:
                # Load more comments if available
                try:
                    load_more_count = 0
                    while load_more_count < 5:
                        await page.click("Load more comments button")
                        await page.wait_for_network_idle(idle_time=1500, timeout=5000)
                        load_more_count += 1
                except Exception:
                    pass  # All comments loaded or button not found

                comment_batch = await page.extract_json(template={
                    "comments": [{
                        "author": "commenter username",
                        "text": "comment text",
                        "likes": "comment like count",
                        "timestamp": "when posted"
                    }]
                })
                comments = comment_batch.get("comments", [])[:max_comments]

            return {
                "post": post_data,
                "media_urls": list(set(media_urls)),  # Dedupe
                "comments": comments
            }

        finally:
            await page.close()

    async def scrape_profile(
        self,
        username: str,
    ) -> InstagramProfile:
        """Scrape Instagram profile metadata.

        Args:
            username: Instagram username.

        Returns:
            InstagramProfile object.
        """
        page = self._browser.new_page(
            proxy=self._proxy_config,
            profile_path=self._profile_path
        )

        try:
            if self._profile_path:
                await page.load_profile(self._profile_path)

            await page.goto(
                f"https://www.instagram.com/{username}/",
                wait_until="networkidle",
                timeout=20000
            )

            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Extract profile data using AI
            profile_data = await page.ai_extract(
                "Extract Instagram profile: full name, bio text, external URL link, "
                "follower count, following count, post count, "
                "verified badge status (yes/no), private account status (yes/no), "
                "profile picture URL"
            )

            return InstagramProfile(
                username=username,
                full_name=profile_data.get("full_name", ""),
                bio=profile_data.get("bio", ""),
                external_url=profile_data.get("external_url"),
                follower_count=self._parse_count(profile_data.get("follower_count", "0")),
                following_count=self._parse_count(profile_data.get("following_count", "0")),
                post_count=self._parse_count(profile_data.get("post_count", "0")),
                is_verified="yes" in str(profile_data.get("verified", "no")).lower(),
                is_private="yes" in str(profile_data.get("private", "no")).lower(),
                profile_pic_url=profile_data.get("profile_picture"),
            )

        finally:
            await page.close()

    async def scrape_hashtag(
        self,
        hashtag: str,
        max_posts: int = 100,
        section: Literal["top", "recent"] = "recent",
    ) -> list[InstagramPost]:
        """Scrape posts from a hashtag page.

        Args:
            hashtag: Hashtag without # prefix.
            max_posts: Maximum posts to collect.
            section: 'top' for top posts, 'recent' for recent posts.

        Returns:
            List of InstagramPost objects.
        """
        page = self._browser.new_page(
            proxy=self._proxy_config,
            profile_path=self._profile_path
        )
        posts: list[InstagramPost] = []

        try:
            if self._profile_path:
                await page.load_profile(self._profile_path)

            await page.goto(
                f"https://www.instagram.com/explore/tags/{hashtag}/",
                wait_until="networkidle",
                timeout=20000
            )

            await page.wait_for_network_idle(idle_time=2000, timeout=10000)

            # Get hashtag stats
            hashtag_info = await page.ai_extract(
                "Extract hashtag page info: total post count for this hashtag"
            )

            # Scroll to recent posts section if needed
            if section == "recent":
                await page.scroll_to_element("Recent posts section")
                await page.wait(1000)

            scroll_attempts = 0
            while len(posts) < max_posts and scroll_attempts < self.MAX_SCROLL_ATTEMPTS:
                batch_data = await page.extract_json(template={
                    "posts": [{
                        "shortcode": "post shortcode from link",
                        "thumbnail": "thumbnail URL",
                        "engagement": "likes or views indicator"
                    }]
                })

                for raw in batch_data.get("posts", []):
                    shortcode = raw.get("shortcode", "")
                    if shortcode and shortcode not in self._seen_ids:
                        self._seen_ids.add(shortcode)
                        post = InstagramPost(
                            post_id=shortcode,
                            shortcode=shortcode,
                            author_username="",  # Need post details for author
                            caption="",
                            likes=0,
                            comments=0,
                            post_type="image",
                            media_urls=[raw.get("thumbnail", "")],
                            hashtags=[hashtag],
                        )
                        posts.append(post)

                await page.scroll_by(x=0, y=self.SCROLL_INCREMENT)
                await page.wait_for_network_idle(idle_time=1500, timeout=5000)
                scroll_attempts += 1

            return posts[:max_posts]

        finally:
            await page.close()

    def _determine_post_type(
        self,
        type_indicator: str,
    ) -> Literal["image", "video", "carousel", "reel"]:
        """Determine post type from extraction indicator."""
        indicator = type_indicator.lower()
        if "carousel" in indicator or "multiple" in indicator:
            return "carousel"
        if "reel" in indicator:
            return "reel"
        if "video" in indicator:
            return "video"
        return "image"

    def _parse_count(self, count_str: str) -> int:
        """Parse Instagram's abbreviated counts."""
        if not count_str:
            return 0

        count_str = str(count_str).strip().upper().replace(",", "")
        multipliers = {"K": 1_000, "M": 1_000_000, "B": 1_000_000_000}

        for suffix, multiplier in multipliers.items():
            if suffix in count_str:
                try:
                    return int(float(count_str.replace(suffix, "")) * multiplier)
                except ValueError:
                    return 0

        try:
            return int(count_str)
        except ValueError:
            return 0
```

## 5. Content Analysis Pipeline

The content analysis pipeline processes scraped data through sentiment analysis, entity extraction, and multi-modal understanding.

### 5.1. Sentiment Analysis Integration

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    from owl_browser import Page


class SentimentLabel(Enum):
    """Sentiment classification labels."""
    VERY_NEGATIVE = -2
    NEGATIVE = -1
    NEUTRAL = 0
    POSITIVE = 1
    VERY_POSITIVE = 2


@dataclass(slots=True)
class SentimentResult:
    """Result of sentiment analysis."""
    label: SentimentLabel
    score: float  # -1.0 to 1.0
    confidence: float  # 0.0 to 1.0
    emotions: dict[str, float]  # emotion -> intensity


@dataclass(slots=True)
class EntityExtraction:
    """Extracted entities from content."""
    hashtags: list[str]
    mentions: list[str]
    urls: list[str]
    brands: list[str]
    products: list[str]
    locations: list[str]
    persons: list[str]
    organizations: list[str]


class ContentAnalyzer:
    """Multi-modal content analysis pipeline.

    Combines text sentiment, entity extraction, and visual analysis
    using both local models and Owl Browser's VLM capabilities.
    """

    def __init__(
        self,
        sentiment_model_path: str | None = None,
        use_gpu: bool = True,
    ) -> None:
        """Initialize content analyzer.

        Args:
            sentiment_model_path: Path to fine-tuned sentiment model.
            use_gpu: Whether to use GPU acceleration.
        """
        self._sentiment_model = None
        self._ner_model = None
        self._use_gpu = use_gpu

        # Lazy load models
        self._models_loaded = False

    async def analyze_text(
        self,
        text: str,
        language: str = "en",
    ) -> tuple[SentimentResult, EntityExtraction]:
        """Analyze text content for sentiment and entities.

        Args:
            text: Text content to analyze.
            language: Language code for analysis.

        Returns:
            Tuple of (SentimentResult, EntityExtraction).
        """
        if not self._models_loaded:
            await self._load_models()

        # Run sentiment and NER in parallel
        sentiment_task = asyncio.create_task(
            self._analyze_sentiment(text, language)
        )
        entity_task = asyncio.create_task(
            self._extract_entities(text, language)
        )

        sentiment, entities = await asyncio.gather(sentiment_task, entity_task)
        return sentiment, entities

    async def analyze_visual_content(
        self,
        page: Page,
        include_ocr: bool = True,
    ) -> dict[str, Any]:
        """Analyze visual content using Owl Browser's VLM.

        Args:
            page: Page with visual content to analyze.
            include_ocr: Whether to extract text from images.

        Returns:
            Dictionary with visual analysis results.
        """
        # Use Owl Browser's built-in VLM for comprehensive analysis
        visual_description = await page.query_page(
            "Describe this image/video in detail. Include: "
            "1) Main subjects and their actions "
            "2) Objects and products visible "
            "3) Brands or logos "
            "4) Text or captions "
            "5) Emotional tone and mood "
            "6) Setting and context "
            "7) Color palette and aesthetic style"
        )

        # Brand detection
        brand_analysis = await page.query_page(
            "List all brands, logos, or products visible in this content. "
            "For each, indicate: brand name, product type, prominence level (high/medium/low)"
        )

        # Content categorization
        category_analysis = await page.query_page(
            "Categorize this content. Primary category and subcategories from: "
            "entertainment, news, tutorial, product_review, lifestyle, "
            "sports, gaming, food, travel, fashion, technology, politics, "
            "comedy, music, dance, art, education, business"
        )

        # Sentiment from visual cues
        visual_sentiment = await page.query_page(
            "Analyze the emotional tone of this visual content. "
            "Rate on scale: very_negative, negative, neutral, positive, very_positive. "
            "Also identify specific emotions: joy, sadness, anger, fear, surprise, disgust"
        )

        result: dict[str, Any] = {
            "description": visual_description,
            "brands": self._parse_brand_response(brand_analysis),
            "categories": self._parse_category_response(category_analysis),
            "visual_sentiment": self._parse_sentiment_response(visual_sentiment),
        }

        if include_ocr:
            # Extract text from images using VLM
            ocr_text = await page.query_page(
                "Extract all text visible in this image, including: "
                "captions, watermarks, overlays, signs, and labels. "
                "Preserve the original text exactly."
            )
            result["ocr_text"] = ocr_text

        return result

    async def generate_embeddings(
        self,
        text: str | None = None,
        image_url: str | None = None,
    ) -> np.ndarray:
        """Generate CLIP embeddings for text or images.

        Args:
            text: Optional text to embed.
            image_url: Optional image URL to embed.

        Returns:
            numpy array of embedding vector (512 or 768 dimensions).
        """
        # In production, use sentence-transformers or OpenCLIP
        # This is a placeholder for the embedding generation
        raise NotImplementedError(
            "Implement with sentence-transformers or OpenCLIP"
        )

    async def batch_analyze(
        self,
        items: list[dict[str, Any]],
        batch_size: int = 32,
    ) -> list[dict[str, Any]]:
        """Batch analyze multiple content items efficiently.

        Args:
            items: List of content items with 'text' and optional 'image_url'.
            batch_size: Number of items to process in parallel.

        Returns:
            List of analysis results.
        """
        results: list[dict[str, Any]] = []

        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]

            # Process batch in parallel
            tasks = [
                self.analyze_text(item.get("text", ""))
                for item in batch
            ]

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for item, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    results.append({
                        "id": item.get("id"),
                        "error": str(result),
                    })
                else:
                    sentiment, entities = result
                    results.append({
                        "id": item.get("id"),
                        "sentiment": {
                            "label": sentiment.label.name,
                            "score": sentiment.score,
                            "confidence": sentiment.confidence,
                            "emotions": sentiment.emotions,
                        },
                        "entities": {
                            "hashtags": entities.hashtags,
                            "mentions": entities.mentions,
                            "brands": entities.brands,
                            "locations": entities.locations,
                        },
                    })

        return results

    async def _load_models(self) -> None:
        """Lazy load ML models."""
        # Load sentiment model (e.g., cardiffnlp/twitter-roberta-base-sentiment)
        # Load NER model (e.g., dslim/bert-base-NER)
        self._models_loaded = True

    async def _analyze_sentiment(
        self,
        text: str,
        language: str,
    ) -> SentimentResult:
        """Run sentiment analysis on text."""
        # Placeholder - implement with transformers pipeline
        # Example with cardiffnlp/twitter-roberta-base-sentiment-latest
        return SentimentResult(
            label=SentimentLabel.NEUTRAL,
            score=0.0,
            confidence=0.0,
            emotions={},
        )

    async def _extract_entities(
        self,
        text: str,
        language: str,
    ) -> EntityExtraction:
        """Extract named entities from text."""
        import re

        # Regex-based extraction for social media entities
        hashtags = re.findall(r"#(\w+)", text)
        mentions = re.findall(r"@(\w+)", text)
        urls = re.findall(r"https?://\S+", text)

        # For brands, locations, persons - use NER model
        # Placeholder implementation
        return EntityExtraction(
            hashtags=hashtags,
            mentions=mentions,
            urls=urls,
            brands=[],
            products=[],
            locations=[],
            persons=[],
            organizations=[],
        )

    def _parse_brand_response(self, response: str) -> list[dict[str, str]]:
        """Parse brand detection response."""
        # Parse structured response from VLM
        return []

    def _parse_category_response(self, response: str) -> list[str]:
        """Parse category response."""
        return []

    def _parse_sentiment_response(self, response: str) -> dict[str, Any]:
        """Parse visual sentiment response."""
        return {}
```

### 5.2. CLIP Embedding Generation for Visual Search

```python
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    from PIL import Image


class CLIPEmbeddingService:
    """Generate CLIP embeddings for visual similarity search.

    Supports both text and image embeddings for cross-modal search
    (e.g., "find videos showing dancing" or "find similar memes").
    """

    EMBEDDING_DIM = 512  # CLIP ViT-B/32 dimension

    def __init__(
        self,
        model_name: str = "ViT-B/32",
        device: str = "cuda",
    ) -> None:
        """Initialize CLIP embedding service.

        Args:
            model_name: CLIP model variant.
            device: Device for inference ("cuda" or "cpu").
        """
        self._model_name = model_name
        self._device = device
        self._model = None
        self._preprocess = None

    async def initialize(self) -> None:
        """Load CLIP model."""
        # Use OpenCLIP or transformers CLIPModel
        # import open_clip
        # self._model, _, self._preprocess = open_clip.create_model_and_transforms(
        #     self._model_name, pretrained='openai'
        # )
        # self._model = self._model.to(self._device)
        pass

    async def embed_text(
        self,
        texts: list[str],
    ) -> np.ndarray:
        """Generate embeddings for text queries.

        Args:
            texts: List of text strings to embed.

        Returns:
            numpy array of shape (len(texts), EMBEDDING_DIM).
        """
        # Tokenize and encode
        # with torch.no_grad():
        #     text_features = self._model.encode_text(tokenized)
        #     text_features /= text_features.norm(dim=-1, keepdim=True)
        # return text_features.cpu().numpy()
        return np.zeros((len(texts), self.EMBEDDING_DIM))

    async def embed_image(
        self,
        image_paths: list[str | Path],
    ) -> np.ndarray:
        """Generate embeddings for images.

        Args:
            image_paths: List of image file paths.

        Returns:
            numpy array of shape (len(image_paths), EMBEDDING_DIM).
        """
        # Load and preprocess images
        # with torch.no_grad():
        #     image_features = self._model.encode_image(preprocessed)
        #     image_features /= image_features.norm(dim=-1, keepdim=True)
        # return image_features.cpu().numpy()
        return np.zeros((len(image_paths), self.EMBEDDING_DIM))

    async def embed_video_keyframes(
        self,
        video_path: str | Path,
        num_keyframes: int = 5,
    ) -> np.ndarray:
        """Extract keyframes from video and generate embeddings.

        Args:
            video_path: Path to video file.
            num_keyframes: Number of keyframes to extract.

        Returns:
            numpy array of shape (num_keyframes, EMBEDDING_DIM).
        """
        # Extract keyframes using ffmpeg or opencv
        # Then embed each keyframe
        return np.zeros((num_keyframes, self.EMBEDDING_DIM))

    async def similarity_search(
        self,
        query_embedding: np.ndarray,
        candidate_embeddings: np.ndarray,
        top_k: int = 10,
    ) -> list[tuple[int, float]]:
        """Find most similar embeddings using cosine similarity.

        Args:
            query_embedding: Query vector of shape (EMBEDDING_DIM,).
            candidate_embeddings: Candidate matrix of shape (N, EMBEDDING_DIM).
            top_k: Number of results to return.

        Returns:
            List of (index, similarity_score) tuples.
        """
        # Normalize
        query_norm = query_embedding / np.linalg.norm(query_embedding)
        candidates_norm = candidate_embeddings / np.linalg.norm(
            candidate_embeddings, axis=1, keepdims=True
        )

        # Cosine similarity
        similarities = candidates_norm @ query_norm

        # Top-k
        top_indices = np.argsort(similarities)[-top_k:][::-1]
        return [(int(idx), float(similarities[idx])) for idx in top_indices]
```

## 6. Storage & Analytics (Big Data)

### 6.1. Complete Database Schema (TimescaleDB)

TimescaleDB provides time-series optimization for metrics while maintaining PostgreSQL compatibility for relational queries.

```sql
-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ============================================
-- CORE TABLES (PostgreSQL)
-- ============================================

-- Platform accounts being tracked
CREATE TABLE tracked_accounts (
    id              BIGSERIAL PRIMARY KEY,
    platform        VARCHAR(20) NOT NULL,  -- twitter, tiktok, linkedin, instagram
    platform_id     VARCHAR(100) NOT NULL, -- Platform-specific user ID
    username        VARCHAR(100) NOT NULL,
    display_name    VARCHAR(255),
    bio             TEXT,
    follower_count  BIGINT DEFAULT 0,
    following_count BIGINT DEFAULT 0,
    post_count      BIGINT DEFAULT 0,
    is_verified     BOOLEAN DEFAULT FALSE,
    profile_image   TEXT,
    external_url    TEXT,
    location        VARCHAR(255),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    metadata        JSONB DEFAULT '{}',
    UNIQUE(platform, platform_id)
);

CREATE INDEX idx_tracked_accounts_platform ON tracked_accounts(platform);
CREATE INDEX idx_tracked_accounts_username ON tracked_accounts(username);
CREATE INDEX idx_tracked_accounts_metadata ON tracked_accounts USING GIN(metadata);

-- Content posts from all platforms
CREATE TABLE posts (
    id              BIGSERIAL PRIMARY KEY,
    platform        VARCHAR(20) NOT NULL,
    platform_post_id VARCHAR(100) NOT NULL,
    account_id      BIGINT REFERENCES tracked_accounts(id),
    content_text    TEXT,
    content_html    TEXT,
    post_type       VARCHAR(50),  -- text, image, video, carousel, reel, story
    media_urls      TEXT[],
    hashtags        TEXT[],
    mentions        TEXT[],
    like_count      BIGINT DEFAULT 0,
    comment_count   BIGINT DEFAULT 0,
    share_count     BIGINT DEFAULT 0,
    view_count      BIGINT DEFAULT 0,
    posted_at       TIMESTAMPTZ,
    scraped_at      TIMESTAMPTZ DEFAULT NOW(),
    location        VARCHAR(255),
    language        VARCHAR(10),
    is_reply        BOOLEAN DEFAULT FALSE,
    reply_to_id     VARCHAR(100),
    is_quote        BOOLEAN DEFAULT FALSE,
    quoted_post_id  VARCHAR(100),
    metadata        JSONB DEFAULT '{}',
    UNIQUE(platform, platform_post_id)
);

CREATE INDEX idx_posts_account ON posts(account_id);
CREATE INDEX idx_posts_platform_time ON posts(platform, posted_at DESC);
CREATE INDEX idx_posts_hashtags ON posts USING GIN(hashtags);
CREATE INDEX idx_posts_mentions ON posts USING GIN(mentions);
CREATE INDEX idx_posts_metadata ON posts USING GIN(metadata);
CREATE INDEX idx_posts_posted_at ON posts(posted_at DESC);

-- Post analysis results
CREATE TABLE post_analysis (
    id                  BIGSERIAL PRIMARY KEY,
    post_id             BIGINT REFERENCES posts(id) ON DELETE CASCADE,
    sentiment_score     FLOAT,  -- -1.0 to 1.0
    sentiment_label     VARCHAR(20),  -- very_negative, negative, neutral, positive, very_positive
    sentiment_confidence FLOAT,
    emotions            JSONB,  -- {"joy": 0.8, "anger": 0.1, ...}
    topics              TEXT[],
    entities_persons    TEXT[],
    entities_orgs       TEXT[],
    entities_locations  TEXT[],
    entities_brands     TEXT[],
    visual_description  TEXT,
    visual_categories   TEXT[],
    detected_brands     JSONB,  -- [{"name": "Nike", "confidence": 0.95}]
    ocr_text            TEXT,
    analyzed_at         TIMESTAMPTZ DEFAULT NOW(),
    model_version       VARCHAR(50),
    UNIQUE(post_id)
);

CREATE INDEX idx_post_analysis_sentiment ON post_analysis(sentiment_score);
CREATE INDEX idx_post_analysis_brands ON post_analysis USING GIN(entities_brands);

-- Campaigns for tracking specific topics/brands
CREATE TABLE campaigns (
    id              BIGSERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    keywords        TEXT[],
    hashtags        TEXT[],
    tracked_accounts BIGINT[],  -- Array of account IDs
    platforms       TEXT[],  -- Which platforms to monitor
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    config          JSONB DEFAULT '{}'
);

-- ============================================
-- TIME-SERIES TABLES (TimescaleDB Hypertables)
-- ============================================

-- Real-time sentiment metrics (aggregated per 15-minute windows)
CREATE TABLE sentiment_metrics (
    time            TIMESTAMPTZ NOT NULL,
    campaign_id     BIGINT,
    platform        VARCHAR(20),
    hashtag         VARCHAR(255),
    sentiment_avg   FLOAT,
    sentiment_std   FLOAT,
    post_count      INTEGER,
    positive_count  INTEGER,
    negative_count  INTEGER,
    neutral_count   INTEGER
);
SELECT create_hypertable('sentiment_metrics', 'time');
CREATE INDEX idx_sentiment_metrics_campaign ON sentiment_metrics(campaign_id, time DESC);

-- Engagement metrics over time
CREATE TABLE engagement_metrics (
    time            TIMESTAMPTZ NOT NULL,
    account_id      BIGINT,
    platform        VARCHAR(20),
    follower_delta  INTEGER,  -- Change in followers
    total_likes     BIGINT,
    total_comments  BIGINT,
    total_shares    BIGINT,
    total_views     BIGINT,
    post_count      INTEGER,
    engagement_rate FLOAT
);
SELECT create_hypertable('engagement_metrics', 'time');
CREATE INDEX idx_engagement_metrics_account ON engagement_metrics(account_id, time DESC);

-- Hashtag trending metrics
CREATE TABLE hashtag_metrics (
    time            TIMESTAMPTZ NOT NULL,
    platform        VARCHAR(20),
    hashtag         VARCHAR(255),
    post_count      INTEGER,
    unique_authors  INTEGER,
    total_engagement BIGINT,
    velocity        FLOAT,  -- Posts per hour
    sentiment_avg   FLOAT
);
SELECT create_hypertable('hashtag_metrics', 'time');
CREATE INDEX idx_hashtag_metrics_tag ON hashtag_metrics(hashtag, time DESC);

-- Continuous aggregates for fast dashboard queries
CREATE MATERIALIZED VIEW hourly_sentiment
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    campaign_id,
    platform,
    AVG(sentiment_avg) AS avg_sentiment,
    SUM(post_count) AS total_posts,
    SUM(positive_count) AS total_positive,
    SUM(negative_count) AS total_negative
FROM sentiment_metrics
GROUP BY bucket, campaign_id, platform
WITH NO DATA;

SELECT add_continuous_aggregate_policy('hourly_sentiment',
    start_offset => INTERVAL '1 day',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour');

-- Data retention policy (90 days for raw, 1 year for aggregates)
SELECT add_retention_policy('sentiment_metrics', INTERVAL '90 days');
SELECT add_retention_policy('engagement_metrics', INTERVAL '90 days');
SELECT add_retention_policy('hashtag_metrics', INTERVAL '90 days');
```

### 6.2. Vector Search Schema (Milvus/Pinecone)

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Milvus collection schema
MILVUS_COLLECTIONS = {
    "post_embeddings": {
        "description": "CLIP embeddings for posts with images/videos",
        "fields": [
            {"name": "id", "type": "INT64", "is_primary": True},
            {"name": "post_id", "type": "INT64"},
            {"name": "platform", "type": "VARCHAR", "max_length": 20},
            {"name": "media_type", "type": "VARCHAR", "max_length": 20},
            {"name": "embedding", "type": "FLOAT_VECTOR", "dim": 512},
            {"name": "created_at", "type": "INT64"},  # Unix timestamp
        ],
        "index": {
            "field": "embedding",
            "index_type": "IVF_FLAT",
            "metric_type": "COSINE",
            "params": {"nlist": 1024},
        },
    },
    "text_embeddings": {
        "description": "Sentence embeddings for text search",
        "fields": [
            {"name": "id", "type": "INT64", "is_primary": True},
            {"name": "post_id", "type": "INT64"},
            {"name": "platform", "type": "VARCHAR", "max_length": 20},
            {"name": "embedding", "type": "FLOAT_VECTOR", "dim": 768},  # sentence-transformers
            {"name": "created_at", "type": "INT64"},
        ],
        "index": {
            "field": "embedding",
            "index_type": "HNSW",
            "metric_type": "COSINE",
            "params": {"M": 16, "efConstruction": 256},
        },
    },
}


@dataclass
class VectorSearchResult:
    """Result from vector similarity search."""
    post_id: int
    platform: str
    similarity_score: float
    metadata: dict[str, Any]


class VectorStoreClient:
    """Client for vector similarity search operations."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 19530,
    ) -> None:
        self._host = host
        self._port = port
        self._client = None

    async def connect(self) -> None:
        """Connect to Milvus server."""
        # from pymilvus import connections
        # connections.connect(host=self._host, port=self._port)
        pass

    async def insert_embeddings(
        self,
        collection: str,
        embeddings: list[dict[str, Any]],
    ) -> list[int]:
        """Insert embeddings into collection.

        Args:
            collection: Collection name.
            embeddings: List of embedding records.

        Returns:
            List of inserted IDs.
        """
        # from pymilvus import Collection
        # col = Collection(collection)
        # result = col.insert(embeddings)
        # return result.primary_keys
        return []

    async def search_similar(
        self,
        collection: str,
        query_embedding: list[float],
        top_k: int = 10,
        filters: dict[str, Any] | None = None,
    ) -> list[VectorSearchResult]:
        """Search for similar embeddings.

        Args:
            collection: Collection to search.
            query_embedding: Query vector.
            top_k: Number of results.
            filters: Optional metadata filters.

        Returns:
            List of search results.
        """
        # Build filter expression
        # expr = None
        # if filters:
        #     conditions = [f'{k} == "{v}"' for k, v in filters.items()]
        #     expr = " and ".join(conditions)

        # from pymilvus import Collection
        # col = Collection(collection)
        # results = col.search(
        #     data=[query_embedding],
        #     anns_field="embedding",
        #     param={"metric_type": "COSINE", "params": {"nprobe": 16}},
        #     limit=top_k,
        #     expr=expr,
        # )
        return []
```

## 7. Infrastructure & Deployment

### 7.1. Complete Docker Compose Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  # ===========================================
  # OWL BROWSER NODES
  # ===========================================
  owl-browser:
    image: olib/owl-browser:latest
    deploy:
      replicas: 4
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
    environment:
      - OWL_LICENSE_KEY=${OWL_LICENSE_KEY}
      - OWL_API_PORT=8080
      - OWL_ENABLE_GPU=false
      - OWL_MAX_CONCURRENT_PAGES=5
      - OWL_STEALTH_MODE=aggressive
    volumes:
      - owl-profiles:/data/profiles
    networks:
      - trendscope-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ===========================================
  # MESSAGE QUEUE
  # ===========================================
  rabbitmq:
    image: rabbitmq:3.12-management
    ports:
      - "5672:5672"
      - "15672:15672"
    environment:
      - RABBITMQ_DEFAULT_USER=trendscope
      - RABBITMQ_DEFAULT_PASS=${RABBITMQ_PASSWORD}
    volumes:
      - rabbitmq-data:/var/lib/rabbitmq
    networks:
      - trendscope-net

  # ===========================================
  # DATABASES
  # ===========================================
  timescaledb:
    image: timescale/timescaledb:latest-pg15
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_USER=trendscope
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=trendscope
    volumes:
      - timescale-data:/var/lib/postgresql/data
      - ./init-scripts:/docker-entrypoint-initdb.d
    networks:
      - trendscope-net
    command: >
      postgres
        -c shared_preload_libraries=timescaledb
        -c timescaledb.max_background_workers=8
        -c max_connections=200

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - trendscope-net
    command: redis-server --appendonly yes

  milvus:
    image: milvusdb/milvus:v2.3.0
    ports:
      - "19530:19530"
      - "9091:9091"
    environment:
      - ETCD_ENDPOINTS=etcd:2379
      - MINIO_ADDRESS=minio:9000
    depends_on:
      - etcd
      - minio
    volumes:
      - milvus-data:/var/lib/milvus
    networks:
      - trendscope-net

  etcd:
    image: quay.io/coreos/etcd:v3.5.5
    environment:
      - ETCD_AUTO_COMPACTION_MODE=revision
      - ETCD_AUTO_COMPACTION_RETENTION=1000
    volumes:
      - etcd-data:/etcd
    networks:
      - trendscope-net
    command: etcd --listen-client-urls=http://0.0.0.0:2379 --advertise-client-urls=http://etcd:2379

  minio:
    image: minio/minio:latest
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      - MINIO_ROOT_USER=minioadmin
      - MINIO_ROOT_PASSWORD=${MINIO_PASSWORD}
    volumes:
      - minio-data:/data
    networks:
      - trendscope-net
    command: minio server /data --console-address ":9001"

  # ===========================================
  # APPLICATION SERVICES
  # ===========================================
  api:
    build:
      context: .
      dockerfile: Dockerfile.api
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://trendscope:${POSTGRES_PASSWORD}@timescaledb:5432/trendscope
      - REDIS_URL=redis://redis:6379
      - RABBITMQ_URL=amqp://trendscope:${RABBITMQ_PASSWORD}@rabbitmq:5672
      - OWL_BROWSER_URL=http://owl-browser:8080
    depends_on:
      - timescaledb
      - redis
      - rabbitmq
      - owl-browser
    networks:
      - trendscope-net

  worker:
    build:
      context: .
      dockerfile: Dockerfile.worker
    deploy:
      replicas: 8
    environment:
      - DATABASE_URL=postgresql://trendscope:${POSTGRES_PASSWORD}@timescaledb:5432/trendscope
      - REDIS_URL=redis://redis:6379
      - RABBITMQ_URL=amqp://trendscope:${RABBITMQ_PASSWORD}@rabbitmq:5672
      - OWL_BROWSER_URL=http://owl-browser:8080
      - MILVUS_HOST=milvus
      - MILVUS_PORT=19530
    depends_on:
      - timescaledb
      - redis
      - rabbitmq
      - owl-browser
      - milvus
    networks:
      - trendscope-net

  # ===========================================
  # MONITORING
  # ===========================================
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/datasources:/etc/grafana/provisioning/datasources
    networks:
      - trendscope-net

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    networks:
      - trendscope-net

volumes:
  owl-profiles:
  rabbitmq-data:
  timescale-data:
  redis-data:
  milvus-data:
  etcd-data:
  minio-data:
  grafana-data:
  prometheus-data:

networks:
  trendscope-net:
    driver: bridge
```

### 7.2. Kubernetes with Karpenter Autoscaling

```yaml
# karpenter-provisioner.yaml
apiVersion: karpenter.sh/v1alpha5
kind: Provisioner
metadata:
  name: trendscope-browser-nodes
spec:
  # Node requirements for browser workloads
  requirements:
    - key: "karpenter.k8s.aws/instance-category"
      operator: In
      values: ["c", "m", "r"]  # Compute, memory, or balanced
    - key: "karpenter.k8s.aws/instance-size"
      operator: In
      values: ["large", "xlarge", "2xlarge"]
    - key: "karpenter.sh/capacity-type"
      operator: In
      values: ["spot", "on-demand"]
    - key: "kubernetes.io/arch"
      operator: In
      values: ["amd64"]

  # Prioritize spot instances for cost savings
  weight: 100

  # Resource limits for the provisioner
  limits:
    resources:
      cpu: "2000"      # Max 2000 vCPUs
      memory: "4000Gi" # Max 4TB memory

  # Node consolidation settings
  consolidation:
    enabled: true

  # TTL settings
  ttlSecondsAfterEmpty: 30
  ttlSecondsUntilExpired: 2592000  # 30 days

  # Provider configuration
  provider:
    subnetSelector:
      karpenter.sh/discovery: trendscope
    securityGroupSelector:
      karpenter.sh/discovery: trendscope
    instanceProfile: KarpenterNodeInstanceProfile

    # Block device configuration
    blockDeviceMappings:
      - deviceName: /dev/xvda
        ebs:
          volumeSize: 100Gi
          volumeType: gp3
          encrypted: true
          deleteOnTermination: true

---
# owl-browser-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: owl-browser
  labels:
    app: owl-browser
spec:
  replicas: 10
  selector:
    matchLabels:
      app: owl-browser
  template:
    metadata:
      labels:
        app: owl-browser
    spec:
      # Schedule on Karpenter-managed nodes
      nodeSelector:
        karpenter.sh/provisioner-name: trendscope-browser-nodes

      # Spread across availability zones
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app: owl-browser

      containers:
        - name: owl-browser
          image: olib/owl-browser:latest
          ports:
            - containerPort: 8080
          env:
            - name: OWL_LICENSE_KEY
              valueFrom:
                secretKeyRef:
                  name: owl-secrets
                  key: license-key
            - name: OWL_MAX_CONCURRENT_PAGES
              value: "5"
            - name: OWL_STEALTH_MODE
              value: "aggressive"
          resources:
            requests:
              cpu: "1000m"
              memory: "1Gi"
            limits:
              cpu: "2000m"
              memory: "2Gi"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 5
          volumeMounts:
            - name: profiles
              mountPath: /data/profiles

      volumes:
        - name: profiles
          persistentVolumeClaim:
            claimName: owl-profiles-pvc

---
# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: owl-browser-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: owl-browser
  minReplicas: 5
  maxReplicas: 100
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Pods
      pods:
        metric:
          name: active_pages
        target:
          type: AverageValue
          averageValue: "3"  # Scale when avg pages per pod > 3
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 100
          periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
```

### 7.3. Cost Optimization Strategies

```python
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any


class InstanceType(Enum):
    """AWS instance type categories."""
    SPOT = "spot"
    ON_DEMAND = "on-demand"
    RESERVED = "reserved"


@dataclass
class CostMetrics:
    """Cost tracking metrics."""
    period_start: datetime
    period_end: datetime
    total_cost_usd: float
    browser_node_cost: float
    database_cost: float
    network_cost: float
    storage_cost: float
    spot_savings: float
    requests_processed: int

    @property
    def cost_per_request(self) -> float:
        """Calculate cost per request."""
        if self.requests_processed == 0:
            return 0.0
        return self.total_cost_usd / self.requests_processed


class CostOptimizer:
    """Cost optimization strategies for TrendScope infrastructure.

    Key strategies:
    1. Spot instances for browser nodes (70-90% savings)
    2. Network rule blocking to reduce bandwidth
    3. Tiered scraping frequency based on content importance
    4. Off-peak scheduling for batch jobs
    """

    # Spot instance pricing (approximate, varies by region)
    SPOT_DISCOUNT = 0.70  # 70% off on-demand

    def __init__(self) -> None:
        self._metrics: list[CostMetrics] = []

    def calculate_bandwidth_savings(
        self,
        requests_with_blocking: int,
        avg_blocked_resources: int,
        avg_resource_size_kb: float,
    ) -> dict[str, float]:
        """Calculate savings from ad/tracker blocking.

        Args:
            requests_with_blocking: Number of page loads with blocking.
            avg_blocked_resources: Average blocked resources per page.
            avg_resource_size_kb: Average size of blocked resource.

        Returns:
            Dictionary with bandwidth and cost savings.
        """
        blocked_data_gb = (
            requests_with_blocking *
            avg_blocked_resources *
            avg_resource_size_kb
        ) / (1024 * 1024)  # Convert to GB

        # AWS data transfer out pricing (~$0.09/GB)
        cost_savings = blocked_data_gb * 0.09

        return {
            "blocked_data_gb": blocked_data_gb,
            "cost_savings_usd": cost_savings,
            "monthly_projection_usd": cost_savings * 30,
        }

    def recommend_scrape_frequency(
        self,
        account_follower_count: int,
        avg_posts_per_day: float,
        engagement_rate: float,
    ) -> timedelta:
        """Recommend scraping frequency based on account importance.

        Higher follower count and engagement = more frequent scraping.

        Args:
            account_follower_count: Number of followers.
            avg_posts_per_day: Average daily post count.
            engagement_rate: Engagement rate (0.0 to 1.0).

        Returns:
            Recommended interval between scrapes.
        """
        # Base interval: 1 hour
        base_interval = timedelta(hours=1)

        # Adjust based on follower count
        if account_follower_count > 1_000_000:
            interval_multiplier = 0.25  # Every 15 minutes
        elif account_follower_count > 100_000:
            interval_multiplier = 0.5   # Every 30 minutes
        elif account_follower_count > 10_000:
            interval_multiplier = 1.0   # Every hour
        else:
            interval_multiplier = 4.0   # Every 4 hours

        # Adjust for posting frequency
        if avg_posts_per_day > 10:
            interval_multiplier *= 0.5
        elif avg_posts_per_day < 1:
            interval_multiplier *= 2.0

        # Adjust for engagement
        if engagement_rate > 0.05:  # High engagement
            interval_multiplier *= 0.75

        return base_interval * interval_multiplier

    def schedule_for_off_peak(
        self,
        job_type: str,
        priority: int,
    ) -> dict[str, Any]:
        """Generate off-peak scheduling recommendation.

        Args:
            job_type: Type of job (batch_analysis, historical_scrape, etc.)
            priority: Priority level (1-5, 1 being highest).

        Returns:
            Scheduling configuration.
        """
        # Off-peak hours (UTC): 02:00 - 08:00
        off_peak_start = 2
        off_peak_end = 8

        if job_type == "batch_analysis":
            # Heavy compute jobs - always off-peak
            return {
                "schedule_type": "off_peak_only",
                "preferred_hours": list(range(off_peak_start, off_peak_end)),
                "spot_eligible": True,
                "preemptible": priority > 2,
            }
        elif job_type == "historical_scrape":
            # Can run anytime but prefer off-peak
            return {
                "schedule_type": "prefer_off_peak",
                "preferred_hours": list(range(off_peak_start, off_peak_end)),
                "fallback_hours": list(range(24)),
                "spot_eligible": True,
                "preemptible": True,
            }
        else:
            # Real-time jobs - run immediately
            return {
                "schedule_type": "immediate",
                "spot_eligible": priority > 3,
                "preemptible": False,
            }
```

## 8. Legal & Ethical Compliance

### 8.1. GDPR Data Handling Implementation

```python
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from owl_browser import Page


class PIIType(Enum):
    """Types of Personally Identifiable Information."""
    EMAIL = "email"
    PHONE = "phone"
    NAME = "name"
    ADDRESS = "address"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    FACE = "face"


@dataclass
class PIIDetection:
    """Detected PII instance."""
    pii_type: PIIType
    original_value: str
    start_position: int
    end_position: int
    confidence: float


@dataclass
class RedactionResult:
    """Result of PII redaction."""
    original_text: str
    redacted_text: str
    detections: list[PIIDetection]
    redaction_count: int


class ComplianceEngine:
    """GDPR and privacy compliance engine.

    Handles:
    - PII detection and redaction in text
    - Face detection and blurring in images
    - Data retention policy enforcement
    - Consent tracking
    - Right to deletion (RTBF) processing
    """

    # PII detection patterns
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    PHONE_PATTERN = re.compile(
        r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'
    )
    SSN_PATTERN = re.compile(
        r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'
    )
    CREDIT_CARD_PATTERN = re.compile(
        r'\b(?:\d{4}[-.\s]?){3}\d{4}\b'
    )

    def __init__(
        self,
        data_retention_days: int = 90,
        enable_face_blur: bool = True,
    ) -> None:
        """Initialize compliance engine.

        Args:
            data_retention_days: Days to retain raw data.
            enable_face_blur: Whether to blur faces in images.
        """
        self._retention_days = data_retention_days
        self._enable_face_blur = enable_face_blur
        self._deletion_queue: list[str] = []

    def detect_pii_in_text(
        self,
        text: str,
    ) -> list[PIIDetection]:
        """Detect PII in text content.

        Args:
            text: Text to scan for PII.

        Returns:
            List of detected PII instances.
        """
        detections: list[PIIDetection] = []

        # Email detection
        for match in self.EMAIL_PATTERN.finditer(text):
            detections.append(PIIDetection(
                pii_type=PIIType.EMAIL,
                original_value=match.group(),
                start_position=match.start(),
                end_position=match.end(),
                confidence=0.95,
            ))

        # Phone detection
        for match in self.PHONE_PATTERN.finditer(text):
            detections.append(PIIDetection(
                pii_type=PIIType.PHONE,
                original_value=match.group(),
                start_position=match.start(),
                end_position=match.end(),
                confidence=0.90,
            ))

        # SSN detection
        for match in self.SSN_PATTERN.finditer(text):
            detections.append(PIIDetection(
                pii_type=PIIType.SSN,
                original_value=match.group(),
                start_position=match.start(),
                end_position=match.end(),
                confidence=0.85,
            ))

        # Credit card detection
        for match in self.CREDIT_CARD_PATTERN.finditer(text):
            if self._validate_credit_card(match.group()):
                detections.append(PIIDetection(
                    pii_type=PIIType.CREDIT_CARD,
                    original_value=match.group(),
                    start_position=match.start(),
                    end_position=match.end(),
                    confidence=0.90,
                ))

        return detections

    def redact_text(
        self,
        text: str,
        pii_types: list[PIIType] | None = None,
        replacement_style: str = "hash",
    ) -> RedactionResult:
        """Redact PII from text.

        Args:
            text: Text to redact.
            pii_types: Specific PII types to redact (all if None).
            replacement_style: "hash", "mask", or "remove".

        Returns:
            RedactionResult with redacted text.
        """
        detections = self.detect_pii_in_text(text)

        if pii_types:
            detections = [d for d in detections if d.pii_type in pii_types]

        # Sort by position (reverse order to preserve indices)
        detections.sort(key=lambda d: d.start_position, reverse=True)

        redacted_text = text
        for detection in detections:
            replacement = self._get_replacement(
                detection.original_value,
                detection.pii_type,
                replacement_style,
            )
            redacted_text = (
                redacted_text[:detection.start_position] +
                replacement +
                redacted_text[detection.end_position:]
            )

        return RedactionResult(
            original_text=text,
            redacted_text=redacted_text,
            detections=detections,
            redaction_count=len(detections),
        )

    async def detect_and_blur_faces(
        self,
        page: Page,
        screenshot_path: str,
    ) -> dict[str, Any]:
        """Detect and blur faces in a screenshot.

        Args:
            page: Owl Browser page for VLM analysis.
            screenshot_path: Path to screenshot file.

        Returns:
            Dictionary with face detection results.
        """
        if not self._enable_face_blur:
            return {"faces_detected": 0, "blurred": False}

        # Use VLM to detect faces
        face_analysis = await page.query_page(
            "Analyze this image for human faces. For each face, provide: "
            "approximate bounding box coordinates (x, y, width, height), "
            "whether the face is clearly identifiable, "
            "and an estimated age range. Return as structured data."
        )

        # In production, use OpenCV or dlib for actual face detection and blurring
        # This is a placeholder showing the integration pattern
        return {
            "analysis": face_analysis,
            "faces_detected": 0,  # Parse from analysis
            "blurred": False,
            "blur_applied_to": [],
        }

    async def process_deletion_request(
        self,
        subject_identifier: str,
        platforms: list[str] | None = None,
    ) -> dict[str, Any]:
        """Process GDPR Right to Deletion (RTBF) request.

        Args:
            subject_identifier: Username, email, or ID of data subject.
            platforms: Specific platforms to delete from (all if None).

        Returns:
            Dictionary with deletion results.
        """
        # This would connect to the database and delete all data
        # associated with the subject
        deletion_results = {
            "subject": subject_identifier,
            "request_time": datetime.now().isoformat(),
            "platforms_processed": platforms or ["all"],
            "records_deleted": {
                "posts": 0,
                "analysis": 0,
                "embeddings": 0,
            },
            "status": "completed",
        }

        return deletion_results

    def check_data_retention(
        self,
        record_timestamp: datetime,
    ) -> bool:
        """Check if data should be retained or deleted.

        Args:
            record_timestamp: When the record was created.

        Returns:
            True if data should be retained, False if it should be deleted.
        """
        retention_cutoff = datetime.now() - timedelta(days=self._retention_days)
        return record_timestamp > retention_cutoff

    def generate_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> dict[str, Any]:
        """Generate compliance report for auditing.

        Args:
            start_date: Report period start.
            end_date: Report period end.

        Returns:
            Comprehensive compliance report.
        """
        return {
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
            },
            "data_collected": {
                "total_records": 0,
                "by_platform": {},
            },
            "pii_redactions": {
                "total": 0,
                "by_type": {},
            },
            "deletion_requests": {
                "received": 0,
                "processed": 0,
                "pending": 0,
            },
            "data_retention": {
                "records_expired": 0,
                "records_deleted": 0,
            },
            "consent_records": {
                "active": 0,
                "withdrawn": 0,
            },
        }

    def _get_replacement(
        self,
        value: str,
        pii_type: PIIType,
        style: str,
    ) -> str:
        """Generate replacement string for redacted PII."""
        if style == "remove":
            return ""
        elif style == "mask":
            return f"[{pii_type.value.upper()}]"
        else:  # hash
            hash_value = hashlib.sha256(value.encode()).hexdigest()[:8]
            return f"[{pii_type.value.upper()}:{hash_value}]"

    def _validate_credit_card(self, number: str) -> bool:
        """Validate credit card using Luhn algorithm."""
        digits = re.sub(r'\D', '', number)
        if len(digits) < 13 or len(digits) > 19:
            return False

        # Luhn checksum
        total = 0
        for i, digit in enumerate(reversed(digits)):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n

        return total % 10 == 0


class RateLimitingCompliance:
    """Rate limiting to respect platform ToS and prevent abuse."""

    # Conservative rate limits per platform (requests per minute)
    PLATFORM_LIMITS: dict[str, int] = {
        "twitter": 15,
        "tiktok": 10,
        "linkedin": 5,
        "instagram": 8,
    }

    # Minimum delay between requests (seconds)
    MIN_DELAY: dict[str, float] = {
        "twitter": 2.0,
        "tiktok": 3.0,
        "linkedin": 5.0,
        "instagram": 3.5,
    }

    def __init__(self) -> None:
        self._request_counts: dict[str, list[datetime]] = {}
        self._last_request: dict[str, datetime] = {}

    async def check_rate_limit(
        self,
        platform: str,
    ) -> tuple[bool, float]:
        """Check if rate limit allows a new request.

        Args:
            platform: Platform to check.

        Returns:
            Tuple of (allowed, wait_seconds).
        """
        now = datetime.now()
        limit = self.PLATFORM_LIMITS.get(platform, 10)
        min_delay = self.MIN_DELAY.get(platform, 2.0)

        # Check minimum delay
        last = self._last_request.get(platform)
        if last:
            elapsed = (now - last).total_seconds()
            if elapsed < min_delay:
                return False, min_delay - elapsed

        # Check requests per minute
        if platform not in self._request_counts:
            self._request_counts[platform] = []

        # Remove requests older than 1 minute
        cutoff = now - timedelta(minutes=1)
        self._request_counts[platform] = [
            t for t in self._request_counts[platform] if t > cutoff
        ]

        if len(self._request_counts[platform]) >= limit:
            oldest = min(self._request_counts[platform])
            wait_time = 60 - (now - oldest).total_seconds()
            return False, max(0, wait_time)

        return True, 0.0

    async def record_request(
        self,
        platform: str,
    ) -> None:
        """Record that a request was made.

        Args:
            platform: Platform that was accessed.
        """
        now = datetime.now()
        self._last_request[platform] = now

        if platform not in self._request_counts:
            self._request_counts[platform] = []
        self._request_counts[platform].append(now)
```

## 9. Roadmap

*   **Deepfake Detection:** Integration with forensic models to flag synthetic media.
*   **Cross-Platform Identity Graph:** Using Neo4j to map "UserA" on Twitter to "UserA_Official" on Instagram.
*   **Real-time Alerts:** Slack/Discord webhooks triggered by anomaly detection algorithms (e.g., "Sentiment dropped 40% in 5 minutes").

---
*End of Documentation - TrendScope*

---

## Disclaimer

This project documentation was generated by generative AI. While the architectural concepts and implementation patterns are based on real-world best practices, some features, configurations, or code examples may require adjustments for production use. Please review and test thoroughly before deploying.