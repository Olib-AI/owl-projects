"""
Main Browser class for automation.

Provides a high-level interface for browser automation with
support for multiple contexts, LLM features, and concurrent usage.

Supports dual mode:
- LOCAL: Connect to local browser binary via stdin/stdout IPC
- REMOTE: Connect to remote browser HTTP server via REST API
"""

import atexit
import signal
import threading
from typing import Dict, List, Optional, Any

from .core import BrowserCore
from .context import BrowserContext
from .types import (
    BrowserConfig,
    ContextId,
    ContextOptions,
    LLMStatus,
    LLMConfig,
    ProxyConfig,
    DemographicsInfo,
    LocationInfo,
    DateTimeInfo,
    WeatherInfo,
    ConnectionMode,
    RemoteConfig,
    BrowserProfile,
    LicenseStatusResponse,
    LicenseInfo,
    HardwareFingerprint,
    LiveStreamInfo,
)


class Browser:
    """
    Main Browser class for automation.

    Thread-safe and supports multiple concurrent contexts (pages).

    Supports dual mode:
    - LOCAL: Connect to local browser binary (default)
    - REMOTE: Connect to remote browser HTTP server

    Local Example:
        ```python
        from owl_browser import Browser

        browser = Browser()
        browser.launch()

        page = browser.new_page()
        page.goto("https://example.com")
        page.screenshot("screenshot.png")

        browser.close()
        ```

    Remote Example:
        ```python
        from owl_browser import Browser, RemoteConfig

        # Connect to remote browser server
        browser = Browser(remote=RemoteConfig(
            url="http://192.168.1.100:8080",
            token="your-secret-token"
        ))
        browser.launch()

        page = browser.new_page()
        page.goto("https://example.com")
        page.screenshot("screenshot.png")

        browser.close()
        ```

    Context Manager Example:
        ```python
        from owl_browser import Browser

        with Browser() as browser:
            page = browser.new_page()
            page.goto("https://example.com")
            # Browser automatically closes when exiting the context
        ```

    Concurrent Example:
        ```python
        from owl_browser import Browser
        from concurrent.futures import ThreadPoolExecutor

        browser = Browser()
        browser.launch()

        def scrape_url(url):
            page = browser.new_page()
            page.goto(url)
            text = page.extract_text()
            page.close()
            return text

        with ThreadPoolExecutor(max_workers=5) as executor:
            urls = ["https://example1.com", "https://example2.com", ...]
            results = list(executor.map(scrape_url, urls))

        browser.close()
        ```
    """

    def __init__(
        self,
        browser_path: Optional[str] = None,
        headless: bool = True,
        verbose: bool = False,
        init_timeout: int = 30000,
        remote: Optional[RemoteConfig] = None
    ):
        """
        Initialize the Browser.

        Args:
            browser_path: Path to browser binary (auto-detected if not provided, ignored for remote mode)
            headless: Enable headless mode (default: True, ignored for remote mode)
            verbose: Enable verbose logging (default: False)
            init_timeout: Initialization timeout in milliseconds (default: 30000)
            remote: Remote server configuration. If provided, connects to a remote
                   browser server instead of launching a local browser process.

        Example (Local):
            ```python
            browser = Browser()  # Auto-detect browser binary
            browser = Browser(browser_path="/path/to/browser")  # Explicit path
            ```

        Example (Remote):
            ```python
            browser = Browser(remote=RemoteConfig(
                url="http://localhost:8080",
                token="secret-token"
            ))
            ```
        """
        self._config = BrowserConfig(
            browser_path=browser_path,
            headless=headless,
            verbose=verbose,
            init_timeout=init_timeout
        )
        self._remote_config = remote
        self._core = BrowserCore(self._config, remote=remote)
        self._contexts: Dict[ContextId, BrowserContext] = {}
        self._lock = threading.Lock()
        self._is_launched = False
        self._cleanup_registered = False

    @property
    def mode(self) -> ConnectionMode:
        """Get the connection mode (LOCAL or REMOTE)."""
        return self._core.mode

    @property
    def is_remote(self) -> bool:
        """Check if running in remote mode."""
        return self._core.is_remote

    def launch(self) -> "Browser":
        """
        Launch the browser connection.

        For LOCAL mode: Starts the browser process.
        For REMOTE mode: Connects to the HTTP server and verifies it's ready.

        Returns:
            self for method chaining

        Raises:
            RuntimeError: If browser already launched or fails to start
            LicenseError: If browser license is invalid (local or remote)
            BrowserInitializationError: If connection fails

        Example (Local):
            ```python
            browser = Browser().launch()
            # or
            browser = Browser()
            browser.launch()
            ```

        Example (Remote):
            ```python
            browser = Browser(remote=RemoteConfig(
                url="http://localhost:8080",
                token="token"
            )).launch()
            ```
        """
        if self._is_launched:
            raise RuntimeError("Browser already launched")

        self._core.initialize()
        self._is_launched = True

        # Register cleanup handlers
        if not self._cleanup_registered:
            self._cleanup_registered = True
            atexit.register(self._cleanup_on_exit)

            # Handle SIGINT and SIGTERM gracefully
            def signal_handler(signum, frame):
                self.close()
                raise SystemExit(0)

            try:
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)
            except (ValueError, OSError):
                # Signal handling may fail in some environments (e.g., threads)
                pass

        return self

    def new_page(
        self,
        proxy: Optional[ProxyConfig] = None,
        llm: Optional[LLMConfig] = None,
        profile_path: Optional[str] = None
    ) -> BrowserContext:
        """
        Create a new page (browser context).

        Each page is isolated with its own cookies, storage, and session.

        Args:
            proxy: Optional proxy configuration
            llm: Optional LLM configuration
            profile_path: Optional path to browser profile JSON file. If the file
                         exists, fingerprints and cookies will be loaded from it.
                         This enables persistent browser identities across sessions.

        Returns:
            New BrowserContext instance

        Raises:
            RuntimeError: If browser not launched

        Example:
            ```python
            # Simple page
            page = browser.new_page()

            # Page with proxy
            from owl_browser import ProxyConfig, ProxyType
            page = browser.new_page(proxy=ProxyConfig(
                type=ProxyType.SOCKS5H,
                host="proxy.example.com",
                port=1080,
                timezone_override="America/New_York"
            ))

            # Page with external LLM
            from owl_browser import LLMConfig
            page = browser.new_page(llm=LLMConfig(
                endpoint="https://api.openai.com",
                model="gpt-4-vision-preview",
                api_key="sk-..."
            ))

            # Page with browser profile (persistent identity)
            page = browser.new_page(profile_path="/path/to/profile.json")
            page.goto("https://example.com/login")
            # ... login ...
            page.save_profile()  # Save cookies and fingerprints
            page.close()

            # Later, restore the session
            page = browser.new_page(profile_path="/path/to/profile.json")
            page.goto("https://example.com")  # Already logged in!
            ```
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")

        options = None
        if proxy or llm or profile_path:
            options = ContextOptions(llm=llm, proxy=proxy, profile_path=profile_path)

        result = self._core.create_context(options)
        if isinstance(result, dict):
            context_id = result.get("context_id")
        elif hasattr(result, "context_id"):
            context_id = result.context_id
        else:
            context_id = result
        context = BrowserContext(context_id, self._core)

        with self._lock:
            self._contexts[context_id] = context

        return context

    def pages(self) -> List[BrowserContext]:
        """
        Get all active pages (contexts).

        Returns:
            List of active BrowserContext instances
        """
        with self._lock:
            return list(self._contexts.values())

    def list_contexts(self) -> List[str]:
        """
        List all active context IDs from the browser.

        This queries the browser directly, useful for debugging.

        Returns:
            List of context ID strings

        Example:
            ```python
            context_ids = browser.list_contexts()
            print(f"Active contexts: {', '.join(context_ids)}")
            ```
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")
        import json
        result = self._core.send_command("listContexts", {})
        if isinstance(result, str):
            result = json.loads(result)
        return result if isinstance(result, list) else []

    def get_llm_status(self) -> LLMStatus:
        """
        Check if on-device LLM is ready.

        Returns:
            LLMStatus.READY, LLMStatus.LOADING, or LLMStatus.UNAVAILABLE
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")
        return self._core.get_llm_status()

    def list_templates(self) -> List[str]:
        """
        List available extraction templates.

        Returns:
            List of template names
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")
        return self._core.list_templates()

    def get_demographics(self) -> Dict[str, Any]:
        """
        Get complete demographics information (location, time, weather).

        Returns:
            Demographics information dict

        Example:
            ```python
            demographics = browser.get_demographics()
            print(f"Location: {demographics['location']['city']}")
            print(f"Weather: {demographics['weather']['temperature_c']}°C")
            print(f"Time: {demographics['datetime']['time']}")
            ```
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")
        return self._core.get_demographics()

    def get_location(self) -> Dict[str, Any]:
        """
        Get geographic location information based on IP address.

        Returns:
            Location information dict
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")
        return self._core.get_location()

    def get_datetime(self) -> Dict[str, Any]:
        """
        Get current date and time information.

        Returns:
            DateTime information dict
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")
        return self._core.get_datetime()

    def get_weather(self) -> Dict[str, Any]:
        """
        Get current weather for user's location.

        Returns:
            Weather information dict
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")
        return self._core.get_weather()

    def get_homepage(self) -> str:
        """
        Get the custom browser homepage HTML.

        Shows demographics, weather, LLM status, and browser information.

        Returns:
            Homepage HTML string
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")
        return self._core.get_homepage()

    # ==================== PROFILE MANAGEMENT ====================

    def create_profile(self, name: Optional[str] = None) -> BrowserProfile:
        """
        Create a new browser profile with randomized fingerprint.

        Args:
            name: Human-readable name for the profile

        Returns:
            BrowserProfile object

        Example:
            ```python
            profile = browser.create_profile("My Profile")
            print(f"Created profile: {profile.profile_id}")
            ```
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")
        result = self._core.send_command("createProfile", {"name": name} if name else {})
        return self._parse_profile(result)

    def _parse_profile(self, data: Any) -> BrowserProfile:
        """Parse profile data from API response."""
        import json
        if isinstance(data, str):
            data = json.loads(data)
        return BrowserProfile(
            profile_id=data.get("profileId", ""),
            profile_name=data.get("profileName", ""),
            created_at=data.get("createdAt", ""),
            modified_at=data.get("modifiedAt", ""),
            version=data.get("version", 1),
            cookies=data.get("cookies", []),
            has_llm_config=data.get("hasLlmConfig", False),
            has_proxy_config=data.get("hasProxyConfig", False),
            auto_save_cookies=data.get("autoSaveCookies", True),
            persist_local_storage=data.get("persistLocalStorage", True)
        )

    # ==================== LIVE STREAMING ====================

    def list_live_streams(self) -> List[LiveStreamInfo]:
        """
        List all active live streams across all contexts.

        Returns:
            List of LiveStreamInfo objects

        Example:
            ```python
            streams = browser.list_live_streams()
            for stream in streams:
                print(f"Stream {stream.context_id}: {stream.fps}fps, {stream.subscribers} viewers")
            ```
        """
        if not self._is_launched:
            raise RuntimeError("Browser not launched. Call launch() first.")
        import json
        result = self._core.send_command("listLiveStreams", {})
        if isinstance(result, str):
            result = json.loads(result)
        if not result:
            return []
        return [
            LiveStreamInfo(
                context_id=s.get("contextId", ""),
                fps=s.get("fps", 15),
                quality=s.get("quality", 75),
                subscribers=s.get("subscribers", 0)
            )
            for s in result
        ]

    # ==================== LICENSE MANAGEMENT ====================

    def get_license_status(self) -> LicenseStatusResponse:
        """
        Get current license status.

        Returns:
            LicenseStatusResponse object

        Example:
            ```python
            status = browser.get_license_status()
            if status.valid:
                print("License is active")
            else:
                print(f"License issue: {status.status}")
            ```
        """
        import json
        # License methods work even before launch
        result = self._core.send_command("getLicenseStatus", {})
        if isinstance(result, str):
            result = json.loads(result)
        return LicenseStatusResponse(
            valid=result.get("valid", False),
            status=result.get("status", ""),
            error=result.get("error")
        )

    def get_license_info(self) -> LicenseInfo:
        """
        Get detailed license information.

        Returns:
            LicenseInfo object

        Example:
            ```python
            info = browser.get_license_info()
            print(f"License: {info.license_id}")
            print(f"Expires: {info.expires_at}")
            print(f"Features: {', '.join(info.features)}")
            ```
        """
        import json
        result = self._core.send_command("getLicenseInfo", {})
        if isinstance(result, str):
            result = json.loads(result)
        return LicenseInfo(
            license_id=result.get("licenseId", ""),
            type=result.get("type", ""),
            expires_at=result.get("expiresAt", ""),
            features=result.get("features", []),
            hardware_id=result.get("hardwareId")
        )

    def get_hardware_fingerprint(self) -> HardwareFingerprint:
        """
        Get hardware fingerprint for license binding.

        Returns:
            HardwareFingerprint object

        Example:
            ```python
            hw = browser.get_hardware_fingerprint()
            print(f"Hardware ID: {hw.fingerprint}")
            ```
        """
        import json
        result = self._core.send_command("getHardwareFingerprint", {})
        if isinstance(result, str):
            result = json.loads(result)
        return HardwareFingerprint(
            fingerprint=result.get("fingerprint", "")
        )

    def add_license(self, license_path: str) -> None:
        """
        Add/activate a license.

        Args:
            license_path: Path to the license file (.olic)

        Example:
            ```python
            browser.add_license(license_path="/path/to/license.olic")
            ```
        """
        self._core.send_command("addLicense", {"license_path": license_path})

    def remove_license(self) -> None:
        """
        Remove the current license.

        Example:
            ```python
            browser.remove_license()
            ```
        """
        self._core.send_command("removeLicense", {})

    def close(self) -> None:
        """
        Close all contexts and shutdown browser.

        Safe to call multiple times.
        """
        if not self._is_launched:
            return

        # Close all contexts
        with self._lock:
            for context_id, context in list(self._contexts.items()):
                try:
                    context.close()
                except Exception:
                    pass
            self._contexts.clear()

        # Shutdown browser
        self._core.shutdown()
        self._is_launched = False

    def _cleanup_on_exit(self):
        """Cleanup handler for atexit."""
        try:
            self.close()
        except Exception:
            pass

    def is_running(self) -> bool:
        """Check if browser is running."""
        return self._is_launched and self._core.is_running()

    def __enter__(self) -> "Browser":
        """Context manager entry - auto-launch."""
        if not self._is_launched:
            self.launch()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - auto-close."""
        self.close()
        return False

    def __del__(self):
        """Destructor - ensure cleanup."""
        try:
            self.close()
        except Exception:
            pass


# Convenience function for quick one-off operations
def quick_screenshot(url: str, path: str = "screenshot.png") -> bytes:
    """
    Quick utility to take a screenshot of a URL.

    Args:
        url: URL to screenshot
        path: Path to save screenshot (default: "screenshot.png")

    Returns:
        PNG image data as bytes

    Example:
        ```python
        from owl_browser import quick_screenshot
        quick_screenshot("https://example.com", "example.png")
        ```
    """
    with Browser() as browser:
        page = browser.new_page()
        page.goto(url)
        return page.screenshot(path)


def quick_extract(url: str, selector: str = "body") -> str:
    """
    Quick utility to extract text from a URL.

    Args:
        url: URL to extract from
        selector: CSS selector or natural language description

    Returns:
        Extracted text content

    Example:
        ```python
        from owl_browser import quick_extract
        text = quick_extract("https://example.com", "main article")
        ```
    """
    with Browser() as browser:
        page = browser.new_page()
        page.goto(url)
        return page.extract_text(selector)


def quick_query(url: str, query: str) -> str:
    """
    Quick utility to query a page using LLM.

    Args:
        url: URL to query
        query: Natural language question

    Returns:
        Answer from the LLM

    Example:
        ```python
        from owl_browser import quick_query
        answer = quick_query("https://example.com", "What is this page about?")
        ```
    """
    with Browser() as browser:
        page = browser.new_page()
        page.goto(url)
        return page.query_page(query)
