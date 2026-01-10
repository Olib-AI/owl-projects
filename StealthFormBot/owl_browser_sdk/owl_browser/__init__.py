"""
Owl Browser SDK for Python

AI-first browser automation SDK with on-device vision model,
natural language selectors, and comprehensive stealth features.

Supports dual mode:
- LOCAL: Connect to local browser binary via stdin/stdout IPC (default)
- REMOTE: Connect to remote browser HTTP server via REST API

Basic Example (Local):
    ```python
    from owl_browser import Browser

    with Browser() as browser:
        page = browser.new_page()
        page.goto("https://example.com")

        # Use natural language selectors
        page.click("search button")
        page.type("search input", "hello world")

        screenshot = page.screenshot("screenshot.png")
    ```

Remote Server Example:
    ```python
    from owl_browser import Browser, RemoteConfig

    # Connect to a remote browser server
    with Browser(remote=RemoteConfig(
        url="http://192.168.1.100:8080",
        token="your-secret-token"
    )) as browser:
        page = browser.new_page()
        page.goto("https://example.com")
        page.screenshot("screenshot.png")
    ```

Concurrent Example:
    ```python
    from owl_browser import Browser
    from concurrent.futures import ThreadPoolExecutor

    browser = Browser()
    browser.launch()

    def scrape(url):
        page = browser.new_page()
        page.goto(url)
        text = page.extract_text()
        page.close()
        return text

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(scrape, urls))

    browser.close()
    ```

Proxy Example:
    ```python
    from owl_browser import Browser, ProxyConfig, ProxyType

    with Browser() as browser:
        page = browser.new_page(proxy=ProxyConfig(
            type=ProxyType.SOCKS5H,
            host="proxy.example.com",
            port=1080,
            timezone_override="America/New_York"
        ))
        page.goto("https://whatismyip.com")
    ```
"""

__version__ = "1.0.0"
__author__ = "Olib AI"

# Main classes
from .browser import Browser, quick_screenshot, quick_extract, quick_query
from .context import BrowserContext
from .core import BrowserCore

# Exceptions
from .exceptions import (
    OwlBrowserError,
    LicenseError,
    BrowserInitializationError,
    BrowserNotRunningError,
    CommandTimeoutError,
    ContextError,
    ContextLimitError,
    NavigationError,
    ElementNotFoundError,
    FirewallError,
    AuthenticationError,
    RateLimitError,
    IPBlockedError,
    # Action result validation
    ActionStatus,
    ActionResult,
    ActionError,
    is_action_result,
    throw_if_action_failed,
)

# Async classes
from .async_browser import (
    AsyncBrowser,
    AsyncBrowserContext,
    async_screenshot,
    async_extract,
    async_query,
)

# JWT utilities for HTTP authentication
from .jwt import (
    generate_jwt,
    decode_jwt,
    is_jwt_expired,
    get_jwt_remaining_time,
    JWTManager,
    generate_key_pair,
)

# Types and enums
from .types import (
    # Enums
    CleanLevel,
    CookieSameSite,
    ProxyType,
    LLMStatus,
    KeyName,
    ExtractionTemplate,
    CaptchaProvider,
    ConnectionMode,
    AuthMode,
    TransportMode,
    NetworkAction,
    DownloadStatus,
    DialogType,
    DialogAction,
    PopupPolicy,

    # Configuration
    BrowserConfig,
    ContextOptions,
    ProxyConfig,
    ProxyStatus,
    LLMConfig,
    MarkdownOptions,
    ExtractSiteOutputFormat,
    ExtractSiteOptions,
    ExtractSiteJob,
    ExtractSiteStatus,
    ExtractSiteProgress,
    ExtractSitePage,
    ExtractSiteResult,
    VideoRecordingOptions,
    ScreenshotOptions,
    SetCookieOptions,
    WaitOptions,
    RemoteConfig,
    JWTConfig,
    RetryConfig,
    ReconnectConfig,
    ConcurrencyConfig,

    # Data classes
    Viewport,
    PageInfo,
    ElementMatch,
    Cookie,
    VideoStats,
    DateTimeInfo,
    LocationInfo,
    WeatherInfo,
    DemographicsInfo,
    CaptchaDetectionResult,
    CaptchaSolveResult,
    NetworkRule,
    NetworkLogEntry,
    DownloadInfo,
    DialogInfo,
    TabInfo,
    BoundingBox,
    FrameInfo,
    ModifierKey,

    # Browser profile types
    BrowserFingerprint,
    BrowserProfile,
    ProfileOptions,

    # Context info types
    ContextInfo,
    VMProfile,
    CanvasInfo,
    AudioInfo,
    GPUInfo,

    # Test types
    TestStep,
    TestTemplate,
    TestExecutionOptions,
    TestExecutionResult,
    TestError,

    # Live streaming types
    LiveStreamOptions,
    LiveStreamStats,
    LiveStreamInfo,

    # Element picker types
    ElementAtPositionInfo,
    InteractiveElement,

    # License types
    LicenseStatusType,
    LicenseStatusResponse,
    LicenseInfo,
    HardwareFingerprint,

    # Flow types
    ConditionOperator,
    FlowStepStatus,
    FlowCondition,
    FlowStep,
    Flow,
    FlowExecutionResult,

    # Type aliases
    ContextId,
)

# Flow utilities
from .flow import (
    evaluate_condition,
    get_value_at_path,
    execute_flow,
)

# Convenience aliases
Page = BrowserContext  # Alias for familiarity with Playwright/Puppeteer
AsyncPage = AsyncBrowserContext  # Async alias

__all__ = [
    # Version
    "__version__",

    # Main classes
    "Browser",
    "BrowserContext",
    "BrowserCore",
    "Page",  # Alias

    # Async classes
    "AsyncBrowser",
    "AsyncBrowserContext",
    "AsyncPage",  # Alias

    # Exceptions
    "OwlBrowserError",
    "LicenseError",
    "BrowserInitializationError",
    "BrowserNotRunningError",
    "CommandTimeoutError",
    "ContextError",
    "ContextLimitError",
    "NavigationError",
    "ElementNotFoundError",
    "FirewallError",
    "AuthenticationError",
    "RateLimitError",
    "IPBlockedError",
    # Action result validation
    "ActionStatus",
    "ActionResult",
    "ActionError",
    "is_action_result",
    "throw_if_action_failed",

    # Quick utilities (sync)
    "quick_screenshot",
    "quick_extract",
    "quick_query",

    # Quick utilities (async)
    "async_screenshot",
    "async_extract",
    "async_query",

    # JWT utilities
    "generate_jwt",
    "decode_jwt",
    "is_jwt_expired",
    "get_jwt_remaining_time",
    "JWTManager",
    "generate_key_pair",

    # Enums
    "CleanLevel",
    "CookieSameSite",
    "ProxyType",
    "LLMStatus",
    "KeyName",
    "ExtractionTemplate",
    "CaptchaProvider",
    "ConnectionMode",
    "AuthMode",
    "TransportMode",
    "NetworkAction",
    "DownloadStatus",
    "DialogType",
    "DialogAction",
    "PopupPolicy",

    # Configuration
    "BrowserConfig",
    "ContextOptions",
    "ProxyConfig",
    "ProxyStatus",
    "LLMConfig",
    "MarkdownOptions",
    "ExtractSiteOutputFormat",
    "ExtractSiteOptions",
    "ExtractSiteJob",
    "ExtractSiteStatus",
    "ExtractSiteProgress",
    "ExtractSitePage",
    "ExtractSiteResult",
    "VideoRecordingOptions",
    "ScreenshotOptions",
    "SetCookieOptions",
    "WaitOptions",
    "RemoteConfig",
    "JWTConfig",
    "RetryConfig",
    "ReconnectConfig",
    "ConcurrencyConfig",

    # Data classes
    "Viewport",
    "PageInfo",
    "ElementMatch",
    "Cookie",
    "VideoStats",
    "DateTimeInfo",
    "LocationInfo",
    "WeatherInfo",
    "DemographicsInfo",
    "CaptchaDetectionResult",
    "CaptchaSolveResult",
    "NetworkRule",
    "NetworkLogEntry",
    "DownloadInfo",
    "DialogInfo",
    "TabInfo",
    "BoundingBox",
    "FrameInfo",
    "ModifierKey",

    # Browser profile types
    "BrowserFingerprint",
    "BrowserProfile",
    "ProfileOptions",

    # Context info types
    "ContextInfo",
    "VMProfile",
    "CanvasInfo",
    "AudioInfo",
    "GPUInfo",

    # Test types
    "TestStep",
    "TestTemplate",
    "TestExecutionOptions",
    "TestExecutionResult",
    "TestError",

    # Live streaming types
    "LiveStreamOptions",
    "LiveStreamStats",
    "LiveStreamInfo",

    # Element picker types
    "ElementAtPositionInfo",
    "InteractiveElement",

    # License types
    "LicenseStatusType",
    "LicenseStatusResponse",
    "LicenseInfo",
    "HardwareFingerprint",

    # Flow types
    "ConditionOperator",
    "FlowStepStatus",
    "FlowCondition",
    "FlowStep",
    "Flow",
    "FlowExecutionResult",

    # Flow utilities
    "evaluate_condition",
    "get_value_at_path",
    "execute_flow",

    # Type aliases
    "ContextId",
]
