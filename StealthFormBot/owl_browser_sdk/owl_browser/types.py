"""
Type definitions for Owl Browser SDK.

This module contains all type definitions, dataclasses, and enums
used throughout the SDK.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any, Union, Literal


# ==================== ENUMS ====================

class CleanLevel(str, Enum):
    """HTML cleaning levels for getHTML()"""
    MINIMAL = "minimal"
    BASIC = "basic"
    AGGRESSIVE = "aggressive"


class CookieSameSite(str, Enum):
    """SameSite cookie attribute"""
    UNSPECIFIED = "unspecified"
    NONE = "none"
    LAX = "lax"
    STRICT = "strict"


class ProxyType(str, Enum):
    """Proxy protocol types"""
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    SOCKS5H = "socks5h"  # SOCKS5 with remote DNS resolution (recommended for stealth)
    GAE = "gae"  # Private app proxy (uses JSON REST API)


class LLMStatus(str, Enum):
    """LLM availability status"""
    READY = "ready"
    LOADING = "loading"
    UNAVAILABLE = "unavailable"


class KeyName(str, Enum):
    """Special key names for press_key()"""
    ENTER = "Enter"
    RETURN = "Return"
    TAB = "Tab"
    ESCAPE = "Escape"
    ESC = "Esc"
    BACKSPACE = "Backspace"
    DELETE = "Delete"
    DEL = "Del"
    ARROW_UP = "ArrowUp"
    UP = "Up"
    ARROW_DOWN = "ArrowDown"
    DOWN = "Down"
    ARROW_LEFT = "ArrowLeft"
    LEFT = "Left"
    ARROW_RIGHT = "ArrowRight"
    RIGHT = "Right"
    SPACE = "Space"
    HOME = "Home"
    END = "End"
    PAGE_UP = "PageUp"
    PAGE_DOWN = "PageDown"


class ExtractionTemplate(str, Enum):
    """JSON extraction templates"""
    GOOGLE_SEARCH = "google_search"
    WIKIPEDIA = "wikipedia"
    AMAZON_PRODUCT = "amazon_product"
    GITHUB_REPO = "github_repo"
    TWITTER_FEED = "twitter_feed"
    REDDIT_THREAD = "reddit_thread"
    AUTO = ""  # Auto-detect


class CaptchaProvider(str, Enum):
    """CAPTCHA provider types for image CAPTCHA solving"""
    AUTO = "auto"  # Auto-detect provider based on page analysis
    OWL = "owl"  # Owl Browser's internal test CAPTCHA
    RECAPTCHA = "recaptcha"  # Google reCAPTCHA v2 image challenges
    CLOUDFLARE = "cloudflare"  # Cloudflare Turnstile/hCaptcha
    HCAPTCHA = "hcaptcha"  # hCaptcha standalone


# ==================== DATA CLASSES ====================

@dataclass
class Viewport:
    """Viewport size configuration"""
    width: int
    height: int


@dataclass
class PageInfo:
    """Page information"""
    url: str
    title: str
    can_go_back: bool = False
    can_go_forward: bool = False


@dataclass
class ElementMatch:
    """Element match result from semantic matching"""
    selector: str
    confidence: float
    tag: str
    text: Optional[str] = None
    x: int = 0
    y: int = 0
    width: int = 0
    height: int = 0


@dataclass
class Cookie:
    """Cookie object"""
    name: str
    value: str
    domain: str
    path: str
    secure: bool = False
    http_only: bool = False
    same_site: CookieSameSite = CookieSameSite.LAX
    expires: int = -1  # Unix epoch or -1 for session cookie


@dataclass
class VideoStats:
    """Video recording statistics"""
    frames: int
    duration: float
    is_recording: bool
    is_paused: bool


@dataclass
class DateTimeInfo:
    """Date and time information"""
    current: str  # ISO 8601 format
    date: str  # YYYY-MM-DD
    time: str  # HH:MM:SS
    day_of_week: str
    timezone: str
    timezone_offset: str
    unix_timestamp: int


@dataclass
class LocationInfo:
    """Geographic location information"""
    success: bool
    ip: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    error: Optional[str] = None


@dataclass
class WeatherInfo:
    """Weather information"""
    success: bool
    condition: Optional[str] = None
    description: Optional[str] = None
    temperature_c: Optional[float] = None
    temperature_f: Optional[float] = None
    humidity: Optional[int] = None
    wind_speed_kmh: Optional[float] = None
    wind_speed_mph: Optional[float] = None
    error: Optional[str] = None


@dataclass
class DemographicsInfo:
    """Complete demographics information"""
    datetime: DateTimeInfo
    location: Optional[LocationInfo] = None
    weather: Optional[WeatherInfo] = None


@dataclass
class CaptchaDetectionResult:
    """CAPTCHA detection result"""
    detected: bool
    confidence: float
    type: Optional[str] = None
    selectors: Optional[Dict[str, str]] = None


@dataclass
class CaptchaSolveResult:
    """CAPTCHA solve result"""
    success: bool
    attempts: int
    message: Optional[str] = None
    extracted_text: Optional[str] = None
    provider: Optional[str] = None  # Provider that was used (for image CAPTCHAs)


# ==================== CONFIGURATION CLASSES ====================

@dataclass
class ProxyConfig:
    """Proxy configuration"""
    type: ProxyType
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    stealth: bool = True  # Block WebRTC leaks and other detection vectors
    block_webrtc: bool = True
    spoof_timezone: bool = False
    spoof_language: bool = False
    timezone_override: Optional[str] = None  # e.g., "America/New_York"
    language_override: Optional[str] = None  # e.g., "en-US"
    ca_cert_path: Optional[str] = None  # For SSL interception proxies
    trust_custom_ca: bool = False
    # Tor-specific settings for circuit isolation
    is_tor: bool = False  # Mark proxy as Tor (auto-detected if localhost:9050/9150)
    tor_control_port: int = 0  # Control port (0=auto-detect 9051/9151, -1=disabled)
    tor_control_password: Optional[str] = None  # Password for control port (empty=cookie auth)


@dataclass
class ProxyStatus:
    """Proxy status response"""
    enabled: bool
    connected: bool
    type: Optional[ProxyType] = None
    host: Optional[str] = None
    port: Optional[int] = None
    stealth: Optional[bool] = None
    block_webrtc: Optional[bool] = None


@dataclass
class LLMConfig:
    """LLM configuration"""
    enabled: bool = True
    use_builtin: bool = True
    endpoint: Optional[str] = None  # External LLM API endpoint
    model: Optional[str] = None  # External LLM model name
    api_key: Optional[str] = None


@dataclass
class ContextOptions:
    """Context creation options"""
    llm: Optional[LLMConfig] = None
    proxy: Optional[ProxyConfig] = None
    profile_path: Optional[str] = None  # Path to browser profile JSON file
    resource_blocking: bool = True  # Enable resource blocking (ads, trackers, analytics)
    os: Optional[str] = None  # Filter profiles by OS (windows, macos, linux)
    gpu: Optional[str] = None  # Filter profiles by GPU vendor/model (nvidia, amd, intel)


@dataclass
class BrowserConfig:
    """Browser configuration"""
    browser_path: Optional[str] = None  # Auto-detected if not provided
    headless: bool = True
    verbose: bool = False
    init_timeout: int = 30000  # milliseconds


@dataclass
class MarkdownOptions:
    """Markdown extraction options"""
    include_links: bool = True
    include_images: bool = True
    max_length: int = -1  # -1 for no limit


class ExtractSiteOutputFormat(str, Enum):
    """Site extraction output formats"""
    MARKDOWN = "markdown"
    TEXT = "text"
    JSON = "json"


class ExtractSiteStatus(str, Enum):
    """Site extraction job status"""
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass
class ExtractSiteOptions:
    """Site extraction options"""
    depth: int = 2  # How many link levels to follow
    max_pages: int = 5  # Maximum pages to extract
    follow_external: bool = False  # Follow external domains
    output_format: ExtractSiteOutputFormat = ExtractSiteOutputFormat.MARKDOWN
    include_images: bool = True  # Include image URLs
    include_metadata: bool = True  # Include title/description
    exclude_patterns: Optional[List[str]] = None  # URL patterns to skip
    timeout_per_page: int = 10000  # ms


@dataclass
class ExtractSiteJob:
    """Site extraction job information"""
    job_id: str


@dataclass
class ExtractSiteProgress:
    """Site extraction progress information"""
    status: ExtractSiteStatus
    pages_completed: int
    pages_total: int
    current_url: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ExtractSitePage:
    """Extracted page information"""
    url: str
    title: Optional[str] = None
    description: Optional[str] = None


@dataclass
class ExtractSiteResult:
    """Site extraction result"""
    content: Union[str, Dict[str, Any]]  # Format depends on output_format
    pages: List[ExtractSitePage] = field(default_factory=list)
    total_pages: int = 0


@dataclass
class VideoRecordingOptions:
    """Video recording options"""
    fps: int = 30
    codec: str = "libx264"


@dataclass
class SetCookieOptions:
    """Options for setting a cookie"""
    domain: Optional[str] = None
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: CookieSameSite = CookieSameSite.LAX
    expires: int = -1  # Unix epoch or -1 for session cookie


@dataclass
class ScreenshotOptions:
    """Screenshot options"""
    path: Optional[str] = None  # If provided, save to file
    format: str = "png"
    quality: int = 80  # For JPEG
    mode: str = "viewport"  # "viewport", "element", or "fullpage"
    selector: Optional[str] = None  # CSS selector for element mode
    scale: int = 100  # Scale percentage (1-100). Default is 100 (no scaling)


@dataclass
class WaitOptions:
    """Wait options"""
    timeout: int = 5000  # milliseconds
    visible: bool = False


# ==================== TEST TYPES ====================

@dataclass
class TestStep:
    """Test step from Developer Playground JSON export.

    Supports all step types from the flow designer including:
    - Navigation: navigate, reload, go_back, go_forward
    - Interaction: click, type, pick, submit_form, press_key, drag_drop,
      html5_drag_drop, mouse_move, hover, double_click, right_click,
      clear_input, focus, blur, select_all, keyboard_combo, upload_file
    - Element State: is_visible, is_enabled, is_checked, get_attribute, get_bounding_box
    - JavaScript: evaluate
    - Frames: list_frames, switch_to_frame, switch_to_main_frame
    - Scrolling: scroll_up, scroll_down, scroll_to_top, scroll_to_bottom,
      scroll_by, scroll_to_element
    - Waiting: wait, wait_for_selector, wait_for_network_idle,
      wait_for_function, wait_for_url
    - Extraction: extract, extract_text, get_html, get_markdown,
      extract_json, get_page_info
    - AI: query, query_page, summarize_page, nla
    - CAPTCHA: detect_captcha, classify_captcha, solve_captcha
    - Cookies: get_cookies, set_cookie, delete_cookies
    - Visual: screenshot, highlight, set_viewport
    - Video: record_video, start_video_recording, stop_video, stop_video_recording
    - Network: add_network_rule, remove_network_rule, enable_network_interception,
      get_network_log, clear_network_log
    - Downloads: set_download_path, get_downloads, wait_for_download, cancel_download
    - Dialogs: set_dialog_action, get_pending_dialog, handle_dialog, wait_for_dialog
    - Tabs: new_tab, get_tabs, switch_tab, get_active_tab, close_tab,
      get_tab_count, set_popup_policy, get_blocked_popups
    """
    type: str
    selected: bool = True

    # Navigation
    url: Optional[str] = None
    ignore_cache: Optional[bool] = None

    # Interaction - basic
    selector: Optional[str] = None
    text: Optional[str] = None
    value: Optional[str] = None
    key: Optional[str] = None
    combo: Optional[str] = None

    # Interaction - coordinates
    start_x: Optional[int] = None
    start_y: Optional[int] = None
    end_x: Optional[int] = None
    end_y: Optional[int] = None
    x: Optional[int] = None
    y: Optional[int] = None
    mid_points: Optional[List[List[int]]] = None
    stop_points: Optional[List[List[int]]] = None
    steps: Optional[int] = None

    # Interaction - drag and drop
    source_selector: Optional[str] = None
    target_selector: Optional[str] = None

    # Upload
    file_paths: Optional[List[str]] = None

    # Element state
    attribute: Optional[str] = None

    # JavaScript
    script: Optional[str] = None

    # Frames
    frame_selector: Optional[str] = None

    # Waiting
    timeout: Optional[int] = None
    duration: Optional[int] = None
    idle_time: Optional[int] = None
    js_function: Optional[str] = None
    url_pattern: Optional[str] = None
    is_regex: Optional[bool] = None

    # Extraction
    clean_level: Optional[str] = None
    include_links: Optional[bool] = None
    include_images: Optional[bool] = None
    max_length: Optional[int] = None
    template: Optional[str] = None

    # AI
    query: Optional[str] = None
    command: Optional[str] = None
    force_refresh: Optional[bool] = None

    # CAPTCHA
    max_attempts: Optional[int] = None
    provider: Optional[str] = None

    # Cookies
    name: Optional[str] = None
    cookie_value: Optional[str] = None  # 'value' already used
    domain: Optional[str] = None
    path: Optional[str] = None
    expires: Optional[int] = None
    http_only: Optional[bool] = None
    secure: Optional[bool] = None
    same_site: Optional[str] = None

    # Screenshot/Visual
    filename: Optional[str] = None
    mode: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None

    # Video
    fps: Optional[int] = None
    codec: Optional[str] = None

    # Network
    action: Optional[str] = None
    rule_id: Optional[str] = None
    enable: Optional[bool] = None

    # Downloads
    download_path: Optional[str] = None
    download_id: Optional[str] = None

    # Dialogs
    dialog_type: Optional[str] = None
    dialog_action: Optional[str] = None
    dialog_id: Optional[str] = None
    accept: Optional[bool] = None
    prompt_text: Optional[str] = None
    response_text: Optional[str] = None

    # Tabs
    tab_id: Optional[str] = None
    policy: Optional[str] = None

    # Generic params dict (for frontend compatibility)
    params: Optional[Dict[str, Any]] = None


@dataclass
class TestTemplate:
    """Test template from Developer Playground JSON export"""
    name: str
    steps: List[TestStep]
    description: Optional[str] = None


@dataclass
class TestExecutionOptions:
    """Test execution options"""
    continue_on_error: bool = False
    screenshot_on_error: bool = True
    verbose: bool = False


@dataclass
class TestError:
    """Test step error"""
    step: int
    type: str
    message: str


@dataclass
class TestExecutionResult:
    """Test execution result"""
    test_name: str
    total_steps: int
    executed_steps: int
    successful_steps: int
    failed_steps: int
    execution_time: float  # milliseconds
    success: bool
    errors: List[TestError] = field(default_factory=list)


# ==================== BROWSER PROFILE TYPES ====================

@dataclass
class BrowserFingerprint:
    """Browser fingerprint configuration for consistent identity across sessions."""
    # User Agent and Navigator
    user_agent: str = ""
    platform: str = "Win32"
    vendor: str = "Google Inc."
    languages: List[str] = field(default_factory=lambda: ["en-US", "en"])
    hardware_concurrency: int = 8
    device_memory: int = 8
    max_touch_points: int = 0

    # Canvas fingerprinting
    canvas_noise_seed: float = 0.0

    # WebGL fingerprinting
    gpu_profile_index: int = 0
    webgl_vendor: str = ""
    webgl_renderer: str = ""

    # Screen/Display
    screen_width: int = 1920
    screen_height: int = 1080
    color_depth: int = 24
    pixel_ratio: int = 1

    # Timezone and locale
    timezone: str = ""
    locale: str = "en-US"

    # Audio context
    audio_noise_seed: float = 0.0

    # Font fingerprinting
    installed_fonts: List[str] = field(default_factory=list)

    # Plugin info
    has_pdf_plugin: bool = True
    has_chrome_pdf: bool = True


@dataclass
class BrowserProfile:
    """
    Complete browser profile containing identity fingerprint, cookies, and settings.

    Profiles enable persistent browser identities across sessions, useful for:
    - Maintaining login sessions
    - Consistent fingerprinting for anti-detection
    - Saving/loading browser state
    """
    # Profile metadata
    profile_id: str = ""
    profile_name: str = ""
    created_at: str = ""
    modified_at: str = ""
    version: int = 1

    # Browser fingerprint
    fingerprint: Optional[BrowserFingerprint] = None

    # Cookies
    cookies: List[Cookie] = field(default_factory=list)

    # LLM configuration
    has_llm_config: bool = False
    llm_config: Optional[LLMConfig] = None

    # Proxy configuration
    has_proxy_config: bool = False
    proxy_config: Optional[ProxyConfig] = None

    # Profile settings
    auto_save_cookies: bool = True
    persist_local_storage: bool = True


@dataclass
class ProfileOptions:
    """Options for creating a new profile."""
    name: str = ""
    fingerprint: Optional[BrowserFingerprint] = None


# ==================== CONTEXT INFO ====================

@dataclass
class VMProfile:
    """VM profile information for a browser context."""
    vm_id: str = ""
    platform: str = ""
    user_agent: str = ""
    hardware_concurrency: int = 0
    device_memory: int = 0
    screen_width: int = 0
    screen_height: int = 0
    timezone: str = ""
    locale: str = ""


@dataclass
class CanvasInfo:
    """Canvas fingerprint configuration."""
    hash_seed: int = 0
    noise_seed: float = 0.0


@dataclass
class AudioInfo:
    """Audio fingerprint configuration."""
    noise_seed: float = 0.0


@dataclass
class GPUInfo:
    """GPU fingerprint configuration."""
    profile_index: int = 0
    webgl_vendor: str = ""
    webgl_renderer: str = ""


@dataclass
class ContextInfo:
    """
    Context information containing VM profile and fingerprint hashes.

    This provides detailed information about the browser context's stealth
    configuration including the VM profile being used and all fingerprint
    hash values (canvas, audio, GPU).

    Attributes:
        context_id: Browser context ID
        vm_profile: VM profile information
        canvas: Canvas fingerprint configuration
        audio: Audio fingerprint configuration
        gpu: GPU fingerprint configuration
        has_profile: Whether a profile is loaded
        profile_path: Path to the loaded profile file (if any)
    """
    context_id: str = ""
    vm_profile: VMProfile = field(default_factory=VMProfile)
    canvas: CanvasInfo = field(default_factory=CanvasInfo)
    audio: AudioInfo = field(default_factory=AudioInfo)
    gpu: GPUInfo = field(default_factory=GPUInfo)
    has_profile: bool = False
    profile_path: Optional[str] = None


# ==================== CONNECTION MODE ====================

class ConnectionMode(str, Enum):
    """Browser connection mode - local binary or remote HTTP server."""
    LOCAL = "local"   # Connect to local browser binary via stdin/stdout
    REMOTE = "remote"  # Connect to remote HTTP server


class AuthMode(str, Enum):
    """Authentication mode for remote HTTP server."""
    TOKEN = "token"  # Simple bearer token authentication
    JWT = "jwt"      # JWT (JSON Web Token) authentication with RSA signing


class TransportMode(str, Enum):
    """Transport mode for remote connections."""
    HTTP = "http"      # REST API over HTTP (default)
    WEBSOCKET = "websocket"  # WebSocket for real-time communication
    WS = "websocket"   # Alias for WEBSOCKET


@dataclass
class JWTConfig:
    """
    Configuration for JWT authentication with automatic token generation.

    Example:
        ```python
        from owl_browser import Browser, RemoteConfig, JWTConfig, AuthMode

        # Connect with JWT authentication using private key
        browser = Browser(remote=RemoteConfig(
            url="http://192.168.1.100:8080",
            auth_mode=AuthMode.JWT,
            jwt=JWTConfig(
                private_key="/path/to/private.pem",
                expires_in=3600,  # 1 hour
                issuer="my-app"
            )
        ))
        browser.launch()
        ```
    """
    # Path to RSA private key file (PEM format) or the key string itself
    private_key: str

    # Token validity duration in seconds (default: 3600 = 1 hour)
    expires_in: int = 3600

    # Seconds before expiry to auto-refresh token (default: 300 = 5 minutes)
    refresh_threshold: int = 300

    # Issuer claim (iss)
    issuer: Optional[str] = None

    # Subject claim (sub)
    subject: Optional[str] = None

    # Audience claim (aud)
    audience: Optional[str] = None

    # Additional custom claims
    claims: Optional[Dict[str, Any]] = None


@dataclass
class RetryConfig:
    """
    Configuration for retry behavior with exponential backoff.

    Used by HTTP transport for automatic retries on transient failures.

    Example:
        ```python
        from owl_browser import Browser, RemoteConfig, RetryConfig

        browser = Browser(remote=RemoteConfig(
            url="http://192.168.1.100:8080",
            token="your-secret-token",
            retry=RetryConfig(
                max_retries=5,
                initial_delay_ms=200,
                max_delay_ms=15000,
                backoff_multiplier=2.0,
                jitter_factor=0.1
            )
        ))
        ```
    """
    max_retries: int = 3  # Maximum number of retry attempts
    initial_delay_ms: int = 100  # Initial delay in milliseconds
    max_delay_ms: int = 10000  # Maximum delay cap in milliseconds
    backoff_multiplier: float = 2.0  # Multiplier for exponential backoff
    jitter_factor: float = 0.1  # Random jitter factor (0-1)


@dataclass
class ReconnectConfig:
    """
    Configuration for automatic WebSocket reconnection.

    Used by WebSocket transport for auto-reconnection on connection loss.

    Example:
        ```python
        from owl_browser import Browser, RemoteConfig, TransportMode, ReconnectConfig

        browser = Browser(remote=RemoteConfig(
            url="http://192.168.1.100:8080",
            token="your-secret-token",
            transport=TransportMode.WEBSOCKET,
            reconnect=ReconnectConfig(
                enabled=True,
                max_attempts=10,
                initial_delay_ms=500,
                max_delay_ms=60000
            )
        ))
        ```
    """
    enabled: bool = True  # Whether auto-reconnection is enabled
    max_attempts: int = 5  # Maximum reconnection attempts (0 = infinite)
    initial_delay_ms: int = 1000  # Initial delay in milliseconds
    max_delay_ms: int = 30000  # Maximum delay cap in milliseconds
    backoff_multiplier: float = 2.0  # Multiplier for exponential backoff
    jitter_factor: float = 0.1  # Random jitter factor (0-1)


@dataclass
class ConcurrencyConfig:
    """
    Configuration for concurrency limiting.

    Limits the number of concurrent requests to prevent overwhelming the server.

    Example:
        ```python
        from owl_browser import Browser, RemoteConfig, ConcurrencyConfig

        browser = Browser(remote=RemoteConfig(
            url="http://192.168.1.100:8080",
            token="your-secret-token",
            concurrency=ConcurrencyConfig(max_concurrent=20)
        ))
        ```
    """
    max_concurrent: int = 10  # Maximum concurrent requests


@dataclass
class RemoteConfig:
    """
    Configuration for connecting to a remote Owl Browser HTTP server.

    Supports two authentication modes:
    - TOKEN (default): Simple bearer token authentication
    - JWT: JSON Web Token authentication with RSA signing (auto-generated)

    Supports two transport modes:
    - HTTP (default): REST API over HTTP
    - WEBSOCKET: WebSocket for real-time, low-latency communication

    Example (Token mode with HTTP):
        ```python
        from owl_browser import Browser, RemoteConfig

        # Connect with simple token authentication (HTTP REST API)
        browser = Browser(remote=RemoteConfig(
            url="http://192.168.1.100:8080",
            token="your-secret-token"
        ))
        browser.launch()
        ```

    Example (Token mode with WebSocket):
        ```python
        from owl_browser import Browser, RemoteConfig, TransportMode

        # Connect with WebSocket for real-time communication
        browser = Browser(remote=RemoteConfig(
            url="http://192.168.1.100:8080",
            token="your-secret-token",
            transport=TransportMode.WEBSOCKET
        ))
        browser.launch()
        ```

    Example (JWT mode with private key):
        ```python
        from owl_browser import Browser, RemoteConfig, JWTConfig, AuthMode

        # Connect with JWT authentication - SDK generates tokens automatically
        browser = Browser(remote=RemoteConfig(
            url="http://192.168.1.100:8080",
            auth_mode=AuthMode.JWT,
            jwt=JWTConfig(
                private_key="/path/to/private.pem",
                expires_in=3600,
                issuer="my-app"
            )
        ))
        browser.launch()
        ```

    Example (High-performance configuration):
        ```python
        from owl_browser import Browser, RemoteConfig, RetryConfig, ConcurrencyConfig

        # Configure for high-performance concurrent usage
        browser = Browser(remote=RemoteConfig(
            url="http://192.168.1.100:8080",
            token="your-secret-token",
            retry=RetryConfig(max_retries=5, initial_delay_ms=50),
            concurrency=ConcurrencyConfig(max_concurrent=50)
        ))
        browser.launch()
        ```
    """
    url: str  # Base URL of the HTTP server (e.g., "http://localhost:8080")
    token: Optional[str] = None  # Bearer token (required for TOKEN mode)
    auth_mode: AuthMode = AuthMode.TOKEN  # Authentication mode (token or jwt)
    jwt: Optional[JWTConfig] = None  # JWT configuration (required for JWT mode)
    transport: TransportMode = TransportMode.HTTP  # Transport mode (http or websocket)
    timeout: int = 30000  # Request timeout in milliseconds
    verify_ssl: bool = True  # Verify SSL certificates
    retry: Optional[RetryConfig] = None  # Retry configuration for HTTP transport
    reconnect: Optional[ReconnectConfig] = None  # Reconnection config for WebSocket
    concurrency: Optional[ConcurrencyConfig] = None  # Concurrency limiting config
    api_prefix: str = ""  # API path prefix for all endpoints (e.g., "/api" for nginx proxy)

    def __post_init__(self):
        # Normalize URL - remove trailing slash
        self.url = self.url.rstrip('/')
        # Normalize api_prefix - ensure it starts with '/' if provided, and has no trailing slash
        if self.api_prefix:
            if not self.api_prefix.startswith('/'):
                self.api_prefix = '/' + self.api_prefix
            self.api_prefix = self.api_prefix.rstrip('/')

        # Validate configuration
        if self.auth_mode == AuthMode.TOKEN and not self.token:
            raise ValueError("Token is required for TOKEN authentication mode")
        if self.auth_mode == AuthMode.JWT and not self.jwt:
            raise ValueError("JWTConfig is required for JWT authentication mode")


# ==================== NETWORK INTERCEPTION TYPES ====================

class NetworkAction(str, Enum):
    """Network interception action"""
    ALLOW = "allow"
    BLOCK = "block"
    MOCK = "mock"
    REDIRECT = "redirect"


@dataclass
class NetworkRule:
    """Network interception rule configuration."""
    url_pattern: str  # URL pattern to match (glob or regex)
    action: NetworkAction  # Action to take when URL matches
    is_regex: bool = False  # Whether url_pattern is a regex (default: false for glob)
    redirect_url: Optional[str] = None  # URL to redirect to (for redirect action)
    mock_body: Optional[str] = None  # Response body to return (for mock action)
    mock_status: int = 200  # HTTP status code for mock response
    mock_content_type: Optional[str] = None  # Content-Type header for mock response


@dataclass
class NetworkLogEntry:
    """Network log entry."""
    url: str  # Request URL
    method: str  # HTTP method
    status: int  # HTTP status code
    timestamp: int  # Request timestamp
    intercepted: bool  # Whether request was intercepted


# ==================== FILE DOWNLOAD TYPES ====================

class DownloadStatus(str, Enum):
    """Download status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass
class DownloadInfo:
    """Download information."""
    id: str  # Download ID
    url: str  # Source URL
    filename: str  # File name
    path: str  # Full path to downloaded file
    status: DownloadStatus  # Download status
    bytes_received: int  # Bytes received so far
    total_bytes: int  # Total bytes (may be -1 if unknown)


# ==================== DIALOG HANDLING TYPES ====================

class DialogType(str, Enum):
    """Dialog type"""
    ALERT = "alert"
    CONFIRM = "confirm"
    PROMPT = "prompt"
    BEFOREUNLOAD = "beforeunload"


class DialogAction(str, Enum):
    """Dialog action"""
    ACCEPT = "accept"
    DISMISS = "dismiss"
    ACCEPT_WITH_TEXT = "accept_with_text"


@dataclass
class DialogInfo:
    """Dialog information."""
    id: str  # Dialog ID
    type: DialogType  # Dialog type
    message: str  # Dialog message
    default_value: Optional[str] = None  # Default value for prompt dialogs


# ==================== TAB/WINDOW MANAGEMENT TYPES ====================

class PopupPolicy(str, Enum):
    """Popup handling policy"""
    ALLOW = "allow"
    BLOCK = "block"
    NEW_TAB = "new_tab"
    BACKGROUND = "background"


@dataclass
class TabInfo:
    """Tab information."""
    tab_id: str  # Tab ID
    url: str  # Current URL
    title: str  # Page title
    active: bool  # Whether this tab is active


# ==================== ELEMENT STATE TYPES ====================

@dataclass
class BoundingBox:
    """Element bounding box (position and size)."""
    x: float  # X coordinate relative to viewport
    y: float  # Y coordinate relative to viewport
    width: float  # Element width in pixels
    height: float  # Element height in pixels


# ==================== FRAME TYPES ====================

@dataclass
class FrameInfo:
    """Frame information."""
    id: str  # Frame identifier
    url: str  # Frame URL
    is_main: bool  # Whether this is the main frame
    name: Optional[str] = None  # Frame name (if set)


# ==================== KEYBOARD TYPES ====================

class ModifierKey(str, Enum):
    """Modifier key for keyboard combinations"""
    CTRL = "ctrl"
    ALT = "alt"
    SHIFT = "shift"
    META = "meta"


# ==================== LIVE STREAMING TYPES ====================

@dataclass
class LiveStreamOptions:
    """Live stream options"""
    fps: int = 15  # Frames per second (default: 15)
    quality: int = 75  # JPEG quality 1-100 (default: 75)


@dataclass
class LiveStreamStats:
    """Live stream statistics"""
    active: bool = False  # Whether stream is active
    fps: int = 15  # Current FPS
    quality: int = 75  # JPEG quality
    subscribers: int = 0  # Number of subscribers
    frames_sent: int = 0  # Total frames sent
    bytes_sent: int = 0  # Total bytes sent


@dataclass
class LiveStreamInfo:
    """Live stream info"""
    context_id: str = ""  # Context ID
    fps: int = 15  # Current FPS
    quality: int = 75  # JPEG quality
    subscribers: int = 0  # Number of subscribers


# ==================== ELEMENT INFO TYPES ====================

@dataclass
class ElementAtPositionInfo:
    """Element information from position query"""
    tag: str = ""  # HTML tag name
    selector: str = ""  # CSS selector for the element
    text: Optional[str] = None  # Element text content
    id: Optional[str] = None  # Element ID if set
    classes: List[str] = field(default_factory=list)  # Element class names
    x: int = 0  # Bounding box X
    y: int = 0  # Bounding box Y
    width: int = 0  # Bounding box width
    height: int = 0  # Bounding box height


@dataclass
class InteractiveElement:
    """Interactive element information"""
    tag: str = ""  # HTML tag name
    selector: str = ""  # CSS selector for the element
    type: Optional[str] = None  # Element type (for inputs)
    text: Optional[str] = None  # Element text content
    role: Optional[str] = None  # Element role
    x: int = 0  # Bounding box X
    y: int = 0  # Bounding box Y
    width: int = 0  # Bounding box width
    height: int = 0  # Bounding box height
    visible: bool = True  # Whether element is visible
    enabled: bool = True  # Whether element is enabled


# ==================== LICENSE TYPES ====================

class LicenseStatusType(str, Enum):
    """License status type for API responses"""
    VALID = "valid"
    EXPIRED = "expired"
    NOT_FOUND = "not_found"
    INVALID = "invalid"
    HARDWARE_MISMATCH = "hardware_mismatch"


@dataclass
class LicenseStatusResponse:
    """License status response from API"""
    valid: bool = False  # Whether license is valid
    status: str = ""  # License status
    error: Optional[str] = None  # Error message if any


@dataclass
class LicenseInfo:
    """License information"""
    license_id: str = ""  # License ID
    type: str = ""  # License type
    expires_at: str = ""  # Expiration date (ISO 8601)
    features: List[str] = field(default_factory=list)  # Features enabled
    hardware_id: Optional[str] = None  # Hardware fingerprint


@dataclass
class HardwareFingerprint:
    """Hardware fingerprint"""
    fingerprint: str = ""  # Fingerprint ID


# ==================== AI ELEMENT FINDING TYPES ====================

@dataclass
class FoundElement:
    """Found element from AI element finding"""
    selector: str = ""  # CSS selector for the element
    confidence: float = 0.0  # Confidence score (0-1)
    tag: str = ""  # Element tag name
    text: Optional[str] = None  # Element text content
    x: int = 0  # Bounding box X
    y: int = 0  # Bounding box Y
    width: int = 0  # Bounding box width
    height: int = 0  # Bounding box height


@dataclass
class AIExtractionResult:
    """AI extraction result"""
    content: str = ""  # Extracted content
    confidence: float = 0.0  # Confidence score


@dataclass
class AIAnalysisResult:
    """AI analysis result"""
    topic: Optional[str] = None  # Page topic/summary
    main_content: Optional[str] = None  # Main content
    elements: List[str] = field(default_factory=list)  # Key elements identified
    structure: Optional[Dict[str, Any]] = None  # Page structure analysis


# ==================== BLOCKER STATS TYPES ====================

@dataclass
class BlockerStats:
    """Ad/tracker blocker statistics"""
    ads_blocked: int = 0  # Number of ads blocked
    trackers_blocked: int = 0  # Number of trackers blocked
    analytics_blocked: int = 0  # Number of analytics requests blocked
    total_blocked: int = 0  # Total requests blocked
    total_allowed: int = 0  # Total requests allowed


# Type aliases for convenience
ContextId = str
SelectorType = Union[str, None]


# ==================== FLOW TYPES ====================

class ConditionOperator(str, Enum):
    """Condition operators for comparing values in flow conditions"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IS_TRUTHY = "is_truthy"
    IS_FALSY = "is_falsy"
    IS_EMPTY = "is_empty"
    IS_NOT_EMPTY = "is_not_empty"
    REGEX_MATCH = "regex_match"


class FlowStepStatus(str, Enum):
    """Flow step status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class FlowCondition:
    """Flow condition configuration"""
    source: Literal["previous", "step"]  # What to check: 'previous' or specific 'step'
    operator: ConditionOperator  # Comparison operator
    source_step_id: Optional[str] = None  # Step ID to check (when source is 'step')
    field: Optional[str] = None  # Field path in result (e.g., 'success', 'data.count')
    value: Optional[Any] = None  # Value to compare against


@dataclass
class FlowStep:
    """A step in a flow"""
    id: str  # Unique identifier
    type: str  # Tool/action type (e.g., 'navigate', 'click', 'condition')
    enabled: bool = True  # Whether this step is enabled
    params: Dict[str, Any] = field(default_factory=dict)  # Tool parameters
    condition: Optional[FlowCondition] = None  # Condition for conditional execution
    on_true: Optional[List["FlowStep"]] = None  # Steps if condition is true
    on_false: Optional[List["FlowStep"]] = None  # Steps if condition is false
    status: Optional[FlowStepStatus] = None  # Execution status
    result: Optional[Any] = None  # Execution result
    error: Optional[str] = None  # Error message if failed
    duration: Optional[int] = None  # Execution duration in milliseconds
    branch_taken: Optional[Literal["true", "false"]] = None  # Which branch was taken


@dataclass
class Flow:
    """Flow definition"""
    name: str  # Flow name
    steps: List[FlowStep]  # Steps in the flow
    id: Optional[str] = None  # Unique identifier
    description: Optional[str] = None  # Flow description


@dataclass
class FlowExecutionResult:
    """Flow execution result"""
    success: bool  # Overall success status
    steps: List[FlowStep]  # Executed steps with results
    total_duration: int  # Total execution time in milliseconds
    error: Optional[str] = None  # Error message if failed
