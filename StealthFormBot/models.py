"""
StealthFormBot Type Definitions

Type-safe dataclasses and enums for form automation.
All types are Pydantic models for runtime validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


class FieldType(str, Enum):
    """Form field types supported by the bot."""
    TEXT = "text"
    EMAIL = "email"
    PASSWORD = "password"
    PHONE = "phone"
    NUMBER = "number"
    TEXTAREA = "textarea"
    SELECT = "select"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    DATE = "date"
    DATETIME = "datetime"
    FILE = "file"
    HIDDEN = "hidden"
    CUSTOM = "custom"  # For custom components (React, Vue, etc.)


class WaitCondition(str, Enum):
    """Wait conditions for form steps."""
    LOAD = "load"
    DOMCONTENTLOADED = "domcontentloaded"
    NETWORKIDLE = "networkidle"
    SELECTOR = "selector"  # Wait for specific selector
    URL = "url"  # Wait for URL to match pattern


class FormSubmissionStatus(str, Enum):
    """Form submission result status."""
    SUCCESS = "success"
    PARTIAL = "partial"  # Some fields failed but form submitted
    FAILED = "failed"
    TIMEOUT = "timeout"
    VALIDATION_ERROR = "validation_error"
    CAPTCHA_FAILED = "captcha_failed"
    LOGIN_REQUIRED = "login_required"


@dataclass
class FormField:
    """
    Configuration for a single form field.
    
    Attributes:
        selector: CSS selector, XPath, or natural language description
        value: Value to fill (string, bool for checkboxes, list for multi-select)
        field_type: Type of field for specialized handling
        wait_before: Milliseconds to wait before interacting
        clear_first: Whether to clear existing value before typing
        required: Whether this field must succeed for form to submit
        retry_count: Number of retries on failure
        file_paths: For file uploads, list of file paths
        custom_handler: JavaScript to execute for custom fields
    """
    selector: str
    value: Any
    field_type: FieldType = FieldType.TEXT
    wait_before: int = 0
    clear_first: bool = True
    required: bool = True
    retry_count: int = 2
    file_paths: list[str] = field(default_factory=list)
    custom_handler: str | None = None


@dataclass
class FormStep:
    """
    Configuration for a multi-step form step.
    
    Attributes:
        name: Human-readable step name
        fields: Fields to fill in this step
        next_selector: Selector for "Next" button (None for final step)
        wait_condition: What to wait for after clicking next
        wait_selector: Selector to wait for (when wait_condition is SELECTOR)
        wait_url_pattern: URL pattern to wait for (when wait_condition is URL)
        wait_timeout: Timeout for wait condition in ms
        pre_actions: Actions to perform before filling fields
        post_actions: Actions to perform after filling fields
    """
    name: str
    fields: list[FormField]
    next_selector: str | None = None
    wait_condition: WaitCondition = WaitCondition.NETWORKIDLE
    wait_selector: str | None = None
    wait_url_pattern: str | None = None
    wait_timeout: int = 10000
    pre_actions: list[dict[str, Any]] = field(default_factory=list)
    post_actions: list[dict[str, Any]] = field(default_factory=list)


@dataclass 
class LoginConfig:
    """
    Configuration for logging in before form submission.
    
    Attributes:
        url: Login page URL
        username_selector: Selector for username field
        password_selector: Selector for password field  
        username: Username value
        password: Password value
        submit_selector: Selector for login button
        success_indicator: Selector that appears on successful login
        wait_timeout: Timeout waiting for login success
    """
    url: str
    username_selector: str
    password_selector: str
    username: str
    password: str
    submit_selector: str = "button[type='submit']"
    success_indicator: str | None = None
    wait_timeout: int = 15000


@dataclass
class ProxyConfig:
    """
    Custom proxy configuration for stealth mode.

    Attributes:
        type: Proxy type (http, https, socks5, socks5h)
        host: Proxy host
        port: Proxy port
        username: Proxy auth username
        password: Proxy auth password
        timezone_override: Timezone to spoof (e.g., "America/New_York")
        language_override: Language to spoof (e.g., "en-US")
    """
    type: Literal["http", "https", "socks5", "socks5h"]
    host: str
    port: int
    username: str | None = None
    password: str | None = None
    timezone_override: str | None = None
    language_override: str | None = None


@dataclass
class ApifyProxyConfig:
    """
    Apify proxy service configuration.

    Uses Apify's built-in proxy service with datacenter or residential proxies.
    See: https://docs.apify.com/platform/proxy

    Attributes:
        groups: Proxy groups to use (e.g., ["RESIDENTIAL", "SHADER"])
                Empty list uses default datacenter proxies.
        country_code: Two-letter country code for geo-targeting (e.g., "US", "DE")
    """
    groups: list[str] = field(default_factory=list)
    country_code: str | None = None


@dataclass
class FileUploadConfig:
    """
    Configuration for file upload fields.
    
    Attributes:
        field_selector: Selector for file input element
        file_url: Remote URL to download file from (Apify storage)
        local_path: Local path if file already exists
        filename: Optional custom filename
    """
    field_selector: str
    file_url: str | None = None
    local_path: str | None = None
    filename: str | None = None


@dataclass
class RetryConfig:
    """
    Retry configuration for resilient form submission.
    
    Attributes:
        max_retries: Maximum retry attempts
        retry_delay: Base delay between retries in ms
        exponential_backoff: Whether to use exponential backoff
        retry_on: List of error types to retry on
    """
    max_retries: int = 3
    retry_delay: int = 1000
    exponential_backoff: bool = True
    retry_on: list[str] = field(default_factory=lambda: ["timeout", "element_not_found"])


@dataclass
class ActorInput:
    """
    Complete input schema for StealthFormBot actor.
    
    This is the JSON input expected from Apify.
    """
    target_url: str
    form_data: dict[str, Any]  # Simple key-value for basic forms
    
    # Advanced field configuration (overrides form_data)
    field_configs: list[FormField] = field(default_factory=list)
    
    # Multi-step form support
    steps: list[FormStep] = field(default_factory=list)
    
    # Submit button configuration
    submit_selector: str | None = None
    
    # Login configuration
    login: LoginConfig | None = None
    
    # File uploads
    file_uploads: list[FileUploadConfig] = field(default_factory=list)
    
    # Proxy configuration (custom proxy)
    proxy: ProxyConfig | None = None

    # Apify proxy configuration
    use_apify_proxy: bool = False
    apify_proxy: ApifyProxyConfig | None = None

    # Browser profile for persistent identity
    profile_path: str | None = None
    
    # Retry configuration
    retry: RetryConfig = field(default_factory=RetryConfig)
    
    # Timeouts
    navigation_timeout: int = 30000
    field_timeout: int = 5000
    
    # Screenshot options
    screenshot_before_submit: bool = True
    screenshot_after_submit: bool = True
    screenshot_on_error: bool = True
    
    # Dialog handling
    auto_accept_alerts: bool = True
    auto_accept_confirms: bool = True
    
    # Validation
    success_indicator: str | None = None  # Selector that appears on success
    success_url_pattern: str | None = None  # URL pattern after success
    
    # Debug options
    verbose: bool = False


@dataclass
class FieldResult:
    """Result of filling a single field."""
    selector: str
    success: bool
    value_set: Any
    error: str | None = None
    retries: int = 0


@dataclass
class StepResult:
    """Result of completing a form step."""
    step_name: str
    success: bool
    fields_filled: int
    fields_failed: int
    field_results: list[FieldResult] = field(default_factory=list)
    error: str | None = None
    screenshot_path: str | None = None


@dataclass
class ActorOutput:
    """
    Output schema for StealthFormBot actor.
    
    This is returned to Apify after completion.
    """
    success: bool
    status: FormSubmissionStatus
    target_url: str
    confirmation_id: str | None = None  # Extracted confirmation ID if found
    submitted_at: str | None = None  # ISO 8601 timestamp
    
    # Detailed results
    steps_completed: int = 0
    total_steps: int = 0
    step_results: list[StepResult] = field(default_factory=list)
    
    # Screenshots
    screenshot_before: str | None = None
    screenshot_after: str | None = None
    screenshot_error: str | None = None
    
    # Session info
    cookies: list[dict[str, Any]] = field(default_factory=list)
    final_url: str | None = None
    
    # Errors
    errors: list[str] = field(default_factory=list)
    
    # Timing
    duration_ms: int = 0
