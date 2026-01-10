"""
Owl Browser SDK Exceptions.

Custom exception classes for better error handling and reporting.
"""

from enum import Enum
from typing import Any, Dict, Optional
from dataclasses import dataclass


class ActionStatus(str, Enum):
    """Action status codes returned by the browser."""
    # Success
    OK = "ok"

    # Browser/context errors
    BROWSER_NOT_FOUND = "browser_not_found"
    BROWSER_NOT_READY = "browser_not_ready"
    CONTEXT_NOT_FOUND = "context_not_found"

    # Navigation errors
    NAVIGATION_FAILED = "navigation_failed"
    NAVIGATION_TIMEOUT = "navigation_timeout"
    PAGE_LOAD_ERROR = "page_load_error"
    REDIRECT_DETECTED = "redirect_detected"
    CAPTCHA_DETECTED = "captcha_detected"
    FIREWALL_DETECTED = "firewall_detected"

    # Element errors
    ELEMENT_NOT_FOUND = "element_not_found"
    ELEMENT_NOT_VISIBLE = "element_not_visible"
    ELEMENT_NOT_INTERACTABLE = "element_not_interactable"
    ELEMENT_STALE = "element_stale"
    MULTIPLE_ELEMENTS = "multiple_elements"

    # Action execution errors
    CLICK_FAILED = "click_failed"
    CLICK_INTERCEPTED = "click_intercepted"
    TYPE_FAILED = "type_failed"
    TYPE_PARTIAL = "type_partial"
    SCROLL_FAILED = "scroll_failed"
    FOCUS_FAILED = "focus_failed"
    BLUR_FAILED = "blur_failed"
    CLEAR_FAILED = "clear_failed"
    PICK_FAILED = "pick_failed"
    OPTION_NOT_FOUND = "option_not_found"
    UPLOAD_FAILED = "upload_failed"
    FRAME_SWITCH_FAILED = "frame_switch_failed"
    TAB_SWITCH_FAILED = "tab_switch_failed"
    DIALOG_NOT_HANDLED = "dialog_not_handled"

    # Validation errors
    INVALID_SELECTOR = "invalid_selector"
    INVALID_URL = "invalid_url"
    INVALID_PARAMETER = "invalid_parameter"

    # System/timeout errors
    INTERNAL_ERROR = "internal_error"
    TIMEOUT = "timeout"
    NETWORK_TIMEOUT = "network_timeout"
    WAIT_TIMEOUT = "wait_timeout"
    VERIFICATION_TIMEOUT = "verification_timeout"

    # Unknown
    UNKNOWN = "unknown"


@dataclass
class ActionResult:
    """
    ActionResult returned by browser for validated actions.
    Contains success status, status code, message, and additional details.
    """
    success: bool
    status: str
    message: str
    selector: Optional[str] = None
    url: Optional[str] = None
    error_code: Optional[str] = None
    http_status: Optional[int] = None
    element_count: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionResult":
        """Create ActionResult from dictionary."""
        return cls(
            success=data.get("success", False),
            status=data.get("status", "unknown"),
            message=data.get("message", ""),
            selector=data.get("selector"),
            url=data.get("url"),
            error_code=data.get("error_code"),
            http_status=data.get("http_status"),
            element_count=data.get("element_count"),
        )


def is_action_result(result: Any) -> bool:
    """Check if a result is an ActionResult object or dict."""
    if isinstance(result, ActionResult):
        return True
    if isinstance(result, dict):
        return "success" in result and "status" in result and isinstance(result.get("success"), bool)
    return False


class OwlBrowserError(Exception):
    """Base exception for all Owl Browser SDK errors."""
    pass


class LicenseError(OwlBrowserError):
    """
    Raised when the browser fails due to license issues.

    This can happen when:
    - No license file is installed
    - The license has expired
    - The license signature is invalid
    - Hardware mismatch for hardware-bound licenses
    - Maximum seats exceeded
    - Subscription validation failed

    Attributes:
        status: The license status code (e.g., 'not_found', 'expired', 'invalid_signature')
        message: Human-readable error message
        fingerprint: Hardware fingerprint (if available) for requesting a new license
    """

    # License status codes
    NOT_FOUND = "not_found"
    EXPIRED = "expired"
    INVALID_SIGNATURE = "invalid_signature"
    CORRUPTED = "corrupted"
    HARDWARE_MISMATCH = "hardware_mismatch"
    TAMPERED = "tampered"
    DEBUG_DETECTED = "debug_detected"
    CLOCK_MANIPULATED = "clock_manipulated"
    SUBSCRIPTION_INACTIVE = "subscription_inactive"
    SUBSCRIPTION_CHECK_FAILED = "subscription_check_failed"
    SEAT_EXCEEDED = "seat_exceeded"

    def __init__(
        self,
        message: str,
        status: Optional[str] = None,
        fingerprint: Optional[str] = None
    ):
        self.status = status
        self.message = message
        self.fingerprint = fingerprint
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format the exception message with helpful information."""
        lines = [f"License Error: {self.message}"]

        if self.status:
            lines.append(f"Status: {self.status}")

        if self.fingerprint:
            lines.append(f"Hardware Fingerprint: {self.fingerprint}")

        # Add helpful instructions based on status
        if self.status == self.NOT_FOUND:
            lines.append("")
            lines.append("To activate a license, run:")
            lines.append("  owl_browser --license add /path/to/license.olic")
            lines.append("")
            lines.append("Contact support@owlbrowser.net for licensing inquiries.")
        elif self.status == self.EXPIRED:
            lines.append("")
            lines.append("Please renew your license at https://owlbrowser.net")
            lines.append("Contact support@owlbrowser.net for assistance.")
        elif self.status == self.SEAT_EXCEEDED:
            lines.append("")
            lines.append("Maximum number of devices reached for this license.")
            lines.append("Deactivate unused devices or upgrade your license.")
            lines.append("Contact support@owlbrowser.net for assistance.")
        elif self.status == self.SUBSCRIPTION_CHECK_FAILED:
            lines.append("")
            lines.append("Could not validate subscription with license server.")
            lines.append("Check your internet connection or contact support@owlbrowser.net")

        return "\n".join(lines)


class BrowserInitializationError(OwlBrowserError):
    """Raised when the browser process fails to initialize."""
    pass


class BrowserNotRunningError(OwlBrowserError):
    """Raised when trying to use a browser that is not running."""
    pass


class CommandTimeoutError(OwlBrowserError):
    """Raised when a browser command times out."""
    pass


class ContextError(OwlBrowserError):
    """Raised when there's an error with browser context operations."""
    pass


class NavigationError(OwlBrowserError):
    """Raised when page navigation fails."""
    pass


class ElementNotFoundError(OwlBrowserError):
    """Raised when an element cannot be found on the page."""
    pass


class FirewallError(OwlBrowserError):
    """
    Raised when a web firewall or bot protection challenge is detected.

    This can happen when:
    - Cloudflare is protecting the site (JS challenge, Turnstile, etc.)
    - Akamai Bot Manager blocks access
    - Imperva/Incapsula security challenge
    - PerimeterX human challenge
    - DataDome bot detection
    - Other WAF/bot protection services

    Attributes:
        url: The URL where the firewall was detected
        provider: The firewall provider (Cloudflare, Akamai, etc.)
        challenge_type: The type of challenge (JS challenge, CAPTCHA, etc.)
    """

    def __init__(self, url: str, provider: str, challenge_type: Optional[str] = None):
        self.url = url
        self.provider = provider
        self.challenge_type = challenge_type
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format the exception message with helpful information."""
        lines = [f"Firewall detected: {self.provider}"]

        if self.challenge_type:
            lines.append(f"Challenge type: {self.challenge_type}")

        lines.append(f"URL: {self.url}")
        lines.append("")
        lines.append("The website is protected by bot detection that blocked this request.")
        lines.append("")
        lines.append("Possible solutions:")
        lines.append("  - Wait and retry (some challenges auto-solve)")
        lines.append("  - Use stealth mode with proxy")
        lines.append("  - Rotate IP addresses")
        lines.append("  - Solve CAPTCHA if required")

        return "\n".join(lines)


class AuthenticationError(OwlBrowserError):
    """
    Raised when authentication fails (401 Unauthorized).

    This can happen when:
    - The bearer token is invalid or missing
    - The JWT token has expired
    - The JWT token signature is invalid
    - The JWT token was issued for a different audience

    Attributes:
        message: Human-readable error message
        reason: Optional specific reason for the failure
        status_code: HTTP status code (always 401)
    """

    def __init__(self, message: str, reason: Optional[str] = None):
        self.message = message
        self.reason = reason
        self.status_code = 401
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format the exception message with helpful information."""
        lines = [f"Authentication Error: {self.message}"]

        if self.reason:
            lines.append(f"Reason: {self.reason}")

        lines.append("")
        lines.append("Possible causes:")
        lines.append("  - Invalid or expired bearer token")
        lines.append("  - JWT token has expired (check exp claim)")
        lines.append("  - JWT signature verification failed")
        lines.append("  - Token issued for different audience (aud claim mismatch)")
        lines.append("")
        lines.append("For JWT authentication, ensure your token:")
        lines.append("  - Has not expired (exp > current time)")
        lines.append("  - Is signed with the correct private key")
        lines.append("  - Has matching issuer (iss) and audience (aud) claims")

        return "\n".join(lines)


class RateLimitError(OwlBrowserError):
    """
    Raised when the client is rate limited (429 Too Many Requests).

    The server implements rate limiting to prevent abuse. When this error
    is raised, the client should wait before retrying.

    Attributes:
        message: Human-readable error message
        retry_after: Number of seconds to wait before retrying
        limit: Maximum requests allowed per window
        remaining: Remaining requests in current window
        status_code: HTTP status code (always 429)
    """

    def __init__(
        self,
        message: str,
        retry_after: int,
        limit: Optional[int] = None,
        remaining: Optional[int] = None
    ):
        self.message = message
        self.retry_after = retry_after
        self.limit = limit
        self.remaining = remaining
        self.status_code = 429
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format the exception message with helpful information."""
        lines = [f"Rate Limit Error: {self.message}"]

        lines.append(f"Retry After: {self.retry_after} seconds")

        if self.limit is not None:
            lines.append(f"Rate Limit: {self.limit} requests per window")

        if self.remaining is not None:
            lines.append(f"Remaining: {self.remaining}")

        lines.append("")
        lines.append("To avoid rate limiting:")
        lines.append("  - Reduce request frequency")
        lines.append("  - Implement exponential backoff")
        lines.append("  - Contact support for higher limits")

        return "\n".join(lines)


class IPBlockedError(OwlBrowserError):
    """
    Raised when the client IP is blacklisted/not whitelisted (403 Forbidden).

    The server may implement IP-based access control. When this error
    is raised, the client's IP is not allowed to access the server.

    Attributes:
        message: Human-readable error message
        ip_address: The blocked IP address (if known)
        status_code: HTTP status code (always 403)
    """

    def __init__(self, message: str, ip_address: Optional[str] = None):
        self.message = message
        self.ip_address = ip_address
        self.status_code = 403
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format the exception message with helpful information."""
        lines = [f"IP Blocked Error: {self.message}"]

        if self.ip_address:
            lines.append(f"Your IP: {self.ip_address}")

        lines.append("")
        lines.append("Your IP address is not allowed to access this server.")
        lines.append("")
        lines.append("Possible causes:")
        lines.append("  - IP whitelist is enabled and your IP is not whitelisted")
        lines.append("  - Your IP has been blocked due to suspicious activity")
        lines.append("")
        lines.append("To resolve:")
        lines.append("  - Contact the server administrator")
        lines.append("  - Request your IP to be added to the whitelist")

        return "\n".join(lines)


class ContextLimitError(OwlBrowserError):
    """
    Raised when the developer license context limit is exceeded.

    Developer licenses have a maximum number of concurrent browser contexts.
    When this limit is reached, no new contexts can be created until existing
    ones are closed.

    Attributes:
        message: Human-readable error message
        current_contexts: Number of currently active contexts
        max_contexts: Maximum allowed contexts for this license
        license_type: The type of license (always 'developer' for this error)
    """

    def __init__(
        self,
        message: str,
        current_contexts: Optional[int] = None,
        max_contexts: Optional[int] = None,
        license_type: str = "developer"
    ):
        self.message = message
        self.current_contexts = current_contexts
        self.max_contexts = max_contexts
        self.license_type = license_type
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format the exception message with helpful information."""
        lines = [f"Context Limit Error: {self.message}"]

        if self.current_contexts is not None and self.max_contexts is not None:
            lines.append(f"Current contexts: {self.current_contexts}/{self.max_contexts}")

        lines.append(f"License type: {self.license_type}")
        lines.append("")
        lines.append("To resolve:")
        lines.append("  - Close existing browser contexts using browser.release_context(context_id)")
        lines.append("  - Upgrade to a license with more concurrent contexts")
        lines.append("")
        lines.append("Contact support@owlbrowser.net for licensing inquiries.")

        return "\n".join(lines)


class ActionError(OwlBrowserError):
    """
    Raised when a browser action fails with a specific status code.
    This provides detailed information about what went wrong.

    Attributes:
        status: The action status code
        message: Human-readable error message
        selector: The selector that failed (for element errors)
        url: The URL involved (for navigation errors)
        http_status: HTTP status code (for navigation errors)
        error_code: Error code from the browser
        element_count: Number of elements found (for multiple_elements error)
    """

    def __init__(self, result: ActionResult):
        self.status = result.status
        self.message = result.message
        self.selector = result.selector
        self.url = result.url
        self.http_status = result.http_status
        self.error_code = result.error_code
        self.element_count = result.element_count
        super().__init__(result.message)

    def is_element_not_found(self) -> bool:
        """Check if this is an element not found error."""
        return self.status == ActionStatus.ELEMENT_NOT_FOUND.value

    def is_navigation_error(self) -> bool:
        """Check if this is a navigation error."""
        return self.status in (
            ActionStatus.NAVIGATION_FAILED.value,
            ActionStatus.NAVIGATION_TIMEOUT.value,
            ActionStatus.PAGE_LOAD_ERROR.value,
        )

    def is_timeout(self) -> bool:
        """Check if this is a timeout error."""
        return self.status in (
            ActionStatus.TIMEOUT.value,
            ActionStatus.NAVIGATION_TIMEOUT.value,
        )


def throw_if_action_failed(result: Any) -> None:
    """
    Check if result is a failed ActionResult and raise appropriate exception.

    Args:
        result: The result to check (can be dict or ActionResult)

    Raises:
        ElementNotFoundError: If element was not found
        NavigationError: If navigation failed
        ContextError: If context was not found
        ActionError: For other action failures
    """
    if not is_action_result(result):
        return

    # Convert dict to ActionResult if needed
    if isinstance(result, dict):
        action_result = ActionResult.from_dict(result)
    else:
        action_result = result

    if action_result.success:
        return

    # Use specific error types for common cases
    if action_result.status == ActionStatus.ELEMENT_NOT_FOUND.value and action_result.selector:
        raise ElementNotFoundError(f"Element not found: {action_result.selector}")

    if action_result.status in (
        ActionStatus.NAVIGATION_FAILED.value,
        ActionStatus.NAVIGATION_TIMEOUT.value,
        ActionStatus.PAGE_LOAD_ERROR.value,
    ):
        raise NavigationError(action_result.message)

    if action_result.status == ActionStatus.FIREWALL_DETECTED.value:
        # error_code contains the provider name
        raise FirewallError(
            url=action_result.url or "",
            provider=action_result.error_code or "Unknown",
            challenge_type=action_result.message
        )

    if action_result.status in (
        ActionStatus.BROWSER_NOT_FOUND.value,
        ActionStatus.CONTEXT_NOT_FOUND.value,
    ):
        raise ContextError(action_result.message)

    # Generic action error for other cases
    raise ActionError(action_result)