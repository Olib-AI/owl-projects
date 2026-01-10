"""
HTTP client for connecting to remote Owl Browser HTTP server.

This module provides the HTTP transport layer for remote browser connections,
enabling the SDK to work with a remote browser server via REST API.

Features:
- HTTP connection pooling with keep-alive
- Retry with exponential backoff and jitter
- Concurrency limiting via semaphore
- Comprehensive error handling
"""

import json
import urllib.request
import urllib.error
import ssl
import socket
import time
import random
import threading
import http.client
import os
import uuid
import mimetypes
from typing import Any, Dict, Optional, Callable, List, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .types import RemoteConfig, AuthMode, RetryConfig, ConcurrencyConfig
from .exceptions import (
    OwlBrowserError,
    LicenseError,
    BrowserInitializationError,
    CommandTimeoutError,
    AuthenticationError,
    RateLimitError,
    IPBlockedError,
)
from .jwt import JWTManager


def calculate_retry_delay(config: RetryConfig, attempt: int) -> float:
    """Calculate delay in seconds with exponential backoff and jitter."""
    delay_ms = config.initial_delay_ms * (config.backoff_multiplier ** attempt)
    delay_ms = min(delay_ms, config.max_delay_ms)
    # Add jitter to prevent thundering herd
    jitter = delay_ms * config.jitter_factor * (random.random() * 2 - 1)
    return max(0, (delay_ms + jitter) / 1000.0)


class Semaphore:
    """Thread-safe semaphore for concurrency limiting."""

    def __init__(self, permits: int):
        self._permits = permits
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)

    def acquire(self, timeout: Optional[float] = None) -> bool:
        """Acquire a permit, blocking if necessary."""
        with self._condition:
            end_time = None if timeout is None else time.time() + timeout
            while self._permits <= 0:
                if timeout is not None:
                    remaining = end_time - time.time()
                    if remaining <= 0:
                        return False
                    self._condition.wait(timeout=remaining)
                else:
                    self._condition.wait()
            self._permits -= 1
            return True

    def release(self):
        """Release a permit."""
        with self._condition:
            self._permits += 1
            self._condition.notify()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


class ConnectionPool:
    """
    HTTP connection pool with keep-alive support.

    Maintains a pool of persistent HTTP connections to reduce
    connection overhead for high-frequency operations.
    """

    def __init__(
        self,
        host: str,
        port: int,
        use_ssl: bool = False,
        max_connections: int = 10,
        ssl_context: Optional[ssl.SSLContext] = None,
        timeout: float = 30.0
    ):
        self._host = host
        self._port = port
        self._use_ssl = use_ssl
        self._max_connections = max_connections
        self._ssl_context = ssl_context
        self._timeout = timeout

        self._pool: list = []
        self._lock = threading.Lock()
        self._created = 0

    def _create_connection(self) -> http.client.HTTPConnection:
        """Create a new HTTP connection."""
        if self._use_ssl:
            conn = http.client.HTTPSConnection(
                self._host,
                self._port,
                timeout=self._timeout,
                context=self._ssl_context
            )
        else:
            conn = http.client.HTTPConnection(
                self._host,
                self._port,
                timeout=self._timeout
            )
        return conn

    def get_connection(self) -> http.client.HTTPConnection:
        """Get a connection from the pool or create a new one."""
        with self._lock:
            # Try to get an existing connection
            while self._pool:
                conn = self._pool.pop()
                try:
                    # Check if connection is still alive
                    conn.sock.getpeername()
                    return conn
                except (AttributeError, OSError):
                    # Connection is dead, discard it
                    self._created -= 1
                    continue

            # Create new connection if under limit
            if self._created < self._max_connections:
                self._created += 1
                return self._create_connection()

        # At limit, create a new connection anyway (will be discarded after use)
        return self._create_connection()

    def return_connection(self, conn: http.client.HTTPConnection):
        """Return a connection to the pool."""
        with self._lock:
            if len(self._pool) < self._max_connections:
                self._pool.append(conn)
            else:
                # Pool is full, close the connection
                try:
                    conn.close()
                except:
                    pass

    def close_connection(self, conn: http.client.HTTPConnection):
        """Close a connection without returning it to the pool."""
        with self._lock:
            self._created = max(0, self._created - 1)
        try:
            conn.close()
        except:
            pass

    def close_all(self):
        """Close all connections in the pool."""
        with self._lock:
            for conn in self._pool:
                try:
                    conn.close()
                except:
                    pass
            self._pool.clear()
            self._created = 0


class HttpTransport:
    """
    HTTP transport for communicating with remote Owl Browser HTTP server.

    This class handles all HTTP communication with the remote server,
    including authentication, request/response handling, and error mapping.

    Features:
    - Connection pooling with keep-alive for reduced latency
    - Retry with exponential backoff and jitter
    - Concurrency limiting to prevent server overload
    """

    # Tools that may take longer due to network operations
    LONG_RUNNING_TOOLS = {
        "browser_navigate",
        "browser_reload",
        "browser_wait",
        "browser_wait_for_selector",
        "browser_query_page",
        "browser_summarize_page",
        "browser_nla",
        "browser_solve_captcha",
        "browser_solve_text_captcha",
        "browser_solve_image_captcha",
        "browser_extract_site",
        "browser_extract_site_progress",
        "browser_extract_site_result",
        "browser_get_markdown",
        "browser_get_html",
        "browser_extract_text",
    }

    # Errors that are safe to retry
    RETRYABLE_ERRORS = (
        ConnectionResetError,
        BrokenPipeError,
        ConnectionRefusedError,
        ConnectionAbortedError,
        http.client.RemoteDisconnected,
        http.client.CannotSendRequest,
        http.client.BadStatusLine,
        OSError,
    )

    # Tools that support file uploads and their file parameter names
    FILE_UPLOAD_PARAMS = {
        "browser_create_context": ["proxy_ca_cert_path", "proxy_ca_key_path", "profile_path"],
        "browser_load_profile": ["profile_path"],
        "browser_add_license": ["license_path"],
        "browser_upload_file": ["file_paths"],
    }

    def __init__(
        self,
        config: RemoteConfig,
        retry_config: Optional[RetryConfig] = None,
        max_concurrent: int = 10,
        max_pool_connections: int = 10
    ):
        """
        Initialize HTTP transport.

        Args:
            config: Remote server configuration
            retry_config: Retry configuration (uses defaults if not provided)
            max_concurrent: Maximum concurrent requests (semaphore permits)
            max_pool_connections: Maximum connections in the pool
        """
        self._config = config
        self._base_url = config.url
        self._api_prefix = config.api_prefix  # API prefix for nginx proxy (e.g., "/api")
        self._static_token = config.token
        self._jwt_manager: Optional[JWTManager] = None
        self._timeout = config.timeout / 1000.0  # Convert to seconds
        self._long_timeout = max(120.0, self._timeout * 4)  # 2 minutes or 4x base timeout
        self._ssl_context = self._create_ssl_context()

        # Retry configuration
        self._retry_config = retry_config or RetryConfig()

        # Concurrency limiter
        self._semaphore = Semaphore(max_concurrent)

        # Parse URL for connection pool
        parsed = urlparse(self._base_url)
        use_ssl = parsed.scheme == "https"
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if use_ssl else 80)

        # Connection pool
        self._pool = ConnectionPool(
            host=host,
            port=port,
            use_ssl=use_ssl,
            max_connections=max_pool_connections,
            ssl_context=self._ssl_context,
            timeout=self._timeout
        )

        # Setup JWT manager if using JWT authentication
        if config.auth_mode == AuthMode.JWT and config.jwt:
            self._jwt_manager = JWTManager(
                private_key=config.jwt.private_key,
                expires_in=config.jwt.expires_in,
                refresh_threshold=config.jwt.refresh_threshold,
                issuer=config.jwt.issuer,
                subject=config.jwt.subject,
                audience=config.jwt.audience,
                claims=config.jwt.claims
            )

    def _get_auth_token(self) -> str:
        """Get the current authentication token (static or JWT)."""
        if self._jwt_manager:
            return self._jwt_manager.get_token()
        if self._static_token:
            return self._static_token
        raise OwlBrowserError("No authentication token available")

    def _prefix_path(self, path: str) -> str:
        """
        Apply API prefix to a path.

        Args:
            path: The API path (e.g., '/health', '/execute/browser_click')

        Returns:
            The path with api_prefix applied (e.g., '/api/health')
        """
        return self._api_prefix + path

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context based on configuration."""
        if self._config.verify_ssl:
            return ssl.create_default_context()
        else:
            # Disable SSL verification (not recommended for production)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx

    def _needs_file_upload(self, tool_name: str, params: Optional[Dict[str, Any]]) -> bool:
        """Check if request needs multipart file upload."""
        if not params or tool_name not in self.FILE_UPLOAD_PARAMS:
            return False

        file_params = self.FILE_UPLOAD_PARAMS[tool_name]
        for param in file_params:
            value = params.get(param)
            # Handle single file path
            if value and isinstance(value, str) and os.path.isfile(value):
                return True
            # Handle array of file paths (for file_paths parameter)
            if isinstance(value, list):
                for file_path in value:
                    if isinstance(file_path, str) and os.path.isfile(file_path):
                        return True
        return False

    def _build_multipart_body(
        self,
        params: Dict[str, Any],
        file_params: List[str]
    ) -> Tuple[bytes, str]:
        """
        Build multipart/form-data request body.

        Args:
            params: Request parameters
            file_params: List of parameter names that should be treated as files

        Returns:
            Tuple of (body bytes, content-type header with boundary)
        """
        boundary = f"----OwlBrowser{uuid.uuid4().hex}"
        lines: List[bytes] = []

        def get_mime_type(filename: str) -> str:
            """Get MIME type for a file."""
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type:
                return mime_type
            # Default MIME types based on extension
            ext = os.path.splitext(filename)[1].lower()
            mime_type_defaults = {
                '.pem': 'application/x-pem-file',
                '.crt': 'application/x-x509-ca-cert',
                '.cer': 'application/x-x509-ca-cert',
                '.key': 'application/x-pem-file',
                '.json': 'application/json',
                '.olic': 'application/octet-stream',
            }
            return mime_type_defaults.get(ext, 'application/octet-stream')

        def add_file_part(key: str, file_path: str) -> None:
            """Add a file part to the multipart body."""
            filename = os.path.basename(file_path)
            mime_type = get_mime_type(filename)

            with open(file_path, 'rb') as f:
                file_content = f.read()

            lines.append(f'--{boundary}\r\n'.encode('utf-8'))
            lines.append(
                f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'.encode('utf-8')
            )
            lines.append(f'Content-Type: {mime_type}\r\n\r\n'.encode('utf-8'))
            lines.append(file_content)
            lines.append(b'\r\n')

        for key, value in params.items():
            if value is None:
                continue

            # Check if this is a file parameter with a valid file path
            if key in file_params and isinstance(value, str) and os.path.isfile(value):
                # Single file upload
                add_file_part(key, value)
            elif key in file_params and isinstance(value, list):
                # Multiple file uploads (for file_paths parameter)
                for file_path in value:
                    if isinstance(file_path, str) and os.path.isfile(file_path):
                        add_file_part(key, file_path)
            else:
                # Regular form field
                lines.append(f'--{boundary}\r\n'.encode('utf-8'))
                lines.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode('utf-8'))
                # Convert value to string
                if isinstance(value, bool):
                    str_value = 'true' if value else 'false'
                elif isinstance(value, (int, float)):
                    str_value = str(value)
                elif isinstance(value, (dict, list)):
                    str_value = json.dumps(value)
                else:
                    str_value = str(value)
                lines.append(str_value.encode('utf-8'))
                lines.append(b'\r\n')

        # End boundary
        lines.append(f'--{boundary}--\r\n'.encode('utf-8'))

        body = b''.join(lines)
        content_type = f'multipart/form-data; boundary={boundary}'

        return body, content_type

    def _make_multipart_request(
        self,
        path: str,
        params: Dict[str, Any],
        file_params: List[str],
        long_running: bool = False
    ) -> Dict[str, Any]:
        """
        Make a multipart/form-data HTTP request for file uploads.

        Args:
            path: URL path
            params: Request parameters
            file_params: List of parameter names that are files
            long_running: Use extended timeout

        Returns:
            Response data as dictionary
        """
        body, content_type = self._build_multipart_body(params, file_params)

        headers = {
            "Content-Type": content_type,
            "Accept": "application/json",
            "Connection": "keep-alive",
            "Authorization": f"Bearer {self._get_auth_token()}",
        }

        timeout = self._long_timeout if long_running else self._timeout
        last_error = None
        max_retries = self._retry_config.max_retries

        with self._semaphore:
            for attempt in range(max_retries):
                conn = None
                try:
                    conn = self._pool.get_connection()
                    conn.timeout = timeout

                    conn.request("POST", path, body=body, headers=headers)
                    response = conn.getresponse()

                    response_data = response.read().decode('utf-8')

                    if response.status >= 400:
                        self._pool.return_connection(conn)
                        conn = None
                        return self._handle_http_error_status(
                            response.status, response_data, path
                        )

                    self._pool.return_connection(conn)
                    conn = None

                    if response_data:
                        return json.loads(response_data)
                    return {}

                except self.RETRYABLE_ERRORS as e:
                    if conn:
                        self._pool.close_connection(conn)
                        conn = None

                    last_error = e
                    if attempt < max_retries - 1:
                        delay = calculate_retry_delay(self._retry_config, attempt)
                        time.sleep(delay)
                        continue
                    raise OwlBrowserError(
                        f"Connection failed after {max_retries} retries: {e}"
                    )

                except socket.timeout:
                    if conn:
                        self._pool.close_connection(conn)
                    raise CommandTimeoutError(f"Request timed out: {path}")

                except Exception as e:
                    if conn:
                        self._pool.close_connection(conn)

                    error_name = type(e).__name__
                    if any(name in error_name for name in
                           ["RemoteDisconnected", "ConnectionReset", "BrokenPipe"]):
                        last_error = e
                        if attempt < max_retries - 1:
                            delay = calculate_retry_delay(self._retry_config, attempt)
                            time.sleep(delay)
                            continue
                        raise OwlBrowserError(
                            f"Connection failed after {max_retries} retries: {e}"
                        )
                    raise

        if last_error:
            raise OwlBrowserError(f"Request failed: {last_error}")

    def _make_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        require_auth: bool = True,
        long_running: bool = False
    ) -> Dict[str, Any]:
        """
        Make an HTTP request to the server using connection pooling.

        Args:
            method: HTTP method (GET, POST)
            path: URL path
            data: Request body data (JSON)
            require_auth: Whether to include authorization header
            long_running: Use extended timeout for long-running operations

        Returns:
            Response data as dictionary

        Raises:
            OwlBrowserError: On request failure
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Connection": "keep-alive",  # Use keep-alive for connection reuse
        }

        if require_auth:
            headers["Authorization"] = f"Bearer {self._get_auth_token()}"

        body = None
        if data is not None:
            body = json.dumps(data).encode('utf-8')

        # Use longer timeout for operations that may take a while
        timeout = self._long_timeout if long_running else self._timeout

        last_error = None
        max_retries = self._retry_config.max_retries

        # Acquire semaphore to limit concurrent requests
        with self._semaphore:
            for attempt in range(max_retries):
                conn = None
                try:
                    # Get connection from pool
                    conn = self._pool.get_connection()
                    conn.timeout = timeout

                    # Make request
                    conn.request(method, path, body=body, headers=headers)
                    response = conn.getresponse()

                    # Read response
                    response_data = response.read().decode('utf-8')

                    # Check for HTTP errors
                    if response.status >= 400:
                        # Return connection to pool before handling error
                        self._pool.return_connection(conn)
                        conn = None
                        return self._handle_http_error_status(
                            response.status, response_data, path
                        )

                    # Success - return connection to pool
                    self._pool.return_connection(conn)
                    conn = None

                    if response_data:
                        return json.loads(response_data)
                    return {}

                except self.RETRYABLE_ERRORS as e:
                    # Close failed connection
                    if conn:
                        self._pool.close_connection(conn)
                        conn = None

                    last_error = e
                    if attempt < max_retries - 1:
                        delay = calculate_retry_delay(self._retry_config, attempt)
                        time.sleep(delay)
                        continue
                    raise OwlBrowserError(
                        f"Connection failed after {max_retries} retries: {e}"
                    )

                except socket.timeout:
                    if conn:
                        self._pool.close_connection(conn)
                    raise CommandTimeoutError(f"Request timed out: {path}")

                except Exception as e:
                    if conn:
                        self._pool.close_connection(conn)

                    # Check if it's a retryable error type by name
                    error_name = type(e).__name__
                    if any(name in error_name for name in
                           ["RemoteDisconnected", "ConnectionReset", "BrokenPipe"]):
                        last_error = e
                        if attempt < max_retries - 1:
                            delay = calculate_retry_delay(self._retry_config, attempt)
                            time.sleep(delay)
                            continue
                        raise OwlBrowserError(
                            f"Connection failed after {max_retries} retries: {e}"
                        )
                    raise

        if last_error:
            raise OwlBrowserError(f"Request failed: {last_error}")

    def _handle_http_error_status(
        self,
        status: int,
        response_body: str,
        path: str
    ) -> Dict[str, Any]:
        """
        Handle HTTP error responses by status code.

        Args:
            status: HTTP status code
            response_body: Response body text
            path: Request path

        Raises:
            Appropriate exception based on error type
        """
        try:
            response_data = json.loads(response_body) if response_body else {}
        except json.JSONDecodeError:
            response_data = {"error": response_body}

        error_message = response_data.get("error", f"HTTP {status}")

        if status == 401:
            raise AuthenticationError(
                message=error_message or "Invalid or missing authorization token",
                reason=response_data.get("reason")
            )

        if status == 403:
            raise IPBlockedError(
                message=error_message or "Access forbidden - IP not allowed",
                ip_address=response_data.get("client_ip")
            )

        if status == 429:
            raise RateLimitError(
                message=error_message or "Rate limit exceeded",
                retry_after=response_data.get("retry_after", 60),
                limit=response_data.get("limit"),
                remaining=response_data.get("remaining")
            )

        if status == 503:
            if response_data.get("license_status"):
                raise LicenseError(
                    message=response_data.get("license_message", "License error"),
                    status=response_data.get("license_status"),
                    fingerprint=response_data.get("hardware_fingerprint")
                )
            raise BrowserInitializationError(f"Browser not ready: {error_message}")

        if status == 404:
            raise OwlBrowserError(f"Endpoint not found: {path}")

        if status == 422:
            missing = response_data.get("missing_fields", "")
            unknown = response_data.get("unknown_fields", "")
            raise OwlBrowserError(
                f"Validation error: {error_message}. "
                f"Missing: {missing}. Unknown: {unknown}"
            )

        if status == 502:
            raise OwlBrowserError(f"Browser command failed: {error_message}")

        raise OwlBrowserError(f"HTTP {status}: {error_message}")

    def close(self):
        """Close the transport and all pooled connections."""
        self._pool.close_all()

    def health_check(self) -> Dict[str, Any]:
        """
        Check server health status.

        Returns:
            Health status dict with 'status', 'browser_ready', 'browser_state'
        """
        return self._make_request("GET", self._prefix_path("/health"), require_auth=False)

    def list_tools(self) -> Dict[str, Any]:
        """
        List available browser tools.

        Returns:
            Dict with 'tools' list
        """
        return self._make_request("GET", self._prefix_path("/tools"))

    def get_tool_info(self, tool_name: str) -> Dict[str, Any]:
        """
        Get documentation for a specific tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Tool documentation
        """
        return self._make_request("GET", self._prefix_path(f"/tools/{tool_name}"))

    def execute_tool(
        self,
        tool_name: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Execute a browser tool.

        Args:
            tool_name: Name of the tool to execute
            params: Tool parameters (file paths are automatically uploaded)

        Returns:
            Tool execution result

        Raises:
            OwlBrowserError: On execution failure
        """
        # Check if this is a long-running operation
        long_running = tool_name in self.LONG_RUNNING_TOOLS

        # Check if this request needs file upload (multipart/form-data)
        if self._needs_file_upload(tool_name, params):
            file_params = self.FILE_UPLOAD_PARAMS.get(tool_name, [])
            response = self._make_multipart_request(
                self._prefix_path(f"/execute/{tool_name}"),
                params or {},
                file_params,
                long_running=long_running
            )
        else:
            response = self._make_request(
                "POST",
                self._prefix_path(f"/execute/{tool_name}"),
                data=params or {},
                long_running=long_running
            )

        if not response.get("success", False):
            error_msg = response.get("error", "Unknown error")
            raise OwlBrowserError(f"Tool execution failed: {error_msg}")

        result = response.get("result")

        # Handle nested response format from browser IPC
        # Some commands return {"id": N, "result": {...}} structure
        if isinstance(result, dict) and "id" in result and "result" in result:
            result = result["result"]

        return result

    def send_raw_command(self, command: Dict[str, Any]) -> Any:
        """
        Send a raw command to the browser (advanced usage).

        Args:
            command: Raw command dict with 'method' and parameters

        Returns:
            Command result
        """
        response = self._make_request("POST", self._prefix_path("/command"), data=command)

        if not response.get("success", False):
            error_msg = response.get("error", "Unknown error")
            raise OwlBrowserError(f"Command failed: {error_msg}")

        return response.get("result")

    def is_browser_ready(self) -> bool:
        """
        Check if browser is ready to accept commands.

        Returns:
            True if browser is ready
        """
        try:
            health = self.health_check()
            return health.get("browser_ready", False)
        except Exception:
            return False


# Tool name mapping from SDK method names to HTTP API tool names
TOOL_NAME_MAP = {
    # Context management
    "createContext": "browser_create_context",
    "releaseContext": "browser_close_context",
    "listContexts": "browser_list_contexts",

    # Navigation
    "navigate": "browser_navigate",
    "reload": "browser_reload",
    "goBack": "browser_go_back",
    "goForward": "browser_go_forward",
    "canGoBack": "browser_can_go_back",
    "canGoForward": "browser_can_go_forward",

    # Interaction
    "click": "browser_click",
    "type": "browser_type",
    "pick": "browser_pick",
    "pressKey": "browser_press_key",
    "submitForm": "browser_submit_form",
    "highlight": "browser_highlight",
    "showGridOverlay": "browser_show_grid_overlay",
    "hover": "browser_hover",
    "doubleClick": "browser_double_click",
    "rightClick": "browser_right_click",
    "clearInput": "browser_clear_input",
    "focus": "browser_focus",
    "blur": "browser_blur",
    "selectAll": "browser_select_all",
    "keyboardCombo": "browser_keyboard_combo",
    "dragDrop": "browser_drag_drop",
    "html5DragDrop": "browser_html5_drag_drop",
    "mouseMove": "browser_mouse_move",
    "uploadFile": "browser_upload_file",

    # Element State
    "isVisible": "browser_is_visible",
    "isEnabled": "browser_is_enabled",
    "isChecked": "browser_is_checked",
    "getAttribute": "browser_get_attribute",
    "getBoundingBox": "browser_get_bounding_box",

    # Frames
    "listFrames": "browser_list_frames",
    "switchToFrame": "browser_switch_to_frame",
    "switchToMainFrame": "browser_switch_to_main_frame",

    # JavaScript
    "evaluate": "browser_evaluate",

    # Content extraction
    "extractText": "browser_extract_text",
    "screenshot": "browser_screenshot",
    "getHTML": "browser_get_html",
    "getMarkdown": "browser_get_markdown",
    "extractJSON": "browser_extract_json",
    "detectWebsiteType": "browser_detect_site",
    "listTemplates": "browser_list_templates",

    # Site extraction
    "extractSite": "browser_extract_site",
    "extractSiteProgress": "browser_extract_site_progress",
    "extractSiteResult": "browser_extract_site_result",
    "extractSiteCancel": "browser_extract_site_cancel",

    # AI features
    "summarizePage": "browser_summarize_page",
    "queryPage": "browser_query_page",
    "llmStatus": "browser_llm_status",
    "executeNLA": "browser_nla",
    "getLLMStatus": "browser_llm_status",
    "aiClick": "browser_ai_click",
    "aiType": "browser_ai_type",
    "aiExtract": "browser_ai_extract",
    "aiQuery": "browser_ai_query",
    "aiAnalyze": "browser_ai_analyze",
    "findElement": "browser_find_element",

    # Scrolling
    "scrollBy": "browser_scroll_by",
    "scrollToElement": "browser_scroll_to_element",
    "scrollToTop": "browser_scroll_to_top",
    "scrollToBottom": "browser_scroll_to_bottom",

    # Waiting
    "waitForSelector": "browser_wait_for_selector",
    "waitForTimeout": "browser_wait",
    "waitForNetworkIdle": "browser_wait_for_network_idle",
    "waitForFunction": "browser_wait_for_function",
    "waitForURL": "browser_wait_for_url",

    # Clipboard
    "clipboardRead": "browser_clipboard_read",
    "clipboardWrite": "browser_clipboard_write",
    "clipboardClear": "browser_clipboard_clear",

    # Network
    "addNetworkRule": "browser_add_network_rule",
    "removeNetworkRule": "browser_remove_network_rule",
    "enableNetworkInterception": "browser_enable_network_interception",
    "getNetworkLog": "browser_get_network_log",
    "clearNetworkLog": "browser_clear_network_log",

    # Downloads
    "setDownloadPath": "browser_set_download_path",
    "getDownloads": "browser_get_downloads",
    "waitForDownload": "browser_wait_for_download",
    "cancelDownload": "browser_cancel_download",

    # Dialogs
    "setDialogAction": "browser_set_dialog_action",
    "getPendingDialog": "browser_get_pending_dialog",
    "handleDialog": "browser_handle_dialog",
    "waitForDialog": "browser_wait_for_dialog",

    # Tabs
    "newTab": "browser_new_tab",
    "getTabs": "browser_get_tabs",
    "switchTab": "browser_switch_tab",
    "closeTab": "browser_close_tab",
    "getActiveTab": "browser_get_active_tab",
    "getTabCount": "browser_get_tab_count",
    "setPopupPolicy": "browser_set_popup_policy",
    "getBlockedPopups": "browser_get_blocked_popups",

    # Page info
    "getPageInfo": "browser_get_page_info",
    "getCurrentURL": "browser_get_page_info",
    "getPageTitle": "browser_get_page_info",
    "setViewport": "browser_set_viewport",

    # Zoom
    "zoomIn": "browser_zoom_in",
    "zoomOut": "browser_zoom_out",
    "zoomReset": "browser_zoom_reset",

    # Console logs
    "getConsoleLogs": "browser_get_console_log",
    "clearConsoleLogs": "browser_clear_console_log",

    # Video recording
    "startVideoRecording": "browser_start_video_recording",
    "pauseVideoRecording": "browser_pause_video_recording",
    "resumeVideoRecording": "browser_resume_video_recording",
    "stopVideoRecording": "browser_stop_video_recording",
    "getVideoRecordingStats": "browser_get_video_recording_stats",

    # Demographics
    "getDemographics": "browser_get_demographics",
    "getLocation": "browser_get_location",
    "getDateTime": "browser_get_datetime",
    "getWeather": "browser_get_weather",

    # CAPTCHA
    "detectCaptcha": "browser_detect_captcha",
    "classifyCaptcha": "browser_classify_captcha",
    "solveTextCaptcha": "browser_solve_text_captcha",
    "solveImageCaptcha": "browser_solve_image_captcha",
    "solveCaptcha": "browser_solve_captcha",

    # Cookies
    "getCookies": "browser_get_cookies",
    "setCookie": "browser_set_cookie",
    "deleteCookies": "browser_delete_cookies",

    # Proxy
    "setProxy": "browser_set_proxy",
    "getProxyStatus": "browser_get_proxy_status",
    "connectProxy": "browser_connect_proxy",
    "disconnectProxy": "browser_disconnect_proxy",

    # Profiles
    "createProfile": "browser_create_profile",
    "loadProfile": "browser_load_profile",
    "saveProfile": "browser_save_profile",
    "downloadProfile": "browser_download_profile",
    "getProfile": "browser_get_profile",
    "updateProfileCookies": "browser_update_profile_cookies",
    "getContextInfo": "browser_get_context_info",

    # Element Picker
    "getElementAtPosition": "browser_get_element_at_position",
    "getInteractiveElements": "browser_get_interactive_elements",
    "getBlockerStats": "browser_get_blocker_stats",

    # Downloads
    "getActiveDownloads": "browser_get_active_downloads",

    # Dialogs
    "getDialogs": "browser_get_dialogs",

    # Network
    "enableNetworkLogging": "browser_enable_network_logging",

    # Live Streaming
    "startLiveStream": "browser_start_live_stream",
    "stopLiveStream": "browser_stop_live_stream",
    "getLiveStreamStats": "browser_get_live_stream_stats",
    "listLiveStreams": "browser_list_live_streams",
    "getLiveFrame": "browser_get_live_frame",

    # IPC Tests
    "runIPCTests": "ipc_tests_run",
    "getIPCTestsStatus": "ipc_tests_status",
    "abortIPCTests": "ipc_tests_abort",
    "listIPCTestsReports": "ipc_tests_list_reports",
    "getIPCTestsReport": "ipc_tests_get_report",
    "deleteIPCTestsReport": "ipc_tests_delete_report",
    "cleanAllIPCTestsReports": "ipc_tests_clean_all",

    # License management
    "getLicenseStatus": "browser_get_license_status",
    "getLicenseInfo": "browser_get_license_info",
    "getHardwareFingerprint": "browser_get_hardware_fingerprint",
    "addLicense": "browser_add_license",
    "removeLicense": "browser_remove_license",

    # Server management
    "serverRestartBrowser": "server_restart_browser",
    "serverReadLogs": "server_read_logs",
}


# Parameter name mapping from SDK to HTTP API
PARAM_NAME_MAP = {
    # Common renames
    "context_id": "context_id",
    "url": "url",
    "selector": "selector",
    "text": "text",
    "value": "value",
    "query": "query",
    "command": "command",
    "timeout": "timeout",
    "ignore_cache": "ignore_cache",
    "clean_level": "clean_level",
    "include_links": "include_links",
    "include_images": "include_images",
    "max_length": "max_length",
    "template_name": "template",
    "force_refresh": "force_refresh",
    "key": "key",
    "border_color": "border_color",
    "background_color": "background_color",
    "x": "x",
    "y": "y",
    "width": "width",
    "height": "height",
    "fps": "fps",
    "codec": "codec",
    "max_attempts": "max_attempts",

    # Cookie parameters
    "cookie_name": "cookie_name",
    "httpOnly": "httpOnly",
    "sameSite": "sameSite",
    "expires": "expires",
    "secure": "secure",
    "path": "path",
    "domain": "domain",
    "name": "name",

    # Proxy parameters
    "type": "type",
    "host": "host",
    "port": "port",
    "username": "username",
    "password": "password",
    "stealth": "stealth",
    "block_webrtc": "block_webrtc",
    "spoof_timezone": "spoof_timezone",
    "spoof_language": "spoof_language",
    "timezone_override": "timezone_override",
    "language_override": "language_override",

    # Context creation parameters (LLM)
    "llm_enabled": "llm_enabled",
    "llm_use_builtin": "llm_use_builtin",
    "llm_endpoint": "llm_endpoint",
    "llm_model": "llm_model",
    "llm_api_key": "llm_api_key",

    # Context creation parameters (Proxy)
    "proxy_type": "proxy_type",
    "proxy_host": "proxy_host",
    "proxy_port": "proxy_port",
    "proxy_username": "proxy_username",
    "proxy_password": "proxy_password",
    "proxy_stealth": "proxy_stealth",
    "proxy_block_webrtc": "proxy_block_webrtc",
    "proxy_spoof_timezone": "proxy_spoof_timezone",
    "proxy_spoof_language": "proxy_spoof_language",
    "proxy_timezone_override": "proxy_timezone_override",
    "proxy_language_override": "proxy_language_override",
    "proxy_ca_cert_path": "proxy_ca_cert_path",
    "proxy_trust_custom_ca": "proxy_trust_custom_ca",

    # Profile
    "profile_path": "profile_path",
}


def map_method_to_tool(method: str) -> str:
    """
    Map SDK method name to HTTP API tool name.

    Args:
        method: SDK method name (e.g., 'navigate', 'click')

    Returns:
        HTTP API tool name (e.g., 'browser_navigate', 'browser_click')
    """
    return TOOL_NAME_MAP.get(method, f"browser_{method}")


def map_params_for_http(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map SDK parameter names to HTTP API parameter names.

    Args:
        params: SDK parameters

    Returns:
        HTTP API parameters
    """
    mapped = {}
    for key, value in params.items():
        # Use mapping if available, otherwise use original key
        mapped_key = PARAM_NAME_MAP.get(key, key)
        mapped[mapped_key] = value
    return mapped
