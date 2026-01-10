"""
Core browser process manager.

Handles IPC communication with the native browser binary.
Supports both sync and async operations with thread-safe design.

Now supports dual mode:
- LOCAL: Connect to local browser binary via stdin/stdout IPC
- REMOTE: Connect to remote browser HTTP server via REST API
"""

import json
import os
import re
import subprocess
import threading
import time
import uuid
import atexit
from pathlib import Path
from typing import Any, Dict, Optional, Callable
from concurrent.futures import Future, ThreadPoolExecutor
import queue

from .types import (
    BrowserConfig,
    ContextId,
    ContextInfo,
    ContextOptions,
    LLMStatus,
    DemographicsInfo,
    LocationInfo,
    DateTimeInfo,
    WeatherInfo,
    ConnectionMode,
    RemoteConfig,
    TransportMode,
    VMProfile,
)
from .exceptions import (
    LicenseError,
    BrowserInitializationError,
    ContextLimitError,
    is_action_result,
    throw_if_action_failed,
)
from .http_client import HttpTransport, map_method_to_tool, map_params_for_http
from .ws_client import WebSocketTransport


class BrowserCore:
    """
    Core browser process manager.

    Handles spawning the browser process, sending commands via stdin,
    and receiving responses via stdout. Thread-safe for concurrent usage.

    Supports dual mode:
    - LOCAL: Connect to local browser binary via stdin/stdout IPC
    - REMOTE: Connect to remote browser HTTP server via REST API

    Example (Local mode):
        ```python
        core = BrowserCore(config=BrowserConfig(browser_path="/path/to/browser"))
        core.initialize()
        ```

    Example (Remote mode):
        ```python
        core = BrowserCore(remote=RemoteConfig(
            url="http://localhost:8080",
            token="your-secret-token"
        ))
        core.initialize()
        ```
    """

    def __init__(
        self,
        config: Optional[BrowserConfig] = None,
        remote: Optional[RemoteConfig] = None
    ):
        """
        Initialize BrowserCore.

        Args:
            config: Local browser configuration (for LOCAL mode)
            remote: Remote server configuration (for REMOTE mode)

        Note: If both config and remote are provided, remote takes precedence.
        """
        self._config = config or BrowserConfig()
        self._remote_config = remote
        self._mode = ConnectionMode.REMOTE if remote else ConnectionMode.LOCAL

        # Remote mode transports
        self._http_transport: Optional[HttpTransport] = None
        self._ws_transport: Optional[WebSocketTransport] = None

        # Local mode state
        self._process: Optional[subprocess.Popen] = None
        self._command_id = 0
        self._pending_commands: Dict[int, Future] = {}
        self._lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._ready_event = threading.Event()
        self._running = False
        self._buffer = ""
        self._instance_id = f"browser_{int(time.time())}_{uuid.uuid4().hex[:9]}"
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="owl_browser")

        # License error tracking
        self._license_error: Optional[LicenseError] = None
        self._license_error_event = threading.Event()
        self._hardware_fingerprint: Optional[str] = None

        # Detect browser path if not provided (only for local mode)
        if self._mode == ConnectionMode.LOCAL and not self._config.browser_path:
            self._config.browser_path = self._detect_browser_path()

    @property
    def mode(self) -> ConnectionMode:
        """Get the connection mode (LOCAL or REMOTE)."""
        return self._mode

    @property
    def is_remote(self) -> bool:
        """Check if running in remote mode."""
        return self._mode == ConnectionMode.REMOTE

    def _detect_browser_path(self) -> str:
        """Auto-detect browser binary path."""
        possible_paths = [
            # When SDK is in python-sdk/ folder
            Path(__file__).parent.parent.parent / "build" / "Release" / "owl_browser.app" / "Contents" / "MacOS" / "owl_browser",
            # Development path
            Path.cwd() / "build" / "Release" / "owl_browser.app" / "Contents" / "MacOS" / "owl_browser",
            # System-wide installation
            Path("/usr/local/bin/owl_browser"),
            Path("/opt/owl-browser/owl_browser"),
        ]

        for browser_path in possible_paths:
            if browser_path.exists():
                return str(browser_path)

        raise FileNotFoundError(
            "Browser binary not found. Please build the browser first or provide browser_path in config."
        )

    def initialize(self) -> None:
        """
        Initialize and start the browser connection.

        For LOCAL mode: Starts the browser process.
        For REMOTE mode: Connects to the HTTP server and verifies it's ready.

        This is a synchronous operation that blocks until the browser is ready.
        """
        if self._mode == ConnectionMode.REMOTE:
            self._initialize_remote()
            return

        self._initialize_local()

    def _initialize_remote(self) -> None:
        """Initialize remote connection (HTTP or WebSocket)."""
        if self._http_transport is not None or self._ws_transport is not None:
            raise RuntimeError("Browser already initialized")

        if not self._remote_config:
            raise RuntimeError("Remote config not provided")

        # Check transport mode
        use_websocket = (
            self._remote_config.transport == TransportMode.WEBSOCKET or
            self._remote_config.transport == TransportMode.WS
        )

        if use_websocket:
            self._initialize_websocket()
        else:
            self._initialize_http()

    def _initialize_http(self) -> None:
        """Initialize HTTP REST API connection."""
        # Create HTTP transport
        self._http_transport = HttpTransport(self._remote_config)

        # Check server health
        try:
            health = self._http_transport.health_check()

            if health.get("status") != "healthy":
                raise BrowserInitializationError(
                    f"Remote browser server is not healthy: {health}"
                )

            if not health.get("browser_ready"):
                browser_state = health.get("browser_state", "unknown")
                if browser_state == "license_error":
                    raise LicenseError(
                        message="Remote browser has license error",
                        status="license_error"
                    )
                raise BrowserInitializationError(
                    f"Remote browser not ready. State: {browser_state}"
                )

            self._running = True

            if self._config.verbose:
                print(f"[Browser] Connected to remote server at {self._remote_config.url} (HTTP)")

        except LicenseError:
            raise
        except BrowserInitializationError:
            raise
        except Exception as e:
            raise BrowserInitializationError(
                f"Failed to connect to remote browser server: {e}"
            )

    def _initialize_websocket(self) -> None:
        """Initialize WebSocket connection."""
        try:
            # Create WebSocket transport
            self._ws_transport = WebSocketTransport(self._remote_config)
            self._ws_transport.connect()

            # Check if connected successfully
            if not self._ws_transport.is_connected():
                raise BrowserInitializationError(
                    "WebSocket connection failed"
                )

            self._running = True

            if self._config.verbose:
                print(f"[Browser] Connected to remote server at {self._remote_config.url} (WebSocket)")

        except LicenseError:
            raise
        except BrowserInitializationError:
            raise
        except Exception as e:
            if self._ws_transport:
                self._ws_transport.close()
                self._ws_transport = None
            raise BrowserInitializationError(
                f"Failed to connect to WebSocket server: {e}"
            )

    def _initialize_local(self) -> None:
        """Initialize local browser process."""
        if self._process is not None:
            raise RuntimeError("Browser already initialized")

        browser_path = self._config.browser_path
        if not browser_path or not Path(browser_path).exists():
            raise FileNotFoundError(f"Browser binary not found at: {browser_path}")

        # Start the browser process
        env = os.environ.copy()
        env["OLIB_INSTANCE_ID"] = self._instance_id

        self._process = subprocess.Popen(
            [browser_path, "--instance-id", self._instance_id],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            bufsize=0,  # Unbuffered for immediate reads
        )

        self._running = True
        self._ready_event = threading.Event()

        # Start stderr reader thread (for logs)
        self._stderr_thread = threading.Thread(
            target=self._read_stderr,
            daemon=True,
            name=f"owl_stderr_{self._instance_id[:8]}"
        )
        self._stderr_thread.start()

        # Start stdout reader thread (for commands and READY signal)
        self._reader_thread = threading.Thread(
            target=self._read_output,
            daemon=True,
            name=f"owl_reader_{self._instance_id[:8]}"
        )
        self._reader_thread.start()

        # Wait for READY signal or license error
        timeout_sec = self._config.init_timeout / 1000.0
        start_time = time.time()

        while True:
            elapsed = time.time() - start_time
            remaining = timeout_sec - elapsed

            if remaining <= 0:
                # Timeout - check if it's due to license error
                if self._license_error:
                    self.shutdown()
                    raise self._license_error
                self.shutdown()
                raise BrowserInitializationError("Browser initialization timeout")

            # Wait for either READY or license error
            ready = self._ready_event.wait(timeout=min(0.1, remaining))
            if ready:
                break

            # Check for license error
            if self._license_error_event.is_set():
                # Give it a moment to collect more error details (like fingerprint)
                time.sleep(0.2)
                self.shutdown()
                raise self._license_error

            # Check if process has terminated
            if self._process and self._process.poll() is not None:
                # Process exited - check for license error
                if self._license_error:
                    self.shutdown()
                    raise self._license_error
                # Unknown termination
                self.shutdown()
                raise BrowserInitializationError(
                    f"Browser process terminated unexpectedly (exit code: {self._process.returncode})"
                )

        if self._config.verbose:
            print(f"[Browser] Ready (instance: {self._instance_id}, PID: {self._process.pid})")

        # Register cleanup on exit
        atexit.register(self._cleanup_on_exit)

    def _cleanup_on_exit(self):
        """Cleanup handler for atexit."""
        try:
            self.shutdown()
        except Exception:
            pass

    def _read_stderr(self):
        """Background thread to read stderr (logs)."""
        # Patterns for detecting license errors
        license_error_pattern = re.compile(
            r'\[License\].*(?:Validation|validation).*[:]\s*(\w+)',
            re.IGNORECASE
        )
        license_failed_pattern = re.compile(
            r'License validation failed:\s*(\w+)',
            re.IGNORECASE
        )
        fingerprint_pattern = re.compile(
            r'Hardware Fingerprint:\s*([a-f0-9]+)',
            re.IGNORECASE
        )
        activation_failed_pattern = re.compile(
            r'Failed to activate license:\s*(\w+)',
            re.IGNORECASE
        )
        license_required_pattern = re.compile(
            r'Owl Browser requires a valid license',
            re.IGNORECASE
        )

        while self._running and self._process and self._process.stderr:
            try:
                line = self._process.stderr.readline()
                if not line:
                    if self._process.poll() is not None:
                        break
                    continue

                decoded = line.decode('utf-8', errors='ignore').strip()
                if not decoded:
                    continue

                # Check for READY signal in stderr too (some builds output it there)
                if 'READY' in decoded:
                    self._ready_event.set()

                # Check for hardware fingerprint
                fp_match = fingerprint_pattern.search(decoded)
                if fp_match:
                    self._hardware_fingerprint = fp_match.group(1)

                # Check for license errors
                license_status = None
                license_message = None

                # Pattern 1: [License] Validation: status
                match = license_error_pattern.search(decoded)
                if match:
                    status = match.group(1).lower()
                    if status not in ('ok', 'valid'):
                        license_status = status
                        license_message = f"License validation failed: {status}"

                # Pattern 2: License validation failed: status
                match = license_failed_pattern.search(decoded)
                if match:
                    license_status = match.group(1).lower()
                    license_message = f"License validation failed: {license_status}"

                # Pattern 3: Failed to activate license: status
                match = activation_failed_pattern.search(decoded)
                if match:
                    license_status = match.group(1).lower()
                    license_message = f"Failed to activate license: {license_status}"

                # Pattern 4: Generic license required message
                if license_required_pattern.search(decoded):
                    license_status = license_status or LicenseError.NOT_FOUND
                    license_message = license_message or "Owl Browser requires a valid license to run."

                # If we found a license error, set it and signal
                if license_status and license_message:
                    self._license_error = LicenseError(
                        message=license_message,
                        status=license_status,
                        fingerprint=self._hardware_fingerprint
                    )
                    self._license_error_event.set()
                    # Don't break here - continue reading to capture more info

                if self._config.verbose:
                    print(f"[Browser stderr] {decoded}")

            except Exception:
                break

    def _read_output(self):
        """Background thread to read stdout and dispatch responses."""
        while self._running and self._process and self._process.stdout:
            try:
                line = self._process.stdout.readline()
                if not line:
                    if self._process.poll() is not None:
                        # Process has terminated
                        self._running = False
                        break
                    continue

                decoded = line.decode('utf-8', errors='ignore').strip()
                if not decoded:
                    continue

                # Check for READY signal
                if decoded == "READY":
                    self._ready_event.set()
                    if self._config.verbose:
                        print("[Browser] READY signal received")
                    continue

                # Try to parse as JSON response
                try:
                    response = json.loads(decoded)
                    self._handle_response(response)
                except json.JSONDecodeError:
                    # Not a JSON response, likely a log message
                    if self._config.verbose:
                        print(f"[Browser] {decoded}")

            except Exception as e:
                if self._running and self._config.verbose:
                    print(f"[Browser] Read error: {e}")
                break

        # Mark all pending commands as failed
        with self._lock:
            for cmd_id, future in list(self._pending_commands.items()):
                if not future.done():
                    future.set_exception(RuntimeError("Browser process terminated"))
            self._pending_commands.clear()

    def _handle_response(self, response: Dict[str, Any]):
        """Handle a JSON response from the browser."""
        cmd_id = response.get("id")
        if cmd_id is None:
            return

        with self._lock:
            future = self._pending_commands.pop(cmd_id, None)

        if future is None:
            return

        if "error" in response:
            future.set_exception(RuntimeError(response["error"]))
        else:
            result = response.get("result")
            # Check for context limit error (from createContext)
            if isinstance(result, dict) and result.get("error") and result.get("code") == "CONTEXT_LIMIT_EXCEEDED":
                details = result.get("details", {})
                future.set_exception(ContextLimitError(
                    message=result.get("message", "Context limit exceeded"),
                    current_contexts=details.get("current_contexts"),
                    max_contexts=details.get("max_contexts"),
                    license_type=details.get("license_type", "developer")
                ))
                return
            # Check if result is an ActionResult with success=false
            if is_action_result(result) and not result.get("success", True):
                try:
                    throw_if_action_failed(result)
                except Exception as e:
                    future.set_exception(e)
                    return
            future.set_result(result)

    def send_command(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0
    ) -> Any:
        """
        Send a command to the browser and wait for response.

        Thread-safe and blocking. For async usage, use send_command_async.

        Works in both LOCAL and REMOTE modes:
        - LOCAL: Sends via stdin/stdout IPC to browser process
        - REMOTE: Sends via HTTP REST API to browser server

        Args:
            method: Command method name
            params: Command parameters
            timeout: Timeout in seconds

        Returns:
            Command result

        Raises:
            RuntimeError: If command fails or times out
        """
        # Remote mode - use HTTP transport
        if self._mode == ConnectionMode.REMOTE:
            return self._send_command_remote(method, params, timeout)

        # Local mode - use IPC
        future = self.send_command_async(method, params)
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            raise RuntimeError(f"Command timeout: {method}")

    def _send_command_remote(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0
    ) -> Any:
        """
        Send a command via HTTP or WebSocket to remote browser server.

        Args:
            method: Command method name
            params: Command parameters
            timeout: Timeout in seconds (used for HTTP request timeout)

        Returns:
            Command result
        """
        # Use WebSocket if available
        if self._ws_transport:
            return self._send_command_websocket(method, params)

        # Otherwise use HTTP
        if not self._http_transport:
            raise RuntimeError("Browser not initialized. Call initialize() first.")

        # Map method name to HTTP API tool name
        tool_name = map_method_to_tool(method)

        # Map parameter names to HTTP API format
        http_params = map_params_for_http(params) if params else {}

        if self._config.verbose:
            print(f"[Browser] HTTP: {tool_name}", http_params or "")

        # Execute via HTTP
        result = self._http_transport.execute_tool(tool_name, http_params)

        # Handle special cases where we need to extract specific fields
        # The HTTP API returns full objects but SDK methods expect specific values
        if method == "getCurrentURL" and isinstance(result, dict):
            return result.get("url", "")
        if method == "getPageTitle" and isinstance(result, dict):
            return result.get("title", "")

        return result

    def _send_command_websocket(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Send a command via WebSocket to remote browser server.

        Args:
            method: Command method name
            params: Command parameters

        Returns:
            Command result
        """
        if not self._ws_transport:
            raise RuntimeError("WebSocket not initialized")

        # Map method name to HTTP API tool name (same mapping as HTTP)
        tool_name = map_method_to_tool(method)

        # Map parameter names to HTTP API format
        ws_params = map_params_for_http(params) if params else {}

        if self._config.verbose:
            print(f"[Browser] WebSocket: {tool_name}", ws_params or "")

        # Execute via WebSocket
        result = self._ws_transport.execute_tool(tool_name, ws_params)

        # Handle special cases where we need to extract specific fields
        if method == "getCurrentURL" and isinstance(result, dict):
            return result.get("url", "")
        if method == "getPageTitle" and isinstance(result, dict):
            return result.get("title", "")

        return result

    def send_command_async(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Future:
        """
        Send a command asynchronously and return a Future.

        Thread-safe. Use future.result() to get the result.

        Note: For REMOTE mode, this still executes synchronously in a thread pool
        because HTTP requests are inherently blocking.

        Args:
            method: Command method name
            params: Command parameters

        Returns:
            Future that will contain the result
        """
        # Remote mode - wrap HTTP call in Future
        if self._mode == ConnectionMode.REMOTE:
            future: Future = Future()

            def execute():
                try:
                    result = self._send_command_remote(method, params)
                    future.set_result(result)
                except Exception as e:
                    future.set_exception(e)

            self._executor.submit(execute)
            return future

        # Local mode - use IPC
        if not self._process or not self._running:
            future = Future()
            future.set_exception(RuntimeError("Browser not initialized. Call initialize() first."))
            return future

        with self._lock:
            self._command_id += 1
            cmd_id = self._command_id

            command = {"id": cmd_id, "method": method}
            if params:
                command.update(params)

            future = Future()
            self._pending_commands[cmd_id] = future

        # Send command
        try:
            # Use separators without spaces - browser parser expects "key":"value" not "key": "value"
            command_str = json.dumps(command, separators=(',', ':')) + "\n"
            if self._config.verbose:
                print(f"[Browser] Sending: {method}", params or "")
            self._process.stdin.write(command_str.encode('utf-8'))
            self._process.stdin.flush()
        except Exception as e:
            with self._lock:
                self._pending_commands.pop(cmd_id, None)
            future.set_exception(RuntimeError(f"Failed to send command: {e}"))

        return future

    def create_context(self, options: Optional[ContextOptions] = None) -> ContextInfo:
        """Create a new browser context.

        Returns full context info including vm_profile, seeds, hashes, etc.
        """
        params: Dict[str, Any] = {}

        if options:
            # LLM configuration
            if options.llm:
                params["llm_enabled"] = options.llm.enabled
                params["llm_use_builtin"] = options.llm.use_builtin
                if options.llm.endpoint:
                    params["llm_endpoint"] = options.llm.endpoint
                if options.llm.model:
                    params["llm_model"] = options.llm.model
                if options.llm.api_key:
                    params["llm_api_key"] = options.llm.api_key

            # Proxy configuration
            if options.proxy:
                params["proxy_type"] = options.proxy.type.value
                params["proxy_host"] = options.proxy.host
                params["proxy_port"] = options.proxy.port
                if options.proxy.username:
                    params["proxy_username"] = options.proxy.username
                if options.proxy.password:
                    params["proxy_password"] = options.proxy.password
                params["proxy_stealth"] = options.proxy.stealth
                # Only send advanced proxy features when enabled (not supported on all tiers)
                if options.proxy.block_webrtc:
                    params["proxy_block_webrtc"] = options.proxy.block_webrtc
                if options.proxy.spoof_timezone:
                    params["proxy_spoof_timezone"] = options.proxy.spoof_timezone
                if options.proxy.spoof_language:
                    params["proxy_spoof_language"] = options.proxy.spoof_language
                if options.proxy.timezone_override:
                    params["proxy_timezone_override"] = options.proxy.timezone_override
                if options.proxy.language_override:
                    params["proxy_language_override"] = options.proxy.language_override
                if options.proxy.ca_cert_path:
                    params["proxy_ca_cert_path"] = options.proxy.ca_cert_path
                if options.proxy.trust_custom_ca:
                    params["proxy_trust_custom_ca"] = options.proxy.trust_custom_ca
                # Tor-specific settings for circuit isolation (only when enabled)
                if options.proxy.is_tor:
                    params["is_tor"] = options.proxy.is_tor
                if options.proxy.tor_control_port:
                    params["tor_control_port"] = options.proxy.tor_control_port
                if options.proxy.tor_control_password:
                    params["tor_control_password"] = options.proxy.tor_control_password

            # Profile configuration
            if options.profile_path:
                params["profile_path"] = options.profile_path

            # Resource blocking configuration (default: true)
            params["resource_blocking"] = options.resource_blocking

            # Profile filtering options
            if options.os:
                params["os"] = options.os
            if options.gpu:
                params["gpu"] = options.gpu

        return self.send_command("createContext", params if params else None)

    def release_context(self, context_id: ContextId) -> None:
        """Release a browser context."""
        self.send_command("releaseContext", {"context_id": context_id})

    def get_llm_status(self) -> LLMStatus:
        """Get LLM status."""
        result = self.send_command("getLLMStatus")
        return LLMStatus(result) if isinstance(result, str) else LLMStatus.UNAVAILABLE

    def list_templates(self) -> list:
        """List available extraction templates."""
        return self.send_command("listTemplates")

    def get_demographics(self) -> Dict[str, Any]:
        """Get complete demographics information."""
        return self.send_command("getDemographics")

    def get_location(self) -> Dict[str, Any]:
        """Get location information."""
        return self.send_command("getLocation")

    def get_datetime(self) -> Dict[str, Any]:
        """Get current date and time information."""
        return self.send_command("getDateTime")

    def get_weather(self) -> Dict[str, Any]:
        """Get current weather information."""
        return self.send_command("getWeather")

    def get_homepage(self) -> str:
        """Get the custom browser homepage HTML."""
        return self.send_command("getHomepage")

    def shutdown(self) -> None:
        """
        Shutdown the browser connection gracefully.

        For LOCAL mode: Terminates the browser process.
        For REMOTE mode: Closes the HTTP transport (does not shutdown the server).
        """
        # Remote mode - just cleanup transport
        if self._mode == ConnectionMode.REMOTE:
            self._shutdown_remote()
            return

        # Local mode - shutdown process
        self._shutdown_local()

    def _shutdown_remote(self) -> None:
        """Shutdown remote connection (cleanup only, doesn't stop server)."""
        if not self._http_transport and not self._ws_transport:
            return

        if self._config.verbose:
            transport_type = "WebSocket" if self._ws_transport else "HTTP"
            print(f"[Browser] Disconnecting from remote server ({transport_type})...")

        self._running = False

        # Close WebSocket if active
        if self._ws_transport:
            try:
                self._ws_transport.close()
            except Exception:
                pass
            self._ws_transport = None

        # Clear HTTP transport
        self._http_transport = None

        # Shutdown executor
        self._executor.shutdown(wait=False)

        if self._config.verbose:
            print("[Browser] Disconnected from remote server")

    def _shutdown_local(self) -> None:
        """Shutdown local browser process."""
        if not self._process:
            return

        pid = self._process.pid
        if self._config.verbose:
            print(f"[Browser] Shutting down process (PID: {pid})...")

        self._running = False

        # Try graceful shutdown
        try:
            self.send_command("shutdown", timeout=3.0)
        except Exception:
            pass

        # Close stdin
        try:
            if self._process.stdin:
                self._process.stdin.close()
        except Exception:
            pass

        # Wait for graceful termination
        try:
            self._process.wait(timeout=3.0)
            if self._config.verbose:
                print("[Browser] Exited gracefully")
        except subprocess.TimeoutExpired:
            # Force kill
            if self._config.verbose:
                print("[Browser] Force killing...")
            try:
                self._process.kill()
                self._process.wait(timeout=1.0)
            except Exception:
                pass

        self._process = None

        # Shutdown executor
        self._executor.shutdown(wait=False)

        if self._config.verbose:
            print("[Browser] Shutdown complete")

    def is_running(self) -> bool:
        """Check if browser connection is active."""
        if self._mode == ConnectionMode.REMOTE:
            # Check WebSocket or HTTP transport
            if self._ws_transport:
                return self._running and self._ws_transport.is_connected()
            return self._running and self._http_transport is not None
        return self._running and self._process is not None and self._process.poll() is None
