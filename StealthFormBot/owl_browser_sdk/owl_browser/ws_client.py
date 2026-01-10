"""
WebSocket client for connecting to remote Owl Browser HTTP server.

This module provides WebSocket transport layer for real-time browser connections,
enabling lower latency and bidirectional communication compared to REST API.

Benefits of WebSocket over HTTP:
- Lower latency (no HTTP overhead per request)
- Persistent connection (no reconnection overhead)
- Real-time communication
- Efficient for high-frequency operations

Features:
- Automatic reconnection with exponential backoff
- Connection health monitoring
- Thread-safe request/response handling
"""

import json
import threading
import time
import base64
import hashlib
import os
import socket
import ssl
import struct
import random
from typing import Any, Dict, Optional, Callable
from queue import Queue, Empty
from dataclasses import dataclass, field

from .types import RemoteConfig, AuthMode, ReconnectConfig
from .exceptions import (
    OwlBrowserError,
    LicenseError,
    BrowserInitializationError,
    CommandTimeoutError,
    AuthenticationError,
)
from .jwt import JWTManager


# WebSocket opcodes
WS_OPCODE_TEXT = 0x1
WS_OPCODE_BINARY = 0x2
WS_OPCODE_CLOSE = 0x8
WS_OPCODE_PING = 0x9
WS_OPCODE_PONG = 0xA


def calculate_reconnect_delay(config: ReconnectConfig, attempt: int) -> float:
    """Calculate delay in seconds with exponential backoff and jitter."""
    delay_ms = config.initial_delay_ms * (config.backoff_multiplier ** attempt)
    delay_ms = min(delay_ms, config.max_delay_ms)
    jitter = delay_ms * config.jitter_factor * (random.random() * 2 - 1)
    return max(0, (delay_ms + jitter) / 1000.0)


@dataclass
class PendingRequest:
    """Pending request waiting for response."""
    id: int
    event: threading.Event = field(default_factory=threading.Event)
    result: Any = None
    error: Optional[str] = None


class WebSocketTransport:
    """
    WebSocket transport for communicating with remote Owl Browser HTTP server.

    This class handles WebSocket communication with the remote server,
    providing a persistent connection for real-time browser control.

    Example:
        ```python
        from owl_browser.ws_client import WebSocketTransport
        from owl_browser.types import RemoteConfig

        config = RemoteConfig(url="http://localhost:8080", token="test-token")
        ws = WebSocketTransport(config)
        ws.connect()

        # Execute a tool
        result = ws.execute_tool("browser_create_context", {})
        print(f"Context ID: {result}")

        ws.close()
        ```
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
    }

    def __init__(
        self,
        config: RemoteConfig,
        reconnect_config: Optional[ReconnectConfig] = None
    ):
        """
        Initialize WebSocket transport.

        Args:
            config: Remote server configuration
            reconnect_config: Auto-reconnection configuration (enabled by default)
        """
        self._config = config
        self._api_prefix = config.api_prefix  # API prefix for nginx proxy (e.g., "/api")
        self._parse_url()
        self._static_token = config.token
        self._jwt_manager: Optional[JWTManager] = None
        self._timeout = config.timeout / 1000.0  # Convert to seconds
        self._long_timeout = max(120.0, self._timeout * 4)

        # Reconnection configuration
        self._reconnect_config = reconnect_config or ReconnectConfig()
        self._reconnect_attempts = 0
        self._reconnecting = False
        self._reconnect_lock = threading.Lock()

        # WebSocket state
        self._socket: Optional[socket.socket] = None
        self._connected = False
        self._lock = threading.Lock()
        self._request_id = 0
        self._pending_requests: Dict[int, PendingRequest] = {}

        # Receive thread
        self._recv_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Callback for reconnection events
        self._on_reconnect: Optional[Callable[[], None]] = None
        self._on_disconnect: Optional[Callable[[Exception], None]] = None

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

    def _parse_url(self):
        """Parse the server URL into components."""
        url = self._config.url

        # Determine if SSL
        if url.startswith("https://"):
            self._use_ssl = True
            url = url[8:]
        elif url.startswith("http://"):
            self._use_ssl = False
            url = url[7:]
        elif url.startswith("wss://"):
            self._use_ssl = True
            url = url[6:]
        elif url.startswith("ws://"):
            self._use_ssl = False
            url = url[5:]
        else:
            self._use_ssl = False

        # Parse host and port
        if "/" in url:
            url = url.split("/")[0]

        if ":" in url:
            parts = url.split(":")
            self._host = parts[0]
            self._port = int(parts[1])
        else:
            self._host = url
            self._port = 443 if self._use_ssl else 80

    def _get_auth_token(self) -> str:
        """Get the current authentication token (static or JWT)."""
        if self._jwt_manager:
            return self._jwt_manager.get_token()
        if self._static_token:
            return self._static_token
        raise OwlBrowserError("No authentication token available")

    def _create_websocket_key(self) -> str:
        """Generate a random WebSocket key for handshake."""
        return base64.b64encode(os.urandom(16)).decode('utf-8')

    def _do_handshake(self) -> bool:
        """
        Perform WebSocket handshake.

        Returns:
            True if handshake successful
        """
        # Generate WebSocket key
        ws_key = self._create_websocket_key()

        # Build handshake request (apply api_prefix to /ws path)
        ws_path = self._api_prefix + "/ws"
        handshake = (
            f"GET {ws_path} HTTP/1.1\r\n"
            f"Host: {self._host}:{self._port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Authorization: Bearer {self._get_auth_token()}\r\n"
            f"\r\n"
        )

        self._socket.sendall(handshake.encode('utf-8'))

        # Receive response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self._socket.recv(1024)
            if not chunk:
                raise OwlBrowserError("Connection closed during handshake")
            response += chunk

        response_str = response.decode('utf-8')

        # Check response status
        if "101 Switching Protocols" not in response_str:
            if "401" in response_str:
                raise AuthenticationError("WebSocket authentication failed")
            raise OwlBrowserError(f"WebSocket handshake failed: {response_str[:200]}")

        # Verify accept key
        expected_accept = base64.b64encode(
            hashlib.sha1(
                (ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
        ).decode('utf-8')

        if f"Sec-WebSocket-Accept: {expected_accept}" not in response_str:
            raise OwlBrowserError("Invalid WebSocket accept key")

        return True

    def connect(self):
        """
        Connect to the WebSocket server.

        Raises:
            BrowserInitializationError: If connection fails
        """
        if self._connected:
            return

        try:
            self._do_connect()

            self._connected = True
            self._stop_event.clear()
            self._reconnect_attempts = 0

            # Start receive thread
            self._recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self._recv_thread.start()

        except socket.timeout:
            raise BrowserInitializationError(
                f"Connection to {self._host}:{self._port} timed out"
            )
        except socket.error as e:
            raise BrowserInitializationError(
                f"Failed to connect to WebSocket server at {self._host}:{self._port}: {e}"
            )
        except Exception as e:
            if self._socket:
                self._socket.close()
                self._socket = None
            raise BrowserInitializationError(f"WebSocket connection failed: {e}")

    def close(self):
        """Close the WebSocket connection."""
        if not self._connected:
            return

        self._stop_event.set()
        self._connected = False

        # Send close frame
        try:
            self._send_frame(WS_OPCODE_CLOSE, b"")
        except:
            pass

        # Close socket
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None

        # Wait for receive thread
        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=2.0)

        # Clear pending requests
        with self._lock:
            for req in self._pending_requests.values():
                req.error = "Connection closed"
                req.event.set()
            self._pending_requests.clear()

    def _send_frame(self, opcode: int, payload: bytes):
        """Send a WebSocket frame."""
        # Build frame header
        frame = bytearray()

        # FIN + opcode
        frame.append(0x80 | opcode)

        # Mask bit (client must mask) + payload length
        payload_len = len(payload)
        if payload_len < 126:
            frame.append(0x80 | payload_len)
        elif payload_len <= 0xFFFF:
            frame.append(0x80 | 126)
            frame.extend(struct.pack(">H", payload_len))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack(">Q", payload_len))

        # Masking key (random)
        mask_key = os.urandom(4)
        frame.extend(mask_key)

        # Masked payload
        masked_payload = bytearray(payload_len)
        for i in range(payload_len):
            masked_payload[i] = payload[i] ^ mask_key[i % 4]
        frame.extend(masked_payload)

        self._socket.sendall(bytes(frame))

    def _recv_frame(self) -> tuple:
        """
        Receive a WebSocket frame.

        Returns:
            Tuple of (opcode, payload)
        """
        # Read first 2 bytes
        header = self._recv_exact(2)
        if not header:
            return None, None

        fin = (header[0] & 0x80) != 0
        opcode = header[0] & 0x0F
        masked = (header[1] & 0x80) != 0
        payload_len = header[1] & 0x7F

        # Extended payload length
        if payload_len == 126:
            ext_len = self._recv_exact(2)
            if not ext_len:
                return None, None
            payload_len = struct.unpack(">H", ext_len)[0]
        elif payload_len == 127:
            ext_len = self._recv_exact(8)
            if not ext_len:
                return None, None
            payload_len = struct.unpack(">Q", ext_len)[0]

        # Masking key (server shouldn't mask, but handle it)
        mask_key = None
        if masked:
            mask_key = self._recv_exact(4)
            if not mask_key:
                return None, None

        # Payload
        payload = self._recv_exact(payload_len)
        if payload is None:
            return None, None

        # Unmask if needed
        if masked and mask_key:
            unmasked = bytearray(payload_len)
            for i in range(payload_len):
                unmasked[i] = payload[i] ^ mask_key[i % 4]
            payload = bytes(unmasked)

        return opcode, payload

    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes."""
        data = b""
        while len(data) < n:
            try:
                chunk = self._socket.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                return None
            except socket.error:
                return None
        return data

    def _receive_loop(self):
        """Background thread for receiving frames with auto-reconnection."""
        while not self._stop_event.is_set():
            try:
                self._socket.settimeout(1.0)
                opcode, payload = self._recv_frame()

                if opcode is None:
                    continue

                if opcode == WS_OPCODE_TEXT:
                    self._handle_message(payload.decode('utf-8'))
                elif opcode == WS_OPCODE_PING:
                    # Send pong
                    self._send_frame(WS_OPCODE_PONG, payload)
                elif opcode == WS_OPCODE_CLOSE:
                    self._connected = False
                    self._attempt_reconnect()
                    break
                elif opcode == WS_OPCODE_PONG:
                    pass  # Ignore pong

            except socket.timeout:
                continue
            except Exception as e:
                if not self._stop_event.is_set():
                    self._connected = False
                    if self._on_disconnect:
                        try:
                            self._on_disconnect(e)
                        except:
                            pass
                    # Attempt reconnection
                    if self._attempt_reconnect():
                        continue  # Successfully reconnected, continue loop
                break

    def _attempt_reconnect(self) -> bool:
        """
        Attempt to reconnect to the WebSocket server.

        Returns:
            True if reconnection was successful, False otherwise.
        """
        if not self._reconnect_config.enabled:
            return False

        with self._reconnect_lock:
            if self._reconnecting or self._stop_event.is_set():
                return False
            self._reconnecting = True

        try:
            for attempt in range(self._reconnect_config.max_attempts):
                if self._stop_event.is_set():
                    return False

                self._reconnect_attempts = attempt + 1

                # Calculate delay with exponential backoff
                delay = calculate_reconnect_delay(self._reconnect_config, attempt)
                time.sleep(delay)

                try:
                    # Close existing socket if any
                    if self._socket:
                        try:
                            self._socket.close()
                        except:
                            pass
                        self._socket = None

                    # Reconnect
                    self._do_connect()

                    # Reset attempts on success
                    self._reconnect_attempts = 0
                    self._connected = True

                    # Notify callback
                    if self._on_reconnect:
                        try:
                            self._on_reconnect()
                        except:
                            pass

                    return True

                except Exception as e:
                    # Reconnection attempt failed, continue to next attempt
                    continue

            # All attempts exhausted
            return False

        finally:
            with self._reconnect_lock:
                self._reconnecting = False

    def _do_connect(self):
        """Internal method to establish connection (used by connect and reconnect)."""
        # Create socket
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self._timeout)

        # Wrap with SSL if needed
        if self._use_ssl:
            context = ssl.create_default_context()
            if not self._config.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self._socket = context.wrap_socket(self._socket, server_hostname=self._host)

        # Connect
        self._socket.connect((self._host, self._port))

        # Perform handshake
        self._do_handshake()

    def set_reconnect_callback(
        self,
        on_reconnect: Optional[Callable[[], None]] = None,
        on_disconnect: Optional[Callable[[Exception], None]] = None
    ):
        """
        Set callbacks for reconnection events.

        Args:
            on_reconnect: Called when reconnection succeeds
            on_disconnect: Called when connection is lost (before reconnect attempt)
        """
        self._on_reconnect = on_reconnect
        self._on_disconnect = on_disconnect

    def _handle_message(self, message: str):
        """Handle incoming WebSocket message."""
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            return

        # Get request ID
        req_id = data.get("id")
        if req_id is None:
            return

        with self._lock:
            if req_id in self._pending_requests:
                req = self._pending_requests[req_id]
                if data.get("success", False):
                    req.result = data.get("result")
                else:
                    req.error = data.get("error", "Unknown error")
                req.event.set()

    def _next_request_id(self) -> int:
        """Get the next request ID."""
        with self._lock:
            self._request_id += 1
            return self._request_id

    def _send_request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        long_running: bool = False
    ) -> Any:
        """
        Send a request and wait for response.

        Args:
            method: Tool/method name
            params: Parameters
            long_running: Use extended timeout

        Returns:
            Result from server

        Raises:
            OwlBrowserError: On error
        """
        if not self._connected:
            raise OwlBrowserError("Not connected to WebSocket server")

        req_id = self._next_request_id()
        request = PendingRequest(id=req_id)

        with self._lock:
            self._pending_requests[req_id] = request

        try:
            # Build message
            message = {
                "id": req_id,
                "method": method,
                "params": params or {}
            }

            # Send
            self._send_frame(WS_OPCODE_TEXT, json.dumps(message).encode('utf-8'))

            # Wait for response
            timeout = self._long_timeout if long_running else self._timeout
            if not request.event.wait(timeout):
                raise CommandTimeoutError(f"Request timed out: {method}")

            # Check result
            if request.error:
                raise OwlBrowserError(f"Tool execution failed: {request.error}")

            return request.result

        finally:
            with self._lock:
                self._pending_requests.pop(req_id, None)

    def execute_tool(
        self,
        tool_name: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Execute a browser tool.

        Args:
            tool_name: Name of the tool to execute
            params: Tool parameters

        Returns:
            Tool execution result

        Raises:
            OwlBrowserError: On execution failure
        """
        long_running = tool_name in self.LONG_RUNNING_TOOLS
        result = self._send_request(tool_name, params, long_running)

        # Handle nested response format from browser IPC
        if isinstance(result, dict) and "id" in result and "result" in result:
            result = result["result"]

        return result

    def health_check(self) -> Dict[str, Any]:
        """
        Check server health status via HTTP (WebSocket doesn't have health endpoint).

        Returns:
            Health status dict
        """
        # For WebSocket, we just check if connected
        return {
            "status": "healthy" if self._connected else "unhealthy",
            "browser_ready": self._connected,
            "browser_state": "ready" if self._connected else "unknown"
        }

    def is_browser_ready(self) -> bool:
        """Check if browser is ready."""
        return self._connected

    def is_connected(self) -> bool:
        """Check if WebSocket is connected."""
        return self._connected

    def send_raw_command(self, command: Dict[str, Any]) -> Any:
        """
        Send a raw command to the browser.

        Args:
            command: Raw command dict with 'method' and parameters

        Returns:
            Command result
        """
        method = command.pop("method", None)
        if not method:
            raise OwlBrowserError("Command must include 'method'")
        return self._send_request(method, command)


# Transport mode enum for RemoteConfig
class TransportMode:
    """Transport mode for remote connections."""
    HTTP = "http"
    WEBSOCKET = "websocket"
    WS = "websocket"  # Alias
