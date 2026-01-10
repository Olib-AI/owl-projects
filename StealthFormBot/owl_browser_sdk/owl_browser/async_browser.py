"""
Async Browser classes for asyncio-based applications.

Provides async versions of Browser and BrowserContext for use
with async/await syntax and asyncio event loops.

Supports dual mode:
- LOCAL: Connect to local browser binary via stdin/stdout IPC
- REMOTE: Connect to remote browser HTTP server via REST API
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Union

from .browser import Browser as SyncBrowser
from .context import BrowserContext as SyncBrowserContext
from .core import BrowserCore
from .types import (
    ContextId,
    ContextOptions,
    LLMStatus,
    LLMConfig,
    ProxyConfig,
    ProxyStatus,
    PageInfo,
    Viewport,
    Cookie,
    CookieSameSite,
    CleanLevel,
    KeyName,
    ExtractionTemplate,
    TestTemplate,
    TestExecutionResult,
    ConnectionMode,
    RemoteConfig,
)


class AsyncBrowserContext:
    """
    Async browser context (page) for automation.

    Provides async versions of all BrowserContext methods.

    Example:
        ```python
        page = await browser.new_page()
        await page.goto("https://example.com")
        await page.click("search button")
        await page.close()
        ```
    """

    def __init__(self, sync_context: SyncBrowserContext, executor: ThreadPoolExecutor):
        self._sync = sync_context
        self._executor = executor

    @property
    def id(self) -> ContextId:
        """Get the context ID."""
        return self._sync.id

    async def _run(self, func, *args, **kwargs) -> Any:
        """Run a sync function in the thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: func(*args, **kwargs)
        )

    # ==================== NAVIGATION ====================

    async def goto(self, url: str, wait_until: str = "load", timeout: int = 30000) -> None:
        """Navigate to a URL."""
        await self._run(self._sync.goto, url, wait_until, timeout)

    async def reload(
        self,
        ignore_cache: bool = False,
        wait_until: str = "load",
        timeout: int = 30000
    ) -> None:
        """Reload the current page."""
        await self._run(self._sync.reload, ignore_cache, wait_until, timeout)

    async def go_back(self, wait_until: str = "load", timeout: int = 30000) -> None:
        """Navigate back in history."""
        await self._run(self._sync.go_back, wait_until, timeout)

    async def go_forward(self, wait_until: str = "load", timeout: int = 30000) -> None:
        """Navigate forward in history."""
        await self._run(self._sync.go_forward, wait_until, timeout)

    async def can_go_back(self) -> bool:
        """Check if navigation back is possible."""
        return await self._run(self._sync.can_go_back)

    async def can_go_forward(self) -> bool:
        """Check if navigation forward is possible."""
        return await self._run(self._sync.can_go_forward)

    # ==================== INTERACTIONS ====================

    async def click(self, selector: str) -> None:
        """Click an element."""
        await self._run(self._sync.click, selector)

    async def type(self, selector: str, text: str) -> None:
        """Type text into an input field."""
        await self._run(self._sync.type, selector, text)

    async def pick(self, selector: str, value: str) -> None:
        """Select an option from a dropdown."""
        await self._run(self._sync.pick, selector, value)

    async def press_key(self, key: Union[KeyName, str]) -> None:
        """Press a special key."""
        await self._run(self._sync.press_key, key)

    async def submit_form(self) -> None:
        """Submit the currently focused form."""
        await self._run(self._sync.submit_form)

    async def highlight(
        self,
        selector: str,
        border_color: str = "#FF0000",
        background_color: str = "rgba(255, 0, 0, 0.2)"
    ) -> None:
        """Highlight an element for debugging."""
        await self._run(self._sync.highlight, selector, border_color, background_color)

    async def show_grid_overlay(
        self,
        horizontal_lines: int = 25,
        vertical_lines: int = 25,
        line_color: str = "rgba(255, 0, 0, 0.15)",
        text_color: str = "rgba(255, 0, 0, 0.4)"
    ) -> None:
        """
        Show a grid overlay on top of the web page with XY position coordinates at intersections.

        Useful for debugging and understanding element positions.
        """
        await self._run(
            self._sync.show_grid_overlay,
            horizontal_lines,
            vertical_lines,
            line_color,
            text_color
        )

    async def hover(self, selector: str, duration: Optional[int] = None) -> None:
        """Hover over an element."""
        await self._run(self._sync.hover, selector, duration)

    async def double_click(self, selector: str) -> None:
        """Double-click an element."""
        await self._run(self._sync.double_click, selector)

    async def right_click(self, selector: str) -> None:
        """Right-click an element."""
        await self._run(self._sync.right_click, selector)

    async def clear_input(self, selector: str) -> None:
        """Clear input field."""
        await self._run(self._sync.clear_input, selector)

    async def focus(self, selector: str) -> None:
        """Focus on an element."""
        await self._run(self._sync.focus, selector)

    async def blur(self, selector: str) -> None:
        """Blur an element."""
        await self._run(self._sync.blur, selector)

    async def select_all(self, selector: str) -> None:
        """Select all text in input."""
        await self._run(self._sync.select_all, selector)

    async def keyboard_combo(self, key: str, modifiers: List[str]) -> None:
        """Press keyboard combination."""
        await self._run(self._sync.keyboard_combo, key, modifiers)

    async def upload_file(self, selector: str, file_paths: List[str]) -> None:
        """Upload files to file input."""
        await self._run(self._sync.upload_file, selector, file_paths)

    # ==================== DRAG AND DROP ====================

    async def drag_drop(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        mid_points: Optional[List[List[int]]] = None
    ) -> None:
        """
        Drag from a start position to an end position, optionally passing through waypoints.

        Useful for slider CAPTCHAs, puzzle solving, and drawing interactions.

        Args:
            start_x: Start X coordinate for the drag
            start_y: Start Y coordinate for the drag
            end_x: End X coordinate for the drop
            end_y: End Y coordinate for the drop
            mid_points: Optional list of [x, y] waypoints to pass through during drag
        """
        await self._run(self._sync.drag_drop, start_x, start_y, end_x, end_y, mid_points)

    async def html5_drag_drop(
        self,
        source_selector: str,
        target_selector: str
    ) -> None:
        """
        Drag and drop for HTML5 draggable elements.

        For elements with `draggable="true"` attribute. Dispatches proper HTML5
        DragEvent objects (dragstart, dragover, drop, dragend).

        Args:
            source_selector: CSS selector for the source element to drag
            target_selector: CSS selector for the target element to drop onto
        """
        await self._run(self._sync.html5_drag_drop, source_selector, target_selector)

    async def mouse_move(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        steps: int = 0,
        stop_points: Optional[List[List[int]]] = None
    ) -> None:
        """
        Move the mouse cursor along a natural curved path from start to end position.

        Uses bezier curves with random variation, micro-jitter, and easing for
        human-like movement. Essential for avoiding bot detection.

        Args:
            start_x: Start X coordinate (current cursor position)
            start_y: Start Y coordinate (current cursor position)
            end_x: End X coordinate (target position)
            end_y: End Y coordinate (target position)
            steps: Number of intermediate points (0 = auto-calculate based on distance)
            stop_points: Optional list of [x, y] coordinates where cursor pauses briefly (50-150ms)
        """
        await self._run(self._sync.mouse_move, start_x, start_y, end_x, end_y, steps, stop_points)

    # ==================== ELEMENT STATE ====================

    async def is_visible(self, selector: str) -> bool:
        """Check if element is visible."""
        return await self._run(self._sync.is_visible, selector)

    async def is_enabled(self, selector: str) -> bool:
        """Check if element is enabled."""
        return await self._run(self._sync.is_enabled, selector)

    async def is_checked(self, selector: str) -> bool:
        """Check if element is checked."""
        return await self._run(self._sync.is_checked, selector)

    async def get_attribute(self, selector: str, attribute: str) -> Optional[str]:
        """Get element attribute."""
        return await self._run(self._sync.get_attribute, selector, attribute)

    async def get_bounding_box(self, selector: str) -> Dict[str, float]:
        """Get element bounding box."""
        return await self._run(self._sync.get_bounding_box, selector)

    # ==================== JAVASCRIPT EVALUATION ====================

    async def evaluate(
        self,
        script: str,
        return_value: bool = False
    ) -> Any:
        """Execute JavaScript code."""
        return await self._run(self._sync.evaluate, script, return_value)

    async def expression(self, expression: str) -> Any:
        """Evaluate JavaScript expression."""
        return await self._run(self._sync.expression, expression)

    # ==================== CLIPBOARD ====================

    async def clipboard_read(self) -> Dict[str, str]:
        """Read clipboard content."""
        return await self._run(self._sync.clipboard_read)

    async def clipboard_write(self, text: str) -> None:
        """Write to clipboard."""
        await self._run(self._sync.clipboard_write, text)

    async def clipboard_clear(self) -> None:
        """Clear clipboard."""
        await self._run(self._sync.clipboard_clear)

    # ==================== FRAME HANDLING ====================

    async def list_frames(self) -> List[Any]:
        """List all frames."""
        return await self._run(self._sync.list_frames)

    async def switch_to_frame(self, frame_selector: str) -> None:
        """Switch to an iframe."""
        await self._run(self._sync.switch_to_frame, frame_selector)

    async def switch_to_main_frame(self) -> None:
        """Switch to main frame."""
        await self._run(self._sync.switch_to_main_frame)

    # ==================== CONTENT EXTRACTION ====================

    async def extract_text(self, selector: str = "body") -> str:
        """Extract text content from the page."""
        return await self._run(self._sync.extract_text, selector)

    async def get_html(self, clean_level: Union[CleanLevel, str] = CleanLevel.BASIC) -> str:
        """Get HTML content from the page."""
        return await self._run(self._sync.get_html, clean_level)

    async def get_markdown(
        self,
        include_links: bool = True,
        include_images: bool = True,
        max_length: int = -1
    ) -> str:
        """Get page content as Markdown."""
        return await self._run(
            self._sync.get_markdown, include_links, include_images, max_length
        )

    async def extract_json(
        self,
        template: Union[ExtractionTemplate, str] = ExtractionTemplate.AUTO
    ) -> Dict[str, Any]:
        """Extract structured JSON data using templates."""
        return await self._run(self._sync.extract_json, template)

    async def detect_website_type(self) -> str:
        """Detect website type for template matching."""
        return await self._run(self._sync.detect_website_type)

    async def summarize_page(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Get intelligent, structured summary of the current page."""
        return await self._run(self._sync.summarize_page, force_refresh)

    async def list_templates(self) -> List[str]:
        """List available extraction templates."""
        return await self._run(self._sync.list_templates)

    # ==================== AI FEATURES ====================

    async def query_page(self, query: str) -> str:
        """Query the page using on-device LLM."""
        return await self._run(self._sync.query_page, query)

    async def llm_status(self) -> str:
        """Check if the on-device LLM is ready."""
        return await self._run(self._sync.llm_status)

    async def execute_nla(self, command: str) -> str:
        """Execute natural language automation command."""
        return await self._run(self._sync.execute_nla, command)

    async def ai_click(self, description: str) -> bool:
        """AI-powered click by natural language description."""
        return await self._run(self._sync.ai_click, description)

    async def ai_type(self, description: str, text: str) -> bool:
        """AI-powered type by natural language description."""
        return await self._run(self._sync.ai_type, description, text)

    async def ai_extract(self, what: str):
        """AI-powered content extraction."""
        return await self._run(self._sync.ai_extract, what)

    async def ai_query(self, query: str) -> str:
        """AI-powered page query."""
        return await self._run(self._sync.ai_query, query)

    async def ai_analyze(self):
        """AI-powered page analysis."""
        return await self._run(self._sync.ai_analyze)

    async def find_element(self, description: str, max_results: int = 10) -> List:
        """Find elements using AI/natural language description."""
        return await self._run(self._sync.find_element, description, max_results)

    # ==================== SCREENSHOT & VIDEO ====================

    async def screenshot(self, path: Optional[str] = None) -> bytes:
        """Take a screenshot."""
        return await self._run(self._sync.screenshot, path)

    async def start_video_recording(self, fps: int = 30, codec: str = "libx264") -> None:
        """Start video recording."""
        await self._run(self._sync.start_video_recording, fps, codec)

    async def pause_video_recording(self) -> None:
        """Pause video recording."""
        await self._run(self._sync.pause_video_recording)

    async def resume_video_recording(self) -> None:
        """Resume video recording."""
        await self._run(self._sync.resume_video_recording)

    async def stop_video_recording(self) -> str:
        """Stop video recording and get video path."""
        return await self._run(self._sync.stop_video_recording)

    async def get_video_stats(self) -> str:
        """Get video recording statistics."""
        return await self._run(self._sync.get_video_stats)

    # ==================== SCROLLING ====================

    async def scroll_by(self, x: int = 0, y: int = 0, verification_level: str = "none") -> None:
        """Scroll by specified pixels."""
        await self._run(self._sync.scroll_by, x, y, verification_level)

    async def scroll_to(self, x: int, y: int, verification_level: str = "none") -> None:
        """Scroll to absolute position."""
        await self._run(self._sync.scroll_to, x, y, verification_level)

    async def scroll_to_element(self, selector: str) -> None:
        """Scroll element into view."""
        await self._run(self._sync.scroll_to_element, selector)

    async def scroll_to_top(self) -> None:
        """Scroll to top of page."""
        await self._run(self._sync.scroll_to_top)

    async def scroll_to_bottom(self) -> None:
        """Scroll to bottom of page."""
        await self._run(self._sync.scroll_to_bottom)

    # ==================== WAITING ====================

    async def wait_for_selector(self, selector: str, timeout: int = 5000) -> None:
        """Wait for element to appear."""
        await self._run(self._sync.wait_for_selector, selector, timeout)

    async def wait(self, timeout: int) -> None:
        """Wait for specified time."""
        await self._run(self._sync.wait, timeout)

    async def wait_for_network_idle(
        self,
        idle_time: int = 500,
        timeout: int = 30000
    ) -> None:
        """Wait for network activity to become idle."""
        await self._run(self._sync.wait_for_network_idle, idle_time, timeout)

    async def wait_for_function(
        self,
        js_function: str,
        polling: int = 100,
        timeout: int = 30000
    ) -> None:
        """Wait for a JavaScript function to return a truthy value."""
        await self._run(self._sync.wait_for_function, js_function, polling, timeout)

    async def wait_for_url(
        self,
        url_pattern: str,
        is_regex: bool = False,
        timeout: int = 30000
    ) -> str:
        """Wait for URL to match a pattern."""
        return await self._run(self._sync.wait_for_url, url_pattern, is_regex, timeout)

    # ==================== PAGE STATE ====================

    async def get_current_url(self) -> str:
        """Get current URL."""
        return await self._run(self._sync.get_current_url)

    async def get_title(self) -> str:
        """Get page title."""
        return await self._run(self._sync.get_title)

    async def get_page_info(self) -> PageInfo:
        """Get comprehensive page information."""
        return await self._run(self._sync.get_page_info)

    # ==================== VIEWPORT ====================

    async def set_viewport(self, width: int, height: int) -> None:
        """Set viewport size."""
        await self._run(self._sync.set_viewport, width, height)

    async def get_viewport(self) -> Viewport:
        """Get current viewport size."""
        return await self._run(self._sync.get_viewport)

    # ==================== DEMOGRAPHICS ====================

    async def get_demographics(self) -> Dict[str, Any]:
        """Get user demographics and context."""
        return await self._run(self._sync.get_demographics)

    async def get_location(self) -> Dict[str, Any]:
        """Get user's current location."""
        return await self._run(self._sync.get_location)

    async def get_datetime(self) -> Dict[str, Any]:
        """Get current date and time information."""
        return await self._run(self._sync.get_datetime)

    async def get_weather(self) -> Dict[str, Any]:
        """Get current weather."""
        return await self._run(self._sync.get_weather)

    # ==================== CAPTCHA SOLVING ====================

    async def detect_captcha(self) -> Dict[str, Any]:
        """Detect if the current page has a CAPTCHA."""
        return await self._run(self._sync.detect_captcha)

    async def classify_captcha(self) -> Dict[str, Any]:
        """Classify the type of CAPTCHA on the page."""
        return await self._run(self._sync.classify_captcha)

    async def solve_text_captcha(self, max_attempts: int = 3) -> Dict[str, Any]:
        """Solve a text-based CAPTCHA."""
        return await self._run(self._sync.solve_text_captcha, max_attempts)

    async def solve_image_captcha(
        self,
        max_attempts: int = 3,
        provider: str = "auto"
    ) -> Dict[str, Any]:
        """
        Solve an image-selection CAPTCHA.

        Args:
            max_attempts: Maximum number of attempts
            provider: CAPTCHA provider to use ('auto', 'owl', 'recaptcha', 'cloudflare', 'hcaptcha')
        """
        return await self._run(self._sync.solve_image_captcha, max_attempts, provider)

    async def solve_captcha(
        self,
        max_attempts: int = 3,
        provider: str = "auto"
    ) -> Dict[str, Any]:
        """
        Auto-detect and solve any supported CAPTCHA type.

        Args:
            max_attempts: Maximum number of attempts
            provider: CAPTCHA provider to use for image CAPTCHAs ('auto', 'owl', 'recaptcha', 'cloudflare', 'hcaptcha')
        """
        return await self._run(self._sync.solve_captcha, max_attempts, provider)

    # ==================== COOKIE MANAGEMENT ====================

    async def get_cookies(self, url: Optional[str] = None) -> List[Cookie]:
        """Get all cookies from the browser context."""
        return await self._run(self._sync.get_cookies, url)

    async def set_cookie(
        self,
        url: str,
        name: str,
        value: str,
        domain: Optional[str] = None,
        path: str = "/",
        secure: bool = False,
        http_only: bool = False,
        same_site: Union[CookieSameSite, str] = CookieSameSite.LAX,
        expires: int = -1
    ) -> bool:
        """Set a cookie in the browser context."""
        return await self._run(
            self._sync.set_cookie,
            url, name, value, domain, path, secure, http_only, same_site, expires
        )

    async def delete_cookies(self, url: Optional[str] = None, name: Optional[str] = None) -> bool:
        """Delete cookies from the browser context."""
        return await self._run(self._sync.delete_cookies, url, name)

    # ==================== PROXY MANAGEMENT ====================

    async def set_proxy(self, config: ProxyConfig) -> bool:
        """Configure proxy settings for this browser context."""
        return await self._run(self._sync.set_proxy, config)

    async def get_proxy_status(self) -> ProxyStatus:
        """Get current proxy configuration and connection status."""
        return await self._run(self._sync.get_proxy_status)

    async def connect_proxy(self) -> bool:
        """Enable/connect the configured proxy."""
        return await self._run(self._sync.connect_proxy)

    async def disconnect_proxy(self) -> bool:
        """Disable/disconnect the proxy."""
        return await self._run(self._sync.disconnect_proxy)

    # ==================== TEST EXECUTION ====================

    async def run_test(
        self,
        test: Union[TestTemplate, str, Dict[str, Any]],
        continue_on_error: bool = False,
        screenshot_on_error: bool = True,
        verbose: bool = False
    ) -> TestExecutionResult:
        """Execute a test from Developer Playground JSON template."""
        return await self._run(
            self._sync.run_test, test, continue_on_error, screenshot_on_error, verbose
        )

    # ==================== NETWORK INTERCEPTION ====================

    async def add_network_rule(self, rule: Any) -> str:
        """Add network interception rule."""
        return await self._run(self._sync.add_network_rule, rule)

    async def remove_network_rule(self, rule_id: str) -> None:
        """Remove network interception rule."""
        await self._run(self._sync.remove_network_rule, rule_id)

    async def enable_network_interception(self, enable: bool) -> None:
        """Enable/disable network interception."""
        await self._run(self._sync.enable_network_interception, enable)

    async def get_network_log(self) -> List[Any]:
        """Get network log."""
        return await self._run(self._sync.get_network_log)

    async def clear_network_log(self) -> None:
        """Clear network log."""
        await self._run(self._sync.clear_network_log)

    async def enable_network_logging(self, enable: bool) -> None:
        """Enable/disable network logging."""
        await self._run(self._sync.enable_network_logging, enable)

    # ==================== FILE DOWNLOADS ====================

    async def set_download_path(self, path: str) -> None:
        """Set download directory."""
        await self._run(self._sync.set_download_path, path)

    async def get_downloads(self) -> List[Any]:
        """Get list of downloads."""
        return await self._run(self._sync.get_downloads)

    async def get_active_downloads(self) -> List[Any]:
        """Get list of active downloads."""
        return await self._run(self._sync.get_active_downloads)

    async def wait_for_download(
        self,
        download_id: Optional[str] = None,
        timeout: int = 30000
    ) -> Any:
        """Wait for download completion."""
        return await self._run(self._sync.wait_for_download, download_id, timeout)

    async def cancel_download(self, download_id: str) -> None:
        """Cancel a download."""
        await self._run(self._sync.cancel_download, download_id)

    # ==================== DIALOG HANDLING ====================

    async def set_dialog_action(
        self,
        dialog_type: Union[str, Any],
        action: Union[str, Any],
        prompt_text: Optional[str] = None
    ) -> None:
        """Configure dialog handling."""
        await self._run(self._sync.set_dialog_action, dialog_type, action, prompt_text)

    async def get_pending_dialog(self) -> Optional[Any]:
        """Get pending dialog info."""
        return await self._run(self._sync.get_pending_dialog)

    async def get_dialogs(self) -> List[Any]:
        """Get all pending dialogs."""
        return await self._run(self._sync.get_dialogs)

    async def handle_dialog(
        self,
        dialog_id: str,
        accept: bool,
        response_text: Optional[str] = None
    ) -> None:
        """Handle a dialog."""
        await self._run(self._sync.handle_dialog, dialog_id, accept, response_text)

    async def wait_for_dialog(self, timeout: int = 5000) -> Any:
        """Wait for a dialog."""
        return await self._run(self._sync.wait_for_dialog, timeout)

    # ==================== TAB MANAGEMENT ====================

    async def new_tab(self, url: Optional[str] = None) -> Any:
        """Create a new tab."""
        return await self._run(self._sync.new_tab, url)

    async def get_tabs(self) -> List[Any]:
        """Get list of tabs."""
        return await self._run(self._sync.get_tabs)

    async def switch_tab(self, tab_id: str) -> None:
        """Switch to a tab."""
        await self._run(self._sync.switch_tab, tab_id)

    async def get_active_tab(self) -> Any:
        """Get active tab."""
        return await self._run(self._sync.get_active_tab)

    async def close_tab(self, tab_id: str) -> None:
        """Close a tab."""
        await self._run(self._sync.close_tab, tab_id)

    async def get_tab_count(self) -> int:
        """Get tab count."""
        return await self._run(self._sync.get_tab_count)

    async def set_popup_policy(self, policy: Union[str, Any]) -> None:
        """Set popup policy."""
        await self._run(self._sync.set_popup_policy, policy)

    async def get_blocked_popups(self) -> List[str]:
        """Get blocked popups."""
        return await self._run(self._sync.get_blocked_popups)

    # ==================== LIVE STREAMING ====================

    async def start_live_stream(self, fps: int = 15, quality: int = 75) -> None:
        """Start live stream."""
        await self._run(self._sync.start_live_stream, fps, quality)

    async def stop_live_stream(self) -> None:
        """Stop live stream."""
        await self._run(self._sync.stop_live_stream)

    async def get_live_stream_stats(self) -> Any:
        """Get live stream stats."""
        return await self._run(self._sync.get_live_stream_stats)

    async def get_live_frame(self) -> bytes:
        """Get live stream frame."""
        return await self._run(self._sync.get_live_frame)

    # ==================== ADDITIONAL METHODS ====================

    async def get_element_at_position(self, x: int, y: int) -> Any:
        """Get element at position."""
        return await self._run(self._sync.get_element_at_position, x, y)

    async def get_interactive_elements(self) -> List[Any]:
        """Get interactive elements."""
        return await self._run(self._sync.get_interactive_elements)

    async def get_blocker_stats(self) -> Any:
        """Get blocker stats."""
        return await self._run(self._sync.get_blocker_stats)

    async def load_profile(self, profile_path: str) -> None:
        """Load profile."""
        await self._run(self._sync.load_profile, profile_path)

    async def save_profile(self, profile_path: Optional[str] = None) -> Any:
        """Save profile."""
        return await self._run(self._sync.save_profile, profile_path)

    async def get_profile(self) -> Any:
        """Get profile."""
        return await self._run(self._sync.get_profile)

    async def update_profile_cookies(self) -> bool:
        """Update profile cookies."""
        return await self._run(self._sync.update_profile_cookies)

    async def get_context_info(self) -> Any:
        """Get context info."""
        return await self._run(self._sync.get_context_info)

    # ==================== ADDITIONAL METHODS ====================

    async def get_blocker_stats(self):
        """Get ad/tracker blocker statistics for this context."""
        return await self._run(self._sync.get_blocker_stats)

    async def get_active_downloads(self) -> List:
        """Get list of currently active (in-progress) downloads."""
        return await self._run(self._sync.get_active_downloads)

    async def get_dialogs(self) -> List:
        """Get all pending dialogs for this context."""
        return await self._run(self._sync.get_dialogs)

    async def enable_network_logging(self, enable: bool) -> None:
        """Enable or disable network logging for this context."""
        await self._run(self._sync.enable_network_logging, enable)

    async def get_live_frame(self) -> bytes:
        """Get a single frame from the live stream."""
        return await self._run(self._sync.get_live_frame)

    # ==================== CLEANUP ====================

    async def close(self) -> None:
        """Close this context and release resources."""
        await self._run(self._sync.close)

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - auto-close."""
        await self.close()
        return False


class AsyncBrowser:
    """
    Async Browser class for automation.

    Thread-safe and supports multiple concurrent contexts (pages).

    Supports dual mode:
    - LOCAL: Connect to local browser binary (default)
    - REMOTE: Connect to remote browser HTTP server

    Local Example:
        ```python
        from owl_browser import AsyncBrowser

        async def main():
            async with AsyncBrowser() as browser:
                page = await browser.new_page()
                await page.goto("https://example.com")
                await page.screenshot("screenshot.png")

        asyncio.run(main())
        ```

    Remote Example:
        ```python
        from owl_browser import AsyncBrowser, RemoteConfig

        async def main():
            async with AsyncBrowser(remote=RemoteConfig(
                url="http://192.168.1.100:8080",
                token="your-secret-token"
            )) as browser:
                page = await browser.new_page()
                await page.goto("https://example.com")
                await page.screenshot("screenshot.png")

        asyncio.run(main())
        ```

    Concurrent Example:
        ```python
        async def main():
            async with AsyncBrowser() as browser:
                async def scrape(url):
                    page = await browser.new_page()
                    await page.goto(url)
                    text = await page.extract_text()
                    await page.close()
                    return text

                results = await asyncio.gather(*[
                    scrape(url) for url in urls
                ])

        asyncio.run(main())
        ```
    """

    def __init__(
        self,
        browser_path: Optional[str] = None,
        headless: bool = True,
        verbose: bool = False,
        init_timeout: int = 30000,
        max_workers: int = 10,
        remote: Optional[RemoteConfig] = None
    ):
        """
        Initialize the AsyncBrowser.

        Args:
            browser_path: Path to browser binary (auto-detected if not provided, ignored for remote mode)
            headless: Enable headless mode (default: True, ignored for remote mode)
            verbose: Enable verbose logging (default: False)
            init_timeout: Initialization timeout in milliseconds (default: 30000)
            max_workers: Maximum thread pool workers for async operations
            remote: Remote server configuration. If provided, connects to a remote
                   browser server instead of launching a local browser process.
        """
        self._sync_browser = SyncBrowser(
            browser_path=browser_path,
            headless=headless,
            verbose=verbose,
            init_timeout=init_timeout,
            remote=remote
        )
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="owl_async"
        )
        self._contexts: Dict[ContextId, AsyncBrowserContext] = {}

    @property
    def mode(self) -> ConnectionMode:
        """Get the connection mode (LOCAL or REMOTE)."""
        return self._sync_browser.mode

    @property
    def is_remote(self) -> bool:
        """Check if running in remote mode."""
        return self._sync_browser.is_remote

    async def _run(self, func, *args, **kwargs) -> Any:
        """Run a sync function in the thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: func(*args, **kwargs)
        )

    async def launch(self) -> "AsyncBrowser":
        """
        Launch the browser process.

        Returns:
            self for method chaining
        """
        await self._run(self._sync_browser.launch)
        return self

    async def new_page(
        self,
        proxy: Optional[ProxyConfig] = None,
        llm: Optional[LLMConfig] = None
    ) -> AsyncBrowserContext:
        """
        Create a new page (browser context).

        Args:
            proxy: Optional proxy configuration
            llm: Optional LLM configuration

        Returns:
            New AsyncBrowserContext instance
        """
        sync_context = await self._run(self._sync_browser.new_page, proxy, llm)
        async_context = AsyncBrowserContext(sync_context, self._executor)
        self._contexts[sync_context.id] = async_context
        return async_context

    def pages(self) -> List[AsyncBrowserContext]:
        """Get all active pages (contexts)."""
        return list(self._contexts.values())

    async def list_contexts(self) -> List[str]:
        """List all active context IDs from the browser."""
        return await self._run(self._sync_browser.list_contexts)

    async def get_llm_status(self) -> LLMStatus:
        """Check if on-device LLM is ready."""
        return await self._run(self._sync_browser.get_llm_status)

    async def list_templates(self) -> List[str]:
        """List available extraction templates."""
        return await self._run(self._sync_browser.list_templates)

    async def get_demographics(self) -> Dict[str, Any]:
        """Get complete demographics information."""
        return await self._run(self._sync_browser.get_demographics)

    async def get_location(self) -> Dict[str, Any]:
        """Get geographic location information."""
        return await self._run(self._sync_browser.get_location)

    async def get_datetime(self) -> Dict[str, Any]:
        """Get current date and time information."""
        return await self._run(self._sync_browser.get_datetime)

    async def get_weather(self) -> Dict[str, Any]:
        """Get current weather."""
        return await self._run(self._sync_browser.get_weather)

    async def get_homepage(self) -> str:
        """Get the custom browser homepage HTML."""
        return await self._run(self._sync_browser.get_homepage)

    async def close(self) -> None:
        """Close all contexts and shutdown browser."""
        await self._run(self._sync_browser.close)
        self._contexts.clear()
        self._executor.shutdown(wait=False)

    def is_running(self) -> bool:
        """Check if browser is running."""
        return self._sync_browser.is_running()

    async def __aenter__(self) -> "AsyncBrowser":
        """Async context manager entry - auto-launch."""
        if not self._sync_browser.is_running():
            await self.launch()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - auto-close."""
        await self.close()
        return False


# Convenience async functions
async def async_screenshot(url: str, path: str = "screenshot.png") -> bytes:
    """
    Async utility to take a screenshot of a URL.

    Example:
        ```python
        await async_screenshot("https://example.com", "example.png")
        ```
    """
    async with AsyncBrowser() as browser:
        page = await browser.new_page()
        await page.goto(url)
        return await page.screenshot(path)


async def async_extract(url: str, selector: str = "body") -> str:
    """
    Async utility to extract text from a URL.

    Example:
        ```python
        text = await async_extract("https://example.com", "main article")
        ```
    """
    async with AsyncBrowser() as browser:
        page = await browser.new_page()
        await page.goto(url)
        return await page.extract_text(selector)


async def async_query(url: str, query: str) -> str:
    """
    Async utility to query a page using LLM.

    Example:
        ```python
        answer = await async_query("https://news.com", "What is the top headline?")
        ```
    """
    async with AsyncBrowser() as browser:
        page = await browser.new_page()
        await page.goto(url)
        return await page.query_page(query)
