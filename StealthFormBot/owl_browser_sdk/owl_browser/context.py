"""
Browser context (page) for automation.

Each context is an isolated browser tab/window with its own cookies,
storage, and session state.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from concurrent.futures import Future

from .core import BrowserCore
from .types import (
    ContextId,
    Viewport,
    PageInfo,
    CleanLevel,
    MarkdownOptions,
    VideoRecordingOptions,
    ScreenshotOptions,
    WaitOptions,
    KeyName,
    ExtractionTemplate,
    Cookie,
    SetCookieOptions,
    CookieSameSite,
    ProxyConfig,
    ProxyStatus,
    ProxyType,
    TestTemplate,
    TestStep,
    TestExecutionOptions,
    TestExecutionResult,
    TestError,
    BrowserProfile,
    BrowserFingerprint,
    ContextInfo,
    VMProfile,
    CanvasInfo,
    AudioInfo,
    GPUInfo,
    LLMConfig,
    CaptchaProvider,
    NetworkRule,
    NetworkLogEntry,
    NetworkAction,
    DownloadInfo,
    DownloadStatus,
    DialogType,
    DialogAction,
    DialogInfo,
    PopupPolicy,
    TabInfo,
    BoundingBox,
    FrameInfo,
    ModifierKey,
    FoundElement,
    AIExtractionResult,
    AIAnalysisResult,
    BlockerStats,
)


class BrowserContext:
    """
    Browser context (tab/window) for automation.

    Provides methods for navigation, interaction, content extraction,
    AI features, and more. Thread-safe for concurrent usage.

    Example:
        ```python
        page = await browser.new_page()
        await page.goto("https://example.com")
        await page.click("search button")
        await page.type("search input", "hello world")
        screenshot = await page.screenshot()
        await page.close()
        ```
    """

    def __init__(self, context_id: ContextId, core: BrowserCore):
        self._context_id = context_id
        self._core = core

    @property
    def id(self) -> ContextId:
        """Get the context ID."""
        return self._context_id

    def _cmd(self, method: str, **kwargs) -> Any:
        """Send a command with context_id."""
        params = {"context_id": self._context_id, **kwargs}
        return self._core.send_command(method, params)

    # ==================== NAVIGATION ====================

    def goto(self, url: str, wait_until: str = "load", timeout: int = 30000) -> None:
        """
        Navigate to a URL.

        Args:
            url: URL to navigate to (https:// added automatically if missing)
            wait_until: Wait condition ('load', 'domcontentloaded', 'networkidle')
            timeout: Timeout in milliseconds

        Example:
            ```python
            page.goto("https://example.com")
            page.goto("example.com")  # Auto-adds https://
            page.goto("owl://user_form.html")  # Custom schemes preserved
            ```
        """
        # Auto-add protocol if missing (but preserve custom schemes like owl://, about:, data:)
        if "://" not in url and not url.startswith(("about:", "data:")):
            url = "https://" + url

        self._cmd("navigate", url=url, wait_until=wait_until, timeout=timeout)

    def reload(
        self,
        ignore_cache: bool = False,
        wait_until: str = "load",
        timeout: int = 30000
    ) -> None:
        """
        Reload the current page.

        Args:
            ignore_cache: If True, bypass cache (hard reload)
            wait_until: Wait condition ('load', 'domcontentloaded', 'networkidle', '' to skip)
            timeout: Timeout in milliseconds
        """
        self._cmd("reload", ignore_cache=ignore_cache, wait_until=wait_until, timeout=timeout)

    def go_back(self, wait_until: str = "load", timeout: int = 30000) -> None:
        """
        Navigate back in history.

        Args:
            wait_until: Wait condition ('load', 'domcontentloaded', 'networkidle', '' to skip)
            timeout: Timeout in milliseconds
        """
        self._cmd("goBack", wait_until=wait_until, timeout=timeout)

    def go_forward(self, wait_until: str = "load", timeout: int = 30000) -> None:
        """
        Navigate forward in history.

        Args:
            wait_until: Wait condition ('load', 'domcontentloaded', 'networkidle', '' to skip)
            timeout: Timeout in milliseconds
        """
        self._cmd("goForward", wait_until=wait_until, timeout=timeout)

    def can_go_back(self) -> bool:
        """
        Check if navigation back is possible.

        Returns:
            True if can go back
        """
        return self._cmd("canGoBack")

    def can_go_forward(self) -> bool:
        """
        Check if navigation forward is possible.

        Returns:
            True if can go forward
        """
        return self._cmd("canGoForward")

    # ==================== INTERACTIONS ====================

    def click(self, selector: str) -> None:
        """
        Click an element.

        Args:
            selector: CSS selector, coordinates (e.g., "100x200"),
                     or natural language description (e.g., "search button", "login link")

        Example:
            ```python
            page.click("#submit")  # CSS selector
            page.click("100x200")  # Coordinates
            page.click("search button")  # Natural language
            page.click("the blue login button")  # Semantic description
            ```
        """
        self._cmd("click", selector=selector)

    def type(self, selector: str, text: str) -> None:
        """
        Type text into an input field.

        Args:
            selector: CSS selector, coordinates, or natural language description
            text: Text to type

        Example:
            ```python
            page.type("#email", "user@example.com")
            page.type("email input", "user@example.com")  # Natural language
            ```
        """
        self._cmd("type", selector=selector, text=text)

    def pick(self, selector: str, value: str) -> None:
        """
        Select an option from a dropdown/select element.

        Supports both native select elements and custom dropdowns (like select2).

        Args:
            selector: CSS selector or natural language description
            value: Value or visible text of the option to select

        Example:
            ```python
            page.pick("#country", "United States")
            page.pick("country dropdown", "Morocco")  # Natural language
            ```
        """
        self._cmd("pick", selector=selector, value=value)

    def press_key(self, key: Union[KeyName, str]) -> None:
        """
        Press a special key.

        Args:
            key: Key name (Enter, Tab, Escape, ArrowUp, ArrowDown, etc.)

        Example:
            ```python
            page.press_key(KeyName.ENTER)
            page.press_key("Tab")
            page.press_key(KeyName.ESCAPE)
            ```
        """
        key_value = key.value if isinstance(key, KeyName) else key
        self._cmd("pressKey", key=key_value)

    def submit_form(self) -> None:
        """
        Submit the currently focused form by pressing Enter.

        Useful for search boxes and forms that submit on Enter.
        """
        self._cmd("submitForm")

    def highlight(
        self,
        selector: str,
        border_color: str = "#FF0000",
        background_color: str = "rgba(255, 0, 0, 0.2)"
    ) -> None:
        """
        Highlight an element for debugging.

        Args:
            selector: CSS selector or natural language description
            border_color: Border color (CSS color)
            background_color: Background color (CSS color with alpha)

        Example:
            ```python
            page.highlight("submit button")
            page.highlight("#login", border_color="#00FF00")
            ```
        """
        self._cmd(
            "highlight",
            selector=selector,
            border_color=border_color,
            background_color=background_color
        )

    def show_grid_overlay(
        self,
        horizontal_lines: int = 25,
        vertical_lines: int = 25,
        line_color: str = "rgba(255, 0, 0, 0.15)",
        text_color: str = "rgba(255, 0, 0, 0.4)"
    ) -> None:
        """
        Show a grid overlay on top of the web page with XY position coordinates at intersections.

        Useful for debugging and understanding element positions.

        Args:
            horizontal_lines: Number of horizontal lines (top to bottom). Default: 25
            vertical_lines: Number of vertical lines (left to right). Default: 25
            line_color: Line color with opacity (CSS color). Default: "rgba(255, 0, 0, 0.15)"
            text_color: Coordinate label text color (CSS color). Default: "rgba(255, 0, 0, 0.4)"

        Example:
            ```python
            # Show default grid overlay (25x25 lines)
            page.show_grid_overlay()

            # Show custom grid with 10 lines and blue color
            page.show_grid_overlay(10, 10, "rgba(0, 0, 255, 0.2)", "rgba(0, 0, 255, 0.5)")
            ```
        """
        self._cmd(
            "showGridOverlay",
            horizontal_lines=horizontal_lines,
            vertical_lines=vertical_lines,
            line_color=line_color,
            text_color=text_color
        )

    # ==================== DRAG AND DROP ====================

    def drag_drop(
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

        Example:
            ```python
            # Simple drag from point A to point B
            page.drag_drop(100, 200, 300, 200)

            # Drag through waypoints (for drawing or complex paths)
            page.drag_drop(100, 100, 100, 300, [
                [150, 150],
                [200, 200],
                [150, 250]
            ])

            # Slider CAPTCHA
            page.drag_drop(slider_x, slider_y, slider_x + 200, slider_y)
            ```
        """
        self._cmd(
            "dragDrop",
            start_x=start_x,
            start_y=start_y,
            end_x=end_x,
            end_y=end_y,
            mid_points=mid_points or []
        )

    def html5_drag_drop(
        self,
        source_selector: str,
        target_selector: str
    ) -> None:
        """
        Drag and drop for HTML5 draggable elements.

        For elements with `draggable="true"` attribute. Dispatches proper HTML5
        DragEvent objects (dragstart, dragover, drop, dragend).
        Use this for reordering lists, sortable interfaces, and any elements
        using the HTML5 Drag and Drop API.

        Args:
            source_selector: CSS selector for the source element to drag
            target_selector: CSS selector for the target element to drop onto

        Example:
            ```python
            # Reorder items in a sortable list
            page.html5_drag_drop(
                '.item[data-id="3"]',
                '.item[data-id="1"]'
            )

            # Move item to a different container
            page.html5_drag_drop(
                '#source-list .item:first-child',
                '#target-list'
            )
            ```
        """
        self._cmd(
            "html5DragDrop",
            source_selector=source_selector,
            target_selector=target_selector
        )

    def mouse_move(
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
        Optionally specify stop points where the cursor pauses briefly.

        Args:
            start_x: Start X coordinate (current cursor position)
            start_y: Start Y coordinate (current cursor position)
            end_x: End X coordinate (target position)
            end_y: End Y coordinate (target position)
            steps: Number of intermediate points (0 = auto-calculate based on distance)
            stop_points: Optional list of [x, y] coordinates where cursor pauses briefly (50-150ms)

        Example:
            ```python
            # Simple mouse move
            page.mouse_move(100, 100, 500, 300)

            # Mouse move with specific steps for smoother movement
            page.mouse_move(100, 100, 500, 300, steps=50)

            # Mouse move with stop points (pauses briefly at each point)
            page.mouse_move(100, 100, 500, 300, stop_points=[
                [200, 150],
                [350, 250]
            ])
            ```
        """
        self._cmd(
            "mouseMove",
            start_x=start_x,
            start_y=start_y,
            end_x=end_x,
            end_y=end_y,
            steps=steps,
            stop_points=stop_points or []
        )

    # ==================== CONTENT EXTRACTION ====================

    def extract_text(self, selector: str = "body") -> str:
        """
        Extract text content from the page.

        Args:
            selector: CSS selector or natural language description (default: 'body')

        Returns:
            Extracted text content

        Example:
            ```python
            all_text = page.extract_text()
            article = page.extract_text("article")
            headline = page.extract_text("main headline")
            ```
        """
        return self._cmd("extractText", selector=selector)

    def get_html(self, clean_level: Union[CleanLevel, str] = CleanLevel.BASIC) -> str:
        """
        Get HTML content from the page.

        Args:
            clean_level: Cleaning level ('minimal', 'basic', 'aggressive')

        Returns:
            HTML content
        """
        level = clean_level.value if isinstance(clean_level, CleanLevel) else clean_level
        return self._cmd("getHTML", clean_level=level)

    def get_markdown(
        self,
        include_links: bool = True,
        include_images: bool = True,
        max_length: int = -1
    ) -> str:
        """
        Get page content as Markdown.

        Args:
            include_links: Include links in markdown
            include_images: Include images in markdown
            max_length: Maximum length (-1 for no limit)

        Returns:
            Markdown content
        """
        return self._cmd(
            "getMarkdown",
            include_links=include_links,
            include_images=include_images,
            max_length=max_length
        )

    # ==================== SITE EXTRACTION ====================

    def extract_site(
        self,
        url: str,
        depth: int = 2,
        max_pages: int = 5,
        follow_external: bool = False,
        output_format: str = "markdown",
        include_images: bool = True,
        include_metadata: bool = True,
        exclude_patterns: Optional[List[str]] = None,
        timeout_per_page: int = 10000
    ) -> Dict[str, Any]:
        """
        Start a multi-page site extraction job.

        Crawls links from a starting URL and extracts content.
        Returns job info for async progress tracking.

        Args:
            url: Starting URL to extract from
            depth: How many link levels to follow (default: 2)
            max_pages: Maximum number of pages to extract (default: 5)
            follow_external: Follow links to external domains (default: False)
            output_format: Output format - 'markdown', 'text', or 'json' (default: 'markdown')
            include_images: Include image URLs in output (default: True)
            include_metadata: Include title/description metadata (default: True)
            exclude_patterns: URL patterns to skip (glob patterns)
            timeout_per_page: Timeout per page in milliseconds (default: 10000)

        Returns:
            Dict with job_id for tracking

        Example:
            ```python
            job = page.extract_site("https://docs.example.com", depth=3, max_pages=10)
            job_id = job["job_id"]
            ```
        """
        return self._cmd(
            "extractSite",
            url=url,
            depth=depth,
            max_pages=max_pages,
            follow_external=follow_external,
            output_format=output_format,
            include_images=include_images,
            include_metadata=include_metadata,
            exclude_patterns=exclude_patterns or [],
            timeout_per_page=timeout_per_page
        )

    def extract_site_progress(self, job_id: str) -> Dict[str, Any]:
        """
        Get progress of a site extraction job.

        Args:
            job_id: Job ID from extract_site

        Returns:
            Dict with status, pages_completed, pages_total, current_url
        """
        return self._core.send_command("extractSiteProgress", {"job_id": job_id})

    def extract_site_result(self, job_id: str) -> Dict[str, Any]:
        """
        Get the result of a completed site extraction job.

        Args:
            job_id: Job ID from extract_site

        Returns:
            Extraction result with content and page list
        """
        return self._core.send_command("extractSiteResult", {"job_id": job_id})

    def extract_site_cancel(self, job_id: str) -> bool:
        """
        Cancel a running site extraction job.

        Args:
            job_id: Job ID to cancel

        Returns:
            True if cancelled successfully
        """
        return self._core.send_command("extractSiteCancel", {"job_id": job_id})

    def extract_site_and_wait(
        self,
        url: str,
        depth: int = 2,
        max_pages: int = 5,
        follow_external: bool = False,
        output_format: str = "markdown",
        include_images: bool = True,
        include_metadata: bool = True,
        exclude_patterns: Optional[List[str]] = None,
        timeout_per_page: int = 10000,
        poll_interval: float = 1.0
    ) -> Dict[str, Any]:
        """
        Extract site content and wait for completion.

        Convenience wrapper that handles polling internally.

        Args:
            url: Starting URL to extract from
            depth: How many link levels to follow (default: 2)
            max_pages: Maximum number of pages to extract (default: 5)
            follow_external: Follow links to external domains (default: False)
            output_format: Output format - 'markdown', 'text', or 'json'
            include_images: Include image URLs in output (default: True)
            include_metadata: Include title/description metadata (default: True)
            exclude_patterns: URL patterns to skip
            timeout_per_page: Timeout per page in milliseconds
            poll_interval: Polling interval in seconds (default: 1.0)

        Returns:
            Extraction result with content and page list

        Example:
            ```python
            result = page.extract_site_and_wait(
                "https://docs.example.com",
                depth=3,
                max_pages=10
            )
            print(result["content"])
            ```
        """
        import time

        job = self.extract_site(
            url=url,
            depth=depth,
            max_pages=max_pages,
            follow_external=follow_external,
            output_format=output_format,
            include_images=include_images,
            include_metadata=include_metadata,
            exclude_patterns=exclude_patterns,
            timeout_per_page=timeout_per_page
        )

        job_id = job["job_id"]

        while True:
            progress = self.extract_site_progress(job_id)

            if progress["status"] == "completed":
                return self.extract_site_result(job_id)

            if progress["status"] == "error":
                raise RuntimeError(f"Site extraction failed: {progress.get('error', 'Unknown error')}")

            if progress["status"] == "cancelled":
                raise RuntimeError("Site extraction was cancelled")

            time.sleep(poll_interval)

    def extract_json(
        self,
        template: Union[ExtractionTemplate, str] = ExtractionTemplate.AUTO
    ) -> Dict[str, Any]:
        """
        Extract structured JSON data using templates.

        Args:
            template: Template name or empty string for auto-detection

        Returns:
            Extracted JSON data

        Example:
            ```python
            # Auto-detect template
            data = page.extract_json()

            # Use specific template
            data = page.extract_json(ExtractionTemplate.GOOGLE_SEARCH)
            ```
        """
        template_name = template.value if isinstance(template, ExtractionTemplate) else template
        result = self._cmd("extractJSON", template_name=template_name)
        return result if isinstance(result, dict) else json.loads(result)

    def detect_website_type(self) -> str:
        """Detect website type for template matching."""
        return self._cmd("detectWebsiteType")

    def summarize_page(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get intelligent, structured summary of the current page using LLM.

        The summary is cached per URL for fast repeat access.

        Args:
            force_refresh: Force refresh the summary (ignore cache)

        Returns:
            Structured page summary
        """
        result = self._cmd("summarizePage", force_refresh=force_refresh)
        return result if isinstance(result, dict) else json.loads(result) if result else {}

    def list_templates(self) -> List[str]:
        """List available extraction templates."""
        return self._core.list_templates()

    # ==================== AI FEATURES ====================

    def query_page(self, query: str) -> str:
        """
        Query the page using on-device LLM.

        Args:
            query: Natural language question about the page

        Returns:
            Answer from the LLM

        Example:
            ```python
            answer = page.query_page("What is the main topic of this page?")
            prices = page.query_page("Extract all prices mentioned")
            ```
        """
        return self._cmd("queryPage", query=query)

    def llm_status(self) -> str:
        """
        Check if the on-device LLM is ready to use.

        Returns:
            Status: "ready", "loading", or "unavailable"
        """
        return self._cmd("llmStatus")

    def execute_nla(self, command: str) -> str:
        """
        Execute natural language automation command.

        The LLM will plan and execute multi-step browser actions automatically.

        Args:
            command: Natural language command

        Returns:
            Execution result

        Example:
            ```python
            page.execute_nla("go to google.com and search for banana")
            page.execute_nla("click the first search result")
            page.execute_nla("fill out the contact form with test data")
            ```
        """
        return self._cmd("executeNLA", query=command)

    def ai_click(self, description: str) -> bool:
        """
        AI-powered click by natural language description.

        Args:
            description: Natural language description of the element to click

        Returns:
            True if element was found and clicked

        Example:
            ```python
            page.ai_click("search button")
            page.ai_click("the login link at the top")
            ```
        """
        return self._cmd("aiClick", description=description)

    def ai_type(self, description: str, text: str) -> bool:
        """
        AI-powered type by natural language description.

        Args:
            description: Natural language description of the input element
            text: Text to type

        Returns:
            True if element was found and text was typed

        Example:
            ```python
            page.ai_type("search box", "hello world")
            page.ai_type("email input", "user@example.com")
            ```
        """
        return self._cmd("aiType", description=description, text=text)

    def ai_extract(self, what: str) -> AIExtractionResult:
        """
        AI-powered content extraction.

        Args:
            what: Description of what to extract

        Returns:
            AIExtractionResult with extracted content

        Example:
            ```python
            prices = page.ai_extract("all product prices")
            headline = page.ai_extract("main headline")
            ```
        """
        result = self._cmd("aiExtract", what=what)
        if isinstance(result, dict):
            return AIExtractionResult(
                content=result.get("content", ""),
                confidence=result.get("confidence", 0.0)
            )
        return AIExtractionResult(content=str(result) if result else "")

    def ai_query(self, query: str) -> str:
        """
        AI-powered page query.

        Args:
            query: Natural language question about the page

        Returns:
            Answer to the query

        Example:
            ```python
            answer = page.ai_query("What is the price of the product?")
            has_login = page.ai_query("Is there a login button?")
            ```
        """
        return self._cmd("aiQuery", query=query)

    def ai_analyze(self) -> AIAnalysisResult:
        """
        AI-powered page analysis.

        Returns comprehensive analysis of the page including topic,
        structure, and key elements.

        Returns:
            AIAnalysisResult with page analysis

        Example:
            ```python
            analysis = page.ai_analyze()
            print(f"Page topic: {analysis.topic}")
            print(f"Main elements: {analysis.elements}")
            ```
        """
        result = self._cmd("aiAnalyze")
        if isinstance(result, dict):
            return AIAnalysisResult(
                topic=result.get("topic"),
                main_content=result.get("main_content"),
                elements=result.get("elements", []),
                structure=result.get("structure")
            )
        return AIAnalysisResult()

    def find_element(self, description: str, max_results: int = 10) -> List[FoundElement]:
        """
        Find elements using AI/natural language description.

        Args:
            description: Natural language description of elements to find
            max_results: Maximum number of results (default: 10)

        Returns:
            List of found elements with confidence scores

        Example:
            ```python
            buttons = page.find_element("all buttons", 5)
            inputs = page.find_element("form inputs")
            ```
        """
        result = self._cmd("findElement", description=description, max_results=max_results)
        if not result:
            return []
        if isinstance(result, str):
            result = json.loads(result)
        return [
            FoundElement(
                selector=el.get("selector", ""),
                confidence=el.get("confidence", 0.0),
                tag=el.get("tag", ""),
                text=el.get("text"),
                x=el.get("bounds", {}).get("x", 0),
                y=el.get("bounds", {}).get("y", 0),
                width=el.get("bounds", {}).get("width", 0),
                height=el.get("bounds", {}).get("height", 0)
            )
            for el in result
        ]

    # ==================== SCREENSHOT & VIDEO ====================

    def screenshot(
        self,
        path: Optional[str] = None,
        mode: Optional[str] = None,
        selector: Optional[str] = None,
        scale: Optional[int] = None
    ) -> bytes:
        """
        Take a screenshot.

        Args:
            path: Optional file path to save the screenshot
            mode: Screenshot mode - 'viewport' (default), 'element', or 'fullpage'
            selector: CSS selector or natural language description for element mode
            scale: Scale percentage (1-100). Default is 100 (no scaling). Example: 50 returns 50% size

        Returns:
            PNG image data as bytes

        Example:
            ```python
            # Get viewport screenshot as bytes
            png_data = page.screenshot()

            # Save to file
            page.screenshot("screenshot.png")

            # Element screenshot
            png_data = page.screenshot(mode="element", selector="div.profile")

            # Full page screenshot
            page.screenshot("fullpage.png", mode="fullpage")

            # Scaled screenshot (50% size)
            png_data = page.screenshot(scale=50)
            ```
        """
        import base64

        # Build command kwargs
        kwargs = {}
        if mode and mode != 'viewport':
            kwargs['mode'] = mode
        if mode == 'element':
            if not selector:
                raise ValueError("Element screenshot mode requires a selector")
            kwargs['selector'] = selector
        if scale is not None and scale != 100:
            kwargs['scale'] = scale

        result = self._cmd("screenshot", **kwargs)
        png_data = base64.b64decode(result) if isinstance(result, str) else result

        if path:
            Path(path).write_bytes(png_data)

        return png_data

    def start_video_recording(self, fps: int = 30, codec: str = "libx264") -> None:
        """
        Start video recording.

        Args:
            fps: Frames per second (default: 30)
            codec: Video codec (default: "libx264")
        """
        self._cmd("startVideoRecording", fps=fps, codec=codec)

    def pause_video_recording(self) -> None:
        """Pause video recording without stopping it."""
        self._cmd("pauseVideoRecording")

    def resume_video_recording(self) -> None:
        """Resume a paused video recording."""
        self._cmd("resumeVideoRecording")

    def stop_video_recording(self) -> str:
        """
        Stop video recording and get video path.

        Returns:
            Path to the saved video file
        """
        return self._cmd("stopVideoRecording")

    def get_video_stats(self) -> str:
        """Get video recording statistics."""
        return self._cmd("getVideoRecordingStats")

    # ==================== SCROLLING ====================

    def scroll_by(self, x: int = 0, y: int = 0, verification_level: str = "none") -> None:
        """
        Scroll by specified pixels.

        Args:
            x: Horizontal scroll amount
            y: Vertical scroll amount
            verification_level: Verification level - "none", "basic", "standard", or "strict"
        """
        self._cmd("scrollBy", x=x, y=y, verification_level=verification_level)

    def scroll_to(self, x: int, y: int, verification_level: str = "none") -> None:
        """
        Scroll to absolute position.

        Args:
            x: Horizontal position
            y: Vertical position
            verification_level: Verification level - "none", "basic", "standard", or "strict"
        """
        self._cmd("scrollTo", x=x, y=y, verification_level=verification_level)

    def scroll_to_element(self, selector: str) -> None:
        """
        Scroll element into view.

        Args:
            selector: CSS selector or natural language description
        """
        self._cmd("scrollToElement", selector=selector)

    def scroll_to_top(self) -> None:
        """Scroll to top of page."""
        self._cmd("scrollToTop")

    def scroll_to_bottom(self) -> None:
        """Scroll to bottom of page."""
        self._cmd("scrollToBottom")

    # ==================== WAITING ====================

    def wait_for_selector(self, selector: str, timeout: int = 5000) -> None:
        """
        Wait for element to appear.

        Args:
            selector: CSS selector or natural language description
            timeout: Timeout in milliseconds

        Raises:
            RuntimeError: If element not found within timeout
        """
        self._cmd("waitForSelector", selector=selector, timeout=timeout)

    def wait(self, timeout: int) -> None:
        """
        Wait for specified time (use wait_for_selector when possible).

        Args:
            timeout: Time to wait in milliseconds
        """
        self._cmd("waitForTimeout", timeout=timeout)

    def wait_for_network_idle(
        self,
        idle_time: int = 500,
        timeout: int = 30000
    ) -> None:
        """
        Wait for network activity to become idle.

        Args:
            idle_time: Duration of no network activity in milliseconds (default: 500)
            timeout: Timeout in milliseconds (default: 30000)

        Raises:
            RuntimeError: If network does not become idle within timeout
        """
        self._cmd("waitForNetworkIdle", idle_time=idle_time, timeout=timeout)

    def wait_for_function(
        self,
        js_function: str,
        polling: int = 100,
        timeout: int = 30000
    ) -> None:
        """
        Wait for a JavaScript function to return a truthy value.

        Args:
            js_function: JavaScript function body that returns truthy when condition is met
                        (e.g., "return document.querySelector('.loaded') !== null")
            polling: Polling interval in milliseconds (default: 100)
            timeout: Timeout in milliseconds (default: 30000)

        Raises:
            RuntimeError: If function does not return truthy within timeout
        """
        self._cmd(
            "waitForFunction",
            js_function=js_function,
            polling=polling,
            timeout=timeout
        )

    def wait_for_url(
        self,
        url_pattern: str,
        is_regex: bool = False,
        timeout: int = 30000
    ) -> str:
        """
        Wait for URL to match a pattern.

        Args:
            url_pattern: URL pattern to match (substring or glob pattern with * and ?)
            is_regex: Use glob-style pattern matching (default: False for substring match)
            timeout: Timeout in milliseconds (default: 30000)

        Returns:
            The current URL after match

        Raises:
            RuntimeError: If URL does not match pattern within timeout
        """
        self._cmd(
            "waitForURL",
            url_pattern=url_pattern,
            is_regex=is_regex,
            timeout=timeout
        )
        return self.get_current_url()

    # ==================== PAGE STATE ====================

    def get_current_url(self) -> str:
        """Get current URL."""
        return self._cmd("getCurrentURL")

    def get_title(self) -> str:
        """Get page title."""
        return self._cmd("getPageTitle")

    def get_page_info(self) -> PageInfo:
        """Get comprehensive page information."""
        result = self._cmd("getPageInfo")
        if isinstance(result, dict):
            return PageInfo(
                url=result.get("url", ""),
                title=result.get("title", ""),
                can_go_back=result.get("canGoBack", False),
                can_go_forward=result.get("canGoForward", False),
            )
        return PageInfo(url="", title="")

    # ==================== VIEWPORT ====================

    def set_viewport(self, width: int, height: int) -> None:
        """
        Set viewport size.

        Args:
            width: Viewport width in pixels
            height: Viewport height in pixels
        """
        self._cmd("setViewport", width=width, height=height)

    def get_viewport(self) -> Viewport:
        """Get current viewport size."""
        result = self._cmd("getViewport")
        if isinstance(result, dict):
            return Viewport(
                width=result.get("width", 1280),
                height=result.get("height", 720)
            )
        return Viewport(width=1280, height=720)

    # ==================== DOM ZOOM ====================

    def zoom_in(self) -> int:
        """
        Zoom in the page content by 10%.

        Returns:
            Current zoom level percentage
        """
        return self._cmd("zoomIn")

    def zoom_out(self) -> int:
        """
        Zoom out the page content by 10%.

        Returns:
            Current zoom level percentage
        """
        return self._cmd("zoomOut")

    def zoom_reset(self) -> None:
        """Reset page zoom to 100% (default)."""
        self._cmd("zoomReset")

    # ==================== CONSOLE LOGS ====================

    def get_console_logs(
        self,
        level: Optional[str] = None,
        filter: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get console logs from the browser.

        Args:
            level: Filter by log level ('debug', 'info', 'warn', 'error', 'verbose')
            filter: Filter logs containing specific text
            limit: Maximum number of log entries to return

        Returns:
            List of console log entries
        """
        params: Dict[str, Any] = {}
        if level is not None:
            params["level"] = level
        if filter is not None:
            params["filter"] = filter
        if limit is not None:
            params["limit"] = limit
        return self._cmd("getConsoleLogs", **params)

    def clear_console_logs(self) -> None:
        """Clear all console logs from the browser."""
        self._cmd("clearConsoleLogs")

    # ==================== DEMOGRAPHICS ====================

    def get_demographics(self) -> Dict[str, Any]:
        """
        Get user demographics and context (location, time, weather).

        Useful for location-aware searches like "find me a restaurant".
        """
        return self._core.get_demographics()

    def get_location(self) -> Dict[str, Any]:
        """Get user's current location based on IP address."""
        return self._core.get_location()

    def get_datetime(self) -> Dict[str, Any]:
        """Get current date and time information."""
        return self._core.get_datetime()

    def get_weather(self) -> Dict[str, Any]:
        """Get current weather for the user's location."""
        return self._core.get_weather()

    # ==================== CAPTCHA SOLVING ====================

    def detect_captcha(self) -> Dict[str, Any]:
        """
        Detect if the current page has a CAPTCHA.

        Returns:
            Detection result with confidence score
        """
        result = self._cmd("detectCaptcha")
        return result if isinstance(result, dict) else json.loads(result) if result else {}

    def classify_captcha(self) -> Dict[str, Any]:
        """
        Classify the type of CAPTCHA on the page.

        Returns:
            Classification result with CAPTCHA type and element selectors
        """
        result = self._cmd("classifyCaptcha")
        return result if isinstance(result, dict) else json.loads(result) if result else {}

    def solve_text_captcha(self, max_attempts: int = 3) -> Dict[str, Any]:
        """
        Solve a text-based CAPTCHA using vision model.

        Args:
            max_attempts: Maximum number of attempts

        Returns:
            Solve result with success status and extracted text
        """
        result = self._cmd("solveTextCaptcha", max_attempts=max_attempts)
        return result if isinstance(result, dict) else json.loads(result) if result else {}

    def solve_image_captcha(
        self,
        max_attempts: int = 3,
        provider: Union[CaptchaProvider, str] = CaptchaProvider.AUTO
    ) -> Dict[str, Any]:
        """
        Solve an image-selection CAPTCHA (e.g., "select all traffic lights").

        Args:
            max_attempts: Maximum number of attempts
            provider: CAPTCHA provider to use ('auto', 'owl', 'recaptcha', 'cloudflare', 'hcaptcha')

        Returns:
            Solve result with success status and provider used

        Example:
            ```python
            # Auto-detect provider
            result = page.solve_image_captcha()

            # Use specific provider
            result = page.solve_image_captcha(provider=CaptchaProvider.RECAPTCHA)

            # With max attempts
            result = page.solve_image_captcha(max_attempts=5, provider="cloudflare")
            ```
        """
        provider_value = provider.value if isinstance(provider, CaptchaProvider) else provider
        result = self._cmd("solveImageCaptcha", max_attempts=max_attempts, provider=provider_value)
        return result if isinstance(result, dict) else json.loads(result) if result else {}

    def solve_captcha(
        self,
        max_attempts: int = 3,
        provider: Union[CaptchaProvider, str] = CaptchaProvider.AUTO
    ) -> Dict[str, Any]:
        """
        Auto-detect and solve any supported CAPTCHA type.

        Args:
            max_attempts: Maximum number of attempts
            provider: CAPTCHA provider to use for image CAPTCHAs ('auto', 'owl', 'recaptcha', 'cloudflare', 'hcaptcha')

        Returns:
            Solve result with success status

        Example:
            ```python
            # Auto-detect everything
            result = page.solve_captcha()

            # Use specific provider for image CAPTCHAs
            result = page.solve_captcha(provider=CaptchaProvider.RECAPTCHA)

            # With max attempts
            result = page.solve_captcha(max_attempts=5)
            ```
        """
        provider_value = provider.value if isinstance(provider, CaptchaProvider) else provider
        result = self._cmd("solveCaptcha", max_attempts=max_attempts, provider=provider_value)
        return result if isinstance(result, dict) else json.loads(result) if result else {}

    # ==================== COOKIE MANAGEMENT ====================

    def get_cookies(self, url: Optional[str] = None) -> List[Cookie]:
        """
        Get all cookies from the browser context.

        Args:
            url: Optional URL to filter cookies

        Returns:
            List of cookies

        Example:
            ```python
            all_cookies = page.get_cookies()
            site_cookies = page.get_cookies("https://example.com")
            ```
        """
        result = self._cmd("getCookies", url=url or "")
        if not result:
            return []

        cookies = result if isinstance(result, list) else json.loads(result)
        return [
            Cookie(
                name=c.get("name", ""),
                value=c.get("value", ""),
                domain=c.get("domain", ""),
                path=c.get("path", "/"),
                secure=c.get("secure", False),
                http_only=c.get("httpOnly", False),
                same_site=CookieSameSite(c.get("sameSite", "lax")),
                expires=c.get("expires", -1),
            )
            for c in cookies
        ]

    def set_cookie(
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
        """
        Set a cookie in the browser context.

        Args:
            url: URL to associate with the cookie
            name: Cookie name
            value: Cookie value
            domain: Cookie domain (optional)
            path: Cookie path (default: "/")
            secure: Whether cookie should only be sent over HTTPS
            http_only: Whether cookie is inaccessible to JavaScript
            same_site: SameSite attribute ('none', 'lax', 'strict')
            expires: Unix timestamp for expiration (-1 for session cookie)

        Returns:
            True if cookie was set successfully

        Example:
            ```python
            page.set_cookie("https://example.com", "session", "abc123")
            page.set_cookie(
                "https://example.com",
                "prefs",
                "dark-mode",
                secure=True,
                http_only=True,
                expires=int(time.time()) + 86400  # 1 day
            )
            ```
        """
        same_site_value = same_site.value if isinstance(same_site, CookieSameSite) else same_site
        return self._cmd(
            "setCookie",
            url=url,
            name=name,
            value=value,
            domain=domain or "",
            path=path,
            secure=secure,
            httpOnly=http_only,
            sameSite=same_site_value,
            expires=expires,
        )

    def delete_cookies(self, url: Optional[str] = None, name: Optional[str] = None) -> bool:
        """
        Delete cookies from the browser context.

        Args:
            url: Optional URL to filter which cookies to delete
            name: Optional specific cookie name to delete

        Returns:
            True if cookies were deleted successfully

        Example:
            ```python
            page.delete_cookies()  # Delete all
            page.delete_cookies("https://example.com")  # Delete for URL
            page.delete_cookies("https://example.com", "session")  # Delete specific
            ```
        """
        return self._cmd("deleteCookies", url=url or "", cookie_name=name or "")

    # ==================== PROXY MANAGEMENT ====================

    def set_proxy(self, config: ProxyConfig) -> bool:
        """
        Configure proxy settings for this browser context.

        Includes stealth features to prevent proxy/VPN detection.

        Args:
            config: Proxy configuration

        Returns:
            True if proxy was configured successfully

        Example:
            ```python
            page.set_proxy(ProxyConfig(
                type=ProxyType.SOCKS5H,
                host="proxy.example.com",
                port=1080,
                username="user",
                password="pass",
                stealth=True,
                timezone_override="America/New_York"
            ))
            ```
        """
        return self._cmd(
            "setProxy",
            type=config.type.value,
            host=config.host,
            port=config.port,
            username=config.username or "",
            password=config.password or "",
            stealth=config.stealth,
            block_webrtc=config.block_webrtc,
            spoof_timezone=config.spoof_timezone,
            spoof_language=config.spoof_language,
            timezone_override=config.timezone_override or "",
            language_override=config.language_override or "",
        )

    def get_proxy_status(self) -> ProxyStatus:
        """
        Get current proxy configuration and connection status.

        Returns:
            Proxy status object
        """
        result = self._cmd("getProxyStatus")
        if isinstance(result, dict):
            return ProxyStatus(
                enabled=result.get("enabled", False),
                connected=result.get("connected", False),
                type=ProxyType(result["type"]) if result.get("type") else None,
                host=result.get("host"),
                port=result.get("port"),
                stealth=result.get("stealth"),
                block_webrtc=result.get("blockWebrtc"),
            )
        return ProxyStatus(enabled=False, connected=False)

    def connect_proxy(self) -> bool:
        """Enable/connect the configured proxy."""
        return self._cmd("connectProxy")

    def disconnect_proxy(self) -> bool:
        """Disable/disconnect the proxy, reverting to direct connection."""
        return self._cmd("disconnectProxy")

    # ==================== BROWSER PROFILE MANAGEMENT ====================

    def save_profile(self, profile_name: str) -> BrowserProfile:
        """
        Save the current context state to a browser profile.

        The profile includes fingerprints, cookies, and configuration settings.
        This enables persistent browser identities across sessions.

        Args:
            profile_name: Name for the saved profile file (without path or extension).
                The .json extension is added automatically.
                The returned filename can be used with download_profile.

        Returns:
            BrowserProfile object with the saved state

        Example:
            ```python
            # Save profile with a name
            profile = page.save_profile("shopping_account")
            print(f"Saved profile: {profile.profile_id}")
            print(f"Cookies: {len(profile.cookies)}")
            ```
        """
        result = self._cmd("saveProfile", profile_name=profile_name)
        return self._parse_profile(result)

    def download_profile(self, profile_name: str) -> bytes:
        """
        Download a saved profile as base64-encoded content.

        Args:
            profile_name: Name of the profile file to download (as returned by save_profile).
                Example: 'shopping_account.json'

        Returns:
            Profile content as bytes (base64-decoded)

        Example:
            ```python
            # Save and download profile
            profile = page.save_profile("my_profile")
            content = page.download_profile("my_profile.json")
            with open("my_profile.json", "wb") as f:
                f.write(content)
            ```
        """
        import base64
        result = self._cmd("downloadProfile", profile_name=profile_name)
        return base64.b64decode(result) if isinstance(result, str) else result

    def get_profile(self) -> BrowserProfile:
        """
        Get the current profile state for this context.

        Returns the in-memory profile state without saving to disk.

        Returns:
            BrowserProfile object with current state

        Example:
            ```python
            profile = page.get_profile()
            print(f"User Agent: {profile.fingerprint.user_agent}")
            print(f"Cookies: {len(profile.cookies)}")
            ```
        """
        result = self._cmd("getProfile")
        return self._parse_profile(result)

    def update_profile_cookies(self) -> bool:
        """
        Update the profile file with current cookies from the browser.

        This is useful when you want to persist cookie changes without
        saving the entire profile state.

        Returns:
            True if cookies were updated successfully

        Example:
            ```python
            # After logging in
            page.goto("https://example.com/login")
            page.type("email input", "user@example.com")
            page.type("password input", "password")
            page.click("login button")

            # Save the session cookies
            page.update_profile_cookies()
            ```
        """
        return self._cmd("updateProfileCookies")

    def get_context_info(self) -> "ContextInfo":
        """
        Get context information including VM profile and fingerprint hashes.

        Returns detailed information about the browser context's stealth configuration
        including the VM profile being used and all fingerprint hash values (canvas,
        audio, GPU).

        Returns:
            ContextInfo object with VM profile and fingerprint hashes

        Example:
            ```python
            info = page.get_context_info()
            print(f"VM ID: {info.vm_profile.vm_id}")
            print(f"Canvas hash seed: {info.canvas.hash_seed}")
            print(f"GPU profile: {info.gpu.webgl_renderer}")
            ```
        """
        result = self._cmd("getContextInfo")
        return self._parse_context_info(result)

    def _parse_context_info(self, data: Any) -> "ContextInfo":
        """Parse context info data from command result."""
        if isinstance(data, str):
            data = json.loads(data)

        if not isinstance(data, dict):
            return ContextInfo(
                context_id=self.context_id,
                vm_profile=VMProfile(),
                canvas=CanvasInfo(),
                audio=AudioInfo(),
                gpu=GPUInfo(),
                has_profile=False,
            )

        vm_data = data.get("vm_profile", {})
        canvas_data = data.get("canvas", {})
        audio_data = data.get("audio", {})
        gpu_data = data.get("gpu", {})

        return ContextInfo(
            context_id=data.get("context_id", self.context_id),
            vm_profile=VMProfile(
                vm_id=vm_data.get("vm_id", ""),
                platform=vm_data.get("platform", ""),
                user_agent=vm_data.get("user_agent", ""),
                hardware_concurrency=vm_data.get("hardware_concurrency", 0),
                device_memory=vm_data.get("device_memory", 0),
                screen_width=vm_data.get("screen_width", 0),
                screen_height=vm_data.get("screen_height", 0),
                timezone=vm_data.get("timezone", ""),
                locale=vm_data.get("locale", ""),
            ),
            canvas=CanvasInfo(
                hash_seed=canvas_data.get("hash_seed", 0),
                noise_seed=canvas_data.get("noise_seed", 0.0),
            ),
            audio=AudioInfo(
                noise_seed=audio_data.get("noise_seed", 0.0),
            ),
            gpu=GPUInfo(
                profile_index=gpu_data.get("profile_index", 0),
                webgl_vendor=gpu_data.get("webgl_vendor", ""),
                webgl_renderer=gpu_data.get("webgl_renderer", ""),
            ),
            has_profile=data.get("has_profile", False),
            profile_path=data.get("profile_path"),
        )

    def _parse_profile(self, data: Any) -> BrowserProfile:
        """Parse profile data from command result."""
        if isinstance(data, str):
            data = json.loads(data)

        if not isinstance(data, dict):
            return BrowserProfile()

        # Parse fingerprint
        fingerprint = None
        fp_data = data.get("fingerprint", {})
        if fp_data:
            fingerprint = BrowserFingerprint(
                user_agent=fp_data.get("user_agent", ""),
                platform=fp_data.get("platform", "Win32"),
                vendor=fp_data.get("vendor", "Google Inc."),
                languages=fp_data.get("languages", ["en-US", "en"]),
                hardware_concurrency=fp_data.get("hardware_concurrency", 8),
                device_memory=fp_data.get("device_memory", 8),
                max_touch_points=fp_data.get("max_touch_points", 0),
                canvas_noise_seed=fp_data.get("canvas_noise_seed", 0.0),
                gpu_profile_index=fp_data.get("gpu_profile_index", 0),
                webgl_vendor=fp_data.get("webgl_vendor", ""),
                webgl_renderer=fp_data.get("webgl_renderer", ""),
                screen_width=fp_data.get("screen_width", 1920),
                screen_height=fp_data.get("screen_height", 1080),
                color_depth=fp_data.get("color_depth", 24),
                pixel_ratio=fp_data.get("pixel_ratio", 1),
                timezone=fp_data.get("timezone", ""),
                locale=fp_data.get("locale", "en-US"),
                audio_noise_seed=fp_data.get("audio_noise_seed", 0.0),
                installed_fonts=fp_data.get("installed_fonts", []),
                has_pdf_plugin=fp_data.get("has_pdf_plugin", True),
                has_chrome_pdf=fp_data.get("has_chrome_pdf", True),
            )

        # Parse cookies
        cookies = []
        for c in data.get("cookies", []):
            cookies.append(Cookie(
                name=c.get("name", ""),
                value=c.get("value", ""),
                domain=c.get("domain", ""),
                path=c.get("path", "/"),
                secure=c.get("secure", False),
                http_only=c.get("httpOnly", False),
                same_site=CookieSameSite(c.get("sameSite", "lax")),
                expires=c.get("expires", -1),
            ))

        # Parse LLM config
        llm_config = None
        llm_data = data.get("llm_config", {})
        if data.get("has_llm_config") and llm_data:
            llm_config = LLMConfig(
                enabled=llm_data.get("enabled", True),
                use_builtin=llm_data.get("use_builtin", True),
                endpoint=llm_data.get("external_endpoint"),
                model=llm_data.get("external_model"),
            )

        # Parse proxy config
        proxy_config = None
        proxy_data = data.get("proxy_config", {})
        if data.get("has_proxy_config") and proxy_data:
            proxy_config = ProxyConfig(
                type=ProxyType(proxy_data.get("type", "http")),
                host=proxy_data.get("host", ""),
                port=proxy_data.get("port", 0),
                username=proxy_data.get("username"),
                password=proxy_data.get("password"),
            )

        return BrowserProfile(
            profile_id=data.get("profile_id", ""),
            profile_name=data.get("profile_name", ""),
            created_at=data.get("created_at", ""),
            modified_at=data.get("modified_at", ""),
            version=data.get("version", 1),
            fingerprint=fingerprint,
            cookies=cookies,
            has_llm_config=data.get("has_llm_config", False),
            llm_config=llm_config,
            has_proxy_config=data.get("has_proxy_config", False),
            proxy_config=proxy_config,
            auto_save_cookies=data.get("auto_save_cookies", True),
            persist_local_storage=data.get("persist_local_storage", True),
        )

    # ==================== TEST EXECUTION ====================

    def run_test(
        self,
        test: Union[TestTemplate, str, Dict[str, Any]],
        continue_on_error: bool = False,
        screenshot_on_error: bool = True,
        verbose: bool = False
    ) -> TestExecutionResult:
        """
        Execute a test from Developer Playground JSON template.

        Args:
            test: Test template (TestTemplate, dict, or file path)
            continue_on_error: Continue execution after errors
            screenshot_on_error: Take screenshot on error
            verbose: Enable verbose logging

        Returns:
            Test execution result

        Example:
            ```python
            # Load test from JSON file
            result = page.run_test("test.json")

            # Define test inline
            result = page.run_test({
                "name": "Login Test",
                "steps": [
                    {"type": "navigate", "url": "https://example.com/login"},
                    {"type": "type", "selector": "#email", "text": "user@example.com"},
                    {"type": "click", "selector": "button[type='submit']"},
                ]
            })

            print(f"Success: {result.successful_steps}/{result.total_steps}")
            ```
        """
        # Parse test if string (file path) or dict
        if isinstance(test, str):
            test_data = json.loads(Path(test).read_text())
        elif isinstance(test, dict):
            test_data = test
        else:
            test_data = {
                "name": test.name,
                "description": test.description,
                "steps": [
                    {
                        "type": s.type,
                        "selected": s.selected,
                        "url": s.url,
                        "selector": s.selector,
                        "text": s.text,
                        "value": s.value,
                        "duration": s.duration,
                        "filename": s.filename,
                        "query": s.query,
                        "command": s.command,
                        "fps": s.fps,
                    }
                    for s in test.steps
                ]
            }

        # Filter selected steps
        steps = [s for s in test_data.get("steps", []) if s.get("selected", True)]

        result = TestExecutionResult(
            test_name=test_data.get("name", "Unnamed Test"),
            total_steps=len(steps),
            executed_steps=0,
            successful_steps=0,
            failed_steps=0,
            execution_time=0,
            success=True,
            errors=[]
        )

        start_time = time.time()

        if verbose:
            print(f"[Test] Starting: {result.test_name}")
            if test_data.get("description"):
                print(f"[Test] Description: {test_data['description']}")

        for i, step in enumerate(steps):
            result.executed_steps += 1
            step_type = step.get("type", "")

            if verbose:
                print(f"[Test] Step {i + 1}/{result.total_steps}: {step_type}")

            try:
                self._execute_step(step)
                result.successful_steps += 1
                if verbose:
                    print(f"[Test] Step {i + 1}: Success")

            except Exception as e:
                result.failed_steps += 1
                result.success = False
                error_msg = str(e)
                result.errors.append(TestError(step=i + 1, type=step_type, message=error_msg))

                print(f"[Test] Step {i + 1} failed: {error_msg}")

                if screenshot_on_error:
                    try:
                        error_screenshot = f"error-step-{i + 1}.png"
                        self.screenshot(error_screenshot)
                        print(f"[Test] Error screenshot saved: {error_screenshot}")
                    except Exception:
                        pass

                if not continue_on_error:
                    print("[Test] Stopping execution due to error")
                    break

        result.execution_time = (time.time() - start_time) * 1000

        if verbose:
            print(f"[Test] Completed: {result.test_name}")
            print(f"[Test] Time: {result.execution_time:.0f}ms")
            print(f"[Test] Success: {result.successful_steps}/{result.total_steps}")
            if result.failed_steps > 0:
                print(f"[Test] Failed: {result.failed_steps}")

        return result

    def _execute_step(self, step: Dict[str, Any]) -> None:
        """Execute a single test step.

        Supports all step types from the flow designer including browser_ prefixed
        names (e.g., browser_click) and simple names (e.g., click).
        """
        raw_type = step.get("type", "")
        # Normalize step type (remove browser_ prefix if present)
        step_type = raw_type.replace("browser_", "") if raw_type.startswith("browser_") else raw_type

        # Get params from step.params or directly from step
        p = step.get("params", step)

        # Helper to get value from step or params
        def get(key: str, default: Any = None) -> Any:
            return step.get(key) or p.get(key) or default

        # ==================== NAVIGATION ====================
        if step_type == "navigate":
            self.goto(get("url"))

        elif step_type == "reload":
            self.reload(get("ignore_cache", False))

        elif step_type == "go_back":
            self.go_back()

        elif step_type == "go_forward":
            self.go_forward()

        # ==================== INTERACTION ====================
        elif step_type == "click":
            self.click(get("selector"))

        elif step_type == "type":
            self.type(get("selector"), get("text"))

        elif step_type == "pick":
            self.pick(get("selector"), get("value"))

        elif step_type == "submit_form":
            self.submit_form()

        elif step_type == "press_key":
            self.press_key(get("key"))

        elif step_type == "drag_drop":
            self.drag_drop(
                get("start_x"),
                get("start_y"),
                get("end_x"),
                get("end_y"),
                get("mid_points")
            )

        elif step_type == "html5_drag_drop":
            self.html5_drag_drop(
                get("source_selector"),
                get("target_selector")
            )

        elif step_type == "mouse_move":
            self.mouse_move(
                get("start_x"),
                get("start_y"),
                get("end_x"),
                get("end_y"),
                steps=get("steps"),
                stop_points=get("stop_points")
            )

        elif step_type == "hover":
            self.hover(get("selector"))

        elif step_type == "double_click":
            self.double_click(get("selector"))

        elif step_type == "right_click":
            self.right_click(get("selector"))

        elif step_type == "clear_input":
            self.clear_input(get("selector"))

        elif step_type == "focus":
            self.focus(get("selector"))

        elif step_type == "blur":
            self.blur(get("selector"))

        elif step_type == "select_all":
            self.select_all(get("selector"))

        elif step_type == "keyboard_combo":
            self.keyboard_combo(get("combo"))

        elif step_type == "upload_file":
            self.upload_file(get("selector"), get("file_paths", []))

        # ==================== ELEMENT STATE ====================
        elif step_type == "is_visible":
            self.is_visible(get("selector"))

        elif step_type == "is_enabled":
            self.is_enabled(get("selector"))

        elif step_type == "is_checked":
            self.is_checked(get("selector"))

        elif step_type == "get_attribute":
            self.get_attribute(get("selector"), get("attribute"))

        elif step_type == "get_bounding_box":
            self.get_bounding_box(get("selector"))

        # ==================== JAVASCRIPT ====================
        elif step_type == "evaluate":
            self.evaluate(get("script"))

        # ==================== FRAMES ====================
        elif step_type == "list_frames":
            self.list_frames()

        elif step_type == "switch_to_frame":
            self.switch_to_frame(get("frame_selector"))

        elif step_type == "switch_to_main_frame":
            self.switch_to_main_frame()

        # ==================== SCROLLING ====================
        elif step_type == "scroll_up":
            self.scroll_by(0, -(get("y") or 500))

        elif step_type == "scroll_down":
            self.scroll_by(0, get("y") or 500)

        elif step_type == "scroll_to_top":
            self.scroll_to_top()

        elif step_type == "scroll_to_bottom":
            self.scroll_to_bottom()

        elif step_type == "scroll_by":
            self.scroll_by(get("x", 0), get("y", 0))

        elif step_type == "scroll_to_element":
            self.scroll_to_element(get("selector"))

        # ==================== WAITING ====================
        elif step_type == "wait":
            self.wait(get("duration") or get("timeout") or 2000)

        elif step_type == "wait_for_selector":
            self.wait_for_selector(get("selector"), timeout=get("timeout", 5000))

        elif step_type == "wait_for_network_idle":
            self.wait_for_network_idle(
                timeout=get("timeout", 30000),
                idle_time=get("idle_time", 500)
            )

        elif step_type == "wait_for_function":
            self.wait_for_function(
                get("js_function"),
                timeout=get("timeout", 30000)
            )

        elif step_type == "wait_for_url":
            self.wait_for_url(
                get("url_pattern"),
                timeout=get("timeout", 30000),
                is_regex=get("is_regex", False)
            )

        # ==================== EXTRACTION ====================
        elif step_type in ("extract", "extract_text"):
            self.extract_text(get("selector", "body"))

        elif step_type == "get_html":
            self.get_html(get("clean_level", "basic"))

        elif step_type == "get_markdown":
            self.get_markdown(
                include_links=get("include_links", True),
                include_images=get("include_images", True),
                max_length=get("max_length", -1)
            )

        elif step_type == "extract_json":
            self.extract_json(get("template", ""))

        elif step_type == "get_page_info":
            self.get_page_info()

        # ==================== AI FEATURES ====================
        elif step_type in ("query", "query_page"):
            self.query_page(get("query"))

        elif step_type == "summarize_page":
            self.summarize_page(get("force_refresh", False))

        elif step_type == "nla":
            self.execute_nla(get("command"))

        # ==================== CAPTCHA ====================
        elif step_type == "detect_captcha":
            self.detect_captcha()

        elif step_type == "classify_captcha":
            self.classify_captcha()

        elif step_type == "solve_captcha":
            max_attempts = get("max_attempts", 3)
            provider = get("provider")
            if provider:
                self.solve_captcha(provider=provider, max_attempts=max_attempts)
            else:
                self.solve_captcha(max_attempts=max_attempts)

        # ==================== COOKIES ====================
        elif step_type == "get_cookies":
            self.get_cookies(get("url"))

        elif step_type == "set_cookie":
            self.set_cookie(
                url=get("url"),
                name=get("name"),
                value=get("cookie_value") or get("value"),
                domain=get("domain"),
                path=get("path", "/"),
                secure=get("secure", False),
                http_only=get("http_only", False),
                same_site=get("same_site", "lax"),
                expires=get("expires", -1)
            )

        elif step_type == "delete_cookies":
            self.delete_cookies(get("url"), get("name"))

        # ==================== VISUAL ====================
        elif step_type == "screenshot":
            self.screenshot(
                path=get("filename", "screenshot.png"),
                mode=get("mode"),
                selector=get("selector")
            )

        elif step_type == "highlight":
            self.highlight(get("selector"))

        elif step_type == "set_viewport":
            self.set_viewport(get("width"), get("height"))

        # ==================== VIDEO ====================
        elif step_type in ("record_video", "start_video_recording"):
            self.start_video_recording(
                fps=get("fps", 30),
                codec=get("codec", "libx264")
            )

        elif step_type in ("stop_video", "stop_video_recording"):
            self.stop_video_recording()

        # ==================== NETWORK ====================
        elif step_type == "add_network_rule":
            from .types import NetworkRule, NetworkAction
            rule = NetworkRule(
                url_pattern=get("url_pattern"),
                action=NetworkAction(get("action")),
                is_regex=get("is_regex", False)
            )
            self.add_network_rule(rule)

        elif step_type == "remove_network_rule":
            self.remove_network_rule(get("rule_id"))

        elif step_type == "enable_network_interception":
            self.enable_network_interception(get("enable", True))

        elif step_type == "get_network_log":
            self.get_network_log()

        elif step_type == "clear_network_log":
            self.clear_network_log()

        # ==================== DOWNLOADS ====================
        elif step_type == "set_download_path":
            self.set_download_path(get("download_path") or get("path"))

        elif step_type == "get_downloads":
            self.get_downloads()

        elif step_type == "wait_for_download":
            self.wait_for_download(get("download_id"), timeout=get("timeout", 30000))

        elif step_type == "cancel_download":
            self.cancel_download(get("download_id"))

        # ==================== DIALOGS ====================
        elif step_type == "set_dialog_action":
            from .types import DialogType, DialogAction
            self.set_dialog_action(
                DialogType(get("dialog_type")),
                DialogAction(get("dialog_action") or get("action")),
                get("prompt_text")
            )

        elif step_type == "get_pending_dialog":
            self.get_pending_dialog()

        elif step_type == "handle_dialog":
            self.handle_dialog(
                get("dialog_id"),
                get("accept"),
                get("response_text")
            )

        elif step_type == "wait_for_dialog":
            self.wait_for_dialog(get("timeout", 5000))

        # ==================== TABS ====================
        elif step_type == "new_tab":
            self.new_tab(get("url"))

        elif step_type == "get_tabs":
            self.get_tabs()

        elif step_type == "switch_tab":
            self.switch_tab(get("tab_id"))

        elif step_type == "get_active_tab":
            self.get_active_tab()

        elif step_type == "close_tab":
            self.close_tab(get("tab_id"))

        elif step_type == "get_tab_count":
            self.get_tab_count()

        elif step_type == "set_popup_policy":
            from .types import PopupPolicy
            self.set_popup_policy(PopupPolicy(get("policy")))

        elif step_type == "get_blocked_popups":
            self.get_blocked_popups()

        else:
            raise ValueError(f"Unknown step type: {raw_type}")

    # ==================== NETWORK INTERCEPTION ====================

    def add_network_rule(self, rule: NetworkRule) -> str:
        """
        Add a network interception rule.

        Args:
            rule: Network rule configuration

        Returns:
            Rule ID

        Example:
            ```python
            # Block ads
            rule_id = page.add_network_rule(NetworkRule(
                url_pattern='*://ads.example.com/*',
                action=NetworkAction.BLOCK
            ))

            # Mock API response
            rule_id = page.add_network_rule(NetworkRule(
                url_pattern='*/api/data',
                action=NetworkAction.MOCK,
                mock_body='{"status": "ok"}',
                mock_status=200,
                mock_content_type='application/json'
            ))

            # Redirect requests
            rule_id = page.add_network_rule(NetworkRule(
                url_pattern='*://old-api.example.com/*',
                action=NetworkAction.REDIRECT,
                redirect_url='https://new-api.example.com/'
            ))
            ```
        """
        return self._cmd(
            "addNetworkRule",
            url_pattern=rule.url_pattern,
            action=rule.action.value if isinstance(rule.action, NetworkAction) else rule.action,
            is_regex=rule.is_regex,
            redirect_url=rule.redirect_url or "",
            mock_body=rule.mock_body or "",
            mock_status=rule.mock_status,
            mock_content_type=rule.mock_content_type or "",
        )

    def remove_network_rule(self, rule_id: str) -> None:
        """
        Remove a network interception rule.

        Args:
            rule_id: Rule ID to remove
        """
        # This tool doesn't require context_id - only rule_id
        self._core.send_command("removeNetworkRule", {"rule_id": rule_id})

    def set_network_interception(self, enabled: bool) -> None:
        """
        Enable or disable network interception.

        Args:
            enabled: Whether to enable interception
        """
        self._cmd("enableNetworkInterception", enabled=enabled)

    def get_network_log(self) -> List[NetworkLogEntry]:
        """
        Get the network request log.

        Returns:
            List of network log entries
        """
        result = self._cmd("getNetworkLog")
        if not result:
            return []

        # Handle various response formats from server
        if isinstance(result, list):
            entries = result
        elif isinstance(result, dict):
            # Server may return {"entries": [...]} or similar
            entries = result.get("entries", result.get("log", []))
            if not isinstance(entries, list):
                entries = []
        elif isinstance(result, str):
            entries = json.loads(result)
        else:
            return []

        return [
            NetworkLogEntry(
                url=e.get("url", ""),
                method=e.get("method", ""),
                status=e.get("status", 0),
                timestamp=e.get("timestamp", 0),
                intercepted=e.get("intercepted", False),
            )
            for e in entries
        ]

    def clear_network_log(self) -> None:
        """Clear the network request log."""
        self._cmd("clearNetworkLog")

    def enable_network_interception(self, enable: bool) -> None:
        """
        Enable or disable network interception for this context.

        Args:
            enable: True to enable, False to disable

        Example:
            ```python
            # Enable interception
            page.enable_network_interception(True)

            # Add rules and monitor traffic
            page.add_network_rule(NetworkRule(url_pattern="*://ads.*", action=NetworkAction.BLOCK))

            # Disable when done
            page.enable_network_interception(False)
            ```
        """
        self._cmd("enableNetworkInterception", enable=enable)

    def enable_network_logging(self, enable: bool) -> None:
        """
        Enable or disable network logging for this context.

        When enabled, all network requests are captured in the network log.

        Args:
            enable: True to enable, False to disable

        Example:
            ```python
            # Enable logging
            page.enable_network_logging(True)

            # Navigate and perform actions
            page.goto("https://example.com")

            # Get the log
            log = page.get_network_log()
            print(f"Captured {len(log)} requests")
            ```
        """
        self._cmd("enableNetworkLogging", enable=enable)

    # ==================== FILE DOWNLOADS ====================

    def set_download_path(self, path: str) -> None:
        """
        Set the download directory for file downloads.

        Args:
            path: Directory path for downloads

        Example:
            ```python
            page.set_download_path('/tmp/downloads')
            page.click('a[download]')  # Click download link
            downloads = page.get_downloads()
            ```
        """
        self._cmd("setDownloadPath", path=path)

    def get_downloads(self) -> List[DownloadInfo]:
        """
        Get list of downloads for this context.

        Returns:
            List of download information
        """
        result = self._cmd("getDownloads")
        if not result:
            return []

        downloads = result if isinstance(result, list) else json.loads(result)
        return [
            DownloadInfo(
                id=d.get("id", ""),
                url=d.get("url", ""),
                filename=d.get("filename", ""),
                path=d.get("path", ""),
                status=DownloadStatus(d.get("status", "pending")),
                bytes_received=d.get("bytes_received", 0),
                total_bytes=d.get("total_bytes", -1),
            )
            for d in downloads
        ]

    def get_active_downloads(self) -> List[DownloadInfo]:
        """
        Get list of currently active (in-progress) downloads.

        Returns:
            List of active download information
        """
        result = self._cmd("getActiveDownloads")
        if not result:
            return []

        downloads = result if isinstance(result, list) else json.loads(result)
        return [
            DownloadInfo(
                id=d.get("id", ""),
                url=d.get("url", ""),
                filename=d.get("filename", ""),
                path=d.get("path", ""),
                status=DownloadStatus(d.get("status", "in_progress")),
                bytes_received=d.get("bytes_received", 0),
                total_bytes=d.get("total_bytes", -1),
            )
            for d in downloads
        ]

    def wait_for_download(
        self,
        download_id: str,
        timeout: int = 30000
    ) -> DownloadInfo:
        """
        Wait for a download to complete.

        Args:
            download_id: Download ID to wait for (required)
            timeout: Timeout in milliseconds (default: 30000)

        Returns:
            Download information
        """
        # This tool doesn't require context_id - only download_id and timeout
        params: Dict[str, Any] = {"download_id": download_id}
        if timeout != 30000:
            params["timeout"] = timeout
        result = self._core.send_command("waitForDownload", params)
        if isinstance(result, dict):
            return DownloadInfo(
                id=result.get("id", ""),
                url=result.get("url", ""),
                filename=result.get("filename", ""),
                path=result.get("path", ""),
                status=DownloadStatus(result.get("status", "pending")),
                bytes_received=result.get("bytes_received", 0),
                total_bytes=result.get("total_bytes", -1),
            )
        return DownloadInfo(id="", url="", filename="", path="", status=DownloadStatus.FAILED, bytes_received=0, total_bytes=-1)

    def cancel_download(self, download_id: str) -> None:
        """
        Cancel a download in progress.

        Args:
            download_id: Download ID to cancel
        """
        # This tool doesn't require context_id - only download_id
        self._core.send_command("cancelDownload", {"download_id": download_id})

    # ==================== DIALOG HANDLING ====================

    def set_dialog_action(
        self,
        dialog_type: Union[DialogType, str],
        action: Union[DialogAction, str],
        prompt_text: Optional[str] = None
    ) -> None:
        """
        Configure auto-handling policy for JavaScript dialogs.

        Args:
            dialog_type: Type of dialog (alert, confirm, prompt, beforeunload)
            action: Action to take (accept, dismiss, accept_with_text)
            prompt_text: Text to enter for prompt dialogs (when action is accept_with_text)

        Example:
            ```python
            # Auto-accept all alerts
            page.set_dialog_action(DialogType.ALERT, DialogAction.ACCEPT)

            # Auto-respond to prompts
            page.set_dialog_action(
                DialogType.PROMPT,
                DialogAction.ACCEPT_WITH_TEXT,
                "My response"
            )

            # Dismiss all confirm dialogs
            page.set_dialog_action(DialogType.CONFIRM, DialogAction.DISMISS)
            ```
        """
        dialog_type_value = dialog_type.value if isinstance(dialog_type, DialogType) else dialog_type
        action_value = action.value if isinstance(action, DialogAction) else action
        self._cmd(
            "setDialogAction",
            dialog_type=dialog_type_value,
            action=action_value,
            prompt_text=prompt_text or ""
        )

    def get_pending_dialog(self) -> Optional[DialogInfo]:
        """
        Get information about a pending dialog.

        Returns:
            Dialog info or None if no dialog is pending
        """
        result = self._cmd("getPendingDialog")
        if not result:
            return None

        if isinstance(result, dict):
            return DialogInfo(
                id=result.get("id", ""),
                type=DialogType(result.get("type", "alert")),
                message=result.get("message", ""),
                default_value=result.get("default_value"),
            )
        return None

    def get_dialogs(self) -> List[DialogInfo]:
        """
        Get all pending dialogs for this context.

        Returns:
            List of dialog information
        """
        result = self._cmd("getDialogs")
        if not result:
            return []

        dialogs = result if isinstance(result, list) else json.loads(result)
        return [
            DialogInfo(
                id=d.get("id", ""),
                type=DialogType(d.get("type", "alert")),
                message=d.get("message", ""),
                default_value=d.get("default_value"),
            )
            for d in dialogs
        ]

    def handle_dialog(
        self,
        dialog_id: str,
        accept: bool,
        response_text: Optional[str] = None
    ) -> None:
        """
        Accept or dismiss a specific pending dialog.

        Args:
            dialog_id: Dialog ID from get_pending_dialog
            accept: True to accept, false to dismiss
            response_text: Text response for prompt dialogs
        """
        # This tool doesn't require context_id - only dialog_id, accept, response_text
        params: Dict[str, Any] = {
            "dialog_id": dialog_id,
            "accept": accept,
        }
        if response_text:
            params["response_text"] = response_text
        self._core.send_command("handleDialog", params)

    def wait_for_dialog(self, timeout: int = 5000) -> DialogInfo:
        """
        Wait for a dialog to appear.

        Args:
            timeout: Timeout in milliseconds (default: 5000)

        Returns:
            Dialog information
        """
        result = self._cmd("waitForDialog", timeout=timeout)
        if isinstance(result, dict):
            return DialogInfo(
                id=result.get("id", ""),
                type=DialogType(result.get("type", "alert")),
                message=result.get("message", ""),
                default_value=result.get("default_value"),
            )
        return DialogInfo(id="", type=DialogType.ALERT, message="")

    # ==================== TAB/WINDOW MANAGEMENT ====================

    def new_tab(self, url: Optional[str] = None) -> TabInfo:
        """
        Create a new tab within this context.

        Args:
            url: URL to navigate to in the new tab (optional)

        Returns:
            Tab information

        Example:
            ```python
            tab = page.new_tab('https://google.com')
            print(f"New tab ID: {tab.tab_id}")
            ```
        """
        result = self._cmd("newTab", url=url or "")
        if isinstance(result, dict):
            return TabInfo(
                tab_id=result.get("tab_id", ""),
                url=result.get("url", ""),
                title=result.get("title", ""),
                active=result.get("active", True),
            )
        return TabInfo(tab_id="", url="", title="", active=False)

    def get_tabs(self) -> List[TabInfo]:
        """
        Get list of all tabs in this context.

        Returns:
            List of tab information
        """
        result = self._cmd("getTabs")
        if not result:
            return []

        tabs = result if isinstance(result, list) else json.loads(result)
        return [
            TabInfo(
                tab_id=t.get("tab_id", ""),
                url=t.get("url", ""),
                title=t.get("title", ""),
                active=t.get("active", False),
            )
            for t in tabs
        ]

    def switch_tab(self, tab_id: str) -> None:
        """
        Switch to a specific tab.

        Args:
            tab_id: Tab ID to switch to
        """
        self._cmd("switchTab", tab_id=tab_id)

    def get_active_tab(self) -> TabInfo:
        """
        Get the currently active tab.

        Returns:
            Active tab information
        """
        result = self._cmd("getActiveTab")
        if isinstance(result, dict):
            return TabInfo(
                tab_id=result.get("tab_id", ""),
                url=result.get("url", ""),
                title=result.get("title", ""),
                active=True,
            )
        return TabInfo(tab_id="", url="", title="", active=False)

    def close_tab(self, tab_id: str) -> None:
        """
        Close a tab.

        Args:
            tab_id: Tab ID to close

        Note:
            Cannot close the last remaining tab in a context.
        """
        self._cmd("closeTab", tab_id=tab_id)

    def get_tab_count(self) -> int:
        """
        Get the number of tabs in this context.

        Returns:
            Tab count
        """
        return self._cmd("getTabCount")

    def set_popup_policy(self, policy: Union[PopupPolicy, str]) -> None:
        """
        Configure how popups are handled.

        Args:
            policy: Popup policy ('allow', 'block', 'new_tab', 'background')

        Example:
            ```python
            # Block all popups
            page.set_popup_policy(PopupPolicy.BLOCK)

            # Allow popups as new tabs
            page.set_popup_policy(PopupPolicy.NEW_TAB)
            ```
        """
        policy_value = policy.value if isinstance(policy, PopupPolicy) else policy
        self._cmd("setPopupPolicy", policy=policy_value)

    def get_blocked_popups(self) -> List[str]:
        """
        Get list of blocked popup URLs.

        Returns:
            List of blocked popup URLs
        """
        result = self._cmd("getBlockedPopups")
        if not result:
            return []
        return result if isinstance(result, list) else json.loads(result)

    # ==================== ADVANCED INTERACTIONS ====================

    def hover(self, selector: str) -> None:
        """
        Hover over an element without clicking.

        Triggers hover effects like tooltips, dropdown menus, and CSS :hover styles.
        Useful for revealing hidden content or previewing actions before clicking.

        Args:
            selector: CSS selector, coordinates (e.g., "100x200"), or semantic description

        Example:
            ```python
            # Hover to reveal dropdown menu
            page.hover("nav menu")

            # Hover to show tooltip
            page.hover(".info-icon")
            ```
        """
        self._cmd("hover", selector=selector)

    def double_click(self, selector: str) -> None:
        """
        Double-click an element.

        Args:
            selector: CSS selector, coordinates (e.g., "100x200"), or semantic description

        Example:
            ```python
            # Double-click to edit text
            page.double_click(".editable-cell")

            # Double-click with semantic selector
            page.double_click("file name")
            ```
        """
        self._cmd("doubleClick", selector=selector)

    def right_click(self, selector: str) -> None:
        """
        Right-click an element to open context menu.

        Args:
            selector: CSS selector, coordinates (e.g., "100x200"), or semantic description

        Example:
            ```python
            # Right-click to open context menu
            page.right_click(".file-item")

            # Right-click with semantic selector
            page.right_click("profile picture")
            ```
        """
        self._cmd("rightClick", selector=selector)

    def clear_input(self, selector: str) -> None:
        """
        Clear the text content of an input field.

        Args:
            selector: CSS selector or semantic description for input element

        Example:
            ```python
            # Clear existing text before typing new value
            page.clear_input("search input")
            page.type("search input", "new search term")
            ```
        """
        self._cmd("clearInput", selector=selector)

    def focus(self, selector: str) -> None:
        """
        Focus on an element (trigger focus event).

        Args:
            selector: CSS selector or semantic description

        Example:
            ```python
            # Focus input to trigger validation
            page.focus("email input")
            ```
        """
        self._cmd("focus", selector=selector)

    def blur(self, selector: str) -> None:
        """
        Remove focus from an element (trigger blur event).

        Args:
            selector: CSS selector or semantic description

        Example:
            ```python
            # Blur to trigger validation
            page.blur("email input")
            ```
        """
        self._cmd("blur", selector=selector)

    def select_all(self, selector: str) -> None:
        """
        Select all text in an input element.

        Args:
            selector: CSS selector or semantic description for input element

        Example:
            ```python
            # Select all text in input
            page.select_all("search input")
            ```
        """
        self._cmd("selectAll", selector=selector)

    def keyboard_combo(self, combo: str) -> None:
        """
        Press a keyboard combination (e.g., Ctrl+A, Ctrl+C, etc.).

        Args:
            combo: Key combination string using modifiers and keys.
                Supports Ctrl, Shift, Alt, Meta/Cmd.
                Examples: 'Ctrl+A', 'Ctrl+Shift+N', 'Meta+V', 'Shift+Enter'

        Example:
            ```python
            # Select all with Ctrl+A
            page.keyboard_combo("Ctrl+A")

            # Copy with Ctrl+C
            page.keyboard_combo("Ctrl+C")

            # Paste with Ctrl+V
            page.keyboard_combo("Ctrl+V")

            # Complex combination
            page.keyboard_combo("Ctrl+Shift+N")
            ```
        """
        self._cmd("keyboardCombo", combo=combo)

    # ==================== ELEMENT STATE CHECKS ====================

    def is_visible(self, selector: str) -> bool:
        """
        Check if an element is visible.

        Args:
            selector: CSS selector or semantic description

        Returns:
            True if element is visible

        Example:
            ```python
            if page.is_visible("login button"):
                page.click("login button")
            ```
        """
        return self._cmd("isVisible", selector=selector)

    def is_enabled(self, selector: str) -> bool:
        """
        Check if an element is enabled (not disabled).

        Args:
            selector: CSS selector or semantic description

        Returns:
            True if element is enabled

        Example:
            ```python
            if page.is_enabled("submit button"):
                page.click("submit button")
            ```
        """
        return self._cmd("isEnabled", selector=selector)

    def is_checked(self, selector: str) -> bool:
        """
        Check if a checkbox or radio button is checked.

        Args:
            selector: CSS selector or semantic description

        Returns:
            True if element is checked

        Example:
            ```python
            if not page.is_checked("agree to terms"):
                page.click("agree to terms")
            ```
        """
        return self._cmd("isChecked", selector=selector)

    def get_attribute(self, selector: str, attribute: str) -> Optional[str]:
        """
        Get an attribute value from an element.

        Args:
            selector: CSS selector or semantic description
            attribute: Attribute name to get

        Returns:
            Attribute value or None if not found

        Example:
            ```python
            href = page.get_attribute("login link", "href")
            data_id = page.get_attribute(".item", "data-id")
            ```
        """
        return self._cmd("getAttribute", selector=selector, attribute=attribute)

    def get_bounding_box(self, selector: str) -> BoundingBox:
        """
        Get the bounding box (position and size) of an element.

        Args:
            selector: CSS selector or semantic description

        Returns:
            BoundingBox with x, y, width, height

        Example:
            ```python
            box = page.get_bounding_box("search button")
            print(f"Button at ({box.x}, {box.y}), size {box.width}x{box.height}")
            ```
        """
        result = self._cmd("getBoundingBox", selector=selector)
        if isinstance(result, str):
            result = json.loads(result)
        return BoundingBox(
            x=result.get("x", 0),
            y=result.get("y", 0),
            width=result.get("width", 0),
            height=result.get("height", 0)
        )

    # ==================== JAVASCRIPT EVALUATION ====================

    def evaluate(
        self,
        script: str,
        return_value: bool = False
    ) -> Any:
        """
        Execute JavaScript code in the page context.

        Args:
            script: JavaScript code to execute
            return_value: If True, treats script as expression and returns its value

        Returns:
            Result of the script execution

        Example:
            ```python
            # Get page title (use return_value=True for expressions)
            title = page.evaluate("document.title", return_value=True)

            # Execute statement (default, no return)
            page.evaluate("window.scrollTo(0, 100)")

            # Get element count
            count = page.evaluate('document.querySelectorAll(".item").length', return_value=True)
            ```
        """
        return self._cmd("evaluate", script=script, return_value=return_value)

    def expression(self, expression: str) -> Any:
        """
        Evaluate a JavaScript expression and return its value.

        This is a shorthand for evaluate(expression, return_value=True).

        Args:
            expression: JavaScript expression to evaluate

        Returns:
            The value of the expression

        Example:
            ```python
            # Get page title
            title = page.expression("document.title")

            # Get element count
            count = page.expression('document.querySelectorAll(".item").length')

            # Get scroll position
            scroll_y = page.expression("window.scrollY")
            ```
        """
        return self._cmd("evaluate", expression=expression)

    # ==================== CLIPBOARD MANAGEMENT ====================

    def clipboard_read(self) -> Dict[str, str]:
        """
        Read text content from the system clipboard.

        Returns:
            Dict with 'text' key containing clipboard content

        Example:
            ```python
            result = page.clipboard_read()
            print(f"Clipboard: {result['text']}")
            ```
        """
        return self._cmd("clipboardRead")

    def clipboard_write(self, text: str) -> None:
        """
        Write text content to the system clipboard.

        Args:
            text: Text to write to clipboard

        Example:
            ```python
            page.clipboard_write("Hello, World!")
            # Now you can paste this text in the browser
            ```
        """
        self._cmd("clipboardWrite", text=text)

    def clipboard_clear(self) -> None:
        """
        Clear the system clipboard content.

        Example:
            ```python
            page.clipboard_clear()
            ```
        """
        self._cmd("clipboardClear")

    # ==================== FILE UPLOAD ====================

    def upload_file(self, selector: str, file_paths: List[str]) -> None:
        """
        Upload files to a file input element.

        Args:
            selector: CSS selector or semantic description for file input
            file_paths: List of absolute file paths to upload

        Example:
            ```python
            # Upload single file
            page.upload_file("file input", ["/path/to/document.pdf"])

            # Upload multiple files
            page.upload_file("file input", ["/path/to/image1.jpg", "/path/to/image2.jpg"])
            ```
        """
        self._cmd("uploadFile", selector=selector, file_paths=json.dumps(file_paths))

    # ==================== FRAME HANDLING ====================

    def list_frames(self) -> List[FrameInfo]:
        """
        List all frames (iframes) on the page.

        Returns:
            List of FrameInfo objects

        Example:
            ```python
            frames = page.list_frames()
            for frame in frames:
                print(f"Frame: {frame.name or frame.id} - {frame.url}")
            ```
        """
        result = self._cmd("listFrames")
        if isinstance(result, str):
            result = json.loads(result)
        if not result:
            return []
        return [
            FrameInfo(
                id=f.get("id", ""),
                url=f.get("url", ""),
                is_main=f.get("isMain", False),
                name=f.get("name")
            )
            for f in result
        ]

    def switch_to_frame(self, frame_selector: str) -> None:
        """
        Switch to an iframe for interaction.

        Args:
            frame_selector: CSS selector for iframe, frame name, or frame index (as string)

        Example:
            ```python
            # Switch by CSS selector
            page.switch_to_frame("iframe#payment")

            # Switch by frame name
            page.switch_to_frame("payment-frame")

            # Switch by index
            page.switch_to_frame("0")

            # Interact within the frame
            page.type("card number input", "4111111111111111")

            # Return to main frame when done
            page.switch_to_main_frame()
            ```
        """
        self._cmd("switchToFrame", frame_selector=frame_selector)

    def switch_to_main_frame(self) -> None:
        """
        Switch back to the main frame after working in an iframe.

        Example:
            ```python
            # After interacting with iframe
            page.switch_to_main_frame()
            ```
        """
        self._cmd("switchToMainFrame")

    # ==================== LIVE STREAMING ====================

    def start_live_stream(self, fps: int = 15, quality: int = 75) -> None:
        """
        Start live MJPEG video stream for this context.

        Args:
            fps: Frames per second (default: 15)
            quality: JPEG quality 1-100 (default: 75)

        Example:
            ```python
            # Start stream with default settings (15fps, 75% quality)
            page.start_live_stream()

            # Start with custom settings
            page.start_live_stream(fps=30, quality=90)
            ```
        """
        self._cmd("startLiveStream", fps=fps, quality=quality)

    def stop_live_stream(self) -> None:
        """Stop live video stream for this context."""
        self._cmd("stopLiveStream")

    def get_live_stream_stats(self) -> "LiveStreamStats":
        """
        Get live stream statistics for this context.

        Returns:
            LiveStreamStats with stream info
        """
        from .types import LiveStreamStats
        result = self._cmd("getLiveStreamStats")
        if isinstance(result, str):
            result = json.loads(result)
        return LiveStreamStats(
            active=result.get("active", False),
            fps=result.get("fps", 15),
            quality=result.get("quality", 75),
            subscribers=result.get("subscribers", 0),
            frames_sent=result.get("framesSent", 0),
            bytes_sent=result.get("bytesSent", 0)
        )

    def get_live_frame(self) -> bytes:
        """
        Get a single frame from the live stream.

        Returns the current frame as PNG image bytes.

        Returns:
            PNG image data as bytes

        Example:
            ```python
            page.start_live_stream()
            frame = page.get_live_frame()
            # Save to file
            with open("frame.png", "wb") as f:
                f.write(frame)
            ```
        """
        import base64
        result = self._cmd("getLiveFrame")
        return base64.b64decode(result) if isinstance(result, str) else result

    # ==================== ELEMENT PICKER ====================

    def get_element_at_position(self, x: int, y: int) -> "ElementAtPositionInfo":
        """
        Get element information at specific coordinates.

        Useful for UI overlays, click visualization, and element inspection.

        Args:
            x: X coordinate in pixels
            y: Y coordinate in pixels

        Returns:
            ElementAtPositionInfo with element details

        Example:
            ```python
            element = page.get_element_at_position(100, 200)
            print(f"Element: {element.tag} - {element.selector}")
            ```
        """
        from .types import ElementAtPositionInfo
        result = self._cmd("getElementAtPosition", x=x, y=y)
        if isinstance(result, str):
            result = json.loads(result)
        bounds = result.get("bounds", {})
        return ElementAtPositionInfo(
            tag=result.get("tag", ""),
            selector=result.get("selector", ""),
            text=result.get("text"),
            id=result.get("id"),
            classes=result.get("classes", []),
            x=bounds.get("x", 0),
            y=bounds.get("y", 0),
            width=bounds.get("width", 0),
            height=bounds.get("height", 0)
        )

    def get_interactive_elements(self) -> List["InteractiveElement"]:
        """
        Get all interactive elements on the page.

        Returns buttons, links, inputs, and other clickable elements.
        Useful for building UI overlays that show clickable areas.

        Returns:
            List of InteractiveElement objects

        Example:
            ```python
            elements = page.get_interactive_elements()
            for el in elements:
                print(f"{el.tag}: {el.text} at ({el.x}, {el.y})")
            ```
        """
        from .types import InteractiveElement
        result = self._cmd("getInteractiveElements")
        if isinstance(result, str):
            result = json.loads(result)
        if not result:
            return []
        elements = []
        for el in result:
            bounds = el.get("bounds", {})
            elements.append(InteractiveElement(
                tag=el.get("tag", ""),
                selector=el.get("selector", ""),
                type=el.get("type"),
                text=el.get("text"),
                role=el.get("role"),
                x=bounds.get("x", 0),
                y=bounds.get("y", 0),
                width=bounds.get("width", 0),
                height=bounds.get("height", 0),
                visible=el.get("visible", True),
                enabled=el.get("enabled", True)
            ))
        return elements

    # ==================== BLOCKER STATS ====================

    def get_blocker_stats(self) -> BlockerStats:
        """
        Get ad/tracker blocker statistics for this context.

        Shows how many ads, trackers, and analytics requests have been blocked.

        Returns:
            BlockerStats with blocking statistics

        Example:
            ```python
            stats = page.get_blocker_stats()
            print(f"Blocked: {stats.ads_blocked} ads, {stats.trackers_blocked} trackers")
            ```
        """
        result = self._cmd("getBlockerStats")
        if isinstance(result, str):
            result = json.loads(result)
        return BlockerStats(
            ads_blocked=result.get("ads_blocked", 0),
            trackers_blocked=result.get("trackers_blocked", 0),
            analytics_blocked=result.get("analytics_blocked", 0),
            total_blocked=result.get("total_blocked", 0),
            total_allowed=result.get("total_allowed", 0)
        )

    # ==================== PROFILE LOADING ====================

    def load_profile(self, profile_path: str) -> None:
        """
        Load a browser profile into this context.

        Applies fingerprint, cookies, and settings from the profile.

        Args:
            profile_path: Path to the profile JSON file

        Example:
            ```python
            page.load_profile("/path/to/profile.json")
            page.goto("https://example.com")  # Session restored
            ```
        """
        self._cmd("loadProfile", profile_path=profile_path)

    # ==================== CLEANUP ====================

    def close(self) -> None:
        """Close this context and release resources."""
        self._core.release_context(self._context_id)

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - auto-close."""
        self.close()
        return False
