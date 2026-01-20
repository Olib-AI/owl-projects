"""
Auto Test Builder for generating YAML test specifications from page analysis.

Provides:
- Automatic page crawling with depth control
- Login form detection and authentication
- Element discovery with semantic descriptions
- YAML test generation compatible with TestRunner

SDK v2 Notes:
- Uses OwlBrowser instead of Browser
- All browser operations are async and require context_id
- build() method is now async
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import structlog
import yaml

if TYPE_CHECKING:
    from owl_browser import OwlBrowser
    from autoqa.builder.intelligent_layer import (
        ElementClassifier,
        SelectorReliabilityScorer,
        PageTypeDetector,
        StepOrderingStrategy,
    )
    from autoqa.builder.discovery import IntelligentBuilder, VisibilityAnalyzer, ElementState

logger = structlog.get_logger(__name__)


def _extract_sdk_bool(result: Any, default: bool = False) -> bool:
    """Extract boolean from SDK response.

    The owl-browser SDK returns dict with 'success' field for boolean checks
    like is_visible, is_enabled, is_checked. This helper extracts the boolean.

    Args:
        result: SDK response - either dict with 'success' key or direct bool
        default: Default value if extraction fails

    Returns:
        Boolean value from SDK response
    """
    if isinstance(result, dict):
        return bool(result.get("success", default))
    if isinstance(result, bool):
        return result
    return default


class ElementType(StrEnum):
    """Types of interactable elements."""

    BUTTON = "button"
    LINK = "link"
    INPUT_TEXT = "input_text"
    INPUT_EMAIL = "input_email"
    INPUT_PASSWORD = "input_password"
    INPUT_NUMBER = "input_number"
    INPUT_SEARCH = "input_search"
    INPUT_TEL = "input_tel"
    INPUT_URL = "input_url"
    INPUT_DATE = "input_date"
    INPUT_CHECKBOX = "checkbox"
    INPUT_RADIO = "radio"
    INPUT_FILE = "file_upload"
    SELECT = "select"
    TEXTAREA = "textarea"
    FORM = "form"
    NAVIGATION = "navigation"


@dataclass
class ElementInfo:
    """Information about a discovered element."""

    element_type: ElementType
    selector: str
    semantic_description: str
    text_content: str | None = None
    placeholder: str | None = None
    name: str | None = None
    id: str | None = None
    aria_label: str | None = None
    href: str | None = None
    form_id: str | None = None
    is_required: bool = False
    is_visible: bool = True
    bounding_box: dict[str, float] | None = None
    # Intelligent layer additions
    reliability_score: float = 0.5  # 0-1, higher = more reliable selector
    fallback_selectors: list[str] = field(default_factory=list)
    element_category: str | None = None  # From ElementCategory enum
    should_generate_assertion: bool = True  # Based on reliability score
    raw_data: dict[str, Any] | None = None  # Original element data for classification
    # Additional comprehensive fields
    select_options: list[dict[str, Any]] | None = None  # Options for select elements
    label_text: str | None = None  # Associated label text
    is_checked: bool = False  # For checkboxes/radios
    is_disabled: bool = False
    is_readonly: bool = False
    max_length: int | None = None
    min_length: int | None = None
    pattern: str | None = None
    min_value: str | None = None
    max_value: str | None = None
    step: str | None = None
    # Uniqueness tracking for selector generation
    text_is_unique: bool = True  # True if element's text is unique on page
    selector_is_unique: bool = True  # True if generated selector is unique


@dataclass
class PageAnalysis:
    """Complete analysis of a page."""

    url: str
    title: str
    timestamp: datetime
    elements: list[ElementInfo] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    navigation_links: list[ElementInfo] = field(default_factory=list)
    has_login_form: bool = False
    login_form_info: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class BuilderConfig:
    """Configuration for the Auto Test Builder."""

    url: str
    username: str | None = None
    password: str | None = None
    depth: int = 2
    max_pages: int = 20
    include_hidden: bool = False
    timeout_ms: int = 10000  # Navigation timeout - 10 seconds is sufficient for most pages
    wait_after_navigation_ms: int = 0  # Deprecated - network idle is sufficient
    same_domain_only: bool = True
    exclude_patterns: list[str] = field(default_factory=list)
    include_patterns: list[str] = field(default_factory=list)
    # Intelligent layer options
    enable_intelligent_layer: bool = True  # Enable element classification and scoring
    min_selector_reliability: float = 0.2  # Lowered to capture more elements (was 0.4)
    enable_page_type_detection: bool = True  # Detect page type for strategy adjustment
    # Intelligent discovery options (NEW)
    use_intelligent_discovery: bool = False  # Use intelligent flow discovery for hidden content
    discover_modal_flows: bool = True  # Discover and test modal flows
    discover_tab_flows: bool = True  # Discover and test tab panel flows
    # Visibility-first testing with step count limits
    use_visibility_first: bool = True  # ONLY test visible elements, use flows for hidden
    max_total_steps: int = 600  # Increased for comprehensive coverage (was 100)
    max_steps_per_page: int = 60  # Max steps per page for good coverage (was 20)
    skip_redundant_assertions: bool = False  # Generate all assertions including visibility checks
    test_priority: str = "comprehensive"  # high_value, comprehensive, minimal
    # Coverage options - Increased for comprehensive testing
    max_elements_per_page: int = 100  # Maximum elements to test per page (was 30)
    max_assertions_per_page: int = 50  # Maximum assertions per page (was 15)
    max_form_inputs: int = 30  # Maximum form inputs to fill (was 10)
    generate_comprehensive_assertions: bool = True  # Enabled: generates value verification steps


class AutoTestBuilder:
    """
    Automatically builds YAML test specifications from web pages.

    Features:
    - Crawls pages to specified depth
    - Detects and handles login forms
    - Catalogs all interactable elements
    - Generates semantic selectors for owl-browser
    - Produces complete, runnable YAML test specs
    - PAGE-SCOPED ASSERTIONS: Only asserts elements on the page they belong to
    """

    # Login form detection patterns
    LOGIN_INDICATORS: frozenset[str] = frozenset({
        "login",
        "signin",
        "sign-in",
        "sign_in",
        "log-in",
        "log_in",
        "authenticate",
        "auth",
    })

    USERNAME_INDICATORS: frozenset[str] = frozenset({
        "username",
        "user",
        "email",
        "login",
        "userid",
        "user_id",
        "user-id",
        "account",
    })

    PASSWORD_INDICATORS: frozenset[str] = frozenset({
        "password",
        "passwd",
        "pass",
        "pwd",
        "secret",
    })

    # Patterns for detecting shared navigation elements
    # These selectors indicate elements that likely appear on multiple pages
    SHARED_ELEMENT_PATTERNS: frozenset[str] = frozenset({
        "nav-item",
        "nav-link",
        "navbar",
        "sidebar",
        "header",
        "footer",
        "logo",
        "menu-item",
        "main-nav",
        "top-nav",
        "side-nav",
    })

    def __init__(
        self,
        browser: OwlBrowser,
        config: BuilderConfig,
    ) -> None:
        self._browser = browser
        self._config = config
        self._log = logger.bind(component="auto_test_builder")
        self._visited_urls: set[str] = set()
        self._page_analyses: list[PageAnalysis] = []
        self._base_domain: str = urlparse(config.url).netloc
        # Store login form info captured during authentication
        self._captured_login_info: dict[str, Any] | None = None
        # Track elements seen across pages for shared element detection
        # Key: selector, Value: set of page URLs where element was found
        self._element_page_map: dict[str, set[str]] = {}
        # FIX 4: Track seen text values to avoid non-unique text= selectors
        self._seen_text_selectors: dict[str, int] = {}  # text -> count
        # FIX 3: Track total step count across all pages
        self._total_step_count: int = 0

        # Initialize intelligent layer components if enabled
        self._element_classifier: ElementClassifier | None = None
        self._selector_scorer: SelectorReliabilityScorer | None = None
        self._page_type_detector: PageTypeDetector | None = None
        self._step_ordering: StepOrderingStrategy | None = None

        if config.enable_intelligent_layer:
            from autoqa.builder.intelligent_layer import (
                ElementClassifier,
                SelectorReliabilityScorer,
                PageTypeDetector,
                StepOrderingStrategy,
            )
            self._element_classifier = ElementClassifier()
            self._selector_scorer = SelectorReliabilityScorer()
            self._page_type_detector = PageTypeDetector()
            self._step_ordering = StepOrderingStrategy()

        # Initialize intelligent discovery builder if enabled
        self._intelligent_builder: IntelligentBuilder | None = None
        if config.use_intelligent_discovery:
            from autoqa.builder.discovery import IntelligentBuilder
            self._intelligent_builder = IntelligentBuilder()

        # FIX 1: Initialize visibility analyzer for visibility-first testing
        self._visibility_analyzer: "VisibilityAnalyzer | None" = None
        if config.use_visibility_first:
            from autoqa.builder.discovery import VisibilityAnalyzer
            self._visibility_analyzer = VisibilityAnalyzer()

    async def build(self) -> str:
        """
        Build a complete YAML test specification.

        SDK v2 Notes:
            - Async method
            - Creates and manages its own context
            - Uses navigate instead of goto

        Returns:
            YAML string containing the test specification
        """
        self._log.info(
            "Starting test build",
            url=self._config.url,
            depth=self._config.depth,
        )

        # Create a new context for the build
        ctx = await self._browser.create_context()
        context_id = ctx["context_id"]

        try:
            # Navigate to initial URL
            await self._navigate_with_wait(context_id, self._config.url)

            # Handle authentication if credentials provided
            start_url = self._config.url
            if self._config.username and self._config.password:
                auth_success = await self._handle_authentication(context_id)
                if auth_success:
                    # After login, get the current URL (may have redirected)
                    page_info = await self._browser.get_page_info(context_id=context_id)
                    if isinstance(page_info, dict) and page_info.get("url"):
                        start_url = page_info["url"]
                        self._log.info("Starting crawl from post-login URL", url=start_url)

            # Crawl and analyze pages starting from the current URL
            await self._crawl_pages(context_id, start_url, depth=0)

            # Generate YAML spec
            yaml_content = self._generate_yaml_spec()

            self._log.info(
                "Test build complete",
                pages_analyzed=len(self._page_analyses),
                total_elements=sum(len(p.elements) for p in self._page_analyses),
            )

            return yaml_content

        finally:
            await self._browser.close_context(context_id=context_id)

    async def _navigate_with_wait(self, context_id: str, url: str) -> None:
        """Navigate to URL and wait for stability."""
        # Use domcontentloaded instead of load for faster navigation
        # domcontentloaded fires when HTML is parsed, before images/styles finish
        await self._browser.navigate(
            context_id=context_id,
            url=url,
            wait_until="domcontentloaded",
            timeout=self._config.timeout_ms,
        )
        # Short network idle wait to ensure key resources are loaded
        with contextlib.suppress(Exception):
            await self._browser.wait_for_network_idle(
                context_id=context_id,
                idle_time=200,
                timeout=2000,
            )

    async def _handle_authentication(self, context_id: str) -> bool:
        """
        Detect and fill login form if present.

        SDK Enhancement: Uses clear_input, scroll_to_element, and wait_for_url
        for more reliable authentication handling.

        Returns:
            True if login was attempted, False otherwise
        """
        self._log.info("Checking for login form")

        analysis = await self._analyze_page(context_id)

        if not analysis.has_login_form or not analysis.login_form_info:
            self._log.info("No login form detected")
            return False

        login_info = analysis.login_form_info
        # Store login form info for YAML generation
        self._captured_login_info = login_info

        username_selector = login_info.get("username_selector")
        password_selector = login_info.get("password_selector")
        submit_selector = login_info.get("submit_selector")

        if not username_selector or not password_selector:
            self._log.warning("Login form incomplete - missing username or password field")
            return False

        # Get current URL to detect successful redirect after login
        page_info = await self._browser.get_page_info(context_id=context_id)
        pre_login_url = page_info.get("url") if isinstance(page_info, dict) else ""

        try:
            # SDK Enhancement: Scroll to username field to ensure visibility
            with contextlib.suppress(Exception):
                await self._browser.scroll_to_element(
                    context_id=context_id, selector=username_selector
                )

            # SDK Enhancement: Clear input before typing to handle pre-filled forms
            with contextlib.suppress(Exception):
                await self._browser.clear_input(
                    context_id=context_id, selector=username_selector
                )

            # Fill username
            await self._browser.type(
                context_id=context_id,
                selector=username_selector,
                text=self._config.username or "",
            )
            await asyncio.sleep(0.2)

            # SDK Enhancement: Clear password field too
            with contextlib.suppress(Exception):
                await self._browser.clear_input(
                    context_id=context_id, selector=password_selector
                )

            # Fill password
            await self._browser.type(
                context_id=context_id,
                selector=password_selector,
                text=self._config.password or "",
            )
            await asyncio.sleep(0.2)

            # Submit form
            if submit_selector:
                # SDK Enhancement: Scroll to submit button before clicking
                with contextlib.suppress(Exception):
                    await self._browser.scroll_to_element(
                        context_id=context_id, selector=submit_selector
                    )
                await self._browser.click(context_id=context_id, selector=submit_selector)
            else:
                # SDK Enhancement: Use submit_form if available, else press Enter
                try:
                    await self._browser.submit_form(context_id=context_id)
                except Exception:
                    await self._browser.press_key(context_id=context_id, key="Enter")

            # SDK Enhancement: Wait for URL change (indicates successful login redirect)
            try:
                await self._browser.wait_for_url(
                    context_id=context_id,
                    url_pattern=f"^(?!{re.escape(pre_login_url)})",
                    is_regex=True,
                    timeout=5000,
                )
            except Exception:
                # Fall back to network idle wait if URL doesn't change
                await asyncio.sleep(1)
                with contextlib.suppress(Exception):
                    await self._browser.wait_for_network_idle(
                        context_id=context_id,
                        idle_time=500,
                        timeout=5000,
                    )

            page_info = await self._browser.get_page_info(context_id=context_id)
            current_url = page_info.get("url") if isinstance(page_info, dict) else "unknown"
            self._log.info("Login form submitted", url=current_url)
            return True

        except Exception as e:
            self._log.error("Failed to complete login", error=str(e))
            return False

    async def _crawl_pages(
        self,
        context_id: str,
        url: str,
        depth: int,
    ) -> None:
        """Recursively crawl and analyze pages."""
        # Normalize URL
        normalized_url = self._normalize_url(url)

        # Check if already visited or depth exceeded
        if normalized_url in self._visited_urls:
            return
        if depth > self._config.depth:
            return
        if len(self._visited_urls) >= self._config.max_pages:
            return

        # Check domain constraint
        if self._config.same_domain_only:
            url_domain = urlparse(url).netloc
            if url_domain != self._base_domain:
                return

        # Check exclude/include patterns
        if not self._should_crawl_url(url):
            return

        self._visited_urls.add(normalized_url)

        # Navigate if not already on this page
        page_info = await self._browser.get_page_info(context_id=context_id)
        current_url = page_info.get("url") if isinstance(page_info, dict) else ""
        if self._normalize_url(current_url) != normalized_url:
            try:
                await self._navigate_with_wait(context_id, url)
            except Exception as e:
                self._log.warning("Failed to navigate", url=url, error=str(e))
                return

        # Analyze current page
        analysis = await self._analyze_page(context_id)
        self._page_analyses.append(analysis)

        # Track which elements appear on which pages for shared element detection
        for element in analysis.elements:
            selector = element.selector
            if selector not in self._element_page_map:
                self._element_page_map[selector] = set()
            self._element_page_map[selector].add(analysis.url)

        self._log.info(
            "Analyzed page",
            url=url,
            depth=depth,
            elements=len(analysis.elements),
            links=len(analysis.navigation_links),
        )

        # Crawl child links if depth allows
        if depth < self._config.depth:
            child_urls = [
                link.href
                for link in analysis.navigation_links
                if link.href and self._is_valid_crawl_target(link.href)
            ]

            # Process all valid child URLs (coverage is controlled by max_pages)
            for child_url in child_urls:
                # Early exit if we've hit max_pages
                if len(self._visited_urls) >= self._config.max_pages:
                    break
                absolute_url = urljoin(url, child_url)
                await self._crawl_pages(context_id, absolute_url, depth + 1)

    async def _analyze_page(self, context_id: str) -> PageAnalysis:
        """Perform complete analysis of current page."""
        # FIX 1: Use visibility-first analysis when enabled
        if self._visibility_analyzer and self._config.use_visibility_first:
            return await self._visibility_first_analyze_page(context_id)

        # Use intelligent discovery if enabled
        if self._intelligent_builder:
            return await self._intelligent_analyze_page(context_id)

        return await self._legacy_analyze_page(context_id)

    async def _visibility_first_analyze_page(self, context_id: str) -> PageAnalysis:
        """
        FIX 1: Visibility-first page analysis.

        Uses VisibilityAnalyzer to ONLY return visible elements.
        Hidden content (modals, inactive tabs) is NOT included directly.
        Instead, triggers are tracked for flow-based testing.
        """
        assert self._visibility_analyzer is not None

        page_info = await self._browser.get_page_info(context_id=context_id)
        url = page_info.get("url", "") if isinstance(page_info, dict) else ""
        title = page_info.get("title", "Untitled") if isinstance(page_info, dict) else "Untitled"

        analysis = PageAnalysis(
            url=url,
            title=title,
            timestamp=datetime.now(UTC),
        )

        try:
            # Get visibility analysis - this separates visible from hidden
            visibility_result = await self._visibility_analyzer.analyze(
                self._browser, context_id
            )

            self._log.info(
                "Visibility-first analysis",
                url=url,
                visible=visibility_result.visible_count,
                hidden=visibility_result.hidden_count,
                triggers=len(visibility_result.triggers),
            )

            # FIX: If visibility analysis found nothing, fall back to legacy
            if visibility_result.visible_count == 0:
                self._log.info("No visible elements found, falling back to legacy analysis")
                return await self._legacy_analyze_page(context_id)

            # FIX 1: ONLY include visible elements in analysis
            for elem_state in visibility_result.visible_elements:
                element_type = self._infer_element_type_from_state(elem_state)

                # Skip navigation elements (they cause page changes)
                from autoqa.builder.discovery import ElementCategory
                if elem_state.category == ElementCategory.NAVIGATION:
                    # Add to navigation_links but not main elements
                    nav_link = ElementInfo(
                        element_type=ElementType.LINK,
                        selector=elem_state.selector,
                        semantic_description=elem_state.text_content or elem_state.selector,
                        text_content=elem_state.text_content,
                        href=elem_state.attributes.get("href"),
                        is_visible=True,
                    )
                    analysis.navigation_links.append(nav_link)
                    continue

                # FIX 3: Apply high-value filter based on config
                if self._config.test_priority == "high_value":
                    if not self._is_high_value_element(elem_state):
                        continue

                # Extract select_options from raw_data if available
                select_options = None
                if elem_state.raw_data:
                    select_options = elem_state.raw_data.get("selectOptions")

                element = ElementInfo(
                    element_type=element_type,
                    selector=elem_state.selector,
                    semantic_description=elem_state.text_content or elem_state.selector,
                    text_content=elem_state.text_content,
                    aria_label=elem_state.aria_label,
                    id=elem_state.attributes.get("id"),
                    name=elem_state.attributes.get("name"),
                    is_visible=True,
                    is_required=elem_state.attributes.get("required") == "true",
                    bounding_box=elem_state.bounding_box,
                    element_category=elem_state.category.value,
                    raw_data=elem_state.raw_data,
                    select_options=select_options,
                )
                analysis.elements.append(element)

            # FIX 2: Store triggers for flow-based testing
            # These become "forms" in the analysis for YAML generation
            for trigger in visibility_result.triggers:
                # Only include triggers that reveal something
                if trigger.reveals_elements:
                    flow_info = {
                        "id": None,
                        "name": f"Flow: {trigger.text_content or trigger.selector}",
                        "action": None,
                        "method": None,
                        "input_count": 0,
                        "elements": [],
                        "is_trigger_flow": True,  # Mark as trigger-based flow
                        "trigger_selector": trigger.selector,
                        "reveals_selector": trigger.reveals_elements[0] if trigger.reveals_elements else None,
                        "all_reveals": trigger.reveals_elements,
                        "trigger_text": trigger.text_content,
                    }
                    analysis.forms.append(flow_info)

            # Check for login form in visible elements
            login_info = await self._detect_login_form(context_id, analysis)
            if login_info:
                analysis.has_login_form = True
                analysis.login_form_info = login_info

        except Exception as e:
            analysis.errors.append(f"Visibility-first analysis error: {e}")
            self._log.error("Visibility-first analysis failed", url=url, error=str(e))
            # Fall back to legacy analysis
            return await self._legacy_analyze_page(context_id)

        return analysis

    def _infer_element_type_from_state(self, elem_state: "ElementState") -> ElementType:
        """Infer ElementType from an ElementState."""
        from autoqa.builder.discovery import ElementCategory

        tag = elem_state.tag_name.lower()
        input_type = elem_state.attributes.get("type", "text").lower()

        # Map based on tag and type
        if tag == "input":
            type_map = {
                "text": ElementType.INPUT_TEXT,
                "email": ElementType.INPUT_EMAIL,
                "password": ElementType.INPUT_PASSWORD,
                "number": ElementType.INPUT_NUMBER,
                "search": ElementType.INPUT_SEARCH,
                "tel": ElementType.INPUT_TEL,
                "url": ElementType.INPUT_URL,
                "date": ElementType.INPUT_DATE,
                "checkbox": ElementType.INPUT_CHECKBOX,
                "radio": ElementType.INPUT_RADIO,
                "file": ElementType.INPUT_FILE,
                "submit": ElementType.BUTTON,
                "button": ElementType.BUTTON,
            }
            return type_map.get(input_type, ElementType.INPUT_TEXT)

        if tag == "textarea":
            return ElementType.TEXTAREA

        if tag == "select":
            return ElementType.SELECT

        if tag == "button":
            return ElementType.BUTTON

        if tag == "a":
            return ElementType.LINK

        # Default based on category
        if elem_state.category == ElementCategory.FORM_INPUT:
            return ElementType.INPUT_TEXT
        if elem_state.category == ElementCategory.NAVIGATION:
            return ElementType.LINK

        return ElementType.BUTTON

    def _is_high_value_element(self, elem_state: "ElementState") -> bool:
        """
        FIX 3: Determine if element is high-value for testing.

        High value: form inputs, buttons, primary actions
        Low value: repeated items, decorative elements, navigation
        """
        from autoqa.builder.discovery import ElementCategory

        # Form inputs are always high value
        if elem_state.category == ElementCategory.FORM_INPUT:
            return True

        # Triggers that reveal content are high value
        if elem_state.category == ElementCategory.TRIGGER:
            return True

        # Buttons with meaningful text are high value
        tag = elem_state.tag_name.lower()
        if tag in ("button", "input"):
            text = (elem_state.text_content or "").lower()
            # Skip generic/repeated buttons
            if text in ("add to cart", "remove", "close", "cancel"):
                return False
            return True

        # Navigation and content elements are lower value
        if elem_state.category in (ElementCategory.NAVIGATION, ElementCategory.CONTENT):
            return False

        return True

    async def _intelligent_analyze_page(self, context_id: str) -> PageAnalysis:
        """
        Use intelligent discovery to analyze page.

        This method uses the IntelligentBuilder to discover:
        - Visible and hidden elements
        - Interaction flows (modals, tabs, accordions)
        - Network activity patterns
        """
        page_info = await self._browser.get_page_info(context_id=context_id)
        url = page_info.get("url", "") if isinstance(page_info, dict) else ""
        title = page_info.get("title", "Untitled") if isinstance(page_info, dict) else "Untitled"

        analysis = PageAnalysis(
            url=url,
            title=title,
            timestamp=datetime.now(UTC),
        )

        try:
            assert self._intelligent_builder is not None

            # Build intelligent test plan
            test_plan = await self._intelligent_builder.build_page_tests(
                self._browser, context_id, url
            )

            self._log.info(
                "Intelligent analysis complete",
                url=url,
                visible=test_plan.visible_count,
                hidden=test_plan.hidden_count,
                flows=len(test_plan.flows),
            )

            # Convert IntelligentTestPlan to PageAnalysis format
            # Map visible elements to ElementInfo
            from autoqa.builder.discovery import ElementCategory as DiscoveryCategory

            for step in test_plan.visible_element_tests:
                # Create ElementInfo from IntelligentTestStep
                element_type = self._infer_element_type_from_step(step)
                element = ElementInfo(
                    element_type=element_type,
                    selector=step.selector,
                    semantic_description=step.description,
                    is_visible=True,
                    reliability_score=step.reliability_score,
                    element_category=step.element_category,
                    should_generate_assertion=True,
                )
                analysis.elements.append(element)

            # Also store flow information in forms (as a proxy)
            for flow in test_plan.flows:
                flow_info = {
                    "id": None,
                    "name": flow.name,
                    "action": None,
                    "method": None,
                    "input_count": len(flow.target_elements),
                    "elements": [],
                    "flow_type": flow.flow_type.value,
                    "trigger_selector": flow.trigger_selector,
                    "steps": [
                        {"action": s.action, "selector": s.selector, "description": s.description}
                        for s in flow.steps
                    ],
                }
                analysis.forms.append(flow_info)

            # Separate navigation links
            analysis.navigation_links = [
                el for el in analysis.elements
                if el.element_type == ElementType.LINK
            ]

        except Exception as e:
            analysis.errors.append(f"Intelligent analysis error: {e}")
            self._log.error("Intelligent page analysis failed", url=url, error=str(e))
            # Fall back to legacy analysis
            return await self._legacy_analyze_page(context_id)

        return analysis

    def _infer_element_type_from_step(self, step: "IntelligentTestStep") -> ElementType:
        """Infer ElementType from an IntelligentTestStep."""
        if step.action == "type":
            # Look for hints in selector or description
            selector_lower = step.selector.lower()
            desc_lower = step.description.lower()

            if "email" in selector_lower or "email" in desc_lower:
                return ElementType.INPUT_EMAIL
            if "password" in selector_lower or "password" in desc_lower:
                return ElementType.INPUT_PASSWORD
            if "textarea" in selector_lower:
                return ElementType.TEXTAREA
            if "search" in selector_lower or "search" in desc_lower:
                return ElementType.INPUT_SEARCH
            return ElementType.INPUT_TEXT

        if step.action == "click":
            selector_lower = step.selector.lower()
            if selector_lower.startswith("a") or "[href" in selector_lower:
                return ElementType.LINK
            if "checkbox" in selector_lower:
                return ElementType.INPUT_CHECKBOX
            if "radio" in selector_lower:
                return ElementType.INPUT_RADIO
            return ElementType.BUTTON

        if step.action == "select":
            return ElementType.SELECT

        return ElementType.BUTTON

    async def _legacy_analyze_page(self, context_id: str) -> PageAnalysis:
        """Legacy page analysis method (original implementation)."""
        page_info = await self._browser.get_page_info(context_id=context_id)
        url = page_info.get("url", "") if isinstance(page_info, dict) else ""
        title = page_info.get("title", "Untitled") if isinstance(page_info, dict) else "Untitled"

        analysis = PageAnalysis(
            url=url,
            title=title,
            timestamp=datetime.now(UTC),
        )

        try:
            # Discover all elements
            analysis.elements = await self._discover_elements(context_id)

            # Separate navigation links
            analysis.navigation_links = [
                el for el in analysis.elements
                if el.element_type == ElementType.LINK
            ]

            # Detect forms
            analysis.forms = await self._discover_forms(context_id, analysis.elements)

            # Check for login form
            login_info = await self._detect_login_form(context_id, analysis)
            if login_info:
                analysis.has_login_form = True
                analysis.login_form_info = login_info

        except Exception as e:
            analysis.errors.append(f"Analysis error: {e}")
            self._log.error("Page analysis failed", url=url, error=str(e))

        return analysis

    async def _discover_elements(self, context_id: str) -> list[ElementInfo]:
        """Discover all interactable elements on the page.

        SDK Enhancement: Uses browser_get_interactive_elements when available,
        falling back to JavaScript evaluation for detailed metadata.
        """
        # TRY SDK-NATIVE ELEMENT DISCOVERY FIRST
        # This is faster and more reliable than evaluate()
        try:
            return await self._discover_elements_sdk(context_id)
        except Exception as e:
            self._log.debug("SDK element discovery failed, falling back to JS", error=str(e))
            return await self._discover_elements_js(context_id)

    async def _discover_elements_sdk(self, context_id: str) -> list[ElementInfo]:
        """Discover elements using native SDK browser_get_interactive_elements.

        This method replaces 150+ lines of JavaScript with a single SDK call.
        Returns element data optimized for test generation.
        """
        # Use SDK's native interactive elements discovery
        raw_elements = await self._browser.get_interactive_elements(context_id=context_id)

        if not raw_elements or not isinstance(raw_elements, list):
            self._log.debug("No elements from SDK get_interactive_elements")
            raise ValueError("No elements returned from SDK")

        self._log.info(
            "SDK element discovery succeeded",
            element_count=len(raw_elements),
        )

        elements: list[ElementInfo] = []
        generated_selectors: set[str] = set()
        text_counts: dict[str, int] = {}

        # First pass: count text occurrences for uniqueness
        for raw in raw_elements:
            text = (raw.get("text") or raw.get("innerText") or "").strip()
            if text and len(text) <= 30:
                text_counts[text] = text_counts.get(text, 0) + 1

        for raw in raw_elements:
            # Skip hidden elements unless configured
            if not self._config.include_hidden:
                # Use SDK is_visible for accurate visibility check
                selector = raw.get("selector") or raw.get("css_selector")
                if selector:
                    try:
                        visibility_result = await self._browser.is_visible(
                            context_id=context_id, selector=selector
                        )
                        if not _extract_sdk_bool(visibility_result, default=True):
                            continue
                    except Exception:
                        # If visibility check fails, use raw data hint
                        if not raw.get("visible", True):
                            continue

            # Map SDK element type to our ElementType
            element_type = self._map_sdk_element_type(raw)

            # Generate selector - prefer SDK-provided selector
            element_selector = raw.get("selector") or raw.get("css_selector")
            if not element_selector:
                # Fall back to generating our own selector
                element_selector = self._generate_semantic_selector(
                    raw, element_type, text_counts=text_counts
                )

            # Skip duplicate selectors
            if element_selector in generated_selectors:
                continue
            generated_selectors.add(element_selector)

            # Generate semantic description
            semantic_desc = self._generate_semantic_description_sdk(raw, element_type)

            # Calculate reliability score
            reliability_score = 0.5
            fallback_selectors: list[str] = []
            should_generate = True

            if self._selector_scorer:
                score_result = self._selector_scorer.score_selector(element_selector, raw)
                reliability_score = score_result.score
                fallback_selectors = score_result.fallback_selectors
                should_generate = score_result.score >= self._config.min_selector_reliability

            # Classify element category
            element_category: str | None = None
            if self._element_classifier:
                category_info = self._element_classifier.classify_element(raw)
                element_category = category_info.category.value
                if category_info.priority_score <= 0.1:
                    should_generate = False

            # Extract bounding box from SDK data
            bounding_box = None
            if raw.get("boundingBox"):
                bounding_box = raw["boundingBox"]
            elif raw.get("x") is not None and raw.get("y") is not None:
                bounding_box = {
                    "x": raw.get("x", 0),
                    "y": raw.get("y", 0),
                    "width": raw.get("width", 0),
                    "height": raw.get("height", 0),
                }

            # Check if element is enabled using SDK
            is_disabled = raw.get("disabled", False)
            if not is_disabled and element_selector:
                try:
                    enabled_result = await self._browser.is_enabled(
                        context_id=context_id, selector=element_selector
                    )
                    is_disabled = not _extract_sdk_bool(enabled_result, default=True)
                except Exception:
                    pass  # Keep default from raw data

            # Check if checkbox/radio is checked using SDK is_checked
            is_checked = raw.get("checked", False)
            if element_type in (ElementType.INPUT_CHECKBOX, ElementType.INPUT_RADIO):
                try:
                    checked_result = await self._browser.is_checked(
                        context_id=context_id, selector=element_selector
                    )
                    is_checked = _extract_sdk_bool(checked_result, default=False)
                except Exception:
                    pass  # Keep default from raw data

            elements.append(ElementInfo(
                element_type=element_type,
                selector=element_selector,
                semantic_description=semantic_desc,
                text_content=raw.get("text") or raw.get("innerText"),
                placeholder=raw.get("placeholder"),
                name=raw.get("name"),
                id=raw.get("id"),
                aria_label=raw.get("ariaLabel") or raw.get("aria-label"),
                href=raw.get("href"),
                form_id=raw.get("formId"),
                is_required=raw.get("required", False),
                is_visible=raw.get("visible", True),
                bounding_box=bounding_box,
                reliability_score=reliability_score,
                fallback_selectors=fallback_selectors,
                element_category=element_category,
                should_generate_assertion=should_generate,
                raw_data=raw,
                select_options=raw.get("options"),
                label_text=raw.get("label") or raw.get("labelText"),
                is_checked=is_checked,  # Use SDK-verified value
                is_disabled=is_disabled,
                is_readonly=raw.get("readOnly", False),
                max_length=raw.get("maxLength"),
                min_length=raw.get("minLength"),
                pattern=raw.get("pattern"),
                min_value=raw.get("min"),
                max_value=raw.get("max"),
                step=raw.get("step"),
                text_is_unique=text_counts.get(
                    (raw.get("text") or "").strip(), 0
                ) <= 1,
                selector_is_unique=True,
            ))

        return elements

    def _map_sdk_element_type(self, raw: dict[str, Any]) -> ElementType:
        """Map SDK element data to ElementType enum."""
        tag = (raw.get("tag") or raw.get("tagName") or "").lower()
        input_type = (raw.get("type") or raw.get("inputType") or "text").lower()
        role = (raw.get("role") or "").lower()

        # Handle by tag first
        if tag == "button" or role == "button":
            return ElementType.BUTTON
        if tag == "a":
            return ElementType.LINK
        if tag == "select":
            return ElementType.SELECT
        if tag == "textarea":
            return ElementType.TEXTAREA

        # Handle inputs by type
        if tag == "input":
            type_map = {
                "text": ElementType.INPUT_TEXT,
                "email": ElementType.INPUT_EMAIL,
                "password": ElementType.INPUT_PASSWORD,
                "number": ElementType.INPUT_NUMBER,
                "search": ElementType.INPUT_SEARCH,
                "tel": ElementType.INPUT_TEL,
                "url": ElementType.INPUT_URL,
                "date": ElementType.INPUT_DATE,
                "checkbox": ElementType.INPUT_CHECKBOX,
                "radio": ElementType.INPUT_RADIO,
                "file": ElementType.INPUT_FILE,
                "submit": ElementType.BUTTON,
                "button": ElementType.BUTTON,
            }
            return type_map.get(input_type, ElementType.INPUT_TEXT)

        # Default based on interactivity hints
        if raw.get("clickable") or raw.get("isClickable"):
            return ElementType.BUTTON

        return ElementType.BUTTON

    def _generate_semantic_description_sdk(
        self,
        raw: dict[str, Any],
        element_type: ElementType,
    ) -> str:
        """Generate semantic description from SDK element data."""
        parts: list[str] = []

        # Primary identifiers in priority order
        if raw.get("label") or raw.get("labelText"):
            parts.append(raw.get("label") or raw["labelText"])
        elif raw.get("ariaLabel") or raw.get("aria-label"):
            parts.append(raw.get("ariaLabel") or raw["aria-label"])
        elif raw.get("text") or raw.get("innerText"):
            text = (raw.get("text") or raw["innerText"])[:50]
            parts.append(text)
        elif raw.get("placeholder"):
            parts.append(f"{raw['placeholder']} input")
        elif raw.get("name"):
            name = raw["name"].replace("_", " ").replace("-", " ")
            parts.append(f"{name} field")
        elif raw.get("id"):
            id_text = raw["id"].replace("_", " ").replace("-", " ")
            parts.append(id_text)
        elif raw.get("title"):
            parts.append(raw["title"])

        # Add type context if not obvious
        if not parts:
            type_labels = {
                ElementType.BUTTON: "button",
                ElementType.LINK: "link",
                ElementType.INPUT_CHECKBOX: "checkbox",
                ElementType.INPUT_RADIO: "radio button",
                ElementType.SELECT: "dropdown",
            }
            parts.append(type_labels.get(element_type, f"{element_type.value} field"))

        return " ".join(parts) if parts else f"unnamed {element_type.value}"

    async def _discover_elements_js(self, context_id: str) -> list[ElementInfo]:
        """Discover elements using JavaScript evaluation (fallback method)."""
        # Original JavaScript-based discovery
        script = """
        (() => {
            const results = [];
            const seen = new Set();

            // Type mapping for inputs
            const inputTypeMap = {
                'text': 'input_text',
                'email': 'input_email',
                'password': 'input_password',
                'number': 'input_number',
                'search': 'input_search',
                'tel': 'input_tel',
                'url': 'input_url',
                'date': 'input_date',
                'checkbox': 'checkbox',
                'radio': 'radio',
                'file': 'file_upload',
                'button': 'button',
                'submit': 'button',
            };

            // Calculate nth-of-type index for an element
            function getNthOfType(el) {
                const tag = el.tagName;
                const parent = el.parentElement;
                if (!parent) return 1;
                const siblings = parent.querySelectorAll(':scope > ' + tag.toLowerCase());
                for (let i = 0; i < siblings.length; i++) {
                    if (siblings[i] === el) return i + 1;
                }
                return 1;
            }

            // Count siblings of same type
            function getSiblingCount(el) {
                const tag = el.tagName;
                const parent = el.parentElement;
                if (!parent) return 1;
                return parent.querySelectorAll(':scope > ' + tag.toLowerCase()).length;
            }

            // Get all data-* attributes
            function getDataAttributes(el) {
                const data = {};
                for (const attr of el.attributes) {
                    if (attr.name.startsWith('data-')) {
                        data[attr.name] = attr.value;
                    }
                }
                return Object.keys(data).length > 0 ? data : null;
            }

            // Get parent context for uniqueness
            function getParentContext(el) {
                const parent = el.parentElement;
                if (!parent || parent === document.body) return null;
                return {
                    tagName: parent.tagName.toLowerCase(),
                    id: parent.id || null,
                    className: parent.className || null
                };
            }

            // Get options for select elements
            function getSelectOptions(el) {
                if (el.tagName.toLowerCase() !== 'select') return null;
                const options = [];
                for (const opt of el.options) {
                    if (opt.value) {  // Skip empty placeholder options
                        options.push({
                            value: opt.value,
                            text: opt.text,
                            selected: opt.selected
                        });
                    }
                }
                return options.length > 0 ? options.slice(0, 10) : null;  // Limit to 10 options
            }

            // Get associated label text for an input
            function getLabelText(el) {
                // Check for aria-labelledby
                const labelledBy = el.getAttribute('aria-labelledby');
                if (labelledBy) {
                    const labelEl = document.getElementById(labelledBy);
                    if (labelEl) return labelEl.textContent?.trim()?.substring(0, 50);
                }
                // Check for label with for attribute
                if (el.id) {
                    const label = document.querySelector(`label[for="${el.id}"]`);
                    if (label) return label.textContent?.trim()?.substring(0, 50);
                }
                // Check for wrapping label
                const parentLabel = el.closest('label');
                if (parentLabel) {
                    return parentLabel.textContent?.trim()?.substring(0, 50);
                }
                return null;
            }

            function processElement(el, elementType) {
                // Generate unique key to avoid duplicates
                const key = el.outerHTML.substring(0, 200);
                if (seen.has(key)) return null;
                seen.add(key);

                const style = window.getComputedStyle(el);
                // IMPROVED visibility check - include elements that are technically visible
                // but may have small dimensions (like hidden inputs for accessibility)
                const isVisible = style.display !== 'none' &&
                                  style.visibility !== 'hidden' &&
                                  (el.offsetWidth > 0 || el.offsetHeight > 0 ||
                                   // Hidden inputs should still be tracked
                                   (el.type === 'hidden'));

                const rect = el.getBoundingClientRect();

                return {
                    elementType: elementType,
                    tagName: el.tagName.toLowerCase(),
                    id: el.id || null,
                    name: el.name || null,
                    type: el.type || null,
                    text: el.innerText?.trim()?.substring(0, 100) || null,
                    value: el.value || null,
                    placeholder: el.placeholder || null,
                    ariaLabel: el.getAttribute('aria-label') || null,
                    title: el.title || null,
                    href: el.href || null,
                    required: el.required || false,
                    isVisible: isVisible,
                    className: el.className || null,
                    formId: el.form?.id || null,
                    boundingBox: {
                        x: rect.x,
                        y: rect.y,
                        width: rect.width,
                        height: rect.height
                    },
                    // New fields for unique selector generation
                    nthOfType: getNthOfType(el),
                    siblingCount: getSiblingCount(el),
                    dataAttributes: getDataAttributes(el),
                    parentContext: getParentContext(el),
                    role: el.getAttribute('role') || null,
                    // Additional fields for comprehensive testing
                    selectOptions: getSelectOptions(el),
                    labelText: getLabelText(el),
                    checked: el.checked || false,
                    disabled: el.disabled || false,
                    readOnly: el.readOnly || false,
                    maxLength: el.maxLength > 0 ? el.maxLength : null,
                    minLength: el.minLength > 0 ? el.minLength : null,
                    pattern: el.pattern || null,
                    min: el.min || null,
                    max: el.max || null,
                    step: el.step || null
                };
            }

            // Process buttons
            document.querySelectorAll('button, [role="button"]').forEach(el => {
                const r = processElement(el, 'button');
                if (r) results.push(r);
            });

            // Process links
            document.querySelectorAll('a[href]').forEach(el => {
                const r = processElement(el, 'link');
                if (r) results.push(r);
            });

            // Process all inputs
            document.querySelectorAll('input').forEach(el => {
                const inputType = (el.type || 'text').toLowerCase();
                const elementType = inputTypeMap[inputType] || 'input_text';
                const r = processElement(el, elementType);
                if (r) results.push(r);
            });

            // Process selects
            document.querySelectorAll('select').forEach(el => {
                const r = processElement(el, 'select');
                if (r) results.push(r);
            });

            // Process textareas
            document.querySelectorAll('textarea').forEach(el => {
                const r = processElement(el, 'textarea');
                if (r) results.push(r);
            });

            return results;
        })()
        """

        try:
            # SDK v2: use evaluate for JavaScript execution
            result = await self._browser.evaluate(context_id=context_id, expression=script)
            # SDK returns the evaluated expression directly (not wrapped in "result" key)
            raw_elements = result

            if not raw_elements or not isinstance(raw_elements, list):
                self._log.debug("No elements returned from batched query")
                return []

            # FIRST PASS: Count text occurrences for uniqueness detection
            # This allows us to avoid using text= selectors for non-unique text
            text_counts: dict[str, int] = {}
            for raw in raw_elements:
                if not self._config.include_hidden and not raw.get("isVisible"):
                    continue
                text = (raw.get("text") or "").strip()
                if text and len(text) <= 30:
                    text_counts[text] = text_counts.get(text, 0) + 1

            elements: list[ElementInfo] = []
            # Track generated selectors to avoid duplicates
            generated_selectors: set[str] = set()

            for raw in raw_elements:
                if not self._config.include_hidden and not raw.get("isVisible"):
                    continue

                # Map string type to ElementType enum
                element_type_str = raw.get("elementType", "button")
                element_type = self._map_element_type(element_type_str)

                # Check text uniqueness BEFORE generating selector
                text = (raw.get("text") or "").strip()
                text_is_unique = text_counts.get(text, 0) <= 1 if text else True

                semantic_desc = self._generate_semantic_description(raw, element_type)
                # Pass text_counts and raw_elements to selector generator for uniqueness-aware generation
                element_selector = self._generate_semantic_selector(
                    raw, element_type, text_counts=text_counts, all_elements=raw_elements
                )

                # FIX 4: Skip duplicate selectors - don't generate same step twice
                if element_selector in generated_selectors:
                    self._log.debug(
                        "Skipping duplicate selector",
                        selector=element_selector,
                        element_type=element_type_str,
                    )
                    continue
                generated_selectors.add(element_selector)

                # INTELLIGENT LAYER: Score selector reliability
                reliability_score = 0.5
                fallback_selectors: list[str] = []
                should_generate = True

                if self._selector_scorer:
                    score_result = self._selector_scorer.score_selector(
                        element_selector, raw
                    )
                    reliability_score = score_result.score
                    fallback_selectors = score_result.fallback_selectors
                    should_generate = score_result.score >= self._config.min_selector_reliability

                # INTELLIGENT LAYER: Classify element category
                element_category: str | None = None
                if self._element_classifier:
                    category_info = self._element_classifier.classify_element(raw)
                    element_category = category_info.category.value
                    # CRITICAL: Skip assertions for problematic dynamic elements
                    # Modal content, toasts, and animation elements should NOT get assertions
                    if category_info.priority_score <= 0.1:
                        should_generate = False

                elements.append(ElementInfo(
                    element_type=element_type,
                    selector=element_selector,
                    semantic_description=semantic_desc,
                    text_content=raw.get("text"),
                    placeholder=raw.get("placeholder"),
                    name=raw.get("name"),
                    id=raw.get("id"),
                    aria_label=raw.get("ariaLabel"),
                    href=raw.get("href"),
                    form_id=raw.get("formId"),
                    is_required=raw.get("required", False),
                    is_visible=raw.get("isVisible", True),
                    bounding_box=raw.get("boundingBox"),
                    reliability_score=reliability_score,
                    fallback_selectors=fallback_selectors,
                    element_category=element_category,
                    should_generate_assertion=should_generate,
                    raw_data=raw,
                    # New comprehensive fields
                    select_options=raw.get("selectOptions"),
                    label_text=raw.get("labelText"),
                    is_checked=raw.get("checked", False),
                    is_disabled=raw.get("disabled", False),
                    is_readonly=raw.get("readOnly", False),
                    max_length=raw.get("maxLength"),
                    min_length=raw.get("minLength"),
                    pattern=raw.get("pattern"),
                    min_value=raw.get("min"),
                    max_value=raw.get("max"),
                    step=raw.get("step"),
                    # Uniqueness tracking
                    text_is_unique=text_is_unique,
                    selector_is_unique=True,  # We ensured uniqueness by tracking generated_selectors
                ))

            return elements

        except Exception as e:
            self._log.debug("Batched element query failed", error=str(e))
            return []

    def _map_element_type(self, type_str: str) -> ElementType:
        """Map string type to ElementType enum."""
        type_mapping = {
            "button": ElementType.BUTTON,
            "link": ElementType.LINK,
            "input_text": ElementType.INPUT_TEXT,
            "input_email": ElementType.INPUT_EMAIL,
            "input_password": ElementType.INPUT_PASSWORD,
            "input_number": ElementType.INPUT_NUMBER,
            "input_search": ElementType.INPUT_SEARCH,
            "input_tel": ElementType.INPUT_TEL,
            "input_url": ElementType.INPUT_URL,
            "input_date": ElementType.INPUT_DATE,
            "checkbox": ElementType.INPUT_CHECKBOX,
            "radio": ElementType.INPUT_RADIO,
            "file_upload": ElementType.INPUT_FILE,
            "select": ElementType.SELECT,
            "textarea": ElementType.TEXTAREA,
        }
        return type_mapping.get(type_str, ElementType.BUTTON)

    async def _query_elements(
        self,
        context_id: str,
        selector: str,
        element_type: ElementType,
    ) -> list[ElementInfo]:
        """Query and extract information about elements matching selector."""
        elements: list[ElementInfo] = []

        # JavaScript to extract element info
        script = f"""
        (() => {{
            const elements = document.querySelectorAll("{selector}");
            const results = [];

            for (const el of elements) {{
                // Skip hidden elements unless configured otherwise
                const style = window.getComputedStyle(el);
                const isVisible = style.display !== 'none' &&
                                  style.visibility !== 'hidden' &&
                                  el.offsetWidth > 0 &&
                                  el.offsetHeight > 0;

                const rect = el.getBoundingClientRect();

                results.push({{
                    tagName: el.tagName.toLowerCase(),
                    id: el.id || null,
                    name: el.name || null,
                    type: el.type || null,
                    text: el.innerText?.trim()?.substring(0, 100) || null,
                    value: el.value || null,
                    placeholder: el.placeholder || null,
                    ariaLabel: el.getAttribute('aria-label') || null,
                    title: el.title || null,
                    href: el.href || null,
                    required: el.required || false,
                    isVisible: isVisible,
                    className: el.className || null,
                    formId: el.form?.id || null,
                    boundingBox: {{
                        x: rect.x,
                        y: rect.y,
                        width: rect.width,
                        height: rect.height
                    }}
                }});
            }}

            return results;
        }})()
        """

        try:
            # SDK v2: use evaluate for JavaScript execution
            result = await self._browser.evaluate(context_id=context_id, expression=script)
            # SDK returns the evaluated expression directly (not wrapped in "result" key)
            raw_elements = result

            # Handle case where result might be None or not a list
            if not raw_elements or not isinstance(raw_elements, list):
                self._log.debug("No elements returned from query", selector=selector)
                return elements

            for raw in raw_elements:
                if not self._config.include_hidden and not raw.get("isVisible"):
                    continue

                semantic_desc = self._generate_semantic_description(raw, element_type)
                element_selector = self._generate_semantic_selector(raw, element_type)

                elements.append(ElementInfo(
                    element_type=element_type,
                    selector=element_selector,
                    semantic_description=semantic_desc,
                    text_content=raw.get("text"),
                    placeholder=raw.get("placeholder"),
                    name=raw.get("name"),
                    id=raw.get("id"),
                    aria_label=raw.get("ariaLabel"),
                    href=raw.get("href"),
                    form_id=raw.get("formId"),
                    is_required=raw.get("required", False),
                    is_visible=raw.get("isVisible", True),
                    bounding_box=raw.get("boundingBox"),
                ))

        except Exception as e:
            self._log.debug("Element query failed", selector=selector, error=str(e))

        return elements

    def _generate_semantic_description(
        self,
        raw: dict[str, Any],
        element_type: ElementType,
    ) -> str:
        """Generate a human-readable semantic description for an element."""
        parts: list[str] = []

        # Primary identifier - now includes labelText for form elements
        if raw.get("labelText"):
            # Label text is often the best descriptor for form inputs
            parts.append(raw["labelText"])
        elif raw.get("ariaLabel"):
            parts.append(raw["ariaLabel"])
        elif raw.get("text"):
            parts.append(raw["text"][:50])
        elif raw.get("placeholder"):
            parts.append(f"{raw['placeholder']} input")
        elif raw.get("name"):
            # Convert name to readable format
            name = raw["name"].replace("_", " ").replace("-", " ")
            parts.append(f"{name} field")
        elif raw.get("id"):
            # Convert id to readable format
            id_text = raw["id"].replace("_", " ").replace("-", " ")
            parts.append(id_text)
        elif raw.get("title"):
            parts.append(raw["title"])

        # Add type context if not obvious
        if element_type == ElementType.BUTTON and not parts:
            parts.append("button")
        elif element_type == ElementType.LINK:
            if not parts:
                parts.append("link")
        elif element_type == ElementType.INPUT_CHECKBOX:
            if not parts:
                parts.append("checkbox")
        elif element_type == ElementType.INPUT_RADIO:
            if not parts:
                parts.append("radio button")
        elif element_type == ElementType.SELECT:
            if not parts:
                parts.append("dropdown")
        elif (
            element_type in (ElementType.INPUT_TEXT, ElementType.INPUT_EMAIL,
                            ElementType.INPUT_PASSWORD, ElementType.TEXTAREA,
                            ElementType.INPUT_NUMBER, ElementType.INPUT_TEL,
                            ElementType.INPUT_URL, ElementType.INPUT_DATE,
                            ElementType.INPUT_SEARCH)
            and not parts
        ):
            parts.append(f"{element_type.value.replace('_', ' ')} field")

        return " ".join(parts) if parts else f"unnamed {element_type.value}"

    def _generate_semantic_selector(
        self,
        raw: dict[str, Any],
        element_type: ElementType,  # noqa: ARG002
        text_counts: dict[str, int] | None = None,
        all_elements: list[dict[str, Any]] | None = None,  # noqa: ARG002
    ) -> str:
        """
        Generate a unique CSS selector for the element.

        GOAL: Generate selectors that match exactly ONE element on the page.

        FIX 1: Never use text= for non-unique elements
        FIX 3: Prefer CSS selectors over text= selectors

        Priority order for selector generation (UPDATED):
        1. ID selector (#id) - always unique
        2. data-testid, data-test, data-cy attributes - testing best practice
        3. data-product-id, data-item-id - contextual IDs
        4. name attribute - very reliable for form elements
        5. Combination selectors (class + href, class + data-attr)
        6. aria-label with tag
        7. Class + nth-of-type - position-based (reliable)
        8. text=X - ONLY if text is unique on page (FIX 1)
        9. Parent context + element selector
        10. Tag with nth-of-type - last resort
        """
        tag = raw.get("tagName", "div")
        text_counts = text_counts or {}

        # Helper to check if text is unique
        def is_text_unique(text: str) -> bool:
            if not text:
                return False
            return text_counts.get(text, 0) <= 1

        # 1. ID selector - most reliable and unique
        if raw.get("id"):
            return f"#{raw['id']}"

        # 2. data-testid or data-test attribute - testing best practice
        data_attrs = raw.get("dataAttributes") or {}
        if data_attrs.get("data-testid"):
            return f"{tag}[data-testid='{self._escape_attr(data_attrs['data-testid'])}']"
        if data_attrs.get("data-test"):
            return f"{tag}[data-test='{self._escape_attr(data_attrs['data-test'])}']"
        if data_attrs.get("data-cy"):
            return f"{tag}[data-cy='{self._escape_attr(data_attrs['data-cy'])}']"

        # 3. FIX 3: Contextual data attributes (data-product-id, data-item-id, etc.)
        # These are often unique identifiers for specific items
        for attr_name, attr_value in data_attrs.items():
            if any(
                pattern in attr_name.lower()
                for pattern in ("product", "item", "id", "sku", "variant")
            ):
                return f"{tag}[{attr_name}='{self._escape_attr(attr_value)}']"

        # 4. Name attribute - very reliable for form elements
        if raw.get("name"):
            return f"{tag}[name='{self._escape_attr(raw['name'])}']"

        # 5. For links: combine class with href for uniqueness
        if tag == "a" and raw.get("href"):
            href = raw["href"]
            # Extract path from full URL
            path = href
            if "://" in href:
                path = urlparse(href).path

            if path and path != "/":
                # If has meaningful class, combine with href
                if raw.get("className"):
                    first_class = self._get_meaningful_class(raw["className"])
                    if first_class:
                        return f"a.{first_class}[href*='{self._escape_attr(path)}']"
                # Just href path selector
                return f"a[href*='{self._escape_attr(path)}']"

        # 6. aria-label attribute - good for accessible elements
        if raw.get("ariaLabel"):
            label = self._escape_attr(raw["ariaLabel"])
            return f"{tag}[aria-label='{label}']"

        # 7. FIX 3: Class-based selector with nth-of-type for uniqueness
        # Prefer CSS selectors over text= selectors
        class_selector = self._get_class_selector(raw, tag)
        if class_selector:
            # Check if we need to add nth-of-type for uniqueness
            sibling_count = raw.get("siblingCount", 1)
            if sibling_count > 1:
                nth = raw.get("nthOfType", 1)
                return f"{class_selector}:nth-of-type({nth})"
            return class_selector

        # 8. FIX 1: ONLY use text= selector if text is UNIQUE on the page
        # This prevents failures like "text=Add to Cart" matching multiple buttons
        if tag == "button":
            text = raw.get("text", "").strip()

            # CRITICAL: Check text uniqueness before using text= selector
            if (
                text
                and len(text) <= 30
                and not any(c in text for c in "'\"[]")
                and is_text_unique(text)  # FIX 1: Only use if unique
            ):
                return f"text={text}"

            # FIX 3: For non-unique text, use position-based selector
            # This is more reliable than text= for repeated buttons
            nth = raw.get("nthOfType", 1)
            sibling_count = raw.get("siblingCount", 1)

            # Try to build a more specific selector using parent context
            parent_ctx = raw.get("parentContext")
            if parent_ctx:
                parent_selector = self._build_parent_selector(parent_ctx)
                if parent_selector:
                    if sibling_count > 1:
                        return f"{parent_selector} > button:nth-of-type({nth})"
                    return f"{parent_selector} > button"

            # Last resort for buttons: just use button:nth-of-type
            if sibling_count > 1:
                return f"button:nth-of-type({nth})"
            return "button"

        # 9. Type attribute for inputs with placeholder for uniqueness
        if raw.get("type") and tag == "input":
            input_type = raw["type"]
            if raw.get("placeholder"):
                placeholder = self._escape_attr(raw["placeholder"])
                return f"input[type='{input_type}'][placeholder='{placeholder}']"
            # Add nth-of-type if multiple inputs of same type
            if raw.get("siblingCount", 1) > 1:
                nth = raw.get("nthOfType", 1)
                return f"input[type='{input_type}']:nth-of-type({nth})"
            return f"input[type='{input_type}']"

        # 10. Use parent context for uniqueness
        parent_ctx = raw.get("parentContext")
        if parent_ctx:
            parent_selector = self._build_parent_selector(parent_ctx)
            if parent_selector:
                # Use direct child selector with nth-of-type
                nth = raw.get("nthOfType", 1)
                sibling_count = raw.get("siblingCount", 1)
                if sibling_count > 1:
                    return f"{parent_selector} > {tag}:nth-of-type({nth})"
                return f"{parent_selector} > {tag}"

        # 11. Title attribute fallback
        if raw.get("title"):
            title = self._escape_attr(raw["title"])
            return f"{tag}[title='{title}']"

        # 12. Role attribute fallback
        if raw.get("role"):
            role = self._escape_attr(raw["role"])
            nth = raw.get("nthOfType", 1)
            sibling_count = raw.get("siblingCount", 1)
            if sibling_count > 1:
                return f"{tag}[role='{role}']:nth-of-type({nth})"
            return f"{tag}[role='{role}']"

        # 12. Last resort: tag with nth-of-type
        nth = raw.get("nthOfType", 1)
        sibling_count = raw.get("siblingCount", 1)
        if sibling_count > 1:
            return f"{tag}:nth-of-type({nth})"
        return tag

    def _escape_attr(self, value: str) -> str:
        """Escape special characters in CSS attribute values."""
        if not value:
            return ""
        # Escape single quotes and backslashes
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def _get_meaningful_class(self, class_name: str) -> str | None:
        """Extract the first meaningful (non-generic) class name."""
        if not class_name:
            return None

        classes = class_name.split()
        # Filter out common generic/utility classes
        generic_classes = frozenset({
            "active", "disabled", "hidden", "visible", "show", "hide",
            "btn", "button", "input", "form-control", "container",
            "row", "col", "flex", "grid", "block", "inline",
            "d-flex", "d-block", "d-none", "m-0", "p-0", "w-100", "h-100",
        })
        for c in classes:
            if c and c not in generic_classes and not c.startswith("_"):
                return c
        return None

    def _get_class_selector(self, raw: dict[str, Any], tag: str) -> str | None:  # noqa: ARG002
        """Build a class-based selector if meaningful class exists.

        NOTE: SDK bug - is_visible doesn't work with tag.class (e.g., button.btn)
        but works with just .class - so we omit the tag name for class selectors.
        """
        meaningful_class = self._get_meaningful_class(raw.get("className", ""))
        if meaningful_class:
            # Use .class instead of tag.class due to SDK is_visible bug
            return f".{meaningful_class}"
        return None

    def _build_parent_selector(self, parent_ctx: dict[str, Any]) -> str | None:
        """Build a selector for the parent element.

        NOTE: SDK bug - is_visible doesn't work with tag.class (e.g., div.container)
        but works with just .class - so we omit the tag name for class selectors.
        """
        if not parent_ctx:
            return None

        # Prefer ID
        if parent_ctx.get("id"):
            return f"#{parent_ctx['id']}"

        # Use .class instead of tag.class due to SDK is_visible bug
        parent_class = self._get_meaningful_class(parent_ctx.get("className", ""))
        if parent_class:
            return f".{parent_class}"

        return None

    def _build_css_fallback(
        self,
        raw: dict[str, Any],
        element_type: ElementType,  # noqa: ARG002
    ) -> str:
        """Build a CSS selector as fallback."""
        tag = raw.get("tagName", "div")

        if raw.get("id"):
            return f"#{raw['id']}"

        if raw.get("name"):
            return f"{tag}[name='{raw['name']}']"

        if raw.get("className"):
            first_class = raw["className"].split()[0]
            if first_class:
                return f"{tag}.{first_class}"

        if raw.get("type"):
            return f"{tag}[type='{raw['type']}']"

        return tag

    async def _discover_forms(
        self,
        context_id: str,
        elements: list[ElementInfo],
    ) -> list[dict[str, Any]]:
        """Discover and analyze forms on the page."""
        forms: list[dict[str, Any]] = []

        script = """
        (() => {
            const forms = document.querySelectorAll('form');
            return Array.from(forms).map(form => ({
                id: form.id || null,
                name: form.name || null,
                action: form.action || null,
                method: form.method || 'get',
                inputCount: form.querySelectorAll('input, select, textarea').length
            }));
        })()
        """

        try:
            # SDK v2: use evaluate for JavaScript execution
            result = await self._browser.evaluate(context_id=context_id, expression=script)
            # SDK returns the evaluated expression directly (not wrapped in "result" key)
            raw_forms = result

            # Handle case where result might be None or not a list
            if not raw_forms or not isinstance(raw_forms, list):
                return forms

            for raw in raw_forms:
                form_elements = [
                    el for el in elements
                    if el.form_id == raw.get("id")
                ] if raw.get("id") else []

                forms.append({
                    "id": raw.get("id"),
                    "name": raw.get("name"),
                    "action": raw.get("action"),
                    "method": raw.get("method"),
                    "input_count": raw.get("inputCount", 0),
                    "elements": form_elements,
                })

        except Exception as e:
            self._log.debug("Form discovery failed", error=str(e))

        return forms

    async def _detect_login_form(
        self,
        context_id: str,
        analysis: PageAnalysis,
    ) -> dict[str, Any] | None:
        """Detect login form and extract field selectors."""
        page_info = await self._browser.get_page_info(context_id=context_id)
        url_lower = (page_info.get("url", "") if isinstance(page_info, dict) else "").lower()

        # Check URL for login indicators
        url_has_login = any(ind in url_lower for ind in self.LOGIN_INDICATORS)

        # Find potential username/password fields
        username_candidates: list[ElementInfo] = []
        password_candidates: list[ElementInfo] = []
        submit_candidates: list[ElementInfo] = []

        for element in analysis.elements:
            element_lower = (
                (element.name or "").lower() +
                (element.id or "").lower() +
                (element.placeholder or "").lower() +
                (element.aria_label or "").lower()
            )

            if element.element_type == ElementType.INPUT_PASSWORD:
                password_candidates.append(element)
            elif element.element_type in (
                ElementType.INPUT_TEXT,
                ElementType.INPUT_EMAIL,
            ):
                if any(ind in element_lower for ind in self.USERNAME_INDICATORS):
                    username_candidates.append(element)
            elif element.element_type == ElementType.BUTTON:
                text_lower = (element.text_content or "").lower()
                if any(ind in text_lower or ind in element_lower
                       for ind in self.LOGIN_INDICATORS):
                    submit_candidates.append(element)

        # Require at least username and password fields
        if not password_candidates:
            return None

        # If no explicit username field found but we have password,
        # look for any text/email input near the password field
        if not username_candidates:
            for element in analysis.elements:
                if element.element_type in (
                    ElementType.INPUT_TEXT,
                    ElementType.INPUT_EMAIL,
                ):
                    username_candidates.append(element)
                    break

        if not username_candidates:
            return None

        return {
            "username_selector": username_candidates[0].selector,
            "password_selector": password_candidates[0].selector,
            "submit_selector": submit_candidates[0].selector if submit_candidates else None,
            "is_likely_login": url_has_login or bool(submit_candidates),
        }

    def _generate_yaml_spec(self) -> str:
        """Generate complete YAML test specification from analyses."""
        if not self._page_analyses:
            return self._generate_empty_spec()

        first_analysis = self._page_analyses[0]

        # Build test specification
        spec: dict[str, Any] = {
            "name": f"Auto-generated test for {first_analysis.title}",
            "description": self._generate_description(),
            "metadata": {
                "tags": ["auto-generated", "builder"],
                "priority": "medium",
                "timeout_ms": 60000,
            },
            "variables": {
                "base_url": self._extract_base_url(self._config.url),
            },
            "steps": [],
        }

        # Add credential variables if login was configured
        if self._config.username and self._config.password:
            spec["variables"]["username"] = ""  # Placeholder - pass actual value via --var
            spec["variables"]["password"] = ""  # Placeholder - pass actual value via --var

        # Add initial navigation step
        spec["steps"].append({
            "name": "Navigate to starting page",
            "action": "navigate",
            "url": self._config.url,
            "wait_until": "domcontentloaded",
            "timeout": 10000,
        })

        # Add wait for page load
        spec["steps"].append({
            "name": "Wait for page to load",
            "action": "wait_for_network_idle",
            "timeout": 5000,
        })

        # Add login steps if credentials were provided
        login_performed = False
        if self._config.username and self._config.password:
            login_steps = self._generate_login_steps()
            spec["steps"].extend(login_steps)
            login_performed = True

        # Generate test steps for each analyzed page
        # PAGE-SCOPED ASSERTIONS: Each page gets its own section with:
        # 1. Navigation to that specific page
        # 2. Assertions for elements ONLY found on that page
        # 3. Shared navigation elements (appearing on multiple pages) are excluded
        self._log.info(
            "Generating page-scoped test steps",
            total_pages=len(self._page_analyses),
            shared_elements=sum(
                1 for pages in self._element_page_map.values()
                if len(pages) > len(self._page_analyses) / 2
            ),
        )

        for i, analysis in enumerate(self._page_analyses):
            # Skip navigation for first page after login - we're already there from redirect
            skip_initial_nav = login_performed and i == 0
            page_steps = self._generate_page_steps(analysis, skip_initial_navigation=skip_initial_nav)
            spec["steps"].extend(page_steps)

        # Add final assertions
        final_assertions = self._generate_final_assertions()
        spec["steps"].extend(final_assertions)

        # Remove internal fields (starting with _) from steps before YAML output
        # These fields are for internal use and not part of the DSL schema
        for step in spec["steps"]:
            keys_to_remove = [k for k in step.keys() if k.startswith("_")]
            for key in keys_to_remove:
                del step[key]

        # Convert to YAML
        yaml_content = yaml.dump(
            spec,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=100,
        )

        # Count shared elements for header
        shared_count = sum(
            1 for pages in self._element_page_map.values()
            if len(pages) > len(self._page_analyses) / 2
        )

        # Add header comment
        header = f"""# Auto-generated test specification (VISIBILITY-FIRST)
# Generated: {datetime.now(UTC).isoformat()}
# URL: {self._config.url}
# Pages analyzed: {len(self._page_analyses)}
# Total visible elements discovered: {sum(len(p.elements) for p in self._page_analyses)}
# Shared navigation elements excluded: {shared_count}
# Total test steps: {self._total_step_count}
#
# VISIBILITY-FIRST TESTING:
# - ONLY visible elements are tested directly
# - Hidden content (modals, tabs) tested via flow patterns
# - Flow: click trigger -> wait -> verify -> close
# - Step count limited to ~{self._config.max_total_steps} total
#
# Review and customize before running in production.

"""
        return header + yaml_content

    def _generate_empty_spec(self) -> str:
        """Generate an empty specification when no pages were analyzed."""
        spec = {
            "name": f"Test for {self._config.url}",
            "description": "Auto-generated test (no pages analyzed)",
            "steps": [
                {
                    "name": "Navigate to page",
                    "action": "navigate",
                    "url": self._config.url,
                },
                {
                    "name": "Verify page loads",
                    "action": "assert",
                    "assertion": {
                        "selector": "body",
                        "operator": "exists",
                    },
                },
            ],
        }

        return yaml.dump(spec, default_flow_style=False, sort_keys=False)

    def _generate_description(self) -> str:
        """Generate test description from analyses."""
        total_elements = sum(len(p.elements) for p in self._page_analyses)
        total_forms = sum(len(p.forms) for p in self._page_analyses)

        parts = [
            f"Automated test covering {len(self._page_analyses)} page(s),",
            f"{total_elements} interactive elements,",
        ]

        if total_forms > 0:
            parts.append(f"and {total_forms} form(s).")
        else:
            parts.append("discovered by Auto Test Builder.")

        return " ".join(parts)

    def _generate_login_steps(self) -> list[dict[str, Any]]:
        """Generate login-related test steps."""
        steps: list[dict[str, Any]] = []

        # Use login form info captured during authentication
        # This is more reliable than searching through page analyses
        # since the login form might not be visible on post-login pages
        if not self._captured_login_info:
            return steps

        login_info = self._captured_login_info

        steps.append({
            "name": "Enter username",
            "action": "type",
            "selector": login_info["username_selector"],
            "text": "${username}",
        })

        steps.append({
            "name": "Enter password",
            "action": "type",
            "selector": login_info["password_selector"],
            "text": "${password}",
        })

        if login_info.get("submit_selector"):
            steps.append({
                "name": "Click login button",
                "action": "click",
                "selector": login_info["submit_selector"],
                "timeout": 5000,
            })
        else:
            steps.append({
                "name": "Submit login form",
                "action": "press_key",
                "key": "Enter",
            })

        # Wait for login to process - give time for form submission and redirect
        steps.append({
            "name": "Wait for login to process",
            "action": "wait",
            "timeout": 2000,
        })

        steps.append({
            "name": "Wait for login response",
            "action": "wait_for_network_idle",
            "timeout": 5000,
        })

        return steps

    def _generate_page_steps(
        self,
        analysis: PageAnalysis,
        skip_initial_navigation: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Generate test steps for a single page.

        FIX 2 & 3: Visibility-first testing with step count limits.
        - ONLY tests visible elements
        - Generates flow-based tests for triggers (modal, tab flows)
        - Enforces max_steps_per_page limit

        Args:
            analysis: Page analysis data
            skip_initial_navigation: If True, skip the navigation step.
                Used for first page after login where we're already there.
        """
        steps: list[dict[str, Any]] = []
        step_count = 0

        # FIX 3: Check if we've hit total step limit
        remaining_total = self._config.max_total_steps - self._total_step_count
        if remaining_total <= 0:
            self._log.info(
                "Skipping page - max total steps reached",
                url=analysis.url,
                total_steps=self._total_step_count,
            )
            return steps

        # Calculate effective max for this page
        effective_max = min(self._config.max_steps_per_page, remaining_total)

        # Extract path for readable step names
        parsed_url = urlparse(analysis.url)
        page_path = parsed_url.path or "/"

        if not skip_initial_navigation:
            # CRITICAL: Navigate to this page before testing its elements
            steps.append({
                "name": f"Navigate to {page_path}",
                "action": "navigate",
                "url": analysis.url,
                "wait_until": "domcontentloaded",
                "timeout": 10000,
            })
            step_count += 1

            # Wait for page load after navigation
            steps.append({
                "name": f"Wait for {page_path} to load",
                "action": "wait_for_network_idle",
                "timeout": 5000,
            })
            step_count += 1

        # Take screenshot of page (minimal overhead)
        safe_title = re.sub(r"[^\w\-_]", "_", analysis.title[:30])
        # Use dash instead of colon to avoid YAML parsing issues
        steps.append({
            "name": f"Screenshot - {self._sanitize_step_name(analysis.title[:40])}",
            "action": "screenshot",
            "filename": f"page_{safe_title}.png",
        })

        # FIX 1, 2, 3: VISIBILITY-FIRST TESTING WITH STEP LIMITS
        # Only test visible elements, use flows for hidden content, enforce limits
        key_elements = self._select_key_elements(analysis.elements)

        # FIX 3: Use effective_max instead of config values
        max_element_steps = effective_max - step_count

        # Group elements by priority for organized testing
        # HIGH PRIORITY: Form inputs (critical for functionality)
        form_inputs = [
            el for el in key_elements
            if el.element_type in (
                ElementType.INPUT_TEXT, ElementType.INPUT_EMAIL,
                ElementType.INPUT_PASSWORD, ElementType.SELECT,
                ElementType.INPUT_CHECKBOX, ElementType.TEXTAREA,
            )
        ]

        # MEDIUM PRIORITY: Action buttons (not navigation)
        action_buttons = [
            el for el in key_elements
            if el.element_type == ElementType.BUTTON
            and not self._is_shared_navigation_element(el)
            and el.element_category not in ("modal_trigger", "modal_content", "toast", "animation")
        ]

        # Generate MINIMAL test steps for visible elements
        # FIX 3: Skip redundant visibility assertions when we interact with element
        elements_tested = 0

        # 1. Test form inputs (most valuable tests)
        for element in form_inputs:
            if elements_tested >= max_element_steps:
                break

            # FIX 3: Skip visibility assertion if we're going to type/click
            # Just do the action - it will fail if element isn't visible
            if self._config.skip_redundant_assertions:
                input_step = self._generate_minimal_input_step(element)
                if input_step:
                    steps.append(input_step)
                    step_count += 1
                    elements_tested += 1
            else:
                input_steps = self._generate_input_test_steps(element, expected_url=analysis.url)
                steps.extend(input_steps)  # Include all steps (visibility, fill, verify)
                step_count += len(input_steps)
                elements_tested += len(input_steps)  # Count each step

        # 2. Test buttons comprehensively
        buttons_tested = 0
        max_buttons = 15  # Increased for comprehensive coverage (was 3)
        for button in action_buttons:
            if elements_tested >= max_element_steps or buttons_tested >= max_buttons:
                break

            btn_text = (button.text_content or "").lower()
            # Only skip destructive buttons that could break the test flow
            if any(skip in btn_text for skip in ["logout", "sign out", "delete all"]):
                continue

            # Test button visibility first
            steps.append({
                "name": f"Verify visible - {self._sanitize_step_name(button.semantic_description[:40])}",
                "action": "assert",
                "assertion": {
                    "selector": button.selector,
                    "operator": "is_visible",
                    "timeout": 3000,
                },
                "continue_on_failure": True,
            })
            step_count += 1
            elements_tested += 1

            # Click non-destructive buttons to test functionality
            safe_to_click = not any(skip in btn_text for skip in [
                "delete", "remove", "cancel", "close", "reset",
            ])
            if safe_to_click:
                steps.append({
                    "name": f"Click - {self._sanitize_step_name(button.semantic_description[:40])}",
                    "action": "click",
                    "selector": button.selector,
                    "timeout": 3000,
                    "continue_on_failure": True,
                })
                step_count += 1
                elements_tested += 1

            buttons_tested += 1

        # 3. Test links (non-navigation, page-specific links)
        links_tested = 0
        max_links = 10  # Test up to 10 links per page
        page_links = [
            el for el in key_elements
            if el.element_type == ElementType.LINK
            and not self._is_shared_navigation_element(el)
        ]
        for link in page_links:
            if elements_tested >= max_element_steps or links_tested >= max_links:
                break

            link_text = (link.text_content or "").lower()
            # Skip logout/signout links
            if any(skip in link_text for skip in ["logout", "sign out"]):
                continue

            # Verify link visibility
            steps.append({
                "name": f"Verify link - {self._sanitize_step_name(link.semantic_description[:40])}",
                "action": "assert",
                "assertion": {
                    "selector": link.selector,
                    "operator": "is_visible",
                    "timeout": 3000,
                },
                "continue_on_failure": True,
            })
            step_count += 1
            elements_tested += 1
            links_tested += 1

        # Generate FLOW-BASED tests for triggers (modals, tabs)
        # These are in analysis.forms when is_trigger_flow=True
        flow_count = 0
        max_flows = 5  # Increased for comprehensive coverage (was 2)
        for form in analysis.forms:
            if step_count >= effective_max or flow_count >= max_flows:
                break

            # Check if this is a trigger-based flow
            if form.get("is_trigger_flow"):
                flow_steps = self._generate_flow_test(form)
                steps.extend(flow_steps)
                step_count += len(flow_steps)
                flow_count += 1

        # Log statistics
        self._log.info(
            "Generated visibility-first test steps",
            url=page_path,
            form_inputs=len(form_inputs),
            buttons=len(action_buttons),
            links=len(page_links),
            flows=flow_count,
            total_steps=step_count,
            max_allowed=effective_max,
        )

        # FIX 3: Update total step count
        self._total_step_count += step_count

        return steps

    def _generate_minimal_input_step(self, element: ElementInfo) -> dict[str, Any] | None:
        """
        FIX 3: Generate a single minimal step for an input element.

        Combines fill + implicit visibility check (will fail if not visible).
        """
        sample_text = self._generate_sample_input(element)
        desc = self._sanitize_step_name(element.semantic_description[:40])

        # For checkboxes, just click
        if element.element_type == ElementType.INPUT_CHECKBOX:
            return {
                "name": f"Toggle - {desc}",
                "action": "click",
                "selector": element.selector,
                "timeout": 3000,
                "continue_on_failure": True,
            }

        # For selects, pick first available option
        if element.element_type == ElementType.SELECT:
            # Use actual option value if available, otherwise use first non-empty value
            select_value = "1"  # Default fallback
            if element.select_options and len(element.select_options) > 0:
                select_value = element.select_options[0].get("value", "1")
            return {
                "name": f"Select - {desc}",
                "action": "pick",
                "selector": element.selector,
                "value": select_value,
                "timeout": 3000,
                "continue_on_failure": True,
            }

        # For text inputs, type value
        return {
            "name": f"Fill - {desc}",
            "action": "type",
            "selector": element.selector,
            "text": sample_text,
            "timeout": 3000,
            "continue_on_failure": True,
        }

    def _generate_flow_test(self, flow: dict[str, Any]) -> list[dict[str, Any]]:
        """
        FIX 2: Generate flow-based test steps for trigger elements.

        Pattern: click trigger -> wait for content -> verify visible -> close
        """
        steps: list[dict[str, Any]] = []

        trigger_selector = flow.get("trigger_selector")
        reveals_selector = flow.get("reveals_selector")
        trigger_text = flow.get("trigger_text", "trigger")

        if not trigger_selector:
            return steps

        # Step 1: Click trigger to open content
        steps.append({
            "name": f"Open - {self._sanitize_step_name(trigger_text[:30])}",
            "action": "click",
            "selector": trigger_selector,
            "timeout": 3000,
        })

        # Step 2: Wait for revealed content (if known)
        if reveals_selector:
            steps.append({
                "name": f"Wait for revealed content",
                "action": "wait_for_selector",
                "selector": reveals_selector,
                "timeout": 3000,
                "continue_on_failure": True,
            })

            # Step 3: Verify content is visible
            steps.append({
                "name": f"Verify content visible",
                "action": "assert",
                "assertion": {
                    "selector": reveals_selector,
                    "operator": "is_visible",
                    "timeout": 3000,
                },
                "continue_on_failure": True,
            })

        # Step 4: Close/reset (press Escape for modals)
        steps.append({
            "name": "Close modal/panel",
            "action": "press_key",
            "key": "Escape",
            "continue_on_failure": True,
        })

        # Brief wait for animation
        steps.append({
            "name": "Wait for close animation",
            "action": "wait",
            "timeout": 300,
        })

        return steps

    def _is_shared_navigation_element(self, element: ElementInfo) -> bool:
        """
        Determine if an element is a shared navigation element.

        Shared elements are those that appear on multiple pages (like nav bars,
        headers, footers) and should NOT be asserted on every page.

        Detection methods:
        1. Selector contains known navigation patterns (nav-item, nav-link, etc.)
        2. Element appears on multiple pages (tracked during crawling)
        """
        selector_lower = element.selector.lower()

        # Check if selector contains known navigation patterns
        for pattern in self.SHARED_ELEMENT_PATTERNS:
            if pattern in selector_lower:
                return True

        # Check if element appears on multiple pages
        # If we've crawled multiple pages and this element appears on most of them,
        # it's likely a shared navigation element
        total_pages = len(self._page_analyses)
        if total_pages > 1:
            pages_with_element = len(self._element_page_map.get(element.selector, set()))
            # If element appears on more than half of crawled pages, consider it shared
            if pages_with_element > total_pages / 2:
                return True

        return False

    # Categories of dynamic elements that should NOT have assertions generated
    SKIP_ASSERTION_CATEGORIES: frozenset[str] = frozenset({
        "modal_content",
        "toast",
        "animation",
        "dynamic",  # Dynamic content elements
    })

    def _select_key_elements(
        self,
        elements: list[ElementInfo],
        exclude_shared: bool = True,
    ) -> list[ElementInfo]:
        """
        Select key elements for assertion generation.

        COMPREHENSIVE COVERAGE: Now includes ALL testable elements, not just a sample.

        Args:
            elements: List of elements discovered on the page
            exclude_shared: If True, exclude shared navigation elements
                that appear on multiple pages. Default True to ensure
                page-scoped assertions.

        Returns:
            List of key elements suitable for assertions on this specific page.
        """
        key_elements: list[ElementInfo] = []

        # Priority order for element types - form elements first
        # COMPREHENSIVE: Include ALL interactive element types
        priority_types = [
            # High priority - form inputs
            ElementType.INPUT_TEXT,
            ElementType.INPUT_EMAIL,
            ElementType.INPUT_PASSWORD,
            ElementType.INPUT_NUMBER,
            ElementType.INPUT_TEL,
            ElementType.INPUT_URL,
            ElementType.INPUT_DATE,
            ElementType.INPUT_SEARCH,
            ElementType.TEXTAREA,
            # Medium priority - interactive controls
            ElementType.SELECT,
            ElementType.INPUT_CHECKBOX,
            ElementType.INPUT_RADIO,
            ElementType.BUTTON,
            ElementType.INPUT_FILE,
            # Lower priority - navigation (often shared)
            ElementType.LINK,
        ]

        # Calculate per-type limit based on config
        # Allow more elements per type for comprehensive testing
        max_per_type = max(10, self._config.max_elements_per_page // len(priority_types))

        for elem_type in priority_types:
            type_elements = [
                el for el in elements
                if el.element_type == elem_type
                and el.is_visible
                and (not exclude_shared or not self._is_shared_navigation_element(el))
                # Lowered reliability threshold - include more elements
                # Only skip elements with very low reliability (< 0.1)
                and el.reliability_score >= 0.1
                # CRITICAL: Skip dynamic/modal elements that may not be visible
                and el.element_category not in self.SKIP_ASSERTION_CATEGORIES
            ]
            # INTELLIGENT LAYER: Sort by reliability score (highest first)
            type_elements.sort(key=lambda e: e.reliability_score, reverse=True)
            # Add more elements per type for comprehensive coverage
            key_elements.extend(type_elements[:max_per_type])

        # Final sort by reliability score to prioritize most reliable elements
        key_elements.sort(key=lambda e: e.reliability_score, reverse=True)

        # Use config limit instead of hardcoded value
        return key_elements[:self._config.max_elements_per_page]

    def _generate_form_steps(
        self,
        form: dict[str, Any],
        expected_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Generate comprehensive test steps for form interaction.

        COMPREHENSIVE: Tests ALL form elements with type-appropriate actions.

        Args:
            form: Form dictionary with elements
            expected_url: URL where this form exists, for recovery purposes
        """
        steps: list[dict[str, Any]] = []
        form_elements: list[ElementInfo] = form.get("elements", [])

        if not form_elements:
            return steps

        # Use config limit for max form inputs
        max_inputs = self._config.max_form_inputs
        input_count = 0

        # Group by type for organized testing
        text_inputs = [
            el for el in form_elements
            if el.element_type in (
                ElementType.INPUT_TEXT,
                ElementType.INPUT_EMAIL,
                ElementType.INPUT_PASSWORD,
                ElementType.INPUT_NUMBER,
                ElementType.INPUT_TEL,
                ElementType.INPUT_URL,
                ElementType.INPUT_SEARCH,
                ElementType.INPUT_DATE,
                ElementType.TEXTAREA,
            )
        ]

        checkboxes = [
            el for el in form_elements
            if el.element_type == ElementType.INPUT_CHECKBOX
        ]

        radios = [
            el for el in form_elements
            if el.element_type == ElementType.INPUT_RADIO
        ]

        selects = [
            el for el in form_elements
            if el.element_type == ElementType.SELECT
        ]

        # 1. Fill all text inputs with comprehensive testing
        for inp in text_inputs:
            if input_count >= max_inputs:
                break
            input_steps = self._generate_input_test_steps(inp, expected_url=expected_url)
            steps.extend(input_steps)
            input_count += 1

        # 2. Toggle checkboxes
        for checkbox in checkboxes:
            if input_count >= max_inputs:
                break
            checkbox_steps = self._generate_checkbox_test_steps(checkbox, expected_url=expected_url)
            steps.extend(checkbox_steps)
            input_count += 1

        # 3. Select radio buttons (one per group)
        tested_radio_names: set[str] = set()
        for radio in radios:
            if input_count >= max_inputs:
                break
            radio_name = radio.name or radio.selector
            if radio_name in tested_radio_names:
                continue
            tested_radio_names.add(radio_name)
            radio_steps = self._generate_radio_test_steps(radio, expected_url=expected_url)
            steps.extend(radio_steps)
            input_count += 1

        # 4. Select dropdown options
        for select in selects:
            if input_count >= max_inputs:
                break
            select_steps = self._generate_select_test_steps(select, expected_url=expected_url)
            steps.extend(select_steps)
            input_count += 1

        return steps

    def _generate_sample_input(self, element: ElementInfo) -> str:
        """
        Generate appropriate sample input for a field based on type and context.

        Uses element name, placeholder, and type to determine the most realistic test data.
        """
        # Get contextual hints from element
        name_lower = (element.name or "").lower()
        placeholder_lower = (element.placeholder or "").lower()
        id_lower = (element.id or "").lower()
        context = f"{name_lower} {placeholder_lower} {id_lower}"

        # Email type - always return email
        if element.element_type == ElementType.INPUT_EMAIL:
            return "test@example.com"

        # Password type - use strong password
        if element.element_type == ElementType.INPUT_PASSWORD:
            return "TestPassword123!"

        # Number type - context-aware
        if element.element_type == ElementType.INPUT_NUMBER:
            if any(w in context for w in ("age", "years")):
                return "25"
            if any(w in context for w in ("quantity", "qty", "count")):
                return "1"
            if any(w in context for w in ("price", "amount", "cost")):
                return "99.99"
            if any(w in context for w in ("phone", "zip", "postal")):
                return "12345"
            return "42"

        # Phone/Tel type
        if element.element_type == ElementType.INPUT_TEL:
            return "555-123-4567"

        # URL type
        if element.element_type == ElementType.INPUT_URL:
            return "https://example.com"

        # Date type
        if element.element_type == ElementType.INPUT_DATE:
            return "2024-01-15"

        # Search type
        if element.element_type == ElementType.INPUT_SEARCH:
            return "test search"

        # Text inputs - context-aware
        if element.element_type == ElementType.INPUT_TEXT:
            # Name fields
            if any(w in context for w in ("first", "given", "fname")):
                return "John"
            if any(w in context for w in ("last", "surname", "family", "lname")):
                return "Doe"
            if any(w in context for w in ("full name", "fullname", "name")):
                return "John Doe"

            # Address fields
            if any(w in context for w in ("address", "street")):
                return "123 Main Street"
            if any(w in context for w in ("city",)):
                return "New York"
            if any(w in context for w in ("state", "province")):
                return "NY"
            if any(w in context for w in ("zip", "postal", "postcode")):
                return "10001"
            if any(w in context for w in ("country",)):
                return "United States"

            # Company/organization
            if any(w in context for w in ("company", "organization", "org")):
                return "Test Company Inc."

            # Title/subject
            if any(w in context for w in ("title", "subject")):
                return "Test Title"

            # Username
            if any(w in context for w in ("username", "user")):
                return "testuser"

        # Textarea - longer content
        if element.element_type == ElementType.TEXTAREA:
            if any(w in context for w in ("message", "content", "body", "description")):
                return "This is a test message with some content for testing purposes."
            if any(w in context for w in ("comment", "note")):
                return "Test comment or note."
            if any(w in context for w in ("bio", "about")):
                return "This is a test biography or about section."
            return "Test textarea content"

        # Default fallback
        return "Test input"

    def _generate_input_test_steps(
        self,
        element: ElementInfo,
        expected_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Generate comprehensive test steps for an input element.

        Includes:
        1. Visibility assertion
        2. Type action with sample data
        3. Value assertion to verify input was accepted
        """
        steps: list[dict[str, Any]] = []
        sample_text = self._generate_sample_input(element)
        desc = self._sanitize_step_name(element.semantic_description[:40])

        # Step 1: Verify input is visible
        step_visibility: dict[str, Any] = {
            "name": f"Verify visible - {desc}",
            "action": "assert",
            "assertion": {
                "selector": element.selector,
                "operator": "is_visible",
                "timeout": 5000,
            },
            "continue_on_failure": True,
        }
        if expected_url:
            step_visibility["_expected_url"] = expected_url
        steps.append(step_visibility)

        # Step 2: Type sample data
        step_type: dict[str, Any] = {
            "name": f"Fill - {desc}",
            "action": "type",
            "selector": element.selector,
            "text": sample_text,
            "continue_on_failure": True,
        }
        if expected_url:
            step_type["_expected_url"] = expected_url
        steps.append(step_type)

        # Step 3: Verify value was set (comprehensive assertion)
        if self._config.generate_comprehensive_assertions:
            step_value: dict[str, Any] = {
                "name": f"Verify value - {desc}",
                "action": "assert",
                "assertion": {
                    "selector": element.selector,
                    "operator": "attribute_equals",
                    "attribute": "value",
                    "expected": sample_text,
                    "timeout": 5000,
                },
                "continue_on_failure": True,
            }
            if expected_url:
                step_value["_expected_url"] = expected_url
            steps.append(step_value)

        return steps

    def _generate_checkbox_test_steps(
        self,
        element: ElementInfo,
        expected_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Generate comprehensive test steps for a checkbox element.

        Includes:
        1. Visibility assertion
        2. Click to toggle
        3. Checked state assertion
        """
        steps: list[dict[str, Any]] = []
        desc = self._sanitize_step_name(element.semantic_description[:40])

        # Step 1: Verify checkbox is visible
        step_visibility: dict[str, Any] = {
            "name": f"Verify visible - {desc}",
            "action": "assert",
            "assertion": {
                "selector": element.selector,
                "operator": "is_visible",
                "timeout": 5000,
            },
            "continue_on_failure": True,
        }
        if expected_url:
            step_visibility["_expected_url"] = expected_url
        steps.append(step_visibility)

        # Step 2: Click to toggle checkbox
        step_click: dict[str, Any] = {
            "name": f"Toggle - {desc}",
            "action": "click",
            "selector": element.selector,
            "timeout": 5000,
            "continue_on_failure": True,
        }
        if expected_url:
            step_click["_expected_url"] = expected_url
        steps.append(step_click)

        # Step 3: Verify checked state (comprehensive assertion)
        if self._config.generate_comprehensive_assertions:
            step_checked: dict[str, Any] = {
                "name": f"Verify checked - {desc}",
                "action": "assert",
                "assertion": {
                    "selector": element.selector,
                    "operator": "is_checked",
                    "timeout": 5000,
                },
                "continue_on_failure": True,
            }
            if expected_url:
                step_checked["_expected_url"] = expected_url
            steps.append(step_checked)

        return steps

    def _generate_radio_test_steps(
        self,
        element: ElementInfo,
        expected_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Generate comprehensive test steps for a radio button element.

        Includes:
        1. Visibility assertion
        2. Click to select
        3. Checked state assertion
        """
        steps: list[dict[str, Any]] = []
        desc = self._sanitize_step_name(element.semantic_description[:40])

        # Step 1: Verify radio is visible
        step_visibility: dict[str, Any] = {
            "name": f"Verify visible - {desc}",
            "action": "assert",
            "assertion": {
                "selector": element.selector,
                "operator": "is_visible",
                "timeout": 5000,
            },
            "continue_on_failure": True,
        }
        if expected_url:
            step_visibility["_expected_url"] = expected_url
        steps.append(step_visibility)

        # Step 2: Click to select radio
        step_click: dict[str, Any] = {
            "name": f"Select - {desc}",
            "action": "click",
            "selector": element.selector,
            "timeout": 5000,
            "continue_on_failure": True,
        }
        if expected_url:
            step_click["_expected_url"] = expected_url
        steps.append(step_click)

        # Step 3: Verify selected state (comprehensive assertion)
        if self._config.generate_comprehensive_assertions:
            step_checked: dict[str, Any] = {
                "name": f"Verify selected - {desc}",
                "action": "assert",
                "assertion": {
                    "selector": element.selector,
                    "operator": "is_checked",
                    "timeout": 5000,
                },
                "continue_on_failure": True,
            }
            if expected_url:
                step_checked["_expected_url"] = expected_url
            steps.append(step_checked)

        return steps

    def _generate_select_test_steps(
        self,
        element: ElementInfo,
        expected_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Generate comprehensive test steps for a select dropdown element.

        Includes:
        1. Visibility assertion
        2. Select by value (if options known) or by index
        3. Value assertion to verify selection
        """
        steps: list[dict[str, Any]] = []
        desc = self._sanitize_step_name(element.semantic_description[:40])

        # Step 1: Verify select is visible
        step_visibility: dict[str, Any] = {
            "name": f"Verify visible - {desc}",
            "action": "assert",
            "assertion": {
                "selector": element.selector,
                "operator": "is_visible",
                "timeout": 5000,
            },
            "continue_on_failure": True,
        }
        if expected_url:
            step_visibility["_expected_url"] = expected_url
        steps.append(step_visibility)

        # Step 2: Select option - use actual option value if available
        selected_value: str | None = None
        if element.select_options and len(element.select_options) > 0:
            # Use the first available option (with non-empty value)
            first_option = element.select_options[0]
            selected_value = first_option.get("value")
            step_select: dict[str, Any] = {
                "name": f"Select option - {desc}",
                "action": "pick",
                "selector": element.selector,
                "value": selected_value,
                "timeout": 5000,
                "continue_on_failure": True,
            }
        else:
            # Fall back to default value (pick action requires value, not index)
            step_select = {
                "name": f"Select option - {desc}",
                "action": "pick",
                "selector": element.selector,
                "value": "1",  # Default fallback value
                "timeout": 5000,
                "continue_on_failure": True,
            }
        if expected_url:
            step_select["_expected_url"] = expected_url
        steps.append(step_select)

        # Step 3: Verify value was set (if we know the expected value)
        if self._config.generate_comprehensive_assertions and selected_value:
            step_value: dict[str, Any] = {
                "name": f"Verify selection - {desc}",
                "action": "assert",
                "assertion": {
                    "selector": element.selector,
                    "operator": "attribute_equals",
                    "attribute": "value",
                    "expected": selected_value,
                    "timeout": 5000,
                },
                "continue_on_failure": True,
            }
            if expected_url:
                step_value["_expected_url"] = expected_url
            steps.append(step_value)

        return steps

    def _generate_button_test_steps(
        self,
        element: ElementInfo,
        expected_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Generate comprehensive test steps for a button element.

        Includes:
        1. Visibility assertion
        2. Enabled assertion
        3. Click action
        """
        steps: list[dict[str, Any]] = []
        desc = self._sanitize_step_name(element.semantic_description[:40])

        # Step 1: Verify button is visible
        step_visibility: dict[str, Any] = {
            "name": f"Verify visible - {desc}",
            "action": "assert",
            "assertion": {
                "selector": element.selector,
                "operator": "is_visible",
                "timeout": 5000,
            },
            "continue_on_failure": True,
        }
        if expected_url:
            step_visibility["_expected_url"] = expected_url
        steps.append(step_visibility)

        # Step 2: Verify button is enabled (comprehensive assertion)
        if self._config.generate_comprehensive_assertions:
            step_enabled: dict[str, Any] = {
                "name": f"Verify enabled - {desc}",
                "action": "assert",
                "assertion": {
                    "selector": element.selector,
                    "operator": "is_enabled",
                    "timeout": 5000,
                },
                "continue_on_failure": True,
            }
            if expected_url:
                step_enabled["_expected_url"] = expected_url
            steps.append(step_enabled)

        # Step 3: Click button (only if not a submit/destructive button)
        btn_text = (element.text_content or "").lower()
        if not any(skip in btn_text for skip in ["submit", "delete", "remove", "logout", "sign out"]):
            step_click: dict[str, Any] = {
                "name": f"Click - {desc}",
                "action": "click",
                "selector": element.selector,
                "timeout": 5000,
                "continue_on_failure": True,
            }
            if expected_url:
                step_click["_expected_url"] = expected_url
            steps.append(step_click)

        return steps

    def _sanitize_step_name(self, name: str) -> str:
        """
        Sanitize step name for YAML compatibility.

        Removes/replaces characters that could cause YAML parsing issues,
        particularly colons which indicate key-value pairs in YAML.
        """
        # Replace colons with dashes (colons break YAML parsing in strings)
        sanitized = name.replace(":", " -")
        # Remove other potentially problematic characters
        sanitized = sanitized.replace("\n", " ").replace("\r", "")
        # Collapse multiple spaces
        sanitized = re.sub(r"\s+", " ", sanitized).strip()
        return sanitized

    def _element_type_to_tag(self, element_type: ElementType) -> str:
        """Convert ElementType to HTML tag name for step ordering analysis."""
        tag_mapping: dict[ElementType, str] = {
            ElementType.BUTTON: "button",
            ElementType.LINK: "a",
            ElementType.INPUT_TEXT: "input",
            ElementType.INPUT_EMAIL: "input",
            ElementType.INPUT_PASSWORD: "input",
            ElementType.INPUT_NUMBER: "input",
            ElementType.INPUT_SEARCH: "input",
            ElementType.INPUT_TEL: "input",
            ElementType.INPUT_URL: "input",
            ElementType.INPUT_DATE: "input",
            ElementType.INPUT_CHECKBOX: "input",
            ElementType.INPUT_RADIO: "input",
            ElementType.INPUT_FILE: "input",
            ElementType.SELECT: "select",
            ElementType.TEXTAREA: "textarea",
            ElementType.FORM: "form",
            ElementType.NAVIGATION: "a",
        }
        return tag_mapping.get(element_type, "div")

    def _element_type_to_input_type(self, element_type: ElementType) -> str:
        """Convert ElementType to input type attribute for step ordering analysis."""
        type_mapping: dict[ElementType, str] = {
            ElementType.INPUT_TEXT: "text",
            ElementType.INPUT_EMAIL: "email",
            ElementType.INPUT_PASSWORD: "password",
            ElementType.INPUT_NUMBER: "number",
            ElementType.INPUT_SEARCH: "search",
            ElementType.INPUT_TEL: "tel",
            ElementType.INPUT_URL: "url",
            ElementType.INPUT_DATE: "date",
            ElementType.INPUT_CHECKBOX: "checkbox",
            ElementType.INPUT_RADIO: "radio",
            ElementType.INPUT_FILE: "file",
            ElementType.BUTTON: "button",
        }
        return type_mapping.get(element_type, "")

    def _generate_final_assertions(self) -> list[dict[str, Any]]:
        """Generate final assertions for the test."""
        steps: list[dict[str, Any]] = []

        # Body exists assertion
        steps.append({
            "name": "Verify page is functional",
            "action": "assert",
            "assertion": {
                "selector": "body",
                "operator": "exists",
                "message": "Page body should exist",
            },
        })

        # Final screenshot
        steps.append({
            "name": "Final screenshot",
            "action": "screenshot",
            "filename": "test_complete.png",
        })

        return steps

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison."""
        parsed = urlparse(url)
        # Remove fragment and trailing slash
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    def _should_crawl_url(self, url: str) -> bool:
        """Check if URL should be crawled based on patterns."""
        # Check exclude patterns
        for pattern in self._config.exclude_patterns:
            if re.search(pattern, url):
                return False

        # Check include patterns (if any specified)
        if self._config.include_patterns:
            return any(re.search(p, url) for p in self._config.include_patterns)

        return True

    def _is_valid_crawl_target(self, url: str) -> bool:
        """Check if URL is a valid crawl target."""
        if not url:
            return False

        # Skip non-HTTP URLs
        if url.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            return False

        # Skip file downloads
        extensions = (".pdf", ".zip", ".doc", ".docx", ".xls", ".xlsx", ".png",
                     ".jpg", ".jpeg", ".gif", ".svg", ".mp4", ".mp3")
        return not any(url.lower().endswith(ext) for ext in extensions)

    def _extract_base_url(self, url: str) -> str:
        """Extract base URL from full URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
