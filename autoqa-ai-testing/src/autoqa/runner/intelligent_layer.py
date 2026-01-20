"""
Intelligent layer for the test runner providing smart waiting and overlay handling.

Provides:
- Smart wait strategies (network idle, animation complete, content stable)
- Modal/overlay detection and dismissal
- Element interactability checking
- Retry with fallback selectors

SDK v2 Notes:
- All methods are async and require context_id
- Uses OwlBrowser methods directly
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from owl_browser import OwlBrowser

logger = structlog.get_logger(__name__)


class WaitStrategy(StrEnum):
    """Smart wait strategies for different scenarios."""

    IMMEDIATE = "immediate"  # Element should be there now
    NETWORK_IDLE = "network_idle"  # Wait for XHR/fetch to complete
    ANIMATION_COMPLETE = "animation"  # Wait for CSS transitions
    CONTENT_STABLE = "content_stable"  # Wait for text/innerHTML to stop changing
    INTERACTIVE = "interactive"  # Wait for element to be clickable (not just visible)
    DOM_STABLE = "dom_stable"  # Wait for DOM mutations to settle
    DYNAMIC_ELEMENT = "dynamic_element"  # Extended wait for dynamic/modal elements


class OverlayType(StrEnum):
    """Types of overlays that can block interactions."""

    MODAL = "modal"
    POPUP = "popup"
    TOAST = "toast"
    LOADER = "loader"
    COOKIE_BANNER = "cookie_banner"
    DROPDOWN = "dropdown"
    TOOLTIP = "tooltip"


@dataclass
class OverlayInfo:
    """Information about a detected overlay."""

    overlay_type: OverlayType
    selector: str
    dismiss_selector: str | None = None
    can_click_outside: bool = False
    z_index: int = 0
    is_blocking: bool = True


@dataclass
class WaitResult:
    """Result of a smart wait operation."""

    success: bool
    strategy_used: WaitStrategy
    wait_time_ms: int
    element_ready: bool = False
    error: str | None = None


@dataclass
class InteractabilityResult:
    """Result of checking element interactability."""

    is_interactable: bool
    is_visible: bool = False
    is_enabled: bool = False
    is_in_viewport: bool = False
    blocked_by: OverlayInfo | None = None
    error: str | None = None


class SmartWaiter:
    """
    Intelligent waiting system that adapts to page state.

    Instead of fixed timeouts, uses multiple strategies to determine
    when the page is ready for interaction.
    """

    # Default timeouts for different strategies
    DEFAULT_TIMEOUTS: dict[WaitStrategy, int] = {
        WaitStrategy.IMMEDIATE: 100,
        WaitStrategy.NETWORK_IDLE: 5000,
        WaitStrategy.ANIMATION_COMPLETE: 2000,
        WaitStrategy.CONTENT_STABLE: 3000,
        WaitStrategy.INTERACTIVE: 5000,
        WaitStrategy.DOM_STABLE: 2000,
        WaitStrategy.DYNAMIC_ELEMENT: 8000,  # Extended timeout for dynamic elements
    }

    # Patterns indicating dynamic/modal elements that need longer waits
    DYNAMIC_ELEMENT_PATTERNS: frozenset[str] = frozenset({
        "modal", "popup", "dialog", "alert", "toast", "notification",
        "dropdown", "menu", "tooltip", "overlay", "loading", "spinner",
        "cart", "badge", "counter", "collapse", "accordion", "tab",
        "slide", "fade", "animate", "transition",
    })

    # Text-based selectors are more fragile and may need retry
    TEXT_SELECTOR_PREFIX: str = "text="

    def __init__(
        self,
        browser: OwlBrowser,
        default_timeout_ms: int = 10000,
    ) -> None:
        self._browser = browser
        self._default_timeout = default_timeout_ms
        self._log = logger.bind(component="smart_waiter")

    def is_dynamic_selector(self, selector: str) -> bool:
        """
        Determine if a selector targets a likely dynamic element.

        Dynamic elements (modals, alerts, dropdowns) may not be immediately
        visible and require extended wait times with retry logic.
        """
        selector_lower = selector.lower()
        return any(
            pattern in selector_lower
            for pattern in self.DYNAMIC_ELEMENT_PATTERNS
        )

    def is_text_selector(self, selector: str) -> bool:
        """Check if the selector is text-based (text=...)."""
        return selector.startswith(self.TEXT_SELECTOR_PREFIX)

    def get_recommended_strategy(self, selector: str) -> WaitStrategy:
        """
        Get the recommended wait strategy based on selector patterns.

        Args:
            selector: The CSS selector

        Returns:
            Recommended WaitStrategy
        """
        if self.is_dynamic_selector(selector):
            return WaitStrategy.DYNAMIC_ELEMENT
        return WaitStrategy.INTERACTIVE

    async def wait_for_ready(
        self,
        context_id: str,
        strategy: WaitStrategy = WaitStrategy.NETWORK_IDLE,
        timeout_ms: int | None = None,
        selector: str | None = None,
    ) -> WaitResult:
        """
        Wait for page/element to be ready using the specified strategy.

        Args:
            context_id: Browser context ID
            strategy: Wait strategy to use
            timeout_ms: Maximum time to wait
            selector: Optional selector to wait for (for element-specific strategies)

        Returns:
            WaitResult with success status and timing info
        """
        effective_timeout = timeout_ms or self.DEFAULT_TIMEOUTS.get(
            strategy, self._default_timeout
        )

        import time
        start_time = time.monotonic()

        try:
            match strategy:
                case WaitStrategy.IMMEDIATE:
                    # Just a brief pause for rendering
                    await asyncio.sleep(0.05)
                    success = True

                case WaitStrategy.NETWORK_IDLE:
                    success = await self._wait_network_idle(context_id, effective_timeout)

                case WaitStrategy.ANIMATION_COMPLETE:
                    success = await self._wait_animation_complete(context_id, effective_timeout)

                case WaitStrategy.CONTENT_STABLE:
                    success = await self._wait_content_stable(
                        context_id, selector, effective_timeout
                    )

                case WaitStrategy.INTERACTIVE:
                    if selector:
                        success = await self._wait_interactive(
                            context_id, selector, effective_timeout
                        )
                    else:
                        success = await self._wait_network_idle(context_id, effective_timeout)

                case WaitStrategy.DOM_STABLE:
                    success = await self._wait_dom_stable(context_id, effective_timeout)

                case WaitStrategy.DYNAMIC_ELEMENT:
                    # Extended wait with multiple strategies for dynamic elements
                    success = await self._wait_dynamic_element(
                        context_id, selector, effective_timeout
                    )

                case _:
                    success = await self._wait_network_idle(context_id, effective_timeout)

            wait_time = int((time.monotonic() - start_time) * 1000)

            return WaitResult(
                success=success,
                strategy_used=strategy,
                wait_time_ms=wait_time,
                element_ready=success and selector is not None,
            )

        except Exception as e:
            wait_time = int((time.monotonic() - start_time) * 1000)
            self._log.debug(
                "Smart wait failed",
                strategy=strategy,
                error=str(e),
            )
            return WaitResult(
                success=False,
                strategy_used=strategy,
                wait_time_ms=wait_time,
                error=str(e),
            )

    async def _wait_network_idle(self, context_id: str, timeout_ms: int) -> bool:
        """Wait for network to be idle (no pending requests)."""
        try:
            await self._browser.wait_for_network_idle(
                context_id=context_id,
                idle_time=300,
                timeout=timeout_ms,
            )
            return True
        except Exception:
            return False

    async def _wait_animation_complete(self, context_id: str, timeout_ms: int) -> bool:
        """Wait for CSS animations/transitions to complete."""
        # JavaScript to check if any animations are running
        script = """
        (() => {
            const elements = document.querySelectorAll('*');
            for (const el of elements) {
                const style = window.getComputedStyle(el);
                const animationName = style.animationName;
                const transitionDuration = parseFloat(style.transitionDuration);

                if (animationName && animationName !== 'none') {
                    return false;  // Animation in progress
                }
                if (transitionDuration > 0) {
                    // Check if element is transitioning
                    const animations = el.getAnimations();
                    if (animations.length > 0) {
                        return false;
                    }
                }
            }
            return true;  // No animations running
        })()
        """

        start_time = asyncio.get_event_loop().time()
        poll_interval = 0.1  # 100ms

        while (asyncio.get_event_loop().time() - start_time) * 1000 < timeout_ms:
            try:
                result = await self._browser.evaluate(
                    context_id=context_id, expression=script
                )
                is_complete = result.get("result", False) if isinstance(result, dict) else result
                if is_complete:
                    return True
            except Exception:
                pass
            await asyncio.sleep(poll_interval)

        return False

    async def _wait_content_stable(
        self, context_id: str, selector: str | None, timeout_ms: int
    ) -> bool:
        """Wait for content to stop changing."""
        if not selector:
            selector = "body"

        script = f"""
        (() => {{
            const el = document.querySelector('{selector}');
            return el ? el.innerHTML.length : 0;
        }})()
        """

        poll_interval = 0.2  # 200ms
        stability_threshold = 3  # Require 3 consecutive stable reads

        start_time = asyncio.get_event_loop().time()
        last_content_length = -1
        stable_count = 0

        while (asyncio.get_event_loop().time() - start_time) * 1000 < timeout_ms:
            try:
                result = await self._browser.evaluate(
                    context_id=context_id, expression=script
                )
                content_length = result.get("result", 0) if isinstance(result, dict) else result

                if content_length == last_content_length:
                    stable_count += 1
                    if stable_count >= stability_threshold:
                        return True
                else:
                    stable_count = 0
                    last_content_length = content_length

            except Exception:
                pass
            await asyncio.sleep(poll_interval)

        return stable_count > 0

    async def _wait_interactive(
        self, context_id: str, selector: str, timeout_ms: int
    ) -> bool:
        """Wait for element to be fully interactive (visible, enabled, not covered)."""
        try:
            # First wait for selector to exist
            await self._browser.wait_for_selector(
                context_id=context_id,
                selector=selector,
                timeout=timeout_ms,
            )

            # Check visibility
            visibility = await self._browser.is_visible(
                context_id=context_id, selector=selector
            )
            is_visible = (
                visibility.get("visible", False)
                if isinstance(visibility, dict)
                else bool(visibility)
            )

            if not is_visible:
                # Try scrolling into view
                try:
                    await self._browser.scroll_to_element(
                        context_id=context_id, selector=selector
                    )
                    await asyncio.sleep(0.2)
                except Exception:
                    pass

            # Check if element is covered by another element
            is_covered = await self._check_element_covered(context_id, selector)
            if is_covered:
                return False

            return True

        except Exception:
            return False

    async def _wait_dom_stable(self, context_id: str, timeout_ms: int) -> bool:
        """Wait for DOM to stop mutating."""
        script = """
        new Promise((resolve) => {
            let timeout;
            let resolved = false;

            const observer = new MutationObserver(() => {
                clearTimeout(timeout);
                timeout = setTimeout(() => {
                    if (!resolved) {
                        resolved = true;
                        observer.disconnect();
                        resolve(true);
                    }
                }, 300);
            });

            observer.observe(document.body, {
                childList: true,
                subtree: true,
                attributes: true,
            });

            // Start the timer
            timeout = setTimeout(() => {
                if (!resolved) {
                    resolved = true;
                    observer.disconnect();
                    resolve(true);
                }
            }, 300);

            // Failsafe timeout
            setTimeout(() => {
                if (!resolved) {
                    resolved = true;
                    observer.disconnect();
                    resolve(true);
                }
            }, %d);
        })
        """ % timeout_ms

        try:
            result = await self._browser.evaluate(
                context_id=context_id, expression=script
            )
            return bool(result.get("result", False) if isinstance(result, dict) else result)
        except Exception:
            return False

    async def _wait_dynamic_element(
        self, context_id: str, selector: str | None, timeout_ms: int
    ) -> bool:
        """
        Wait for dynamic element with retry and multiple strategies.

        Dynamic elements like modals, alerts, and dropdowns may:
        1. Not be immediately present in DOM
        2. Require animation to complete
        3. Be obscured by overlays initially

        This method uses exponential backoff retry with multiple checks.
        """
        if not selector:
            # If no selector, just do extended network idle wait
            return await self._wait_network_idle(context_id, timeout_ms)

        poll_interval = 0.3  # 300ms initial
        max_polls = 10
        start_time = asyncio.get_event_loop().time()

        for attempt in range(max_polls):
            # Check if timeout exceeded
            elapsed = (asyncio.get_event_loop().time() - start_time) * 1000
            if elapsed >= timeout_ms:
                break

            try:
                # Try to find the element
                remaining_timeout = min(2000, timeout_ms - int(elapsed))
                await self._browser.wait_for_selector(
                    context_id=context_id,
                    selector=selector,
                    timeout=remaining_timeout,
                )

                # Check visibility
                visibility = await self._browser.is_visible(
                    context_id=context_id, selector=selector
                )
                is_visible = (
                    visibility.get("visible", False)
                    if isinstance(visibility, dict)
                    else bool(visibility)
                )

                if is_visible:
                    # Wait a brief moment for any animations
                    await asyncio.sleep(0.1)
                    return True

                # Element exists but not visible - try scrolling
                try:
                    await self._browser.scroll_to_element(
                        context_id=context_id, selector=selector
                    )
                    await asyncio.sleep(0.2)

                    # Re-check visibility
                    visibility = await self._browser.is_visible(
                        context_id=context_id, selector=selector
                    )
                    is_visible = (
                        visibility.get("visible", False)
                        if isinstance(visibility, dict)
                        else bool(visibility)
                    )
                    if is_visible:
                        return True
                except Exception:
                    pass

            except Exception:
                # Element not found yet, continue polling
                pass

            # Exponential backoff with cap
            await asyncio.sleep(min(poll_interval * (1.5 ** attempt), 1.0))

        return False

    async def wait_for_element_with_retry(
        self,
        context_id: str,
        selector: str,
        timeout_ms: int = 10000,
        max_retries: int = 3,
    ) -> bool:
        """
        Wait for element with automatic retry and smart strategy selection.

        Args:
            context_id: Browser context ID
            selector: Element selector
            timeout_ms: Timeout per attempt
            max_retries: Maximum retry attempts

        Returns:
            True if element found and ready, False otherwise
        """
        strategy = self.get_recommended_strategy(selector)

        for attempt in range(max_retries):
            result = await self.wait_for_ready(
                context_id=context_id,
                strategy=strategy,
                timeout_ms=timeout_ms // max_retries,  # Divide timeout across retries
                selector=selector,
            )
            if result.success:
                return True

            # Brief backoff between retries
            if attempt < max_retries - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
                self._log.debug(
                    "Retrying element wait",
                    selector=selector,
                    attempt=attempt + 1,
                    max_retries=max_retries,
                )

        return False

    async def _check_element_covered(self, context_id: str, selector: str) -> bool:
        """Check if an element is covered by another element."""
        script = f"""
        (() => {{
            const el = document.querySelector('{selector}');
            if (!el) return {{ covered: false, error: 'Element not found' }};

            const rect = el.getBoundingClientRect();
            const centerX = rect.left + rect.width / 2;
            const centerY = rect.top + rect.height / 2;

            const elementAtPoint = document.elementFromPoint(centerX, centerY);
            if (!elementAtPoint) return {{ covered: false }};

            // Check if the element at point is the target or a descendant
            if (el.contains(elementAtPoint) || elementAtPoint === el) {{
                return {{ covered: false }};
            }}

            // Element is covered by something else
            return {{
                covered: true,
                blocking_tag: elementAtPoint.tagName,
                blocking_class: elementAtPoint.className,
                blocking_id: elementAtPoint.id,
            }};
        }})()
        """

        try:
            result = await self._browser.evaluate(
                context_id=context_id, expression=script
            )
            data = result.get("result", {}) if isinstance(result, dict) else {}
            return data.get("covered", False) if isinstance(data, dict) else False
        except Exception:
            return False


class OverlayHandler:
    """
    Handles modal/overlay detection and dismissal.

    Modals and overlays often block interactions with underlying elements.
    This class detects and attempts to dismiss blocking overlays.
    """

    # Common selectors for overlay close buttons
    CLOSE_BUTTON_SELECTORS: list[str] = [
        # Standard close buttons
        "button.close",
        ".close-button",
        ".btn-close",
        "[aria-label='Close']",
        "[aria-label='close']",
        "[data-dismiss='modal']",
        "[data-bs-dismiss='modal']",  # Bootstrap 5
        ".modal-close",
        "button[class*='close']",
        # X icons
        ".fa-times",
        ".fa-close",
        "[class*='icon-close']",
        "[class*='icon-x']",
        "svg[class*='close']",
        # Generic patterns
        "button:has(svg[class*='close'])",
        "button:has(.close-icon)",
        # Dialog buttons
        ".dialog-close",
        ".popup-close",
        "[role='dialog'] button[class*='close']",
        # Toast/notification close
        ".toast-close",
        ".notification-close",
        ".alert-close",
        "[class*='dismiss']",
    ]

    # Common selectors for overlay containers
    OVERLAY_SELECTORS: list[str] = [
        # Modals
        ".modal.show",
        ".modal[style*='display: block']",
        "[role='dialog'][aria-modal='true']",
        ".modal-overlay",
        ".modal-backdrop",
        # Popups
        ".popup",
        ".popup-overlay",
        "[data-popup]",
        # Cookie banners
        ".cookie-banner",
        ".cookie-consent",
        "[class*='cookie']",
        "#cookie-notice",
        # Toasts/Alerts
        ".toast",
        ".alert",
        ".notification",
        # Generic overlays
        ".overlay",
        ".backdrop",
        "[class*='overlay']",
    ]

    # Loaders that block interaction
    LOADER_SELECTORS: list[str] = [
        ".loading",
        ".loader",
        ".spinner",
        "[class*='loading']",
        "[class*='spinner']",
        "[aria-busy='true']",
        ".skeleton",
    ]

    def __init__(self, browser: OwlBrowser) -> None:
        self._browser = browser
        self._log = logger.bind(component="overlay_handler")

    async def detect_blocking_overlay(
        self, context_id: str, target_selector: str
    ) -> OverlayInfo | None:
        """
        Detect if target element is blocked by an overlay.

        Args:
            context_id: Browser context ID
            target_selector: Selector of the element we want to interact with

        Returns:
            OverlayInfo if blocked, None otherwise
        """
        # JavaScript to detect blocking overlay
        script = f"""
        (() => {{
            const target = document.querySelector('{target_selector}');
            if (!target) return {{ blocked: false, error: 'Target not found' }};

            const targetRect = target.getBoundingClientRect();
            const centerX = targetRect.left + targetRect.width / 2;
            const centerY = targetRect.top + targetRect.height / 2;

            const elementAtPoint = document.elementFromPoint(centerX, centerY);
            if (!elementAtPoint) return {{ blocked: false }};

            // Check if target is accessible
            if (target.contains(elementAtPoint) || elementAtPoint === target) {{
                return {{ blocked: false }};
            }}

            // Find the blocking overlay
            let blocker = elementAtPoint;
            while (blocker && blocker !== document.body) {{
                const style = window.getComputedStyle(blocker);
                const zIndex = parseInt(style.zIndex) || 0;
                const position = style.position;

                // Check for common overlay patterns
                const classes = blocker.className || '';
                const isModal = blocker.matches('[role="dialog"]') ||
                               classes.includes('modal') ||
                               classes.includes('overlay') ||
                               classes.includes('popup');

                const isBackdrop = classes.includes('backdrop') ||
                                  classes.includes('overlay') ||
                                  style.backgroundColor.includes('rgba');

                if ((position === 'fixed' || position === 'absolute') &&
                    (zIndex > 100 || isModal || isBackdrop)) {{

                    // Try to find close button
                    const closeSelectors = [
                        'button.close', '.close-button', '.btn-close',
                        '[aria-label="Close"]', '[data-dismiss="modal"]',
                        '.modal-close', 'button[class*="close"]'
                    ];

                    let closeSelector = null;
                    for (const sel of closeSelectors) {{
                        const closeBtn = blocker.querySelector(sel);
                        if (closeBtn) {{
                            // Generate a unique selector for the close button
                            if (closeBtn.id) {{
                                closeSelector = '#' + closeBtn.id;
                            }} else if (closeBtn.className) {{
                                closeSelector = '.' + closeBtn.className.split(' ')[0];
                            }} else {{
                                closeSelector = sel;
                            }}
                            break;
                        }}
                    }}

                    return {{
                        blocked: true,
                        overlay_type: isModal ? 'modal' : 'popup',
                        overlay_tag: blocker.tagName,
                        overlay_class: blocker.className,
                        overlay_id: blocker.id,
                        close_selector: closeSelector,
                        z_index: zIndex,
                        can_click_outside: isBackdrop && !isModal,
                    }};
                }}

                blocker = blocker.parentElement;
            }}

            return {{ blocked: false }};
        }})()
        """

        try:
            result = await self._browser.evaluate(
                context_id=context_id, expression=script
            )
            data = result.get("result", {}) if isinstance(result, dict) else {}

            if not isinstance(data, dict) or not data.get("blocked", False):
                return None

            # Determine overlay type
            overlay_type = OverlayType.MODAL
            overlay_class = data.get("overlay_class", "").lower()
            if "popup" in overlay_class:
                overlay_type = OverlayType.POPUP
            elif "toast" in overlay_class or "notification" in overlay_class:
                overlay_type = OverlayType.TOAST
            elif "cookie" in overlay_class:
                overlay_type = OverlayType.COOKIE_BANNER
            elif "loading" in overlay_class or "spinner" in overlay_class:
                overlay_type = OverlayType.LOADER

            # Build selector for the overlay
            if data.get("overlay_id"):
                overlay_selector = f"#{data['overlay_id']}"
            elif data.get("overlay_class"):
                first_class = data["overlay_class"].split()[0]
                overlay_selector = f".{first_class}"
            else:
                overlay_selector = data.get("overlay_tag", "div")

            return OverlayInfo(
                overlay_type=overlay_type,
                selector=overlay_selector,
                dismiss_selector=data.get("close_selector"),
                can_click_outside=data.get("can_click_outside", False),
                z_index=data.get("z_index", 0),
                is_blocking=True,
            )

        except Exception as e:
            self._log.debug("Overlay detection failed", error=str(e))
            return None

    async def dismiss_overlay(
        self, context_id: str, overlay: OverlayInfo
    ) -> bool:
        """
        Attempt to dismiss a detected overlay.

        Tries multiple strategies:
        1. Click close button if found
        2. Click outside (backdrop click) if supported
        3. Press Escape key
        4. Wait for auto-dismiss (for toasts/loaders)

        Returns:
            True if overlay was dismissed, False otherwise
        """
        self._log.info(
            "Attempting to dismiss overlay",
            type=overlay.overlay_type,
            selector=overlay.selector,
        )

        # Strategy 1: Click close button
        if overlay.dismiss_selector:
            try:
                await self._browser.click(
                    context_id=context_id,
                    selector=overlay.dismiss_selector,
                )
                await asyncio.sleep(0.3)

                # Check if overlay is gone
                if not await self._is_overlay_present(context_id, overlay.selector):
                    self._log.info("Overlay dismissed via close button")
                    return True
            except Exception as e:
                self._log.debug("Close button click failed", error=str(e))

        # Strategy 2: Try common close button selectors
        for close_selector in self.CLOSE_BUTTON_SELECTORS:
            try:
                full_selector = f"{overlay.selector} {close_selector}"
                is_visible = await self._browser.is_visible(
                    context_id=context_id, selector=full_selector
                )
                if isinstance(is_visible, dict):
                    is_visible = is_visible.get("visible", False)

                if is_visible:
                    await self._browser.click(
                        context_id=context_id, selector=full_selector
                    )
                    await asyncio.sleep(0.3)

                    if not await self._is_overlay_present(context_id, overlay.selector):
                        self._log.info("Overlay dismissed via common close button")
                        return True
            except Exception:
                continue

        # Strategy 3: Click outside (for popups/dropdowns)
        if overlay.can_click_outside:
            try:
                # Click at a safe position outside the overlay
                await self._browser.evaluate(
                    context_id=context_id,
                    expression="document.body.click()",
                )
                await asyncio.sleep(0.3)

                if not await self._is_overlay_present(context_id, overlay.selector):
                    self._log.info("Overlay dismissed via click outside")
                    return True
            except Exception:
                pass

        # Strategy 4: Press Escape key
        try:
            await self._browser.press_key(context_id=context_id, key="Escape")
            await asyncio.sleep(0.3)

            if not await self._is_overlay_present(context_id, overlay.selector):
                self._log.info("Overlay dismissed via Escape key")
                return True
        except Exception:
            pass

        # Strategy 5: Wait for auto-dismiss (for toasts/loaders)
        if overlay.overlay_type in (OverlayType.TOAST, OverlayType.LOADER):
            # Wait up to 5 seconds for auto-dismiss
            for _ in range(10):
                await asyncio.sleep(0.5)
                if not await self._is_overlay_present(context_id, overlay.selector):
                    self._log.info("Overlay auto-dismissed")
                    return True

        self._log.warning("Could not dismiss overlay", selector=overlay.selector)
        return False

    async def _is_overlay_present(self, context_id: str, selector: str) -> bool:
        """Check if an overlay is still present and visible."""
        try:
            result = await self._browser.is_visible(
                context_id=context_id, selector=selector
            )
            return result.get("visible", False) if isinstance(result, dict) else bool(result)
        except Exception:
            return False

    async def handle_blocking_overlay(
        self, context_id: str, target_selector: str
    ) -> bool:
        """
        Detect and handle any overlay blocking the target element.

        High-level convenience method that combines detection and dismissal.

        Returns:
            True if target is now accessible (either wasn't blocked or overlay was dismissed)
        """
        overlay = await self.detect_blocking_overlay(context_id, target_selector)
        if overlay is None:
            return True  # Not blocked

        return await self.dismiss_overlay(context_id, overlay)


@dataclass
class FallbackSelectorResult:
    """Result of trying fallback selectors."""

    success: bool
    working_selector: str | None = None
    selectors_tried: int = 0
    error: str | None = None


class FallbackSelectorHandler:
    """
    Handles retry with fallback selectors when primary selector fails.

    Uses a scoring system to try selectors in order of reliability.
    """

    def __init__(self, browser: OwlBrowser) -> None:
        self._browser = browser
        self._log = logger.bind(component="fallback_selector")
        # Cache of working selectors for self-healing
        self._selector_cache: dict[str, str] = {}

    async def find_working_selector(
        self,
        context_id: str,
        primary_selector: str,
        fallback_selectors: list[str] | None = None,
        timeout_ms: int = 5000,
    ) -> FallbackSelectorResult:
        """
        Find a working selector from primary and fallback options.

        Args:
            context_id: Browser context ID
            primary_selector: The main selector to try first
            fallback_selectors: Alternative selectors to try if primary fails
            timeout_ms: Timeout for each selector check

        Returns:
            FallbackSelectorResult with working selector if found
        """
        # Check cache first
        if primary_selector in self._selector_cache:
            cached = self._selector_cache[primary_selector]
            if await self._try_selector(context_id, cached, timeout_ms):
                return FallbackSelectorResult(
                    success=True,
                    working_selector=cached,
                    selectors_tried=1,
                )

        all_selectors = [primary_selector] + (fallback_selectors or [])
        selectors_tried = 0

        for selector in all_selectors:
            selectors_tried += 1
            if await self._try_selector(context_id, selector, timeout_ms):
                # Cache the working selector
                if selector != primary_selector:
                    self._selector_cache[primary_selector] = selector
                    self._log.info(
                        "Found working fallback selector",
                        primary=primary_selector,
                        working=selector,
                    )

                return FallbackSelectorResult(
                    success=True,
                    working_selector=selector,
                    selectors_tried=selectors_tried,
                )

        return FallbackSelectorResult(
            success=False,
            selectors_tried=selectors_tried,
            error=f"No working selector found among {selectors_tried} candidates",
        )

    async def _try_selector(
        self, context_id: str, selector: str, timeout_ms: int
    ) -> bool:
        """Test if a selector finds a visible element."""
        try:
            await self._browser.wait_for_selector(
                context_id=context_id,
                selector=selector,
                timeout=min(timeout_ms, 2000),  # Quick check
            )

            result = await self._browser.is_visible(
                context_id=context_id, selector=selector
            )
            return result.get("visible", False) if isinstance(result, dict) else bool(result)
        except Exception:
            return False

    def clear_cache(self) -> None:
        """Clear the selector cache."""
        self._selector_cache.clear()


# Convenience function to create all intelligent layer components
def create_intelligent_runner_layer(
    browser: OwlBrowser,
    default_timeout_ms: int = 10000,
) -> tuple[SmartWaiter, OverlayHandler, FallbackSelectorHandler]:
    """
    Create all intelligent layer components for the test runner.

    Returns:
        Tuple of (SmartWaiter, OverlayHandler, FallbackSelectorHandler)
    """
    return (
        SmartWaiter(browser, default_timeout_ms),
        OverlayHandler(browser),
        FallbackSelectorHandler(browser),
    )
