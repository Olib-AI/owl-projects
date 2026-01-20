"""
Visibility analyzer for intelligent element discovery.

This module determines which DOM elements are actually visible and interactable
on the current page, filtering out hidden modals, collapsed tabs, and other
non-visible content that should not be tested until revealed.

The visibility analysis uses multiple signals:
- CSS computed styles (display, visibility, opacity)
- Bounding box dimensions
- Viewport intersection
- ARIA hidden states
- Parent visibility chain
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from owl_browser import OwlBrowser

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


class VisibilityState(StrEnum):
    """Visibility state of an element."""

    VISIBLE = auto()
    """Element is fully visible and interactable."""

    HIDDEN_CSS = auto()
    """Hidden via CSS (display: none, visibility: hidden, opacity: 0)."""

    HIDDEN_DIMENSIONS = auto()
    """Element has zero width or height."""

    HIDDEN_ARIA = auto()
    """Hidden via aria-hidden attribute."""

    HIDDEN_OVERFLOW = auto()
    """Hidden due to parent overflow clipping."""

    HIDDEN_OFFSCREEN = auto()
    """Element is positioned off-screen."""

    HIDDEN_PARENT = auto()
    """Element is hidden because a parent is hidden."""

    COLLAPSED = auto()
    """Element is in a collapsed container (accordion, details)."""

    IN_CLOSED_MODAL = auto()
    """Element is inside a modal that is not currently open."""

    IN_INACTIVE_TAB = auto()
    """Element is inside an inactive tab panel."""


class ElementCategory(StrEnum):
    """Category of element for interaction planning."""

    TRIGGER = auto()
    """Element that triggers visibility of other elements (buttons that open modals)."""

    CONTENT = auto()
    """Standard content element (text, images)."""

    FORM_INPUT = auto()
    """Form input element."""

    NAVIGATION = auto()
    """Navigation element."""

    MODAL = auto()
    """Modal or dialog element."""

    TAB_PANEL = auto()
    """Tab panel content."""

    ACCORDION_CONTENT = auto()
    """Accordion or collapsible content."""

    DROPDOWN_CONTENT = auto()
    """Dropdown menu content."""


@dataclass
class ElementState:
    """Complete state information for an element."""

    selector: str
    """CSS selector for the element."""

    tag_name: str
    """HTML tag name."""

    visibility_state: VisibilityState
    """Current visibility state."""

    is_interactable: bool
    """Whether element can be interacted with."""

    category: ElementCategory
    """Element category for planning."""

    bounding_box: dict[str, float] | None = None
    """Element position and dimensions."""

    computed_styles: dict[str, str] = field(default_factory=dict)
    """Key computed CSS styles."""

    attributes: dict[str, str] = field(default_factory=dict)
    """Element attributes."""

    text_content: str | None = None
    """Text content (truncated)."""

    aria_label: str | None = None
    """ARIA label if present."""

    parent_selector: str | None = None
    """Selector for parent element."""

    trigger_selector: str | None = None
    """If hidden, selector of element that reveals this."""

    reveals_elements: list[str] = field(default_factory=list)
    """If trigger, selectors of elements this reveals."""

    container_type: str | None = None
    """Type of container (modal, tab-panel, accordion, etc.)."""

    raw_data: dict[str, Any] = field(default_factory=dict)
    """Raw element data from browser."""


@dataclass
class VisibilityAnalysisResult:
    """Result of visibility analysis for a page."""

    url: str
    """Page URL."""

    visible_elements: list[ElementState]
    """Currently visible and interactable elements."""

    hidden_elements: list[ElementState]
    """Elements that exist but are currently hidden."""

    triggers: list[ElementState]
    """Elements that can reveal hidden content."""

    modals: list[ElementState]
    """Modal/dialog elements (visible or hidden)."""

    tab_panels: list[ElementState]
    """Tab panel elements."""

    accordion_sections: list[ElementState]
    """Accordion/collapsible sections."""

    total_elements: int
    """Total elements discovered."""

    visible_count: int
    """Count of visible elements."""

    hidden_count: int
    """Count of hidden elements."""


class VisibilityAnalyzer:
    """
    Analyzes which elements are actually visible and interactable.

    This analyzer uses JavaScript evaluation to determine the true visibility
    state of elements, accounting for:
    - CSS styles (display, visibility, opacity)
    - Element dimensions
    - Viewport position
    - ARIA hidden attributes
    - Parent element visibility
    - Modal/tab/accordion states
    """

    # JavaScript code for comprehensive visibility analysis
    VISIBILITY_SCRIPT: str = """
    (() => {
        const results = {
            elements: [],
            triggers: [],
            modals: [],
            tabPanels: [],
            accordions: []
        };

        const seen = new Set();

        // Check if element is visible via CSS
        function isVisibleViaCSS(el) {
            const style = window.getComputedStyle(el);
            return style.display !== 'none' &&
                   style.visibility !== 'hidden' &&
                   parseFloat(style.opacity) > 0;
        }

        // Check if element has dimensions
        function hasDimensions(el) {
            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0;
        }

        // Check if element is in viewport or near it
        function isInViewportArea(el) {
            const rect = el.getBoundingClientRect();
            const viewHeight = window.innerHeight;
            const viewWidth = window.innerWidth;
            // Consider elements within 2x viewport as potentially visible
            return !(rect.bottom < -viewHeight || rect.top > viewHeight * 2 ||
                     rect.right < -viewWidth || rect.left > viewWidth * 2);
        }

        // Check parent chain visibility
        function isParentChainVisible(el) {
            let parent = el.parentElement;
            while (parent && parent !== document.body) {
                const style = window.getComputedStyle(parent);
                if (style.display === 'none' || style.visibility === 'hidden') {
                    return false;
                }
                // Check aria-hidden on parents
                if (parent.getAttribute('aria-hidden') === 'true') {
                    return false;
                }
                parent = parent.parentElement;
            }
            return true;
        }

        // Detect if element is inside a modal
        function getModalContainer(el) {
            let parent = el.parentElement;
            while (parent && parent !== document.body) {
                const role = parent.getAttribute('role');
                const classes = (parent.className || '').toLowerCase();
                const id = (parent.id || '').toLowerCase();

                if (role === 'dialog' || role === 'alertdialog' ||
                    classes.includes('modal') || classes.includes('dialog') ||
                    id.includes('modal') || id.includes('dialog')) {
                    return parent;
                }
                parent = parent.parentElement;
            }
            return null;
        }

        // Detect if element is inside a tab panel
        function getTabPanel(el) {
            let parent = el.parentElement;
            while (parent && parent !== document.body) {
                const role = parent.getAttribute('role');
                const ariaHidden = parent.getAttribute('aria-hidden');
                const classes = (parent.className || '').toLowerCase();

                if (role === 'tabpanel' || classes.includes('tab-pane') ||
                    classes.includes('tabpanel') || parent.hasAttribute('data-tab-content')) {
                    return {
                        element: parent,
                        isActive: ariaHidden !== 'true' && !classes.includes('hidden')
                    };
                }
                parent = parent.parentElement;
            }
            return null;
        }

        // Detect if element is inside an accordion
        function getAccordionPanel(el) {
            let parent = el.parentElement;
            while (parent && parent !== document.body) {
                const classes = (parent.className || '').toLowerCase();

                const isAccordion = classes.includes('accordion-content') ||
                    classes.includes('collapse') || classes.includes('collapsible') ||
                    parent.hasAttribute('data-accordion-content');
                if (isAccordion) {
                    const isExpanded = classes.includes('show') || classes.includes('expanded') ||
                                       parent.getAttribute('aria-expanded') === 'true';
                    return {
                        element: parent,
                        isExpanded: isExpanded
                    };
                }
                parent = parent.parentElement;
            }
            return null;
        }

        // Generate unique selector for element
        // PRIORITY ORDER: ID > data-testid > name > aria-label > type+placeholder > short path
        function generateSelector(el) {
            const tag = el.tagName.toLowerCase();

            // 1. ID selector - always unique and reliable
            if (el.id) return '#' + el.id;

            // 2. data-testid, data-test, data-cy - testing best practices
            if (el.dataset.testid) {
                return `[data-testid="${el.dataset.testid}"]`;
            }
            if (el.dataset.test) {
                return `[data-test="${el.dataset.test}"]`;
            }
            if (el.dataset.cy) {
                return `[data-cy="${el.dataset.cy}"]`;
            }

            // 3. name attribute - reliable for form elements
            if (el.name) {
                return `${tag}[name="${el.name}"]`;
            }

            // 4. aria-label - good for accessible elements
            const ariaLabel = el.getAttribute('aria-label');
            if (ariaLabel && ariaLabel.length <= 50) {
                return `${tag}[aria-label="${ariaLabel}"]`;
            }

            // 5. For inputs: type + placeholder combination
            if (tag === 'input' && el.type && el.placeholder) {
                return `input[type="${el.type}"][placeholder="${el.placeholder}"]`;
            }

            // 6. For buttons/links: try text content if short and unique-ish
            const text = (el.innerText || '').trim();
            if ((tag === 'button' || tag === 'a') && text && text.length <= 25 &&
                !text.includes('\n') && !/['"\[\]]/.test(text)) {
                // Use text= selector for short, clean text
                return `text=${text}`;
            }

            // 7. For links: href path selector
            if (tag === 'a' && el.href) {
                try {
                    const url = new URL(el.href, window.location.origin);
                    const path = url.pathname;
                    if (path && path !== '/') {
                        return `a[href*="${path}"]`;
                    }
                } catch(e) {}
            }

            // 8. Simple class-based selector (max 2 levels deep)
            // Find the closest parent with ID and build from there
            let parent = el.parentElement;
            let parentWithId = null;
            let depth = 0;
            while (parent && parent !== document.body && depth < 3) {
                if (parent.id) {
                    parentWithId = parent;
                    break;
                }
                depth++;
                parent = parent.parentElement;
            }

            // Get meaningful class for the element
            const getMeaningfulClass = (elem) => {
                if (!elem.className || typeof elem.className !== 'string') return null;
                const classes = elem.className.split(' ').filter(c =>
                    c && c.length > 2 &&
                    !c.match(/^(active|show|hidden|visible|open|closed|disabled|enabled|selected|focus|hover|m-|p-|d-|w-|h-|col-|row)/i)
                );
                return classes.length > 0 ? classes[0] : null;
            };

            const elClass = getMeaningfulClass(el);

            // Build short selector: prefer #parentId .class or just .class
            // NOTE: SDK bug - is_visible doesn't work with tag.class (e.g., button.btn)
            // but works with just .class - so we omit the tag name
            if (parentWithId) {
                if (elClass) {
                    return `#${parentWithId.id} .${elClass}`;
                }
                return `#${parentWithId.id} ${tag}`;
            }

            // No parent with ID found - use direct class selector with nth-of-type if needed
            // NOTE: Using .class instead of tag.class due to SDK is_visible bug
            if (elClass) {
                const siblings = document.querySelectorAll(`.${elClass}`);
                if (siblings.length === 1) {
                    return `.${elClass}`;
                }
                // Multiple matches - add nth-of-type
                const idx = Array.from(siblings).indexOf(el) + 1;
                if (idx > 0) {
                    return `.${elClass}:nth-of-type(${idx})`;
                }
                return `.${elClass}`;
            }

            // 9. Last resort: tag with nth-of-type
            const allSameTags = document.querySelectorAll(tag);
            const tagIdx = Array.from(allSameTags).indexOf(el) + 1;
            if (tagIdx > 0 && allSameTags.length > 1) {
                return `${tag}:nth-of-type(${tagIdx})`;
            }

            return tag;
        }

        // Determine visibility state
        function getVisibilityState(el) {
            const style = window.getComputedStyle(el);

            // CSS hidden
            if (style.display === 'none') return 'hidden_css';
            if (style.visibility === 'hidden') return 'hidden_css';
            if (parseFloat(style.opacity) === 0) return 'hidden_css';

            // ARIA hidden
            if (el.getAttribute('aria-hidden') === 'true') return 'hidden_aria';

            // Zero dimensions
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) return 'hidden_dimensions';

            // Off screen
            const viewHeight = window.innerHeight;
            const viewWidth = window.innerWidth;
            if (rect.bottom < -100 || rect.top > viewHeight + 100 ||
                rect.right < -100 || rect.left > viewWidth + 100) {
                return 'hidden_offscreen';
            }

            // Check modal container
            const modal = getModalContainer(el);
            if (modal) {
                const modalStyle = window.getComputedStyle(modal);
                if (modalStyle.display === 'none' || modalStyle.visibility === 'hidden') {
                    return 'in_closed_modal';
                }
            }

            // Check tab panel
            const tabPanel = getTabPanel(el);
            if (tabPanel && !tabPanel.isActive) {
                return 'in_inactive_tab';
            }

            // Check accordion
            const accordion = getAccordionPanel(el);
            if (accordion && !accordion.isExpanded) {
                return 'collapsed';
            }

            // Check parent visibility
            if (!isParentChainVisible(el)) {
                return 'hidden_parent';
            }

            return 'visible';
        }

        // Detect element category
        function getElementCategory(el) {
            const tag = el.tagName.toLowerCase();
            const role = el.getAttribute('role') || '';
            const classes = (el.className || '').toLowerCase();
            const toggle1 = el.getAttribute('data-toggle') || '';
            const toggle2 = el.getAttribute('data-bs-toggle') || '';
            const dataToggle = toggle1 || toggle2;
            const ariaExpanded = el.hasAttribute('aria-expanded');
            const ariaControls = el.getAttribute('aria-controls') || '';

            // Triggers - elements that reveal other content
            const isTriggerToggle = ['modal', 'collapse', 'tab', 'dropdown'].includes(dataToggle);
            if (isTriggerToggle || ariaExpanded || ariaControls) {
                return 'trigger';
            }

            // Modal elements
            if (role === 'dialog' || role === 'alertdialog' ||
                classes.includes('modal') || classes.includes('dialog')) {
                return 'modal';
            }

            // Tab panels
            const isTabPanel = role === 'tabpanel' ||
                classes.includes('tab-pane') || classes.includes('tabpanel');
            if (isTabPanel) {
                return 'tab_panel';
            }

            // Accordion content
            if (classes.includes('accordion-content') || classes.includes('collapse') ||
                classes.includes('collapsible')) {
                return 'accordion_content';
            }

            // Dropdown content
            if (classes.includes('dropdown-menu') || classes.includes('dropdown-content') ||
                role === 'menu' || role === 'listbox') {
                return 'dropdown_content';
            }

            // Form inputs
            if (tag === 'input' || tag === 'textarea' || tag === 'select' ||
                role === 'textbox' || role === 'combobox') {
                return 'form_input';
            }

            // Navigation
            if (tag === 'nav' || role === 'navigation' || tag === 'a' ||
                classes.includes('nav') || role === 'link') {
                return 'navigation';
            }

            return 'content';
        }

        // Find what element triggers this hidden element
        function findTrigger(hiddenEl) {
            // Check aria-controls pointing to this element
            if (hiddenEl.id) {
                const trigger = document.querySelector(`[aria-controls="${hiddenEl.id}"]`);
                if (trigger) return generateSelector(trigger);

                // Check data-target
                const targetTrigger = document.querySelector(`[data-target="#${hiddenEl.id}"]`) ||
                                       document.querySelector(`[data-bs-target="#${hiddenEl.id}"]`);
                if (targetTrigger) return generateSelector(targetTrigger);

                // Check href
                const hrefTrigger = document.querySelector(`[href="#${hiddenEl.id}"]`);
                if (hrefTrigger) return generateSelector(hrefTrigger);
            }

            // For modals, look for modal trigger buttons
            const modal = getModalContainer(hiddenEl);
            if (modal && modal.id) {
                const modalTrigger = document.querySelector(`[data-target="#${modal.id}"]`) ||
                                      document.querySelector(`[data-bs-target="#${modal.id}"]`) ||
                                      document.querySelector(`[aria-controls="${modal.id}"]`);
                if (modalTrigger) return generateSelector(modalTrigger);
            }

            return null;
        }

        // Process all interactive elements
        const interactiveSelectors = [
            'button', 'a[href]', 'input', 'select', 'textarea',
            '[role="button"]', '[role="link"]', '[role="tab"]',
            '[role="menuitem"]', '[role="option"]', '[role="checkbox"]',
            '[role="radio"]', '[role="switch"]', '[role="textbox"]',
            '[onclick]', '[data-toggle]', '[data-bs-toggle]',
            '[aria-expanded]', '[aria-controls]'
        ];

        const allElements = document.querySelectorAll(interactiveSelectors.join(','));

        for (const el of allElements) {
            const selector = generateSelector(el);
            if (seen.has(selector)) continue;
            seen.add(selector);

            const visibilityState = getVisibilityState(el);
            const category = getElementCategory(el);
            const rect = el.getBoundingClientRect();

            // Get select options for select elements
            let selectOptions = null;
            if (el.tagName.toLowerCase() === 'select') {
                selectOptions = [];
                for (const opt of el.options) {
                    if (opt.value) {  // Skip empty placeholder options
                        selectOptions.push({
                            value: opt.value,
                            text: opt.text,
                            selected: opt.selected
                        });
                    }
                }
                // Keep only first 10 options
                selectOptions = selectOptions.slice(0, 10);
            }

            const elementData = {
                selector: selector,
                tagName: el.tagName.toLowerCase(),
                visibilityState: visibilityState,
                isInteractable: visibilityState === 'visible' && !el.disabled,
                category: category,
                boundingBox: {
                    x: rect.x,
                    y: rect.y,
                    width: rect.width,
                    height: rect.height
                },
                textContent: (el.innerText || '').trim().substring(0, 100),
                ariaLabel: el.getAttribute('aria-label'),
                id: el.id || null,
                name: el.name || null,
                type: el.type || null,
                href: el.href || null,
                placeholder: el.placeholder || null,
                required: el.required || false,
                disabled: el.disabled || false,
                ariaExpanded: el.getAttribute('aria-expanded'),
                ariaControls: el.getAttribute('aria-controls'),
                dataToggle: el.getAttribute('data-toggle') || el.getAttribute('data-bs-toggle'),
                dataTarget: el.getAttribute('data-target') || el.getAttribute('data-bs-target'),
                selectOptions: selectOptions
            };

            // Find trigger for hidden elements
            if (visibilityState !== 'visible') {
                elementData.triggerSelector = findTrigger(el);
            }

            // For triggers, find what they reveal
            if (category === 'trigger') {
                const controls = el.getAttribute('aria-controls');
                const target = el.getAttribute('data-target') || el.getAttribute('data-bs-target');
                const reveals = [];

                if (controls) {
                    const controlled = document.getElementById(controls);
                    if (controlled) reveals.push(generateSelector(controlled));
                }
                if (target) {
                    try {
                        const targeted = document.querySelector(target);
                        if (targeted) reveals.push(generateSelector(targeted));
                    } catch(e) {}
                }
                elementData.revealsElements = reveals;
            }

            results.elements.push(elementData);

            // Categorize
            if (category === 'trigger') {
                results.triggers.push(elementData);
            } else if (category === 'modal') {
                results.modals.push(elementData);
            } else if (category === 'tab_panel') {
                results.tabPanels.push(elementData);
            } else if (category === 'accordion_content') {
                results.accordions.push(elementData);
            }
        }

        return results;
    })()
    """

    def __init__(self) -> None:
        """Initialize the visibility analyzer."""
        self._log = logger.bind(component="visibility_analyzer")

    async def analyze(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> VisibilityAnalysisResult:
        """
        Analyze visibility of all interactive elements on the page.

        Args:
            browser: Browser instance
            context_id: Browser context ID

        Returns:
            Complete visibility analysis result
        """
        self._log.info("Starting visibility analysis", context_id=context_id)

        # Get page URL
        page_info = await browser.get_page_info(context_id=context_id)
        url = page_info.get("url", "") if isinstance(page_info, dict) else ""

        try:
            # Execute visibility analysis script
            result = await browser.evaluate(
                context_id=context_id, expression=self.VISIBILITY_SCRIPT
            )
            # SDK returns the evaluated expression directly (not wrapped in "result" key)
            raw_data = result

            if not raw_data or not isinstance(raw_data, dict):
                self._log.warning("No visibility data returned")
                return VisibilityAnalysisResult(
                    url=url,
                    visible_elements=[],
                    hidden_elements=[],
                    triggers=[],
                    modals=[],
                    tab_panels=[],
                    accordion_sections=[],
                    total_elements=0,
                    visible_count=0,
                    hidden_count=0,
                )

            # Process elements
            visible_elements: list[ElementState] = []
            hidden_elements: list[ElementState] = []
            triggers: list[ElementState] = []
            modals: list[ElementState] = []
            tab_panels: list[ElementState] = []
            accordions: list[ElementState] = []

            for raw_el in raw_data.get("elements", []):
                element_state = self._process_element(raw_el)

                if element_state.visibility_state == VisibilityState.VISIBLE:
                    visible_elements.append(element_state)
                else:
                    hidden_elements.append(element_state)

                # Categorize special elements
                if element_state.category == ElementCategory.TRIGGER:
                    triggers.append(element_state)
                elif element_state.category == ElementCategory.MODAL:
                    modals.append(element_state)
                elif element_state.category == ElementCategory.TAB_PANEL:
                    tab_panels.append(element_state)
                elif element_state.category == ElementCategory.ACCORDION_CONTENT:
                    accordions.append(element_state)

            analysis_result = VisibilityAnalysisResult(
                url=url,
                visible_elements=visible_elements,
                hidden_elements=hidden_elements,
                triggers=triggers,
                modals=modals,
                tab_panels=tab_panels,
                accordion_sections=accordions,
                total_elements=len(visible_elements) + len(hidden_elements),
                visible_count=len(visible_elements),
                hidden_count=len(hidden_elements),
            )

            self._log.info(
                "Visibility analysis complete",
                total=analysis_result.total_elements,
                visible=analysis_result.visible_count,
                hidden=analysis_result.hidden_count,
                triggers=len(triggers),
                modals=len(modals),
            )

            return analysis_result

        except Exception as e:
            self._log.error("Visibility analysis failed", error=str(e))
            return VisibilityAnalysisResult(
                url=url,
                visible_elements=[],
                hidden_elements=[],
                triggers=[],
                modals=[],
                tab_panels=[],
                accordion_sections=[],
                total_elements=0,
                visible_count=0,
                hidden_count=0,
            )

    async def get_visible_elements(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> list[ElementState]:
        """
        Get only the currently visible and interactable elements.

        Args:
            browser: Browser instance
            context_id: Browser context ID

        Returns:
            List of visible element states
        """
        result = await self.analyze(browser, context_id)
        return result.visible_elements

    async def get_hidden_elements(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> list[ElementState]:
        """
        Get elements that exist in DOM but are currently hidden.

        Args:
            browser: Browser instance
            context_id: Browser context ID

        Returns:
            List of hidden element states
        """
        result = await self.analyze(browser, context_id)
        return result.hidden_elements

    async def is_element_visible(
        self,
        browser: OwlBrowser,
        context_id: str,
        selector: str,
    ) -> bool:
        """
        Check if a specific element is currently visible.

        SDK Enhancement: Uses browser_is_visible for reliable visibility checking.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            selector: CSS selector for the element

        Returns:
            True if element is visible, False otherwise
        """
        # TRY SDK-NATIVE VISIBILITY CHECK FIRST
        # browser_is_visible is more reliable and handles edge cases better
        try:
            visibility_result = await browser.is_visible(
                context_id=context_id, selector=selector
            )
            return _extract_sdk_bool(visibility_result, default=False)
        except Exception as sdk_error:
            self._log.debug(
                "SDK is_visible failed, falling back to JS",
                selector=selector,
                error=str(sdk_error),
            )

        # FALLBACK: JavaScript-based visibility check
        escaped_selector = selector.replace("'", "\\'").replace('"', '\\"')

        script = f"""
        (() => {{
            const el = document.querySelector('{escaped_selector}');
            if (!el) return {{ found: false, visible: false }};

            const style = window.getComputedStyle(el);
            const rect = el.getBoundingClientRect();

            const visible = style.display !== 'none' &&
                           style.visibility !== 'hidden' &&
                           parseFloat(style.opacity) > 0 &&
                           rect.width > 0 &&
                           rect.height > 0 &&
                           el.getAttribute('aria-hidden') !== 'true';

            return {{ found: true, visible: visible }};
        }})()
        """

        try:
            result = await browser.evaluate(context_id=context_id, expression=script)
            data = result

            if isinstance(data, dict):
                return data.get("visible", False)
            return False

        except Exception as e:
            self._log.debug("Visibility check failed", selector=selector, error=str(e))
            return False

    async def wait_for_visible(
        self,
        browser: OwlBrowser,
        context_id: str,
        selector: str,
        timeout_ms: int = 5000,
        poll_interval_ms: int = 100,  # noqa: ARG002 - kept for API compatibility
    ) -> bool:
        """
        Wait for an element to become visible.

        SDK Enhancement: Uses browser_wait_for_selector for efficient waiting.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            selector: CSS selector for the element
            timeout_ms: Maximum wait time in milliseconds
            poll_interval_ms: Polling interval (ignored - SDK handles internally)

        Returns:
            True if element became visible, False if timed out
        """
        # TRY SDK-NATIVE WAIT_FOR_SELECTOR FIRST
        # This is more efficient than polling as it uses browser-level waiting
        try:
            await browser.wait_for_selector(
                context_id=context_id,
                selector=selector,
                timeout=timeout_ms,
            )
            return True
        except Exception as sdk_error:
            self._log.debug(
                "SDK wait_for_selector failed, falling back to polling",
                selector=selector,
                error=str(sdk_error),
            )

        # FALLBACK: Manual polling (original implementation)
        import asyncio

        elapsed = 0
        poll_interval = 100  # ms
        while elapsed < timeout_ms:
            if await self.is_element_visible(browser, context_id, selector):
                return True
            await asyncio.sleep(poll_interval / 1000)
            elapsed += poll_interval

        return False

    def _process_element(self, raw: dict[str, Any]) -> ElementState:
        """Process raw element data into ElementState."""
        # Map visibility state string to enum
        visibility_map = {
            "visible": VisibilityState.VISIBLE,
            "hidden_css": VisibilityState.HIDDEN_CSS,
            "hidden_dimensions": VisibilityState.HIDDEN_DIMENSIONS,
            "hidden_aria": VisibilityState.HIDDEN_ARIA,
            "hidden_offscreen": VisibilityState.HIDDEN_OFFSCREEN,
            "hidden_parent": VisibilityState.HIDDEN_PARENT,
            "collapsed": VisibilityState.COLLAPSED,
            "in_closed_modal": VisibilityState.IN_CLOSED_MODAL,
            "in_inactive_tab": VisibilityState.IN_INACTIVE_TAB,
        }

        visibility_str = raw.get("visibilityState", "hidden_css")
        visibility_state = visibility_map.get(visibility_str, VisibilityState.HIDDEN_CSS)

        # Map category string to enum
        category_map = {
            "trigger": ElementCategory.TRIGGER,
            "content": ElementCategory.CONTENT,
            "form_input": ElementCategory.FORM_INPUT,
            "navigation": ElementCategory.NAVIGATION,
            "modal": ElementCategory.MODAL,
            "tab_panel": ElementCategory.TAB_PANEL,
            "accordion_content": ElementCategory.ACCORDION_CONTENT,
            "dropdown_content": ElementCategory.DROPDOWN_CONTENT,
        }

        category_str = raw.get("category", "content")
        category = category_map.get(category_str, ElementCategory.CONTENT)

        # Build attributes dict
        attributes: dict[str, str] = {}
        for key in ("id", "name", "type", "href", "placeholder"):
            if raw.get(key):
                attributes[key] = str(raw[key])

        return ElementState(
            selector=raw.get("selector", ""),
            tag_name=raw.get("tagName", "div"),
            visibility_state=visibility_state,
            is_interactable=raw.get("isInteractable", False),
            category=category,
            bounding_box=raw.get("boundingBox"),
            attributes=attributes,
            text_content=raw.get("textContent"),
            aria_label=raw.get("ariaLabel"),
            trigger_selector=raw.get("triggerSelector"),
            reveals_elements=raw.get("revealsElements", []),
            raw_data=raw,
        )


# Convenience functions for standalone use
async def get_visible_elements(
    browser: OwlBrowser,
    context_id: str,
) -> list[ElementState]:
    """Get visible elements using default analyzer."""
    analyzer = VisibilityAnalyzer()
    return await analyzer.get_visible_elements(browser, context_id)


async def get_hidden_elements(
    browser: OwlBrowser,
    context_id: str,
) -> list[ElementState]:
    """Get hidden elements using default analyzer."""
    analyzer = VisibilityAnalyzer()
    return await analyzer.get_hidden_elements(browser, context_id)


async def is_visible(
    browser: OwlBrowser,
    context_id: str,
    selector: str,
) -> bool:
    """Check element visibility using default analyzer."""
    analyzer = VisibilityAnalyzer()
    return await analyzer.is_element_visible(browser, context_id, selector)
