"""
Intelligent layer for the test builder providing smart element classification
and selector reliability scoring.

Provides:
- Element category classification with testing strategies
- Selector reliability scoring
- Page type detection
- State-aware assertion generation hints

SDK v2 Notes:
- All methods support async operations
- Designed to integrate with AutoTestBuilder
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from enum import IntEnum, StrEnum
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


class ElementCategory(StrEnum):
    """Element categories with different testing strategies."""

    NAVIGATION = "navigation"  # Links, nav items - just verify clickable
    FORM_INPUT = "form_input"  # Inputs, textareas - test with sample data
    FORM_SUBMIT = "form_submit"  # Submit buttons - test form flow
    ACTION_BUTTON = "action_button"  # Buttons that trigger actions (modals, state changes)
    TOGGLE = "toggle"  # Checkboxes, switches, accordions
    DISPLAY_ONLY = "display_only"  # Static content, labels - skip or minimal test
    DYNAMIC_CONTENT = "dynamic"  # Elements that change (counters, live data)
    DROPDOWN = "dropdown"  # Select elements, custom dropdowns
    FILE_UPLOAD = "file_upload"  # File input elements
    SEARCH = "search"  # Search inputs
    DATE_PICKER = "date_picker"  # Date/time inputs
    RICH_TEXT = "rich_text"  # Textareas, content editable
    INTERACTIVE_MEDIA = "media"  # Video controls, audio players
    DATA_TABLE = "data_table"  # Tables with sortable/filterable content
    MODAL_TRIGGER = "modal_trigger"  # Buttons that trigger modals/dialogs
    MODAL_CONTENT = "modal_content"  # Elements inside modals (skip assertions)
    TOAST_NOTIFICATION = "toast"  # Toast/alert/notification elements (skip)
    ANIMATION_ELEMENT = "animation"  # Elements with animation classes (careful)


class WaitStrategyHint(StrEnum):
    """Suggested wait strategy for element category."""

    IMMEDIATE = "immediate"  # Element should be there immediately
    NETWORK_IDLE = "network_idle"  # Wait for XHR/fetch
    ANIMATION = "animation"  # Wait for CSS transitions
    CONTENT_STABLE = "content_stable"  # Wait for content to stop changing
    INTERACTIVE = "interactive"  # Wait until clickable


class AssertionTypeHint(StrEnum):
    """Suggested assertion type for element category."""

    VISIBILITY = "visibility"  # Just check element is visible
    CLICKABLE = "clickable"  # Check element is clickable
    VALUE_CHECK = "value_check"  # Check element has expected value
    STATE_CHANGE = "state_change"  # Check for state change after interaction
    COUNT = "count"  # Check element count
    TEXT_CONTENT = "text_content"  # Check text content


class InteractionHint(StrEnum):
    """Suggested interaction type for element category."""

    CLICK = "click"
    TYPE = "type"
    SELECT = "select"
    TOGGLE = "toggle"
    UPLOAD = "upload"
    HOVER = "hover"
    OBSERVE_ONLY = "observe_only"  # Just observe, don't interact
    SCROLL_INTO_VIEW = "scroll"


@dataclass
class ElementCategoryInfo:
    """Information about an element's category and testing strategy."""

    category: ElementCategory
    wait_strategy: WaitStrategyHint
    assertion_type: AssertionTypeHint
    interaction: InteractionHint
    should_interact: bool = True
    priority_score: float = 0.5  # 0-1, higher = more important to test
    may_trigger_navigation: bool = False
    may_trigger_modal: bool = False
    may_change_state: bool = False
    sample_data_type: str | None = None  # For form inputs


@dataclass
class SelectorReliabilityScore:
    """Reliability score and analysis for a selector."""

    selector: str
    score: float  # 0-1, higher = more reliable
    strategy_used: str  # What type of selector (id, data-testid, text, etc.)
    is_unique: bool = True
    stability_notes: list[str] = field(default_factory=list)
    fallback_selectors: list[str] = field(default_factory=list)


class PageType(StrEnum):
    """Detected page types for strategy adjustment."""

    LOGIN = "login"
    REGISTRATION = "registration"
    LIST_TABLE = "list_table"
    FORM = "form"
    DASHBOARD = "dashboard"
    DETAIL = "detail"
    SEARCH_RESULTS = "search_results"
    CHECKOUT = "checkout"
    PROFILE = "profile"
    SETTINGS = "settings"
    ERROR = "error"
    LANDING = "landing"
    UNKNOWN = "unknown"


@dataclass
class PageTypeInfo:
    """Information about detected page type."""

    page_type: PageType
    confidence: float
    indicators: list[str]
    suggested_flow: str | None = None


# Category configuration mapping
CATEGORY_CONFIG: dict[ElementCategory, ElementCategoryInfo] = {
    ElementCategory.NAVIGATION: ElementCategoryInfo(
        category=ElementCategory.NAVIGATION,
        wait_strategy=WaitStrategyHint.IMMEDIATE,
        assertion_type=AssertionTypeHint.CLICKABLE,
        interaction=InteractionHint.CLICK,
        should_interact=False,  # Just verify, don't click during test generation
        priority_score=0.3,
        may_trigger_navigation=True,
    ),
    ElementCategory.FORM_INPUT: ElementCategoryInfo(
        category=ElementCategory.FORM_INPUT,
        wait_strategy=WaitStrategyHint.INTERACTIVE,
        assertion_type=AssertionTypeHint.VALUE_CHECK,
        interaction=InteractionHint.TYPE,
        should_interact=True,
        priority_score=0.8,
        sample_data_type="text",
    ),
    ElementCategory.FORM_SUBMIT: ElementCategoryInfo(
        category=ElementCategory.FORM_SUBMIT,
        wait_strategy=WaitStrategyHint.NETWORK_IDLE,
        assertion_type=AssertionTypeHint.STATE_CHANGE,
        interaction=InteractionHint.CLICK,
        should_interact=True,
        priority_score=0.9,
        may_trigger_navigation=True,
        may_change_state=True,
    ),
    ElementCategory.ACTION_BUTTON: ElementCategoryInfo(
        category=ElementCategory.ACTION_BUTTON,
        wait_strategy=WaitStrategyHint.ANIMATION,
        assertion_type=AssertionTypeHint.STATE_CHANGE,
        interaction=InteractionHint.CLICK,
        should_interact=True,
        priority_score=0.7,
        may_trigger_modal=True,
        may_change_state=True,
    ),
    ElementCategory.TOGGLE: ElementCategoryInfo(
        category=ElementCategory.TOGGLE,
        wait_strategy=WaitStrategyHint.ANIMATION,
        assertion_type=AssertionTypeHint.STATE_CHANGE,
        interaction=InteractionHint.TOGGLE,
        should_interact=True,
        priority_score=0.6,
        may_change_state=True,
    ),
    ElementCategory.DISPLAY_ONLY: ElementCategoryInfo(
        category=ElementCategory.DISPLAY_ONLY,
        wait_strategy=WaitStrategyHint.IMMEDIATE,
        assertion_type=AssertionTypeHint.VISIBILITY,
        interaction=InteractionHint.OBSERVE_ONLY,
        should_interact=False,
        priority_score=0.2,
    ),
    ElementCategory.DYNAMIC_CONTENT: ElementCategoryInfo(
        category=ElementCategory.DYNAMIC_CONTENT,
        wait_strategy=WaitStrategyHint.CONTENT_STABLE,
        assertion_type=AssertionTypeHint.TEXT_CONTENT,
        interaction=InteractionHint.OBSERVE_ONLY,
        should_interact=False,
        priority_score=0.4,
    ),
    ElementCategory.DROPDOWN: ElementCategoryInfo(
        category=ElementCategory.DROPDOWN,
        wait_strategy=WaitStrategyHint.ANIMATION,
        assertion_type=AssertionTypeHint.VALUE_CHECK,
        interaction=InteractionHint.SELECT,
        should_interact=True,
        priority_score=0.7,
        may_trigger_modal=True,
    ),
    ElementCategory.FILE_UPLOAD: ElementCategoryInfo(
        category=ElementCategory.FILE_UPLOAD,
        wait_strategy=WaitStrategyHint.INTERACTIVE,
        assertion_type=AssertionTypeHint.STATE_CHANGE,
        interaction=InteractionHint.UPLOAD,
        should_interact=False,  # Skip during auto-generation
        priority_score=0.5,
    ),
    ElementCategory.SEARCH: ElementCategoryInfo(
        category=ElementCategory.SEARCH,
        wait_strategy=WaitStrategyHint.NETWORK_IDLE,
        assertion_type=AssertionTypeHint.VALUE_CHECK,
        interaction=InteractionHint.TYPE,
        should_interact=True,
        priority_score=0.8,
        may_trigger_navigation=True,
        sample_data_type="search_query",
    ),
    ElementCategory.DATE_PICKER: ElementCategoryInfo(
        category=ElementCategory.DATE_PICKER,
        wait_strategy=WaitStrategyHint.ANIMATION,
        assertion_type=AssertionTypeHint.VALUE_CHECK,
        interaction=InteractionHint.CLICK,
        should_interact=True,
        priority_score=0.6,
        may_trigger_modal=True,
        sample_data_type="date",
    ),
    ElementCategory.RICH_TEXT: ElementCategoryInfo(
        category=ElementCategory.RICH_TEXT,
        wait_strategy=WaitStrategyHint.INTERACTIVE,
        assertion_type=AssertionTypeHint.VALUE_CHECK,
        interaction=InteractionHint.TYPE,
        should_interact=True,
        priority_score=0.6,
        sample_data_type="text",
    ),
    ElementCategory.INTERACTIVE_MEDIA: ElementCategoryInfo(
        category=ElementCategory.INTERACTIVE_MEDIA,
        wait_strategy=WaitStrategyHint.CONTENT_STABLE,
        assertion_type=AssertionTypeHint.VISIBILITY,
        interaction=InteractionHint.OBSERVE_ONLY,
        should_interact=False,
        priority_score=0.3,
    ),
    ElementCategory.DATA_TABLE: ElementCategoryInfo(
        category=ElementCategory.DATA_TABLE,
        wait_strategy=WaitStrategyHint.NETWORK_IDLE,
        assertion_type=AssertionTypeHint.COUNT,
        interaction=InteractionHint.OBSERVE_ONLY,
        should_interact=False,
        priority_score=0.5,
    ),
    ElementCategory.MODAL_TRIGGER: ElementCategoryInfo(
        category=ElementCategory.MODAL_TRIGGER,
        wait_strategy=WaitStrategyHint.ANIMATION,
        assertion_type=AssertionTypeHint.CLICKABLE,
        interaction=InteractionHint.CLICK,
        should_interact=False,  # Don't auto-click modal triggers
        priority_score=0.3,
        may_trigger_modal=True,
    ),
    ElementCategory.MODAL_CONTENT: ElementCategoryInfo(
        category=ElementCategory.MODAL_CONTENT,
        wait_strategy=WaitStrategyHint.ANIMATION,
        assertion_type=AssertionTypeHint.VISIBILITY,
        interaction=InteractionHint.OBSERVE_ONLY,
        should_interact=False,  # Skip assertions - element may not be visible
        priority_score=0.1,  # Very low priority
    ),
    ElementCategory.TOAST_NOTIFICATION: ElementCategoryInfo(
        category=ElementCategory.TOAST_NOTIFICATION,
        wait_strategy=WaitStrategyHint.CONTENT_STABLE,
        assertion_type=AssertionTypeHint.VISIBILITY,
        interaction=InteractionHint.OBSERVE_ONLY,
        should_interact=False,  # Skip - toasts appear/disappear
        priority_score=0.0,  # Don't generate assertions
    ),
    ElementCategory.ANIMATION_ELEMENT: ElementCategoryInfo(
        category=ElementCategory.ANIMATION_ELEMENT,
        wait_strategy=WaitStrategyHint.ANIMATION,
        assertion_type=AssertionTypeHint.VISIBILITY,
        interaction=InteractionHint.OBSERVE_ONLY,
        should_interact=False,
        priority_score=0.2,  # Low priority
    ),
}


class ElementClassifier:
    """
    Classifies elements into categories with testing strategies.

    Uses element attributes, context, and heuristics to determine
    the best testing approach for each element.
    """

    # Patterns for detecting element types
    SUBMIT_PATTERNS: frozenset[str] = frozenset({
        "submit", "login", "signin", "sign-in", "register", "signup", "sign-up",
        "save", "create", "add", "send", "confirm", "continue", "next", "finish",
        "complete", "checkout", "buy", "purchase", "order", "pay",
    })

    ACTION_PATTERNS: frozenset[str] = frozenset({
        "delete", "remove", "cancel", "edit", "update", "refresh", "reload",
        "open", "close", "show", "hide", "toggle", "expand", "collapse",
        "download", "upload", "export", "import", "copy", "share",
    })

    NAVIGATION_PATTERNS: frozenset[str] = frozenset({
        "home", "back", "menu", "nav", "link", "href", "route",
    })

    TOGGLE_PATTERNS: frozenset[str] = frozenset({
        "checkbox", "switch", "toggle", "radio", "accordion",
    })

    SEARCH_PATTERNS: frozenset[str] = frozenset({
        "search", "query", "filter", "find", "lookup",
    })

    DYNAMIC_PATTERNS: frozenset[str] = frozenset({
        "count", "counter", "badge", "notification", "status", "live",
        "timer", "clock", "score", "progress",
    })

    MODAL_TRIGGER_PATTERNS: frozenset[str] = frozenset({
        "modal", "dialog", "popup", "alert", "confirm", "prompt",
        "show-modal", "open-modal", "trigger-modal",
    })

    MODAL_CONTENT_PATTERNS: frozenset[str] = frozenset({
        "modal-body", "modal-content", "modal-header", "modal-footer",
        "dialog-content", "popup-content",
    })

    TOAST_PATTERNS: frozenset[str] = frozenset({
        "toast", "snackbar", "notification", "alert-message",
        "flash-message", "message-popup", "banner-alert",
    })

    ANIMATION_PATTERNS: frozenset[str] = frozenset({
        "animate", "animation", "transition", "fade", "slide",
        "bounce", "pulse", "shake", "spin", "zoom",
    })

    def __init__(self) -> None:
        self._log = logger.bind(component="element_classifier")

    def classify_element(
        self,
        element_data: dict[str, Any],
        page_context: PageTypeInfo | None = None,
    ) -> ElementCategoryInfo:
        """
        Classify an element and return its testing strategy.

        Args:
            element_data: Element information from page analysis
            page_context: Optional page type context for better classification

        Returns:
            ElementCategoryInfo with category and testing strategy
        """
        tag = (element_data.get("tagName") or "").lower()
        element_type = (element_data.get("type") or "").lower()
        classes = (element_data.get("className") or "").lower()
        text = (element_data.get("text") or "").lower()
        name = (element_data.get("name") or "").lower()
        aria_label = (element_data.get("ariaLabel") or "").lower()
        role = (element_data.get("role") or "").lower()

        # Combine all text for pattern matching
        all_text = f"{text} {name} {aria_label} {classes}"

        # PRIORITY: Check for problematic dynamic element patterns first
        # These should NOT have assertions generated

        # Check for toast/notification patterns - skip assertions entirely
        if any(p in all_text for p in self.TOAST_PATTERNS):
            return self._get_category_info(ElementCategory.TOAST_NOTIFICATION)

        # Check for modal content patterns - elements inside modals
        if any(p in all_text for p in self.MODAL_CONTENT_PATTERNS):
            return self._get_category_info(ElementCategory.MODAL_CONTENT)

        # Check for animation patterns - fragile for assertions
        if any(p in classes for p in self.ANIMATION_PATTERNS):
            return self._get_category_info(ElementCategory.ANIMATION_ELEMENT)

        # Classify based on tag and type
        if tag == "input":
            return self._classify_input(element_type, all_text, element_data)
        elif tag == "button":
            return self._classify_button(all_text, element_data)
        elif tag == "a":
            return self._classify_link(element_data)
        elif tag == "select":
            return self._get_category_info(ElementCategory.DROPDOWN)
        elif tag == "textarea":
            return self._get_category_info(ElementCategory.RICH_TEXT)
        elif role == "button":
            return self._classify_button(all_text, element_data)
        elif role == "checkbox" or role == "switch":
            return self._get_category_info(ElementCategory.TOGGLE)
        elif role == "link":
            return self._get_category_info(ElementCategory.NAVIGATION)
        elif role == "dialog" or role == "alertdialog":
            return self._get_category_info(ElementCategory.MODAL_CONTENT)

        # Check for dynamic content patterns
        if any(p in all_text for p in self.DYNAMIC_PATTERNS):
            return self._get_category_info(ElementCategory.DYNAMIC_CONTENT)

        # Default to display only
        return self._get_category_info(ElementCategory.DISPLAY_ONLY)

    def _classify_input(
        self, input_type: str, all_text: str, element_data: dict[str, Any]
    ) -> ElementCategoryInfo:
        """Classify an input element."""
        if input_type == "submit":
            return self._get_category_info(ElementCategory.FORM_SUBMIT)
        elif input_type == "button":
            return self._classify_button(all_text, element_data)
        elif input_type in ("checkbox", "radio"):
            return self._get_category_info(ElementCategory.TOGGLE)
        elif input_type == "file":
            return self._get_category_info(ElementCategory.FILE_UPLOAD)
        elif input_type in ("date", "datetime-local", "time", "month", "week"):
            return self._get_category_info(ElementCategory.DATE_PICKER)
        elif input_type == "search" or any(p in all_text for p in self.SEARCH_PATTERNS):
            return self._get_category_info(ElementCategory.SEARCH)
        else:
            # Standard text input
            category_info = self._get_category_info(ElementCategory.FORM_INPUT)
            # Set sample data type based on input type
            if input_type == "email":
                category_info.sample_data_type = "email"
            elif input_type == "password":
                category_info.sample_data_type = "password"
            elif input_type == "tel":
                category_info.sample_data_type = "phone"
            elif input_type == "url":
                category_info.sample_data_type = "url"
            elif input_type == "number":
                category_info.sample_data_type = "number"
            return category_info

    def _classify_button(
        self, all_text: str, element_data: dict[str, Any]
    ) -> ElementCategoryInfo:
        """Classify a button element."""
        # Check for modal trigger patterns - buttons that open modals/alerts
        # These should NOT be auto-clicked during test generation
        if any(p in all_text for p in self.MODAL_TRIGGER_PATTERNS):
            return self._get_category_info(ElementCategory.MODAL_TRIGGER)

        # Check for submit patterns
        if any(p in all_text for p in self.SUBMIT_PATTERNS):
            return self._get_category_info(ElementCategory.FORM_SUBMIT)

        # Check for toggle patterns
        if any(p in all_text for p in self.TOGGLE_PATTERNS):
            return self._get_category_info(ElementCategory.TOGGLE)

        # Default to action button
        category_info = self._get_category_info(ElementCategory.ACTION_BUTTON)

        # Adjust flags based on patterns
        if any(p in all_text for p in ("delete", "remove", "cancel")):
            category_info.may_trigger_modal = True

        return category_info

    def _classify_link(self, element_data: dict[str, Any]) -> ElementCategoryInfo:
        """Classify a link element."""
        href = element_data.get("href", "")

        # Check if it's a navigation link or an action link
        if href and not href.startswith(("javascript:", "#")):
            return self._get_category_info(ElementCategory.NAVIGATION)

        # JavaScript links are often action buttons
        return self._get_category_info(ElementCategory.ACTION_BUTTON)

    def _get_category_info(self, category: ElementCategory) -> ElementCategoryInfo:
        """Get a copy of the category configuration."""
        config = CATEGORY_CONFIG.get(category, CATEGORY_CONFIG[ElementCategory.DISPLAY_ONLY])
        # Return a copy to avoid modifying the global config
        return ElementCategoryInfo(
            category=config.category,
            wait_strategy=config.wait_strategy,
            assertion_type=config.assertion_type,
            interaction=config.interaction,
            should_interact=config.should_interact,
            priority_score=config.priority_score,
            may_trigger_navigation=config.may_trigger_navigation,
            may_trigger_modal=config.may_trigger_modal,
            may_change_state=config.may_change_state,
            sample_data_type=config.sample_data_type,
        )


class SelectorReliabilityScorer:
    """
    Scores selector reliability to help decide which elements to test.

    Higher scores indicate more reliable selectors that are less likely
    to break with UI changes.
    """

    # Score weights for different selector strategies
    SCORE_WEIGHTS: dict[str, float] = {
        "id": 1.0,  # #element-id - most reliable
        "data-testid": 0.95,  # [data-testid="..."]
        "data-test": 0.93,
        "data-cy": 0.93,  # Cypress test IDs
        "name": 0.85,  # [name="..."]
        "aria-label": 0.8,  # [aria-label="..."]
        "text": 0.6,  # text=... - can change with i18n
        "class": 0.5,  # .class-name - often changes
        "href": 0.55,  # a[href="..."]
        "type": 0.45,  # input[type="..."]
        "tag": 0.3,  # Just tag name
        "nth-of-type": 0.25,  # Position-based - very fragile
        "xpath": 0.2,  # XPath - usually fragile
    }

    # Patterns that indicate fragile selectors
    FRAGILE_PATTERNS: list[str] = [
        r":nth-child\(",
        r":nth-of-type\(",
        r"\[\d+\]",  # XPath index
        r"_\w{5,}",  # Generated hashes like _abc123
        r"-\d{3,}",  # Numeric suffixes
    ]

    # Patterns for dynamic/modal elements - significantly reduce reliability
    DYNAMIC_ELEMENT_PATTERNS: frozenset[str] = frozenset({
        "modal", "popup", "dialog", "alert", "toast", "notification",
        "dropdown", "menu", "tooltip", "overlay", "loading", "spinner",
        "cart", "badge", "counter", "collapse", "accordion",
        "slide", "fade", "animate", "transition",
    })

    def __init__(self) -> None:
        self._log = logger.bind(component="selector_scorer")

    def score_selector(
        self, selector: str, element_data: dict[str, Any] | None = None
    ) -> SelectorReliabilityScore:
        """
        Score a selector's reliability.

        Args:
            selector: The CSS/XPath selector to score
            element_data: Optional element data for generating fallbacks

        Returns:
            SelectorReliabilityScore with score and analysis
        """
        import re

        score = 0.0
        strategy = "unknown"
        stability_notes: list[str] = []
        fallback_selectors: list[str] = []

        # Determine strategy and base score
        if selector.startswith("#"):
            strategy = "id"
            score = self.SCORE_WEIGHTS["id"]
            stability_notes.append("ID selectors are highly reliable")

        elif "[data-testid=" in selector or "[data-test=" in selector:
            strategy = "data-testid"
            score = self.SCORE_WEIGHTS["data-testid"]
            stability_notes.append("Test IDs are designed for automation")

        elif "[data-cy=" in selector:
            strategy = "data-cy"
            score = self.SCORE_WEIGHTS["data-cy"]

        elif "[name=" in selector:
            strategy = "name"
            score = self.SCORE_WEIGHTS["name"]
            stability_notes.append("Name attributes are usually stable")

        elif "[aria-label=" in selector:
            strategy = "aria-label"
            score = self.SCORE_WEIGHTS["aria-label"]
            stability_notes.append("Aria labels may change with accessibility updates")

        elif selector.startswith("text="):
            strategy = "text"
            score = self.SCORE_WEIGHTS["text"]
            stability_notes.append("Text selectors may break with i18n changes")

        elif "[href" in selector:
            strategy = "href"
            score = self.SCORE_WEIGHTS["href"]
            # Partial href matches are less reliable
            if "*=" in selector:
                score -= 0.1
                stability_notes.append("Partial href match reduces reliability")

        elif "." in selector and not selector.startswith("//"):
            strategy = "class"
            score = self.SCORE_WEIGHTS["class"]
            stability_notes.append("Class selectors may change with CSS refactoring")

        elif selector.startswith("//") or selector.startswith("/"):
            strategy = "xpath"
            score = self.SCORE_WEIGHTS["xpath"]
            stability_notes.append("XPath selectors are often fragile")

        else:
            # Basic tag selector
            strategy = "tag"
            score = self.SCORE_WEIGHTS["tag"]
            stability_notes.append("Tag-only selectors are very fragile")

        # Penalize fragile patterns
        for pattern in self.FRAGILE_PATTERNS:
            if re.search(pattern, selector):
                score -= 0.15
                stability_notes.append(f"Contains fragile pattern: {pattern}")

        # Penalize long, complex selectors
        if selector.count(" > ") > 2:
            score -= 0.1
            stability_notes.append("Deep nesting reduces reliability")

        if selector.count(" ") > 4:
            score -= 0.1
            stability_notes.append("Long selector chains are fragile")

        # CRITICAL: Penalize dynamic/modal element selectors heavily
        # These elements may not be visible or present during test execution
        selector_lower = selector.lower()
        for pattern in self.DYNAMIC_ELEMENT_PATTERNS:
            if pattern in selector_lower:
                score -= 0.3
                stability_notes.append(f"Dynamic element pattern '{pattern}' - may not be visible")
                break  # Only penalize once

        # Generate fallback selectors if element data is provided
        if element_data:
            fallback_selectors = self._generate_fallbacks(element_data, selector)

        # Clamp score to 0-1
        score = max(0.0, min(1.0, score))

        return SelectorReliabilityScore(
            selector=selector,
            score=score,
            strategy_used=strategy,
            is_unique=True,  # Assume unique; caller can verify
            stability_notes=stability_notes,
            fallback_selectors=fallback_selectors,
        )

    def _generate_fallbacks(
        self, element_data: dict[str, Any], primary_selector: str
    ) -> list[str]:
        """Generate fallback selectors from element data."""
        fallbacks: list[str] = []
        tag = element_data.get("tagName", "div").lower()

        # Try ID
        if element_data.get("id") and not primary_selector.startswith("#"):
            fallbacks.append(f"#{element_data['id']}")

        # Try data-testid
        data_attrs = element_data.get("dataAttributes") or {}
        if data_attrs.get("data-testid"):
            fallbacks.append(f"[data-testid='{data_attrs['data-testid']}']")
        if data_attrs.get("data-test"):
            fallbacks.append(f"[data-test='{data_attrs['data-test']}']")

        # Try name
        if element_data.get("name"):
            fallbacks.append(f"{tag}[name='{element_data['name']}']")

        # Try aria-label
        if element_data.get("ariaLabel"):
            fallbacks.append(f"[aria-label='{element_data['ariaLabel']}']")

        # Try text selector for buttons
        if tag in ("button", "a") and element_data.get("text"):
            text = element_data["text"].strip()[:30]
            if text and "'" not in text and '"' not in text:
                fallbacks.append(f"text={text}")

        # Remove duplicates and primary
        fallbacks = [f for f in fallbacks if f != primary_selector]
        return list(dict.fromkeys(fallbacks))[:3]  # Max 3 fallbacks

    def should_generate_assertion(
        self, selector: str, min_score: float = 0.5
    ) -> bool:
        """
        Determine if an assertion should be generated for this selector.

        Low-reliability selectors may be skipped to reduce test flakiness.
        """
        score = self.score_selector(selector)
        return score.score >= min_score


class PageTypeDetector:
    """
    Detects page type to adjust testing strategy.

    Different page types require different approaches:
    - Login pages: Focus on authentication flow
    - List pages: Check pagination, filtering
    - Forms: Validate all fields
    - Dashboards: Check widgets load
    """

    # Indicators for each page type
    PAGE_INDICATORS: dict[PageType, list[str]] = {
        PageType.LOGIN: [
            "password", "login", "signin", "sign-in", "authenticate",
            "username", "email", "forgot password",
        ],
        PageType.REGISTRATION: [
            "register", "signup", "sign-up", "create account",
            "confirm password", "terms", "agree",
        ],
        PageType.LIST_TABLE: [
            "table", "grid", "list", "pagination", "page 1",
            "showing", "results", "items per page", "sort by",
        ],
        PageType.FORM: [
            "form", "submit", "save", "required",
            "please fill", "fields",
        ],
        PageType.DASHBOARD: [
            "dashboard", "overview", "summary", "statistics",
            "chart", "graph", "widget", "metrics",
        ],
        PageType.DETAIL: [
            "details", "view", "back", "edit",
            "delete", "created", "updated",
        ],
        PageType.SEARCH_RESULTS: [
            "search results", "found", "no results",
            "showing results for", "did you mean",
        ],
        PageType.CHECKOUT: [
            "checkout", "cart", "payment", "shipping",
            "billing", "order summary", "total",
        ],
        PageType.PROFILE: [
            "profile", "account", "my account", "settings",
            "preferences", "avatar", "bio",
        ],
        PageType.SETTINGS: [
            "settings", "preferences", "configuration",
            "options", "notifications",
        ],
        PageType.ERROR: [
            "error", "404", "not found", "something went wrong",
            "oops", "forbidden", "unauthorized",
        ],
        PageType.LANDING: [
            "welcome", "get started", "try free", "hero",
            "features", "pricing", "testimonials",
        ],
    }

    def __init__(self) -> None:
        self._log = logger.bind(component="page_type_detector")

    def detect_page_type(
        self,
        url: str,
        page_title: str,
        elements: list[dict[str, Any]],
        page_text: str | None = None,
    ) -> PageTypeInfo:
        """
        Detect the type of page based on URL, content, and elements.

        Args:
            url: Current page URL
            page_title: Page title
            elements: List of element data from page analysis
            page_text: Optional full page text content

        Returns:
            PageTypeInfo with detected type and confidence
        """
        scores: dict[PageType, float] = {pt: 0.0 for pt in PageType}
        found_indicators: dict[PageType, list[str]] = {pt: [] for pt in PageType}

        # Combine all text for analysis
        url_lower = url.lower()
        title_lower = page_title.lower()
        all_text = f"{url_lower} {title_lower} "

        if page_text:
            all_text += page_text.lower()

        # Add element text
        for elem in elements:
            elem_text = elem.get("text", "")
            elem_label = elem.get("ariaLabel", "")
            elem_placeholder = elem.get("placeholder", "")
            all_text += f" {elem_text} {elem_label} {elem_placeholder}"

        all_text = all_text.lower()

        # Score each page type
        for page_type, indicators in self.PAGE_INDICATORS.items():
            for indicator in indicators:
                if indicator in all_text:
                    scores[page_type] += 1.0
                    found_indicators[page_type].append(indicator)

                    # Bonus for URL match
                    if indicator in url_lower:
                        scores[page_type] += 0.5

                    # Bonus for title match
                    if indicator in title_lower:
                        scores[page_type] += 0.3

        # URL path analysis
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()

        if "/login" in path or "/signin" in path:
            scores[PageType.LOGIN] += 2.0
        elif "/register" in path or "/signup" in path:
            scores[PageType.REGISTRATION] += 2.0
        elif "/dashboard" in path:
            scores[PageType.DASHBOARD] += 2.0
        elif "/search" in path:
            scores[PageType.SEARCH_RESULTS] += 1.5
        elif "/checkout" in path or "/cart" in path:
            scores[PageType.CHECKOUT] += 2.0
        elif "/settings" in path or "/preferences" in path:
            scores[PageType.SETTINGS] += 2.0
        elif "/profile" in path or "/account" in path:
            scores[PageType.PROFILE] += 1.5
        elif "/edit" in path or "/new" in path or "/create" in path:
            scores[PageType.FORM] += 1.5

        # Element type analysis
        input_count = sum(1 for e in elements if e.get("tagName", "").lower() == "input")
        button_count = sum(1 for e in elements if e.get("tagName", "").lower() == "button")
        link_count = sum(1 for e in elements if e.get("tagName", "").lower() == "a")
        table_count = sum(1 for e in elements if e.get("tagName", "").lower() == "table")

        # Form-heavy pages
        if input_count >= 3:
            scores[PageType.FORM] += 1.0
        if input_count >= 5:
            scores[PageType.FORM] += 0.5

        # List/table pages
        if table_count > 0:
            scores[PageType.LIST_TABLE] += 2.0

        # Landing pages tend to have many links
        if link_count > 10 and button_count < 3:
            scores[PageType.LANDING] += 1.0

        # Find best match
        best_type = max(scores, key=scores.get)  # type: ignore[arg-type]
        max_score = scores[best_type]

        # Calculate confidence
        total_score = sum(scores.values())
        confidence = max_score / total_score if total_score > 0 else 0.0

        if max_score < 1.0:
            best_type = PageType.UNKNOWN
            confidence = 0.0

        return PageTypeInfo(
            page_type=best_type,
            confidence=min(confidence, 1.0),
            indicators=found_indicators[best_type][:5],
            suggested_flow=self._get_suggested_flow(best_type),
        )

    def _get_suggested_flow(self, page_type: PageType) -> str | None:
        """Get suggested test flow for page type."""
        flows: dict[PageType, str] = {
            PageType.LOGIN: "login_flow",
            PageType.REGISTRATION: "registration_flow",
            PageType.CHECKOUT: "checkout_flow",
            PageType.SEARCH_RESULTS: "search_flow",
            PageType.FORM: "form_submission_flow",
        }
        return flows.get(page_type)


class NavigationRisk(IntEnum):
    """Risk level that an element will cause page navigation when interacted with."""

    NONE = 0       # Form inputs, checkboxes - safe to interact
    LOW = 1        # Buttons inside forms - might submit
    MEDIUM = 2     # Buttons with action words (save, submit, add)
    HIGH = 3       # Links, buttons with href, onclick with location
    CERTAIN = 4    # Links with href to different page


@dataclass
class StepWithRisk:
    """A test step with its associated navigation risk."""

    step: dict[str, Any]
    risk: NavigationRisk
    element_selector: str | None = None


class StepOrderingStrategy:
    """
    Orders test steps so navigation-causing elements are tested last.

    This ensures that form inputs, checkboxes, and other safe elements
    are tested before buttons or links that might navigate away from the page.

    Step ordering priority:
    1. Navigate to page (always first)
    2. Wait for load (always second)
    3. Screenshot (capture initial state)
    4. Assert page elements exist (visibility checks)
    5. Fill form inputs (text, email, password, etc.) - SAFE
    6. Toggle checkboxes/radios - SAFE
    7. Select dropdowns - SAFE
    8. Click non-navigation buttons - LOW RISK
    9. Assert values (verify what we filled)
    10. Final screenshot (capture filled state)
    11. Click navigation elements (links, submit buttons) - HIGH RISK, LAST
    """

    # Patterns that indicate navigation in onclick handlers
    NAVIGATION_ONCLICK_PATTERNS: frozenset[str] = frozenset({
        "location",
        "navigate",
        "redirect",
        "window.open",
        "href",
        "submit",
    })

    # Button text patterns that indicate navigation
    NAVIGATION_TEXT_PATTERNS: frozenset[str] = frozenset({
        "submit",
        "next",
        "continue",
        "go",
        "proceed",
        "login",
        "sign in",
        "signin",
        "register",
        "sign up",
        "signup",
        "save",
        "finish",
        "complete",
        "checkout",
        "buy",
        "purchase",
        "order",
        "confirm",
    })

    # Button text patterns that are unlikely to navigate
    SAFE_BUTTON_PATTERNS: frozenset[str] = frozenset({
        "add to cart",
        "increment",
        "decrement",
        "toggle",
        "expand",
        "collapse",
        "copy",
        "clear",
        "reset",
        "cancel",
        "close",
        "dismiss",
    })

    # Bootstrap/common patterns that indicate non-navigation buttons
    SAFE_DATA_ATTRIBUTES: frozenset[str] = frozenset({
        "data-toggle",
        "data-dismiss",
        "data-bs-toggle",
        "data-bs-dismiss",
        "aria-expanded",
        "aria-haspopup",
    })

    # Action types that indicate step ordering category
    INFRASTRUCTURE_ACTIONS: frozenset[str] = frozenset({
        "navigate",
        "wait_for_network_idle",
        "wait",
        "screenshot",
    })

    SAFE_INTERACTION_ACTIONS: frozenset[str] = frozenset({
        "type",
        "fill",
        "clear",
        "select",
        "check",
        "uncheck",
    })

    def __init__(self) -> None:
        self._log = logger.bind(component="step_ordering_strategy")

    def analyze_navigation_risk(
        self,
        element: dict[str, Any],
        step: dict[str, Any] | None = None,
    ) -> NavigationRisk:
        """
        Determine if element will cause page navigation when interacted with.

        Args:
            element: Element data dictionary with tag, attributes, text, etc.
            step: Optional step dictionary for additional context

        Returns:
            NavigationRisk level from NONE (safe) to CERTAIN (will navigate)
        """
        tag = (element.get("tagName") or element.get("tag") or "").lower()
        element_type = (element.get("type") or "").lower()
        href = element.get("href") or ""
        onclick = (element.get("onclick") or "").lower()
        text = (element.get("text") or element.get("text_content") or "").lower()
        target = (element.get("target") or "").lower()
        classes = (element.get("className") or element.get("class") or "").lower()
        data_attrs = element.get("dataAttributes") or {}

        # Check for safe data attributes (Bootstrap patterns, ARIA)
        for attr in self.SAFE_DATA_ATTRIBUTES:
            if attr in data_attrs or attr in str(element):
                return NavigationRisk.NONE

        # Check target="_blank" - opens in new tab, safe for current page
        if target == "_blank":
            return NavigationRisk.NONE

        # CERTAIN: Links with actual href to different page
        if tag == "a":
            if href and not href.startswith(("#", "javascript:")):
                return NavigationRisk.CERTAIN
            # JavaScript links might navigate
            if href.startswith("javascript:"):
                return NavigationRisk.MEDIUM
            # Anchor links are safe
            if href.startswith("#"):
                return NavigationRisk.NONE
            # Links without href might be action buttons
            return NavigationRisk.LOW

        # HIGH: Onclick handlers with navigation patterns
        if onclick:
            for pattern in self.NAVIGATION_ONCLICK_PATTERNS:
                if pattern in onclick:
                    return NavigationRisk.HIGH

        # Check for form submit buttons
        if tag == "button" or tag == "input":
            # Submit buttons are risky
            if element_type == "submit":
                return NavigationRisk.HIGH

            # Button text patterns
            text_lower = text.strip().lower()

            # Safe button patterns first
            for safe_pattern in self.SAFE_BUTTON_PATTERNS:
                if safe_pattern in text_lower:
                    return NavigationRisk.NONE

            # Navigation patterns
            for nav_pattern in self.NAVIGATION_TEXT_PATTERNS:
                if nav_pattern in text_lower:
                    return NavigationRisk.MEDIUM

        # Form inputs are always safe
        if tag == "input" and element_type not in ("submit", "button"):
            return NavigationRisk.NONE

        # Select, textarea, checkbox, radio are safe
        if tag in ("select", "textarea"):
            return NavigationRisk.NONE

        if element_type in ("checkbox", "radio"):
            return NavigationRisk.NONE

        # Default: buttons have low risk, everything else is safe
        if tag == "button":
            return NavigationRisk.LOW

        return NavigationRisk.NONE

    def analyze_step_risk(self, step: dict[str, Any]) -> NavigationRisk:
        """
        Analyze a test step and determine its navigation risk.

        Args:
            step: Test step dictionary with action, selector, etc.

        Returns:
            NavigationRisk level for this step
        """
        action = step.get("action", "").lower()

        # Infrastructure steps are always first (no risk concept)
        if action in self.INFRASTRUCTURE_ACTIONS:
            return NavigationRisk.NONE

        # Safe interaction actions (typing, selecting)
        if action in self.SAFE_INTERACTION_ACTIONS:
            return NavigationRisk.NONE

        # Assertions are generally safe
        if action == "assert":
            assertion = step.get("assertion", {})
            # URL assertions might indicate navigation test
            operator = assertion.get("operator", "")
            if "url" in operator:
                return NavigationRisk.NONE
            return NavigationRisk.NONE

        # Click actions need more analysis
        if action == "click":
            selector = step.get("selector", "").lower()
            name = step.get("name", "").lower()

            # Check name for navigation hints
            if any(p in name for p in ["submit", "login", "next", "continue"]):
                return NavigationRisk.HIGH

            # Check selector patterns
            if any(p in selector for p in ["submit", "login"]):
                return NavigationRisk.HIGH

            # Link selectors
            if selector.startswith("a[") or "link" in selector:
                return NavigationRisk.CERTAIN

            return NavigationRisk.LOW

        return NavigationRisk.NONE

    def order_steps(
        self,
        steps: list[dict[str, Any]],
        elements: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Reorder steps so navigation-causing ones come last.

        The ordering ensures:
        1. Infrastructure steps (navigate, wait, screenshot) - preserve order
        2. Safe interactions (type, fill, select, check) - come first
        3. Assertions that don't click - come after interactions
        4. Low-risk clicks - come after assertions
        5. High-risk/navigation clicks - come last

        Args:
            steps: List of test step dictionaries
            elements: Optional list of element data for better analysis

        Returns:
            Reordered list of steps with safe steps first, risky steps last
        """
        if not steps:
            return steps

        # Create a selector -> element mapping for lookup
        element_map: dict[str, dict[str, Any]] = {}
        if elements:
            for elem in elements:
                selector = elem.get("selector") or elem.get("css_selector") or ""
                if selector:
                    element_map[selector] = elem

        # Categorize steps by type and risk
        infrastructure_steps: list[dict[str, Any]] = []
        safe_interaction_steps: list[dict[str, Any]] = []
        assertion_steps: list[dict[str, Any]] = []
        low_risk_click_steps: list[dict[str, Any]] = []
        high_risk_steps: list[dict[str, Any]] = []

        for step in steps:
            action = step.get("action", "").lower()

            # Infrastructure steps preserve their relative order
            if action in self.INFRASTRUCTURE_ACTIONS:
                infrastructure_steps.append(step)
                continue

            # Assertions without clicks
            if action == "assert":
                assertion_steps.append(step)
                continue

            # Safe interactions
            if action in self.SAFE_INTERACTION_ACTIONS:
                safe_interaction_steps.append(step)
                continue

            # Click actions - analyze risk
            if action == "click":
                selector = step.get("selector", "")
                element = element_map.get(selector, {})

                # Add basic element info from step if not in element_map
                if not element:
                    element = {
                        "selector": selector,
                        "text": step.get("name", ""),
                    }

                risk = self.analyze_navigation_risk(element, step)

                if risk <= NavigationRisk.LOW:
                    low_risk_click_steps.append(step)
                else:
                    high_risk_steps.append(step)
                continue

            # Unknown actions - treat as low risk
            low_risk_click_steps.append(step)

        # Combine in safe-to-risky order
        ordered_steps: list[dict[str, Any]] = []

        # 1. Infrastructure steps first (in original order)
        ordered_steps.extend(infrastructure_steps)

        # 2. Safe interactions (type, fill, select, etc.)
        ordered_steps.extend(safe_interaction_steps)

        # 3. Assertions (visibility, value checks)
        ordered_steps.extend(assertion_steps)

        # 4. Low-risk clicks
        ordered_steps.extend(low_risk_click_steps)

        # 5. High-risk navigation clicks LAST
        # Sort high-risk by risk level (lower risk first within high-risk category)
        high_risk_steps.sort(
            key=lambda s: self.analyze_step_risk(s),
        )
        ordered_steps.extend(high_risk_steps)

        self._log.debug(
            "Reordered steps by navigation risk",
            total_steps=len(steps),
            infrastructure=len(infrastructure_steps),
            safe_interactions=len(safe_interaction_steps),
            assertions=len(assertion_steps),
            low_risk_clicks=len(low_risk_click_steps),
            high_risk_clicks=len(high_risk_steps),
        )

        return ordered_steps

    def get_step_priority(self, step: dict[str, Any]) -> int:
        """
        Get numeric priority for a step (lower = should come first).

        This can be used for sorting steps directly.

        Args:
            step: Test step dictionary

        Returns:
            Priority number (0-100, lower = higher priority/earlier execution)
        """
        action = step.get("action", "").lower()

        # Infrastructure actions have highest priority
        if action == "navigate":
            return 0
        if action in ("wait_for_network_idle", "wait"):
            return 5
        if action == "screenshot":
            return 10

        # Safe interactions next
        if action in self.SAFE_INTERACTION_ACTIONS:
            return 20

        # Assertions
        if action == "assert":
            return 30

        # Clicks - depends on risk
        if action == "click":
            risk = self.analyze_step_risk(step)
            if risk == NavigationRisk.NONE:
                return 40
            elif risk == NavigationRisk.LOW:
                return 50
            elif risk == NavigationRisk.MEDIUM:
                return 60
            elif risk == NavigationRisk.HIGH:
                return 80
            else:  # CERTAIN
                return 90

        # Unknown actions
        return 45


# Factory function to create all intelligent layer components
def create_intelligent_builder_layer() -> tuple[
    ElementClassifier, SelectorReliabilityScorer, PageTypeDetector
]:
    """
    Create all intelligent layer components for the test builder.

    Returns:
        Tuple of (ElementClassifier, SelectorReliabilityScorer, PageTypeDetector)
    """
    return (
        ElementClassifier(),
        SelectorReliabilityScorer(),
        PageTypeDetector(),
    )


def create_step_ordering_strategy() -> StepOrderingStrategy:
    """
    Create a StepOrderingStrategy instance.

    Returns:
        StepOrderingStrategy for ordering test steps by navigation risk
    """
    return StepOrderingStrategy()
