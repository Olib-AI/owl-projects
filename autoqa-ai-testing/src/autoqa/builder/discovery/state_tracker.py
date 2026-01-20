"""
State tracker for monitoring page state changes during interactions.

This module captures snapshots of page state and computes differences
between states to understand how interactions affect the page.

Key capabilities:
- Capture complete page state (URL, visible elements, modals, forms)
- Compare states to detect changes
- Identify what elements became visible/hidden
- Track form field value changes
- Monitor URL/navigation changes
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from owl_browser import OwlBrowser

logger = structlog.get_logger(__name__)


class ChangeType(StrEnum):
    """Type of state change detected."""

    ELEMENT_APPEARED = auto()
    """An element became visible."""

    ELEMENT_DISAPPEARED = auto()
    """An element became hidden."""

    URL_CHANGED = auto()
    """Page URL changed."""

    MODAL_OPENED = auto()
    """A modal/dialog was opened."""

    MODAL_CLOSED = auto()
    """A modal/dialog was closed."""

    TAB_ACTIVATED = auto()
    """A tab panel became active."""

    ACCORDION_EXPANDED = auto()
    """An accordion section expanded."""

    ACCORDION_COLLAPSED = auto()
    """An accordion section collapsed."""

    FORM_VALUE_CHANGED = auto()
    """A form field value changed."""

    CONTENT_CHANGED = auto()
    """Page content changed significantly."""

    NETWORK_REQUEST = auto()
    """A network request was made."""

    NO_CHANGE = auto()
    """No significant change detected."""


@dataclass
class FormFieldState:
    """State of a form field."""

    selector: str
    """Field selector."""

    name: str | None
    """Field name attribute."""

    field_type: str
    """Field type (text, email, password, etc.)."""

    value: str
    """Current value."""

    is_checked: bool
    """For checkboxes/radios."""

    is_disabled: bool
    """Whether field is disabled."""

    validation_message: str | None
    """Browser validation message if any."""


@dataclass
class ModalState:
    """State of a modal/dialog."""

    selector: str
    """Modal selector."""

    modal_id: str | None
    """Modal ID if present."""

    is_open: bool
    """Whether modal is currently open/visible."""

    title: str | None
    """Modal title if detectable."""


@dataclass
class TabState:
    """State of a tab group."""

    group_selector: str
    """Tab group container selector."""

    active_tab_selector: str | None
    """Currently active tab selector."""

    active_panel_selector: str | None
    """Currently active panel selector."""


@dataclass
class PageState:
    """Complete snapshot of page state."""

    url: str
    """Current page URL."""

    title: str
    """Page title."""

    timestamp: datetime
    """When state was captured."""

    visible_element_selectors: frozenset[str]
    """Set of currently visible element selectors."""

    hidden_element_selectors: frozenset[str]
    """Set of currently hidden element selectors."""

    open_modals: list[ModalState]
    """Currently open modals."""

    active_tabs: list[TabState]
    """Active tab states."""

    form_fields: list[FormFieldState]
    """Form field states."""

    scroll_position: tuple[int, int]
    """Current scroll position (x, y)."""

    document_height: int
    """Total document height."""

    network_idle: bool
    """Whether network is currently idle."""

    raw_data: dict[str, Any] = field(default_factory=dict)
    """Raw state data from browser."""


@dataclass
class StateChange:
    """A single detected change between states."""

    change_type: ChangeType
    """Type of change."""

    selector: str | None
    """Selector of affected element if applicable."""

    old_value: Any
    """Previous value."""

    new_value: Any
    """New value."""

    description: str
    """Human-readable description."""


@dataclass
class StateDiff:
    """Difference between two page states."""

    before_url: str
    """URL before change."""

    after_url: str
    """URL after change."""

    url_changed: bool
    """Whether URL changed."""

    changes: list[StateChange]
    """List of detected changes."""

    elements_appeared: list[str]
    """Selectors of elements that became visible."""

    elements_disappeared: list[str]
    """Selectors of elements that became hidden."""

    modals_opened: list[str]
    """Selectors of modals that opened."""

    modals_closed: list[str]
    """Selectors of modals that closed."""

    has_significant_change: bool
    """Whether any significant change was detected."""


class StateTracker:
    """
    Tracks page state to understand UI changes during interactions.

    This tracker captures detailed page state snapshots and computes
    the differences between them to understand what changed.
    """

    # JavaScript for capturing complete page state
    STATE_CAPTURE_SCRIPT: str = """
    (() => {
        const state = {
            url: window.location.href,
            title: document.title,
            scrollX: window.scrollX,
            scrollY: window.scrollY,
            documentHeight: document.documentElement.scrollHeight,
            visibleElements: [],
            hiddenElements: [],
            openModals: [],
            activeTabs: [],
            formFields: []
        };

        // Check if element is visible
        function isVisible(el) {
            if (!el) return false;
            const style = window.getComputedStyle(el);
            const rect = el.getBoundingClientRect();
            return style.display !== 'none' &&
                   style.visibility !== 'hidden' &&
                   parseFloat(style.opacity) > 0 &&
                   rect.width > 0 &&
                   rect.height > 0 &&
                   el.getAttribute('aria-hidden') !== 'true';
        }

        // Generate selector for element
        function getSelector(el) {
            if (!el) return null;
            if (el.id) return '#' + el.id;
            if (el.dataset && el.dataset.testid) return `[data-testid="${el.dataset.testid}"]`;
            if (el.name) return `${el.tagName.toLowerCase()}[name="${el.name}"]`;

            // Build a path
            const parts = [];
            let current = el;
            let depth = 0;
            while (current && current !== document.body && depth < 5) {
                let part = current.tagName.toLowerCase();
                if (current.id) {
                    part = '#' + current.id;
                    parts.unshift(part);
                    break;
                }
                if (current.className) {
                    const cls = current.className.split(' ')[0];
                    if (cls && !cls.includes('active') && !cls.includes('show')) {
                        part += '.' + cls;
                    }
                }
                parts.unshift(part);
                current = current.parentElement;
                depth++;
            }
            return parts.join(' > ');
        }

        // Get all interactive elements
        const interactive = document.querySelectorAll(
            'button, a[href], input, select, textarea, [role="button"], [role="link"], ' +
            '[onclick], [data-toggle], [data-bs-toggle], [aria-expanded]'
        );

        for (const el of interactive) {
            const selector = getSelector(el);
            if (!selector) continue;

            if (isVisible(el)) {
                state.visibleElements.push(selector);
            } else {
                state.hiddenElements.push(selector);
            }
        }

        // Find open modals
        const modals = document.querySelectorAll('[role="dialog"], .modal, [aria-modal="true"]');
        for (const modal of modals) {
            if (isVisible(modal)) {
                const titleEl = modal.querySelector('.modal-title, [role="heading"]');
                state.openModals.push({
                    selector: getSelector(modal),
                    id: modal.id || null,
                    isOpen: true,
                    title: titleEl?.textContent?.trim() || null
                });
            }
        }

        // Find active tabs
        const tabLists = document.querySelectorAll('[role="tablist"]');
        for (const tabList of tabLists) {
            const tabSel = '[role="tab"][aria-selected="true"], .nav-link.active';
            const activeTab = tabList.querySelector(tabSel);
            if (activeTab) {
                const panelId = activeTab.getAttribute('aria-controls');
                state.activeTabs.push({
                    groupSelector: getSelector(tabList),
                    activeTabSelector: getSelector(activeTab),
                    activePanelSelector: panelId ? '#' + panelId : null
                });
            }
        }

        // Get form field states
        const formFields = document.querySelectorAll('input, select, textarea');
        for (const field of formFields) {
            if (!isVisible(field)) continue;

            state.formFields.push({
                selector: getSelector(field),
                name: field.name || null,
                type: field.type || 'text',
                value: field.type === 'password' ? '***' : (field.value || ''),
                checked: field.checked || false,
                disabled: field.disabled || false,
                validationMessage: field.validationMessage || null
            });
        }

        return state;
    })()
    """

    def __init__(self) -> None:
        """Initialize the state tracker."""
        self._log = logger.bind(component="state_tracker")
        self._state_history: list[PageState] = []

    async def capture_state(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> PageState:
        """
        Capture current page state.

        Args:
            browser: Browser instance
            context_id: Browser context ID

        Returns:
            Complete page state snapshot
        """
        self._log.debug("Capturing page state", context_id=context_id)

        try:
            result = await browser.evaluate(
                context_id=context_id, expression=self.STATE_CAPTURE_SCRIPT
            )
            # SDK returns the evaluated expression directly (not wrapped in "result" key)
            raw_data = result

            if not raw_data or not isinstance(raw_data, dict):
                self._log.warning("Failed to capture state - no data returned")
                return self._empty_state()

            # Process form fields
            form_fields = [
                FormFieldState(
                    selector=f.get("selector", ""),
                    name=f.get("name"),
                    field_type=f.get("type", "text"),
                    value=f.get("value", ""),
                    is_checked=f.get("checked", False),
                    is_disabled=f.get("disabled", False),
                    validation_message=f.get("validationMessage"),
                )
                for f in raw_data.get("formFields", [])
            ]

            # Process modals
            open_modals = [
                ModalState(
                    selector=m.get("selector", ""),
                    modal_id=m.get("id"),
                    is_open=m.get("isOpen", True),
                    title=m.get("title"),
                )
                for m in raw_data.get("openModals", [])
            ]

            # Process tabs
            active_tabs = [
                TabState(
                    group_selector=t.get("groupSelector", ""),
                    active_tab_selector=t.get("activeTabSelector"),
                    active_panel_selector=t.get("activePanelSelector"),
                )
                for t in raw_data.get("activeTabs", [])
            ]

            state = PageState(
                url=raw_data.get("url", ""),
                title=raw_data.get("title", ""),
                timestamp=datetime.now(UTC),
                visible_element_selectors=frozenset(raw_data.get("visibleElements", [])),
                hidden_element_selectors=frozenset(raw_data.get("hiddenElements", [])),
                open_modals=open_modals,
                active_tabs=active_tabs,
                form_fields=form_fields,
                scroll_position=(raw_data.get("scrollX", 0), raw_data.get("scrollY", 0)),
                document_height=raw_data.get("documentHeight", 0),
                network_idle=True,  # Assume idle at capture time
                raw_data=raw_data,
            )

            # Store in history
            self._state_history.append(state)

            self._log.debug(
                "State captured",
                url=state.url,
                visible_count=len(state.visible_element_selectors),
                modals=len(state.open_modals),
            )

            return state

        except Exception as e:
            self._log.error("Failed to capture state", error=str(e))
            return self._empty_state()

    def diff_states(
        self,
        before: PageState,
        after: PageState,
    ) -> StateDiff:
        """
        Compare two states to identify what changed.

        Args:
            before: State before interaction
            after: State after interaction

        Returns:
            Detailed diff between states
        """
        changes: list[StateChange] = []

        # URL change
        url_changed = before.url != after.url
        if url_changed:
            changes.append(StateChange(
                change_type=ChangeType.URL_CHANGED,
                selector=None,
                old_value=before.url,
                new_value=after.url,
                description=f"URL changed from {before.url} to {after.url}",
            ))

        # Elements that appeared (were hidden, now visible)
        appeared_set = after.visible_element_selectors - before.visible_element_selectors
        elements_appeared = list(appeared_set)
        for selector in elements_appeared:
            changes.append(StateChange(
                change_type=ChangeType.ELEMENT_APPEARED,
                selector=selector,
                old_value="hidden",
                new_value="visible",
                description=f"Element became visible: {selector}",
            ))

        # Elements that disappeared (were visible, now hidden)
        disappeared_set = before.visible_element_selectors - after.visible_element_selectors
        elements_disappeared = list(disappeared_set)
        for selector in elements_disappeared:
            # Skip if it was in a modal that closed
            changes.append(StateChange(
                change_type=ChangeType.ELEMENT_DISAPPEARED,
                selector=selector,
                old_value="visible",
                new_value="hidden",
                description=f"Element became hidden: {selector}",
            ))

        # Modal changes
        before_modal_selectors = {m.selector for m in before.open_modals}
        after_modal_selectors = {m.selector for m in after.open_modals}

        modals_opened = list(after_modal_selectors - before_modal_selectors)
        for selector in modals_opened:
            changes.append(StateChange(
                change_type=ChangeType.MODAL_OPENED,
                selector=selector,
                old_value="closed",
                new_value="open",
                description=f"Modal opened: {selector}",
            ))

        modals_closed = list(before_modal_selectors - after_modal_selectors)
        for selector in modals_closed:
            changes.append(StateChange(
                change_type=ChangeType.MODAL_CLOSED,
                selector=selector,
                old_value="open",
                new_value="closed",
                description=f"Modal closed: {selector}",
            ))

        # Tab changes
        before_active_panels = {
            t.active_panel_selector for t in before.active_tabs if t.active_panel_selector
        }
        after_active_panels = {
            t.active_panel_selector for t in after.active_tabs if t.active_panel_selector
        }

        new_active_panels = after_active_panels - before_active_panels
        for panel in new_active_panels:
            changes.append(StateChange(
                change_type=ChangeType.TAB_ACTIVATED,
                selector=panel,
                old_value="inactive",
                new_value="active",
                description=f"Tab panel activated: {panel}",
            ))

        # Form field changes
        before_fields = {f.selector: f for f in before.form_fields}
        after_fields = {f.selector: f for f in after.form_fields}

        for selector, after_field in after_fields.items():
            before_field = before_fields.get(selector)
            if before_field and before_field.value != after_field.value:
                changes.append(StateChange(
                    change_type=ChangeType.FORM_VALUE_CHANGED,
                    selector=selector,
                    old_value=before_field.value,
                    new_value=after_field.value,
                    description=f"Form field value changed: {selector}",
                ))

        # No change case
        has_significant_change = bool(
            url_changed or
            elements_appeared or
            elements_disappeared or
            modals_opened or
            modals_closed or
            new_active_panels
        )

        if not changes:
            changes.append(StateChange(
                change_type=ChangeType.NO_CHANGE,
                selector=None,
                old_value=None,
                new_value=None,
                description="No significant state change detected",
            ))

        return StateDiff(
            before_url=before.url,
            after_url=after.url,
            url_changed=url_changed,
            changes=changes,
            elements_appeared=elements_appeared,
            elements_disappeared=elements_disappeared,
            modals_opened=modals_opened,
            modals_closed=modals_closed,
            has_significant_change=has_significant_change,
        )

    async def track_interaction(
        self,
        browser: OwlBrowser,
        context_id: str,
        interaction_fn: Any,
        wait_ms: int = 500,
    ) -> tuple[PageState, PageState, StateDiff]:
        """
        Track state changes during an interaction.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            interaction_fn: Async function that performs the interaction
            wait_ms: Milliseconds to wait after interaction before capturing

        Returns:
            Tuple of (before_state, after_state, diff)
        """
        import asyncio

        # Capture before state
        before = await self.capture_state(browser, context_id)

        # Perform interaction
        await interaction_fn()

        # Wait for changes to settle
        await asyncio.sleep(wait_ms / 1000)

        # Capture after state
        after = await self.capture_state(browser, context_id)

        # Compute diff
        diff = self.diff_states(before, after)

        self._log.info(
            "Interaction tracked",
            url_changed=diff.url_changed,
            appeared=len(diff.elements_appeared),
            disappeared=len(diff.elements_disappeared),
            modals_opened=len(diff.modals_opened),
        )

        return before, after, diff

    def get_history(self) -> list[PageState]:
        """Get all captured state history."""
        return list(self._state_history)

    def clear_history(self) -> None:
        """Clear state history."""
        self._state_history.clear()

    def _empty_state(self) -> PageState:
        """Create an empty page state."""
        return PageState(
            url="",
            title="",
            timestamp=datetime.now(UTC),
            visible_element_selectors=frozenset(),
            hidden_element_selectors=frozenset(),
            open_modals=[],
            active_tabs=[],
            form_fields=[],
            scroll_position=(0, 0),
            document_height=0,
            network_idle=True,
        )


# Convenience functions
async def capture_page_state(
    browser: OwlBrowser,
    context_id: str,
) -> PageState:
    """Capture page state using default tracker."""
    tracker = StateTracker()
    return await tracker.capture_state(browser, context_id)


def compare_states(before: PageState, after: PageState) -> StateDiff:
    """Compare two page states."""
    tracker = StateTracker()
    return tracker.diff_states(before, after)
