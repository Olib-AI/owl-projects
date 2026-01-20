"""
Interaction analyzer for understanding element behavior.

This module discovers what happens when you interact with elements:
- Which elements reveal modals, tabs, accordions
- Which elements cause navigation
- Which elements submit forms
- Which elements toggle visibility of other elements
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import TYPE_CHECKING

import structlog

from autoqa.builder.discovery.state_tracker import PageState, StateDiff, StateTracker
from autoqa.builder.discovery.visibility_analyzer import ElementState, VisibilityAnalyzer

if TYPE_CHECKING:
    from owl_browser import OwlBrowser

logger = structlog.get_logger(__name__)


class EffectType(StrEnum):
    """Type of effect an interaction has."""

    OPENS_MODAL = auto()
    """Interaction opens a modal/dialog."""

    CLOSES_MODAL = auto()
    """Interaction closes a modal/dialog."""

    ACTIVATES_TAB = auto()
    """Interaction activates a tab panel."""

    EXPANDS_ACCORDION = auto()
    """Interaction expands an accordion section."""

    COLLAPSES_ACCORDION = auto()
    """Interaction collapses an accordion section."""

    TOGGLES_VISIBILITY = auto()
    """Interaction toggles element visibility."""

    REVEALS_CONTENT = auto()
    """Interaction reveals hidden content."""

    HIDES_CONTENT = auto()
    """Interaction hides visible content."""

    NAVIGATES = auto()
    """Interaction causes page navigation."""

    SUBMITS_FORM = auto()
    """Interaction submits a form."""

    TRIGGERS_DROPDOWN = auto()
    """Interaction opens/closes a dropdown."""

    TRIGGERS_NETWORK = auto()
    """Interaction triggers network requests."""

    NO_EFFECT = auto()
    """Interaction has no detectable effect."""

    UNKNOWN = auto()
    """Effect could not be determined."""


@dataclass
class InteractionEffect:
    """Describes the effect of an interaction."""

    action: str
    """The action performed (click, hover, etc.)."""

    selector: str
    """Selector of the interacted element."""

    effect_type: EffectType
    """Primary type of effect."""

    secondary_effects: list[EffectType] = field(default_factory=list)
    """Additional effects triggered."""

    revealed_elements: list[str] = field(default_factory=list)
    """Selectors of elements that became visible."""

    hidden_elements: list[str] = field(default_factory=list)
    """Selectors of elements that became hidden."""

    url_change: str | None = None
    """New URL if navigation occurred."""

    modal_selector: str | None = None
    """Selector of opened/closed modal."""

    tab_panel_selector: str | None = None
    """Selector of activated tab panel."""

    form_selector: str | None = None
    """Selector of submitted form."""

    wait_time_ms: int = 0
    """Time taken for effect to complete."""

    state_diff: StateDiff | None = None
    """Full state diff from the interaction."""

    success: bool = True
    """Whether interaction succeeded."""

    error: str | None = None
    """Error message if interaction failed."""


@dataclass
class ElementInteractionProfile:
    """Profile of all interaction effects for an element."""

    selector: str
    """Element selector."""

    element_info: ElementState | None = None
    """Element state information."""

    click_effect: InteractionEffect | None = None
    """Effect of clicking the element."""

    is_trigger: bool = False
    """Whether element reveals other content."""

    triggered_selectors: list[str] = field(default_factory=list)
    """Selectors of elements this triggers."""

    recommended_test_order: int = 0
    """Recommended order for testing (lower = earlier)."""


class InteractionAnalyzer:
    """
    Analyzes what each interaction does - reveals modals, navigates, etc.

    This analyzer performs interactions and monitors page state to understand
    the effect of each element interaction.
    """

    def __init__(
        self,
        visibility_analyzer: VisibilityAnalyzer | None = None,
        state_tracker: StateTracker | None = None,
    ) -> None:
        """
        Initialize the interaction analyzer.

        Args:
            visibility_analyzer: Visibility analyzer instance
            state_tracker: State tracker instance
        """
        self._visibility = visibility_analyzer or VisibilityAnalyzer()
        self._state_tracker = state_tracker or StateTracker()
        self._log = logger.bind(component="interaction_analyzer")
        self._interaction_cache: dict[str, InteractionEffect] = {}

    async def analyze_click_effect(
        self,
        browser: OwlBrowser,
        context_id: str,
        selector: str,
        wait_after_ms: int = 500,
        restore_state: bool = True,
    ) -> InteractionEffect:
        """
        Click an element and detect what changed.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            selector: Selector of element to click
            wait_after_ms: Time to wait for effect
            restore_state: Whether to restore page state after

        Returns:
            InteractionEffect describing what happened
        """
        self._log.debug("Analyzing click effect", selector=selector)

        # Check cache
        cache_key = f"click:{selector}"
        if cache_key in self._interaction_cache:
            return self._interaction_cache[cache_key]

        # Capture state before
        before_state = await self._state_tracker.capture_state(browser, context_id)

        try:
            # Perform the click
            await browser.click(context_id=context_id, selector=selector)

            # Wait for effect to complete
            await asyncio.sleep(wait_after_ms / 1000)

            # Try to wait for network idle
            try:
                await browser.wait_for_network_idle(
                    context_id=context_id,
                    idle_time=200,
                    timeout=2000,
                )
            except Exception:
                pass  # Timeout is acceptable

            # Capture state after
            after_state = await self._state_tracker.capture_state(browser, context_id)

            # Compute diff
            diff = self._state_tracker.diff_states(before_state, after_state)

            # Analyze the effect
            effect = self._analyze_diff(selector, "click", diff, after_state)

            # Cache result
            self._interaction_cache[cache_key] = effect

            # Restore state if requested
            if restore_state and diff.has_significant_change:
                await self._restore_state(browser, context_id, before_state, diff)

            return effect

        except Exception as e:
            self._log.warning("Click interaction failed", selector=selector, error=str(e))
            return InteractionEffect(
                action="click",
                selector=selector,
                effect_type=EffectType.UNKNOWN,
                success=False,
                error=str(e),
            )

    async def analyze_all_clickables(
        self,
        browser: OwlBrowser,
        context_id: str,
        max_elements: int = 50,
        skip_navigation: bool = True,
    ) -> dict[str, InteractionEffect]:
        """
        Analyze all visible clickable elements to understand their effects.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            max_elements: Maximum elements to analyze
            skip_navigation: Skip links that would navigate away

        Returns:
            Dict mapping selectors to their interaction effects
        """
        self._log.info("Analyzing all clickable elements")

        # Get visible elements
        visible = await self._visibility.get_visible_elements(browser, context_id)

        # Filter to clickable elements
        clickables = [
            el for el in visible
            if el.tag_name in ("button", "a") or
               el.raw_data.get("role") == "button" or
               el.raw_data.get("ariaExpanded") is not None or
               el.raw_data.get("dataToggle") or
               el.raw_data.get("onclick")
        ]

        # Skip external links if requested
        if skip_navigation:
            clickables = [
                el for el in clickables
                if el.tag_name != "a" or
                   not el.raw_data.get("href") or
                   el.raw_data.get("href", "").startswith("#") or
                   el.raw_data.get("dataToggle")
            ]

        # Limit to max
        clickables = clickables[:max_elements]

        results: dict[str, InteractionEffect] = {}
        for element in clickables:
            effect = await self.analyze_click_effect(
                browser,
                context_id,
                element.selector,
                wait_after_ms=300,
                restore_state=True,
            )
            results[element.selector] = effect

        self._log.info(
            "Clickable analysis complete",
            total=len(results),
            triggers=sum(1 for e in results.values() if e.revealed_elements),
        )

        return results

    async def find_triggers_for_hidden(
        self,
        browser: OwlBrowser,
        context_id: str,
        hidden_selector: str,
    ) -> str | None:
        """
        Find which element triggers visibility of a hidden element.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            hidden_selector: Selector of the hidden element

        Returns:
            Selector of trigger element, or None if not found
        """
        # First, try to find via ARIA/data attributes
        trigger_script = f"""
        (() => {{
            const hidden = document.querySelector('{hidden_selector.replace("'", "\\'")}');
            if (!hidden || !hidden.id) return null;

            // Check aria-controls
            const ariaControl = document.querySelector(`[aria-controls="${{hidden.id}}"]`);
            if (ariaControl) return ariaControl.id ? '#' + ariaControl.id : null;

            // Check data-target
            const sel1 = `[data-target="#${{hidden.id}}"]`;
            const sel2 = `[data-bs-target="#${{hidden.id}}"]`;
            const dataTarget = document.querySelector(sel1) || document.querySelector(sel2);
            if (dataTarget) return dataTarget.id ? '#' + dataTarget.id : null;

            // Check href
            const hrefTarget = document.querySelector(`[href="#${{hidden.id}}"]`);
            if (hrefTarget) return hrefTarget.id ? '#' + hrefTarget.id : null;

            return null;
        }})()
        """

        try:
            result = await browser.evaluate(context_id=context_id, expression=trigger_script)
            # SDK returns the evaluated expression directly (not wrapped in "result" key)
            trigger = result
            if trigger:
                return str(trigger)
        except Exception:
            pass

        return None

    async def build_interaction_profiles(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> list[ElementInteractionProfile]:
        """
        Build complete interaction profiles for all visible elements.

        Args:
            browser: Browser instance
            context_id: Browser context ID

        Returns:
            List of interaction profiles
        """
        self._log.info("Building interaction profiles")

        # Get all visible elements
        visible = await self._visibility.get_visible_elements(browser, context_id)

        profiles: list[ElementInteractionProfile] = []

        for element in visible:
            profile = ElementInteractionProfile(
                selector=element.selector,
                element_info=element,
            )

            # Check if this is a known trigger
            if (element.category.value == "trigger" or
                element.raw_data.get("ariaExpanded") is not None or
                element.raw_data.get("dataToggle")):

                profile.is_trigger = True
                profile.triggered_selectors = element.reveals_elements

                # Analyze click effect
                if element.tag_name in ("button", "a"):
                    effect = await self.analyze_click_effect(
                        browser, context_id, element.selector,
                        wait_after_ms=300, restore_state=True
                    )
                    profile.click_effect = effect

                    if effect.revealed_elements:
                        profile.triggered_selectors = effect.revealed_elements

            # Set test order (triggers should be tested last as they change state)
            if profile.is_trigger:
                profile.recommended_test_order = 100
            elif element.category.value == "form_input":
                profile.recommended_test_order = 10
            elif element.category.value == "navigation":
                profile.recommended_test_order = 50
            else:
                profile.recommended_test_order = 30

            profiles.append(profile)

        # Sort by recommended order
        profiles.sort(key=lambda p: p.recommended_test_order)

        return profiles

    def _analyze_diff(
        self,
        selector: str,
        action: str,
        diff: StateDiff,
        after_state: PageState,
    ) -> InteractionEffect:
        """Analyze a state diff to determine effect type."""
        effect = InteractionEffect(
            action=action,
            selector=selector,
            effect_type=EffectType.NO_EFFECT,
            revealed_elements=diff.elements_appeared,
            hidden_elements=diff.elements_disappeared,
            state_diff=diff,
        )

        # URL change = navigation
        if diff.url_changed:
            effect.effect_type = EffectType.NAVIGATES
            effect.url_change = diff.after_url
            return effect

        # Modal opened
        if diff.modals_opened:
            effect.effect_type = EffectType.OPENS_MODAL
            effect.modal_selector = diff.modals_opened[0]
            return effect

        # Modal closed
        if diff.modals_closed:
            effect.effect_type = EffectType.CLOSES_MODAL
            effect.modal_selector = diff.modals_closed[0]
            return effect

        # Tab activated (check if any appeared elements are tab panels)
        for appeared in diff.elements_appeared:
            if "tab" in appeared.lower() or "panel" in appeared.lower():
                effect.effect_type = EffectType.ACTIVATES_TAB
                effect.tab_panel_selector = appeared
                return effect

        # Content revealed
        if diff.elements_appeared and not diff.elements_disappeared:
            effect.effect_type = EffectType.REVEALS_CONTENT
            return effect

        # Content hidden
        if diff.elements_disappeared and not diff.elements_appeared:
            effect.effect_type = EffectType.HIDES_CONTENT
            return effect

        # Toggle
        if diff.elements_appeared and diff.elements_disappeared:
            effect.effect_type = EffectType.TOGGLES_VISIBILITY
            return effect

        return effect

    async def _restore_state(
        self,
        browser: OwlBrowser,
        context_id: str,
        before_state: PageState,
        diff: StateDiff,
    ) -> None:
        """Attempt to restore page state after an interaction."""
        try:
            # If URL changed, navigate back
            if diff.url_changed:
                await browser.navigate(
                    context_id=context_id,
                    url=before_state.url,
                    wait_until="domcontentloaded",
                    timeout=5000,
                )
                return

            # If modal opened, try to close it
            if diff.modals_opened:
                # Try clicking a close button or pressing escape
                close_script = """
                (() => {
                    // Try close button
                    const closeSel = '.modal.show .close, ' +
                        '.modal.show [data-dismiss="modal"], ' +
                        '.modal.show [data-bs-dismiss="modal"]';
                    const closeBtn = document.querySelector(closeSel);
                    if (closeBtn) {
                        closeBtn.click();
                        return true;
                    }
                    // Try clicking backdrop
                    const backdrop = document.querySelector('.modal-backdrop');
                    if (backdrop) {
                        backdrop.click();
                        return true;
                    }
                    return false;
                })()
                """
                await browser.evaluate(context_id=context_id, expression=close_script)
                await asyncio.sleep(0.3)

            # If content revealed, try to collapse it
            elif diff.elements_appeared:
                # Re-click the same trigger might toggle it back
                # This is handled by the caller if needed
                pass

        except Exception as e:
            self._log.debug("State restoration failed", error=str(e))


# Convenience functions
async def analyze_click(
    browser: OwlBrowser,
    context_id: str,
    selector: str,
) -> InteractionEffect:
    """Analyze a click interaction using default analyzer."""
    analyzer = InteractionAnalyzer()
    return await analyzer.analyze_click_effect(browser, context_id, selector)


async def find_trigger(
    browser: OwlBrowser,
    context_id: str,
    hidden_selector: str,
) -> str | None:
    """Find trigger for hidden element using default analyzer."""
    analyzer = InteractionAnalyzer()
    return await analyzer.find_triggers_for_hidden(browser, context_id, hidden_selector)
