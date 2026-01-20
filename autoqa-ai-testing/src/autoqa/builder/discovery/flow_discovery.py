"""Discovers interaction flows to reach and test hidden content.

This module builds on visibility and interaction analysis to discover
complete flows that can reveal and test hidden UI elements. It identifies
modal flows, tab flows, accordion flows, dropdown flows, form flows,
and navigation flows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from owl_browser import OwlBrowser

from autoqa.builder.discovery.interaction_analyzer import (
    EffectType,
    InteractionAnalyzer,
)
from autoqa.builder.discovery.state_tracker import StateTracker
from autoqa.builder.discovery.visibility_analyzer import (
    ElementCategory,
    ElementState,
    VisibilityAnalyzer,
)

logger = structlog.get_logger(__name__)


class FlowType(StrEnum):
    """Type of interaction flow."""

    MODAL_FLOW = "modal_flow"
    """Open modal -> test content -> close modal."""

    TAB_FLOW = "tab_flow"
    """Click tab -> test panel content."""

    ACCORDION_FLOW = "accordion_flow"
    """Expand section -> test content -> collapse."""

    DROPDOWN_FLOW = "dropdown_flow"
    """Open dropdown -> test options -> close."""

    FORM_FLOW = "form_flow"
    """Fill form fields -> submit -> verify response."""

    NAVIGATION_FLOW = "navigation_flow"
    """Click link -> navigate -> verify destination."""


@dataclass
class FlowStep:
    """A single step within an interaction flow."""

    action: str
    """Action to perform: click, type, wait, assert, press_key."""

    selector: str
    """CSS selector for the target element."""

    value: str | None = None
    """Value for type actions or expected value for assertions."""

    wait_for: str | None = None
    """Selector to wait for after action completes."""

    description: str = ""
    """Human-readable description of this step."""

    timeout_ms: int = 5000
    """Timeout for this step in milliseconds."""


@dataclass
class InteractionFlow:
    """A complete interaction flow to test hidden content."""

    name: str
    """Descriptive name for this flow."""

    flow_type: FlowType
    """Type of flow."""

    trigger_selector: str
    """Selector of the element that initiates this flow."""

    target_elements: list[str] = field(default_factory=list)
    """Selectors of elements revealed by this flow."""

    steps: list[FlowStep] = field(default_factory=list)
    """Steps to execute the flow and test revealed content."""

    cleanup_steps: list[FlowStep] = field(default_factory=list)
    """Steps to reset state after flow (close modal, collapse, etc.)."""

    preconditions: list[str] = field(default_factory=list)
    """Selectors that must be visible before flow can execute."""

    reliability_score: float = 0.8
    """Estimated reliability of this flow (0-1)."""


class FlowDiscovery:
    """
    Discovers flows to make hidden elements visible and testable.

    Combines visibility analysis, state tracking, and interaction analysis
    to build complete flows for testing dynamic UI elements like modals,
    tabs, accordions, and dropdowns.
    """

    def __init__(
        self,
        visibility: VisibilityAnalyzer | None = None,
        state: StateTracker | None = None,
        interaction: InteractionAnalyzer | None = None,
    ) -> None:
        """
        Initialize flow discovery.

        Args:
            visibility: Visibility analyzer instance
            state: State tracker instance
            interaction: Interaction analyzer instance
        """
        self.visibility = visibility or VisibilityAnalyzer()
        self.state = state or StateTracker()
        self.interaction = interaction or InteractionAnalyzer()
        self._log = logger.bind(component="flow_discovery")

    async def discover_flows(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> list[InteractionFlow]:
        """
        Discover all flows needed to test hidden content on the current page.

        Args:
            browser: Browser instance
            context_id: Browser context ID

        Returns:
            List of discovered interaction flows
        """
        flows: list[InteractionFlow] = []

        self._log.info("Starting flow discovery", context_id=context_id)

        # Get visibility analysis to find triggers
        analysis = await self.visibility.analyze(browser, context_id)

        self._log.debug(
            "Visibility analysis complete",
            triggers=len(analysis.triggers),
            hidden=analysis.hidden_count,
            modals=len(analysis.modals),
        )

        # For each trigger, analyze what flow it creates
        for trigger in analysis.triggers:
            flow = await self._analyze_trigger_flow(browser, context_id, trigger)
            if flow:
                flows.append(flow)
                self._log.debug(
                    "Discovered flow",
                    flow_type=flow.flow_type,
                    trigger=trigger.selector,
                    targets=len(flow.target_elements),
                )

        self._log.info(
            "Flow discovery complete",
            total_flows=len(flows),
            modal_flows=sum(1 for f in flows if f.flow_type == FlowType.MODAL_FLOW),
            tab_flows=sum(1 for f in flows if f.flow_type == FlowType.TAB_FLOW),
        )

        return flows

    async def _analyze_trigger_flow(
        self,
        browser: OwlBrowser,
        context_id: str,
        trigger: ElementState,
    ) -> InteractionFlow | None:
        """
        Analyze what flow a trigger element creates.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            trigger: The trigger element to analyze

        Returns:
            InteractionFlow if a meaningful flow was discovered, None otherwise
        """
        # Capture state before
        before = await self.state.capture_state(browser, context_id)

        # Click trigger and analyze effect
        effect = await self.interaction.analyze_click_effect(
            browser, context_id, trigger.selector, restore_state=False
        )

        if not effect or not effect.success:
            return None

        if effect.effect_type == EffectType.NO_EFFECT:
            return None

        # Build flow based on effect type
        flow_type = self._effect_to_flow_type(effect.effect_type)

        flow = InteractionFlow(
            name=f"{flow_type.value}: {self._get_trigger_description(trigger)}",
            flow_type=flow_type,
            trigger_selector=trigger.selector,
            target_elements=effect.revealed_elements,
        )

        # Build steps
        flow.steps = self._build_flow_steps(trigger, effect, flow_type)
        flow.cleanup_steps = self._build_cleanup_steps(effect, flow_type)

        # Reset state (close modal, etc.)
        await self._reset_state(browser, context_id, effect)

        return flow

    def _effect_to_flow_type(self, effect: EffectType) -> FlowType:
        """Map an effect type to a flow type."""
        mapping = {
            EffectType.OPENS_MODAL: FlowType.MODAL_FLOW,
            EffectType.ACTIVATES_TAB: FlowType.TAB_FLOW,
            EffectType.EXPANDS_ACCORDION: FlowType.ACCORDION_FLOW,
            EffectType.TRIGGERS_DROPDOWN: FlowType.DROPDOWN_FLOW,
            EffectType.NAVIGATES: FlowType.NAVIGATION_FLOW,
            EffectType.SUBMITS_FORM: FlowType.FORM_FLOW,
            EffectType.REVEALS_CONTENT: FlowType.ACCORDION_FLOW,
        }
        return mapping.get(effect, FlowType.MODAL_FLOW)

    def _get_trigger_description(self, trigger: ElementState) -> str:
        """Generate a readable description for a trigger."""
        if trigger.aria_label:
            return trigger.aria_label
        if trigger.text_content:
            return trigger.text_content[:40]
        return trigger.selector

    def _build_flow_steps(
        self,
        trigger: ElementState,
        effect: "InteractionEffect",  # noqa: F821
        flow_type: FlowType,
    ) -> list[FlowStep]:
        """
        Build test steps for the revealed content.

        Args:
            trigger: The trigger element
            effect: The interaction effect
            flow_type: Type of flow

        Returns:
            List of flow steps
        """
        steps: list[FlowStep] = []

        # Step 1: Click the trigger to open/reveal content
        wait_selector = effect.revealed_elements[0] if effect.revealed_elements else None
        steps.append(
            FlowStep(
                action="click",
                selector=trigger.selector,
                wait_for=wait_selector,
                description=f"Open {flow_type.value.replace('_', ' ')}",
                timeout_ms=5000,
            )
        )

        # If modal, wait for modal animation
        if flow_type == FlowType.MODAL_FLOW and effect.modal_selector:
            steps.append(
                FlowStep(
                    action="wait",
                    selector=effect.modal_selector,
                    value="500",  # ms to wait
                    description="Wait for modal animation",
                    timeout_ms=1000,
                )
            )

        # Add visibility assertions for revealed elements
        for revealed in effect.revealed_elements:
            steps.append(
                FlowStep(
                    action="assert",
                    selector=revealed,
                    value="is_visible",
                    description=f"Verify {revealed} is visible",
                    timeout_ms=5000,
                )
            )

        return steps

    def _build_cleanup_steps(
        self,
        effect: "InteractionEffect",  # noqa: F821
        flow_type: FlowType,
    ) -> list[FlowStep]:
        """
        Build cleanup steps to reset state after flow.

        Args:
            effect: The interaction effect
            flow_type: Type of flow

        Returns:
            List of cleanup steps
        """
        steps: list[FlowStep] = []

        if flow_type == FlowType.MODAL_FLOW:
            # Try various close button selectors
            close_selectors = [
                ".modal .close",
                ".modal [data-dismiss='modal']",
                ".modal [data-bs-dismiss='modal']",
                ".modal-close",
                "button[aria-label='Close']",
                "[aria-label='Close modal']",
            ]
            steps.append(
                FlowStep(
                    action="click",
                    selector=", ".join(close_selectors),
                    description="Close modal",
                    timeout_ms=3000,
                )
            )

        elif flow_type == FlowType.DROPDOWN_FLOW:
            # Press Escape to close dropdown
            steps.append(
                FlowStep(
                    action="press_key",
                    selector="body",
                    value="Escape",
                    description="Close dropdown with Escape",
                    timeout_ms=1000,
                )
            )

        elif flow_type == FlowType.ACCORDION_FLOW:
            # Click trigger again to collapse (toggle behavior)
            if effect.state_diff and effect.state_diff.elements_appeared:
                steps.append(
                    FlowStep(
                        action="click",
                        selector=effect.selector,
                        description="Collapse accordion",
                        timeout_ms=3000,
                    )
                )

        return steps

    async def _reset_state(
        self,
        browser: OwlBrowser,
        context_id: str,
        effect: "InteractionEffect",  # noqa: F821
    ) -> None:
        """
        Reset page state after analyzing a flow.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            effect: The interaction effect to undo
        """
        import asyncio

        if effect.effect_type == EffectType.OPENS_MODAL:
            # Try to close modal
            try:
                close_script = """
                (() => {
                    // Try close button
                    const closeSelectors = [
                        '.modal.show .close',
                        '.modal.show [data-dismiss="modal"]',
                        '.modal.show [data-bs-dismiss="modal"]',
                        '.modal-close',
                        'button[aria-label="Close"]'
                    ];
                    for (const sel of closeSelectors) {
                        const btn = document.querySelector(sel);
                        if (btn) {
                            btn.click();
                            return true;
                        }
                    }
                    return false;
                })()
                """
                await browser.evaluate(context_id=context_id, expression=close_script)
                await asyncio.sleep(0.3)
            except Exception:
                # Try pressing Escape
                try:
                    await browser.press_key(context_id=context_id, key="Escape")
                    await asyncio.sleep(0.2)
                except Exception:
                    pass

        elif effect.effect_type == EffectType.TRIGGERS_DROPDOWN:
            # Press Escape to close dropdown
            try:
                await browser.press_key(context_id=context_id, key="Escape")
                await asyncio.sleep(0.2)
            except Exception:
                pass

        elif effect.effect_type in (
            EffectType.REVEALS_CONTENT,
            EffectType.EXPANDS_ACCORDION,
        ):
            # Try clicking the same trigger to toggle it back
            try:
                await browser.click(context_id=context_id, selector=effect.selector)
                await asyncio.sleep(0.3)
            except Exception:
                pass

    async def discover_modal_flows(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> list[InteractionFlow]:
        """
        Discover only modal-related flows.

        Convenience method for modal-specific discovery.

        Args:
            browser: Browser instance
            context_id: Browser context ID

        Returns:
            List of modal flows
        """
        all_flows = await self.discover_flows(browser, context_id)
        return [f for f in all_flows if f.flow_type == FlowType.MODAL_FLOW]

    async def discover_tab_flows(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> list[InteractionFlow]:
        """
        Discover only tab-related flows.

        Convenience method for tab-specific discovery.

        Args:
            browser: Browser instance
            context_id: Browser context ID

        Returns:
            List of tab flows
        """
        all_flows = await self.discover_flows(browser, context_id)
        return [f for f in all_flows if f.flow_type == FlowType.TAB_FLOW]


# Type hint import for interaction effect (avoids circular import)
from autoqa.builder.discovery.interaction_analyzer import InteractionEffect  # noqa: E402, F811
