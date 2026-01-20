"""Orchestrates intelligent test building using discovery components.

This module integrates visibility analysis, state tracking, interaction
analysis, flow discovery, and network monitoring to build comprehensive
and intelligent test plans for web pages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from owl_browser import OwlBrowser

from autoqa.builder.discovery.flow_discovery import (
    FlowDiscovery,
    FlowStep,
    FlowType,
    InteractionFlow,
)
from autoqa.builder.discovery.interaction_analyzer import EffectType, InteractionAnalyzer
from autoqa.builder.discovery.network_monitor import NetworkMonitor
from autoqa.builder.discovery.state_tracker import StateTracker
from autoqa.builder.discovery.visibility_analyzer import (
    ElementCategory,
    ElementState,
    VisibilityAnalyzer,
)

logger = structlog.get_logger(__name__)


@dataclass
class IntelligentTestStep:
    """A test step with intelligent metadata."""

    action: str
    """Action to perform: click, type, wait, assert, navigate, etc."""

    selector: str
    """CSS selector for target element."""

    value: str | None = None
    """Value for type actions or expected value for assertions."""

    assertion: dict[str, Any] | None = None
    """Assertion configuration for assert actions."""

    wait_for: str | None = None
    """Selector to wait for after action."""

    description: str = ""
    """Human-readable description of this step."""

    # Intelligent metadata
    requires_flow: str | None = None
    """Name of flow that must run first to make this step possible."""

    visibility_state: str = "visible"
    """Expected visibility state of target element."""

    reliability_score: float = 1.0
    """Estimated reliability of this step (0-1)."""

    element_category: str | None = None
    """Category of target element."""

    timeout_ms: int = 5000
    """Timeout for this step in milliseconds."""

    continue_on_failure: bool = False
    """Whether to continue test execution if this step fails."""


@dataclass
class IntelligentTestPlan:
    """A complete test plan with flows and steps."""

    page_url: str
    """URL of the page being tested."""

    page_title: str = ""
    """Title of the page."""

    visible_element_tests: list[IntelligentTestStep] = field(default_factory=list)
    """Tests for immediately visible elements."""

    flows: list[InteractionFlow] = field(default_factory=list)
    """Interaction flows for revealing hidden content."""

    navigation_tests: list[IntelligentTestStep] = field(default_factory=list)
    """Tests for navigation elements (run last)."""

    form_tests: list[IntelligentTestStep] = field(default_factory=list)
    """Tests for form interactions."""

    total_elements: int = 0
    """Total elements discovered on page."""

    visible_count: int = 0
    """Count of visible elements."""

    hidden_count: int = 0
    """Count of hidden elements."""

    coverage_score: float = 0.0
    """Estimated test coverage (0-1)."""


class IntelligentBuilder:
    """
    Builds tests using intelligent discovery.

    Orchestrates visibility analysis, interaction analysis, flow discovery,
    and state tracking to produce comprehensive test plans that:
    - Test visible elements immediately
    - Discover flows to reveal hidden content
    - Generate appropriate test steps for each element type
    - Order steps to maximize reliability
    """

    def __init__(
        self,
        visibility: VisibilityAnalyzer | None = None,
        state: StateTracker | None = None,
        interaction: InteractionAnalyzer | None = None,
        flow_discovery: FlowDiscovery | None = None,
        network: NetworkMonitor | None = None,
    ) -> None:
        """
        Initialize the intelligent builder.

        Args:
            visibility: Visibility analyzer instance
            state: State tracker instance
            interaction: Interaction analyzer instance
            flow_discovery: Flow discovery instance
            network: Network monitor instance
        """
        self.visibility = visibility or VisibilityAnalyzer()
        self.state = state or StateTracker()
        self.interaction = interaction or InteractionAnalyzer()
        self.flow_discovery = flow_discovery or FlowDiscovery()
        self.network = network or NetworkMonitor()
        self._log = logger.bind(component="intelligent_builder")

    async def build_page_tests(
        self,
        browser: OwlBrowser,
        context_id: str,
        url: str,
    ) -> IntelligentTestPlan:
        """
        Build intelligent tests for a page.

        Args:
            browser: Browser instance
            context_id: Browser context ID
            url: Page URL

        Returns:
            Complete test plan for the page
        """
        self._log.info("Building intelligent test plan", url=url)

        plan = IntelligentTestPlan(page_url=url)

        # 1. Analyze visibility
        visibility_result = await self.visibility.analyze(browser, context_id)
        plan.total_elements = visibility_result.total_elements
        plan.visible_count = visibility_result.visible_count
        plan.hidden_count = visibility_result.hidden_count
        plan.page_title = visibility_result.url  # URL is close enough for now

        self._log.debug(
            "Visibility analysis complete",
            visible=plan.visible_count,
            hidden=plan.hidden_count,
            triggers=len(visibility_result.triggers),
        )

        # 2. Generate tests for visible elements (these can run immediately)
        for element in visibility_result.visible_elements:
            steps = self._generate_element_tests(element)
            plan.visible_element_tests.extend(steps)

        # 3. Discover flows for hidden content
        flows = await self.flow_discovery.discover_flows(browser, context_id)
        plan.flows = flows

        self._log.debug(
            "Flow discovery complete",
            flows=len(flows),
        )

        # 4. Identify navigation elements (test last)
        nav_elements = [
            e for e in visibility_result.visible_elements
            if e.category == ElementCategory.NAVIGATION
        ]
        for nav in nav_elements:
            plan.navigation_tests.append(
                IntelligentTestStep(
                    action="click",
                    selector=nav.selector,
                    description=f"Navigate: {nav.text_content or nav.selector}",
                    element_category="navigation",
                    reliability_score=0.7,
                )
            )

        # 5. Calculate coverage score
        total_testable = plan.visible_count + len(flows)
        total_tests = (
            len(plan.visible_element_tests) +
            sum(len(f.steps) for f in plan.flows)
        )
        plan.coverage_score = min(1.0, total_tests / max(1, total_testable))

        self._log.info(
            "Test plan complete",
            visible_tests=len(plan.visible_element_tests),
            flows=len(plan.flows),
            navigation_tests=len(plan.navigation_tests),
            coverage=f"{plan.coverage_score:.1%}",
        )

        return plan

    def _generate_element_tests(
        self,
        element: ElementState,
    ) -> list[IntelligentTestStep]:
        """
        Generate appropriate tests for an element based on its category.

        Args:
            element: Element to generate tests for

        Returns:
            List of test steps for this element
        """
        steps: list[IntelligentTestStep] = []

        # Always add visibility assertion
        steps.append(
            IntelligentTestStep(
                action="assert",
                selector=element.selector,
                assertion={"operator": "is_visible"},
                description=f"Verify visible: {element.selector}",
                element_category=element.category.value,
                continue_on_failure=True,
            )
        )

        # Category-specific tests
        if element.category == ElementCategory.FORM_INPUT:
            steps.extend(self._generate_input_tests(element))
        elif element.category == ElementCategory.TRIGGER:
            # Don't click triggers here - they're handled by flows
            pass
        elif element.category == ElementCategory.NAVIGATION:
            # Navigation tests are collected separately
            pass

        return steps

    def _generate_input_tests(
        self,
        element: ElementState,
    ) -> list[IntelligentTestStep]:
        """
        Generate tests for form inputs.

        Args:
            element: Form input element

        Returns:
            List of test steps for this input
        """
        steps: list[IntelligentTestStep] = []

        # Determine input type
        input_type = element.attributes.get("type", "text")

        # Type test value
        test_value = self._get_test_value(element)
        if test_value:
            steps.append(
                IntelligentTestStep(
                    action="type",
                    selector=element.selector,
                    value=test_value,
                    description=f"Fill: {element.selector}",
                    element_category="form_input",
                )
            )

            # Verify value was entered
            steps.append(
                IntelligentTestStep(
                    action="assert",
                    selector=element.selector,
                    assertion={
                        "operator": "attribute_equals",
                        "attribute": "value",
                        "expected": test_value,
                    },
                    description=f"Verify value: {element.selector}",
                    element_category="form_input",
                    continue_on_failure=True,
                )
            )

        return steps

    def _get_test_value(self, element: ElementState) -> str | None:
        """
        Get appropriate test value for input type.

        Args:
            element: Input element

        Returns:
            Test value appropriate for this input type
        """
        input_type = element.attributes.get("type", "text")

        # Map input types to appropriate test values
        values: dict[str, str] = {
            "text": "Test input",
            "email": "test@example.com",
            "password": "TestPass123!",
            "number": "42",
            "tel": "555-123-4567",
            "url": "https://example.com",
            "date": "2024-01-15",
            "datetime-local": "2024-01-15T10:30",
            "time": "14:30",
            "month": "2024-01",
            "week": "2024-W03",
            "color": "#ff0000",
            "range": "50",
            "search": "test search",
        }

        return values.get(input_type, "Test input")

    def to_yaml_steps(
        self,
        plan: IntelligentTestPlan,
    ) -> list[dict[str, Any]]:
        """
        Convert intelligent test plan to YAML step format.

        Args:
            plan: Intelligent test plan

        Returns:
            List of step dictionaries ready for YAML serialization
        """
        yaml_steps: list[dict[str, Any]] = []

        # 1. Navigate to page
        yaml_steps.append({
            "name": f"Navigate to {plan.page_url}",
            "action": "navigate",
            "url": plan.page_url,
            "wait_until": "domcontentloaded",
            "timeout": 10000,
        })

        # 2. Wait for page load
        yaml_steps.append({
            "name": "Wait for page load",
            "action": "wait_for_network_idle",
            "timeout": 5000,
        })

        # 3. Visible element tests
        for step in plan.visible_element_tests:
            yaml_steps.append(self._step_to_yaml(step))

        # 4. Flow-based tests (modals, tabs, etc.)
        for flow in plan.flows:
            yaml_steps.extend(self._flow_to_yaml(flow))

        # 5. Navigation tests (last)
        for step in plan.navigation_tests:
            yaml_steps.append(self._step_to_yaml(step))

        return yaml_steps

    def _step_to_yaml(
        self,
        step: IntelligentTestStep,
    ) -> dict[str, Any]:
        """
        Convert a test step to YAML dict.

        Args:
            step: Intelligent test step

        Returns:
            Dictionary ready for YAML serialization
        """
        yaml_step: dict[str, Any] = {
            "name": step.description or f"{step.action}: {step.selector}",
            "action": step.action,
            "selector": step.selector,
        }

        if step.value:
            yaml_step["text"] = step.value

        if step.assertion:
            yaml_step["assertion"] = step.assertion

        if step.wait_for:
            yaml_step["wait_for"] = step.wait_for

        if step.timeout_ms != 5000:
            yaml_step["timeout"] = step.timeout_ms

        if step.continue_on_failure:
            yaml_step["continue_on_failure"] = True

        return yaml_step

    def _flow_to_yaml(
        self,
        flow: InteractionFlow,
    ) -> list[dict[str, Any]]:
        """
        Convert flow to YAML steps.

        Args:
            flow: Interaction flow

        Returns:
            List of step dictionaries for this flow
        """
        yaml_steps: list[dict[str, Any]] = []

        # Add comment step to mark flow start
        yaml_steps.append({
            "name": f"[Flow] {flow.name}",
            "action": "wait",
            "timeout": 100,  # Minimal wait as marker
        })

        # Flow steps
        for step in flow.steps:
            yaml_step: dict[str, Any] = {
                "name": step.description or f"{step.action}: {step.selector}",
                "action": step.action,
                "selector": step.selector,
            }

            if step.value:
                yaml_step["text"] = step.value

            if step.timeout_ms != 5000:
                yaml_step["timeout"] = step.timeout_ms

            yaml_steps.append(yaml_step)

            # Wait after action if specified
            if step.wait_for:
                yaml_steps.append({
                    "name": f"Wait for {step.wait_for}",
                    "action": "wait_for_selector",
                    "selector": step.wait_for,
                    "timeout": step.timeout_ms,
                })

        # Cleanup steps
        for step in flow.cleanup_steps:
            yaml_steps.append({
                "name": step.description,
                "action": step.action,
                "selector": step.selector,
                **({"text": step.value} if step.value else {}),
                "continue_on_failure": True,  # Cleanup should not fail test
            })

        return yaml_steps

    async def analyze_page_coverage(
        self,
        browser: OwlBrowser,
        context_id: str,
    ) -> dict[str, Any]:
        """
        Analyze what percentage of page elements can be tested.

        Args:
            browser: Browser instance
            context_id: Browser context ID

        Returns:
            Coverage analysis dictionary
        """
        visibility_result = await self.visibility.analyze(browser, context_id)
        flows = await self.flow_discovery.discover_flows(browser, context_id)

        # Calculate how many hidden elements can be reached via flows
        reachable_hidden = sum(len(f.target_elements) for f in flows)

        total = visibility_result.total_elements
        directly_testable = visibility_result.visible_count
        flow_testable = reachable_hidden
        unreachable = visibility_result.hidden_count - reachable_hidden

        return {
            "total_elements": total,
            "directly_testable": directly_testable,
            "requires_flow": flow_testable,
            "unreachable": max(0, unreachable),
            "coverage_percentage": (
                (directly_testable + flow_testable) / max(1, total) * 100
            ),
            "flows_discovered": len(flows),
        }


# Convenience function
async def build_tests_for_page(
    browser: OwlBrowser,
    context_id: str,
    url: str,
) -> IntelligentTestPlan:
    """Build intelligent tests for a page using default builder."""
    builder = IntelligentBuilder()
    return await builder.build_page_tests(browser, context_id, url)
