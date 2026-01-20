"""
Tests for the visibility analyzer module.

These tests verify that the visibility analyzer correctly identifies
visible vs hidden elements and understands modal/tab/accordion patterns.
"""

from __future__ import annotations

import pytest

from autoqa.builder.discovery.visibility_analyzer import (
    ElementCategory,
    ElementState,
    VisibilityAnalyzer,
    VisibilityAnalysisResult,
    VisibilityState,
)
from autoqa.builder.discovery.state_tracker import (
    ChangeType,
    PageState,
    StateDiff,
    StateTracker,
)
from autoqa.builder.discovery.interaction_analyzer import (
    EffectType,
    InteractionAnalyzer,
    InteractionEffect,
)


class TestVisibilityState:
    """Test VisibilityState enum."""

    def test_visibility_states_exist(self) -> None:
        """Verify all expected visibility states are defined."""
        assert VisibilityState.VISIBLE is not None
        assert VisibilityState.HIDDEN_CSS is not None
        assert VisibilityState.HIDDEN_DIMENSIONS is not None
        assert VisibilityState.HIDDEN_ARIA is not None
        assert VisibilityState.IN_CLOSED_MODAL is not None
        assert VisibilityState.IN_INACTIVE_TAB is not None
        assert VisibilityState.COLLAPSED is not None


class TestElementCategory:
    """Test ElementCategory enum."""

    def test_element_categories_exist(self) -> None:
        """Verify all expected element categories are defined."""
        assert ElementCategory.TRIGGER is not None
        assert ElementCategory.CONTENT is not None
        assert ElementCategory.FORM_INPUT is not None
        assert ElementCategory.NAVIGATION is not None
        assert ElementCategory.MODAL is not None
        assert ElementCategory.TAB_PANEL is not None
        assert ElementCategory.ACCORDION_CONTENT is not None


class TestElementState:
    """Test ElementState dataclass."""

    def test_element_state_creation(self) -> None:
        """Test creating an ElementState instance."""
        state = ElementState(
            selector="#test-button",
            tag_name="button",
            visibility_state=VisibilityState.VISIBLE,
            is_interactable=True,
            category=ElementCategory.TRIGGER,
            text_content="Click me",
        )

        assert state.selector == "#test-button"
        assert state.tag_name == "button"
        assert state.visibility_state == VisibilityState.VISIBLE
        assert state.is_interactable is True
        assert state.category == ElementCategory.TRIGGER
        assert state.text_content == "Click me"

    def test_element_state_defaults(self) -> None:
        """Test ElementState default values."""
        state = ElementState(
            selector="#test",
            tag_name="div",
            visibility_state=VisibilityState.HIDDEN_CSS,
            is_interactable=False,
            category=ElementCategory.CONTENT,
        )

        assert state.bounding_box is None
        assert state.computed_styles == {}
        assert state.attributes == {}
        assert state.text_content is None
        assert state.aria_label is None
        assert state.trigger_selector is None
        assert state.reveals_elements == []


class TestVisibilityAnalysisResult:
    """Test VisibilityAnalysisResult dataclass."""

    def test_analysis_result_creation(self) -> None:
        """Test creating an analysis result."""
        visible_el = ElementState(
            selector="#visible",
            tag_name="button",
            visibility_state=VisibilityState.VISIBLE,
            is_interactable=True,
            category=ElementCategory.TRIGGER,
        )

        hidden_el = ElementState(
            selector="#hidden-modal",
            tag_name="div",
            visibility_state=VisibilityState.IN_CLOSED_MODAL,
            is_interactable=False,
            category=ElementCategory.MODAL,
        )

        result = VisibilityAnalysisResult(
            url="https://example.com",
            visible_elements=[visible_el],
            hidden_elements=[hidden_el],
            triggers=[visible_el],
            modals=[hidden_el],
            tab_panels=[],
            accordion_sections=[],
            total_elements=2,
            visible_count=1,
            hidden_count=1,
        )

        assert result.url == "https://example.com"
        assert len(result.visible_elements) == 1
        assert len(result.hidden_elements) == 1
        assert result.total_elements == 2
        assert result.visible_count == 1
        assert result.hidden_count == 1


class TestVisibilityAnalyzer:
    """Test VisibilityAnalyzer class."""

    def test_analyzer_initialization(self) -> None:
        """Test analyzer can be initialized."""
        analyzer = VisibilityAnalyzer()
        assert analyzer is not None

    def test_process_element_visible(self) -> None:
        """Test processing a visible element."""
        analyzer = VisibilityAnalyzer()

        raw_data = {
            "selector": "#test-btn",
            "tagName": "button",
            "visibilityState": "visible",
            "isInteractable": True,
            "category": "trigger",
            "textContent": "Open Modal",
            "ariaLabel": None,
            "boundingBox": {"x": 100, "y": 200, "width": 80, "height": 30},
        }

        state = analyzer._process_element(raw_data)

        assert state.selector == "#test-btn"
        assert state.tag_name == "button"
        assert state.visibility_state == VisibilityState.VISIBLE
        assert state.is_interactable is True
        assert state.category == ElementCategory.TRIGGER
        assert state.text_content == "Open Modal"

    def test_process_element_hidden_modal(self) -> None:
        """Test processing an element hidden inside a closed modal."""
        analyzer = VisibilityAnalyzer()

        raw_data = {
            "selector": "#modal-form-input",
            "tagName": "input",
            "visibilityState": "in_closed_modal",
            "isInteractable": False,
            "category": "form_input",
            "textContent": "",
            "triggerSelector": "#open-modal-btn",
        }

        state = analyzer._process_element(raw_data)

        assert state.visibility_state == VisibilityState.IN_CLOSED_MODAL
        assert state.is_interactable is False
        assert state.category == ElementCategory.FORM_INPUT
        assert state.trigger_selector == "#open-modal-btn"


class TestStateTracker:
    """Test StateTracker class."""

    def test_tracker_initialization(self) -> None:
        """Test tracker can be initialized."""
        tracker = StateTracker()
        assert tracker is not None
        assert tracker.get_history() == []

    def test_diff_states_no_change(self) -> None:
        """Test diffing identical states."""
        from datetime import UTC, datetime

        tracker = StateTracker()

        state = PageState(
            url="https://example.com",
            title="Test",
            timestamp=datetime.now(UTC),
            visible_element_selectors=frozenset(["#btn1", "#btn2"]),
            hidden_element_selectors=frozenset(["#modal"]),
            open_modals=[],
            active_tabs=[],
            form_fields=[],
            scroll_position=(0, 0),
            document_height=1000,
            network_idle=True,
        )

        diff = tracker.diff_states(state, state)

        assert diff.url_changed is False
        assert diff.elements_appeared == []
        assert diff.elements_disappeared == []
        assert diff.modals_opened == []
        assert diff.modals_closed == []
        assert diff.has_significant_change is False

    def test_diff_states_element_appeared(self) -> None:
        """Test detecting newly visible elements."""
        from datetime import UTC, datetime

        tracker = StateTracker()

        before = PageState(
            url="https://example.com",
            title="Test",
            timestamp=datetime.now(UTC),
            visible_element_selectors=frozenset(["#btn1"]),
            hidden_element_selectors=frozenset(["#modal", "#modal-content"]),
            open_modals=[],
            active_tabs=[],
            form_fields=[],
            scroll_position=(0, 0),
            document_height=1000,
            network_idle=True,
        )

        after = PageState(
            url="https://example.com",
            title="Test",
            timestamp=datetime.now(UTC),
            visible_element_selectors=frozenset(["#btn1", "#modal", "#modal-content"]),
            hidden_element_selectors=frozenset(),
            open_modals=[],
            active_tabs=[],
            form_fields=[],
            scroll_position=(0, 0),
            document_height=1000,
            network_idle=True,
        )

        diff = tracker.diff_states(before, after)

        assert diff.has_significant_change is True
        assert "#modal" in diff.elements_appeared or "#modal-content" in diff.elements_appeared


class TestInteractionAnalyzer:
    """Test InteractionAnalyzer class."""

    def test_analyzer_initialization(self) -> None:
        """Test analyzer can be initialized."""
        analyzer = InteractionAnalyzer()
        assert analyzer is not None
        assert analyzer._visibility is not None
        assert analyzer._state_tracker is not None


class TestEffectType:
    """Test EffectType enum."""

    def test_effect_types_exist(self) -> None:
        """Verify all expected effect types are defined."""
        assert EffectType.OPENS_MODAL is not None
        assert EffectType.CLOSES_MODAL is not None
        assert EffectType.ACTIVATES_TAB is not None
        assert EffectType.NAVIGATES is not None
        assert EffectType.REVEALS_CONTENT is not None
        assert EffectType.NO_EFFECT is not None


class TestInteractionEffect:
    """Test InteractionEffect dataclass."""

    def test_interaction_effect_creation(self) -> None:
        """Test creating an interaction effect."""
        effect = InteractionEffect(
            action="click",
            selector="#open-modal-btn",
            effect_type=EffectType.OPENS_MODAL,
            revealed_elements=["#modal", "#modal-form"],
            modal_selector="#modal",
        )

        assert effect.action == "click"
        assert effect.selector == "#open-modal-btn"
        assert effect.effect_type == EffectType.OPENS_MODAL
        assert "#modal" in effect.revealed_elements
        assert effect.modal_selector == "#modal"
        assert effect.success is True
        assert effect.error is None
