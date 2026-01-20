"""
Discovery module for detecting application patterns, flows, and visibility.

Provides:
- Visibility analysis (what's visible vs hidden)
- State tracking (page state changes during interactions)
- Interaction analysis (what clicking elements does)
- Flow discovery (modal, tab, accordion, dropdown flows)
- Network monitoring (API calls, resource loading)
- Intelligent test building (orchestrates all components)
- User flow detection (login, registration, checkout)
- API/XHR endpoint detection
- Deep form analysis with validation inference
"""

from autoqa.builder.discovery.visibility_analyzer import (
    VisibilityAnalyzer,
    VisibilityState,
    ElementState,
    ElementCategory,
    VisibilityAnalysisResult,
    get_visible_elements,
    get_hidden_elements,
    is_visible,
)
from autoqa.builder.discovery.state_tracker import (
    StateTracker,
    PageState,
    StateDiff,
    StateChange,
    ChangeType,
    FormFieldState,
    ModalState,
    TabState,
    capture_page_state,
    compare_states,
)
from autoqa.builder.discovery.interaction_analyzer import (
    InteractionAnalyzer,
    InteractionEffect,
    EffectType,
    ElementInteractionProfile,
    analyze_click,
    find_trigger,
)
from autoqa.builder.discovery.flow_discovery import (
    FlowDiscovery,
    FlowType as DiscoveryFlowType,
    FlowStep as DiscoveryFlowStep,
    InteractionFlow,
)
from autoqa.builder.discovery.network_monitor import (
    NetworkMonitor,
    NetworkRequest,
    NetworkAnalysis,
    RequestType,
    wait_for_idle,
)
from autoqa.builder.discovery.intelligent_builder import (
    IntelligentBuilder,
    IntelligentTestStep,
    IntelligentTestPlan,
    build_tests_for_page,
)
from autoqa.builder.discovery.flow_detector import (
    FlowDetector,
    FlowConfig,
    UserFlow,
    FlowStep,
    FlowType,
)
from autoqa.builder.discovery.api_detector import (
    APIDetector,
    APIConfig,
    APIEndpoint,
    APIType,
    RequestMethod,
)
from autoqa.builder.discovery.form_analyzer import (
    FormAnalyzer,
    FormConfig,
    FormAnalysis,
    FieldAnalysis,
    FieldType,
    ValidationRule,
    TestCase,
)

__all__ = [
    # Visibility Analyzer
    "VisibilityAnalyzer",
    "VisibilityState",
    "ElementState",
    "ElementCategory",
    "VisibilityAnalysisResult",
    "get_visible_elements",
    "get_hidden_elements",
    "is_visible",
    # State Tracker
    "StateTracker",
    "PageState",
    "StateDiff",
    "StateChange",
    "ChangeType",
    "FormFieldState",
    "ModalState",
    "TabState",
    "capture_page_state",
    "compare_states",
    # Interaction Analyzer
    "InteractionAnalyzer",
    "InteractionEffect",
    "EffectType",
    "ElementInteractionProfile",
    "analyze_click",
    "find_trigger",
    # Flow Discovery (NEW)
    "FlowDiscovery",
    "DiscoveryFlowType",
    "DiscoveryFlowStep",
    "InteractionFlow",
    # Network Monitor (NEW)
    "NetworkMonitor",
    "NetworkRequest",
    "NetworkAnalysis",
    "RequestType",
    "wait_for_idle",
    # Intelligent Builder (NEW)
    "IntelligentBuilder",
    "IntelligentTestStep",
    "IntelligentTestPlan",
    "build_tests_for_page",
    # Flow Detector (legacy)
    "FlowDetector",
    "FlowConfig",
    "UserFlow",
    "FlowStep",
    "FlowType",
    # API Detector
    "APIDetector",
    "APIConfig",
    "APIEndpoint",
    "APIType",
    "RequestMethod",
    # Form Analyzer
    "FormAnalyzer",
    "FormConfig",
    "FormAnalysis",
    "FieldAnalysis",
    "FieldType",
    "ValidationRule",
    "TestCase",
]
