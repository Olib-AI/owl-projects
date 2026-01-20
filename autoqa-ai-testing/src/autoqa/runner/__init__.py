"""
Test runner module with self-healing capabilities and intelligent layer.

Executes tests using owl-browser with:
- Deterministic self-healing (no AI/LLM dependency)
- Smart waits (network idle, selector visibility, animation complete)
- Intelligent overlay/modal detection and dismissal
- Fallback selector handling with self-healing cache
- Exponential backoff retry
- Screenshot/network log capture on failure
"""

from autoqa.runner.self_healing import (
    HealingResult,
    HealingStrategy,
    SelectorCandidate,
    SelectorHistory,
    SelfHealingEngine,
)
from autoqa.runner.test_runner import (
    ElementNotFoundError,
    ElementNotInteractableError,
    NetworkTimeoutError,
    StepResult,
    StepStatus,
    TestRunner,
    TestRunResult,
)
from autoqa.runner.intelligent_layer import (
    WaitStrategy,
    OverlayType,
    OverlayInfo,
    WaitResult,
    InteractabilityResult,
    SmartWaiter,
    OverlayHandler,
    FallbackSelectorResult,
    FallbackSelectorHandler,
    create_intelligent_runner_layer,
)

__all__ = [
    # Test Runner
    "TestRunner",
    "TestRunResult",
    "StepResult",
    "StepStatus",
    # Custom Exceptions
    "ElementNotFoundError",
    "ElementNotInteractableError",
    "NetworkTimeoutError",
    # Self-Healing
    "SelfHealingEngine",
    "HealingStrategy",
    "HealingResult",
    "SelectorCandidate",
    "SelectorHistory",
    # Intelligent Layer
    "WaitStrategy",
    "OverlayType",
    "OverlayInfo",
    "WaitResult",
    "InteractabilityResult",
    "SmartWaiter",
    "OverlayHandler",
    "FallbackSelectorResult",
    "FallbackSelectorHandler",
    "create_intelligent_runner_layer",
]
