"""
AutoQA AI Testing System.

Production-ready AI-powered testing framework with natural language YAML definitions,
self-healing tests, visual regression, and generative testing capabilities.
"""

__version__ = "1.0.0"
__author__ = "Olib AI"

from autoqa.assertions.engine import AssertionEngine
from autoqa.dsl.models import (
    AssertionConfig,
    NetworkAssertionConfig,
    TestSpec,
    TestStep,
    TestSuite,
    VersioningConfigModel,
    VisualAssertionConfig,
)
from autoqa.dsl.parser import DSLParser
from autoqa.generative.chaos_agents import ChaosAgentFactory, ChaosPersona
from autoqa.orchestrator.scheduler import TestOrchestrator
from autoqa.runner.self_healing import SelfHealingEngine
from autoqa.runner.test_runner import TestRunner
from autoqa.storage.artifact_manager import ArtifactManager
from autoqa.versioning import (
    TestRunHistory,
    TestSnapshot,
    VersionDiff,
    VersionDiffAnalyzer,
    VersioningConfig,
)
from autoqa.visual.regression_engine import VisualRegressionEngine

__all__ = [
    "ArtifactManager",
    "AssertionConfig",
    "AssertionEngine",
    "ChaosAgentFactory",
    "ChaosPersona",
    "DSLParser",
    "NetworkAssertionConfig",
    "SelfHealingEngine",
    "TestOrchestrator",
    "TestRunHistory",
    "TestRunner",
    "TestSnapshot",
    "TestSpec",
    "TestStep",
    "TestSuite",
    "VersionDiff",
    "VersionDiffAnalyzer",
    "VersioningConfig",
    "VersioningConfigModel",
    "VisualAssertionConfig",
    "VisualRegressionEngine",
    "__version__",
]
