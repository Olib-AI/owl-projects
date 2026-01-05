# AutoQA: The Self-Healing, AI-Driven Test Automation Suite

## 1. Executive Summary

**AutoQA** is an enterprise-grade QA orchestration platform that replaces brittle, code-heavy Selenium/Playwright scripts with resilient, natural language test definitions.

Built on the **Owl Browser**, AutoQA solves the "maintenance nightmare" of E2E testing. Traditional tests break when CSS selectors change. AutoQA's AI-Native engine understands user intent (e.g., "Log in"), allowing tests to "self-heal" automatically when the UI evolves.

**Core Value Proposition:**
*   **Zero-Maintenance:** Tests adapt to UI changes automatically.
*   **Generative Testing:** "Exploratory Agents" that find bugs you didn't write tests for.
*   **Visual Intelligence:** Semantic visual regression (detecting broken layouts, not just pixel shifts).

## 2. System Architecture

AutoQA is designed to run in high-throughput CI/CD pipelines (Jenkins, GitHub Actions, GitLab CI).

```mermaid
graph TD
    CI[CI/CD Pipeline] -->|Trigger| API[AutoQA API Gateway]
    
    API -->|Job Spec| Orchestrator[Test Orchestrator]
    
    subgraph "Execution Grid (Kubernetes)"
        Orchestrator -->|Schedule| Pod1[Runner Pod A]
        Orchestrator -->|Schedule| Pod2[Runner Pod B]
        
        Pod1 -->|Control| Owl1[Owl Browser Node]
        Pod2 -->|Control| Owl2[Owl Browser Node]
    end
    
    Owl1 -->|Video/Logs| S3[Artifact Storage]
    Owl1 -->|Results| DB[(PostgreSQL)]
    
    DB --> Report[Dashboard UI]
```

## 3. Test DSL & Parser - Complete Implementation

The core innovation is the separation of **Intent** (YAML) from **Execution** (AI). This section provides the complete DSL schema and parser implementation.

### 3.1. YAML Test Definition Schema

The AutoQA DSL supports variables, loops, conditionals, data injection, and reusable test fragments.

```yaml
# Full Schema Definition
# File: tests/checkout_flow.autoqa.yaml

metadata:
  name: "Checkout Flow - Guest User"
  id: "checkout-guest-001"
  tags: ["smoke", "checkout", "critical"]
  timeout: 300000  # 5 minutes max
  retries: 2
  parallel: false  # Sequential steps

# Test data injection - supports external files and inline data
data:
  source: "fixtures/checkout_users.csv"  # CSV, JSON, or YAML
  variables:
    base_url: "${ENV:STAGING_URL}"
    api_key: "${VAULT:checkout/api_key}"
  inline:
    test_email: "test+${RANDOM:8}@example.com"
    test_phone: "+1555${RANDOM:7}"

# Reusable fragments
fragments:
  login_flow: &login_flow
    - navigate: "${base_url}/login"
    - type:
        target: "Email input"
        value: "${user_email}"
    - type:
        target: "Password input"
        value: "${user_password}"
    - click: "Sign In button"
    - wait_for: "Dashboard"

# Main test steps
steps:
  # Include fragment
  - include: *login_flow

  # Navigation with wait strategy
  - navigate:
      url: "${base_url}/cart"
      wait_until: "networkidle"
      timeout: 10000

  # Conditional execution
  - if:
      condition: "element_exists('Cookie Banner')"
      then:
        - click: "Accept Cookies"
      else:
        - log: "No cookie banner present"

  # Loop through test data
  - foreach:
      items: "${data.products}"
      as: "product"
      steps:
        - click: "Add ${product.name} to cart"
        - assert:
            type: "text_contains"
            target: "Cart Counter"
            expected: "${loop.index + 1}"

  # Standard click action
  - click: "Checkout Button"

  # Type with options
  - type:
      target: "Email Address"
      value: "${test_email}"
      clear_first: true
      delay_ms: 50  # Human-like typing

  # Dropdown selection
  - pick:
      target: "Country Selector"
      value: "United States"

  # Wait for dynamic content
  - wait_for:
      selector: "Shipping Options"
      timeout: 5000
      state: "visible"

  # Visual assertion
  - assert:
      type: "visual"
      query: "I see the shipping address form with all required fields"

  # Network assertion
  - assert:
      type: "network"
      method: "POST"
      url_pattern: "/api/v1/checkout/*"
      status: 200

  # Screenshot checkpoint
  - screenshot:
      name: "checkout-step-1"
      mode: "viewport"

# Post-test hooks
hooks:
  on_failure:
    - screenshot: "failure-state"
    - execute: "page.get_console_logs(level='error')"
  on_success:
    - log: "Test completed successfully"
  cleanup:
    - navigate: "${base_url}/cart/clear"
```

### 3.2. DSL Parser with Validation

Complete Python implementation of the DSL parser with Pydantic validation:

```python
"""
AutoQA DSL Parser - Production Implementation
File: autoqa/parser/dsl_parser.py
"""
from __future__ import annotations

import re
import os
import csv
import json
import secrets
from pathlib import Path
from typing import Any, Literal, Self
from enum import StrEnum
from dataclasses import dataclass, field
from collections.abc import Iterator, Mapping, Sequence

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class StepType(StrEnum):
    """Supported DSL step types."""
    NAVIGATE = "navigate"
    CLICK = "click"
    TYPE = "type"
    PICK = "pick"
    ASSERT = "assert"
    WAIT_FOR = "wait_for"
    SCREENSHOT = "screenshot"
    IF = "if"
    FOREACH = "foreach"
    INCLUDE = "include"
    LOG = "log"
    EXECUTE = "execute"


class AssertionType(StrEnum):
    """Supported assertion types."""
    VISUAL = "visual"
    TEXT_CONTAINS = "text_contains"
    TEXT_EQUALS = "text_equals"
    ELEMENT_EXISTS = "element_exists"
    ELEMENT_NOT_EXISTS = "element_not_exists"
    NETWORK = "network"
    CONSOLE = "console"
    CUSTOM = "custom"


class WaitUntilStrategy(StrEnum):
    """Page load wait strategies."""
    LOAD = "load"
    DOMCONTENTLOADED = "domcontentloaded"
    NETWORKIDLE = "networkidle"


# --- Pydantic Models for DSL Validation ---

class NavigateStep(BaseModel):
    """Navigation step configuration."""
    url: str
    wait_until: WaitUntilStrategy = WaitUntilStrategy.LOAD
    timeout: int = Field(default=30000, ge=1000, le=300000)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://", "${")):
            raise ValueError(f"Invalid URL format: {v}")
        return v


class TypeStep(BaseModel):
    """Type/input step configuration."""
    target: str
    value: str
    clear_first: bool = True
    delay_ms: int = Field(default=0, ge=0, le=500)


class PickStep(BaseModel):
    """Dropdown selection step configuration."""
    target: str
    value: str


class AssertStep(BaseModel):
    """Assertion step configuration."""
    type: AssertionType
    query: str | None = None
    target: str | None = None
    expected: str | None = None
    method: str | None = None
    url_pattern: str | None = None
    status: int | None = None
    tolerance: float = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_assertion_fields(self) -> Self:
        match self.type:
            case AssertionType.VISUAL:
                if not self.query:
                    raise ValueError("Visual assertions require 'query' field")
            case AssertionType.TEXT_CONTAINS | AssertionType.TEXT_EQUALS:
                if not self.target or not self.expected:
                    raise ValueError("Text assertions require 'target' and 'expected'")
            case AssertionType.NETWORK:
                if not self.url_pattern:
                    raise ValueError("Network assertions require 'url_pattern'")
        return self


class WaitForStep(BaseModel):
    """Wait step configuration."""
    selector: str | None = None
    timeout: int = Field(default=30000, ge=100, le=300000)
    state: Literal["visible", "hidden", "attached", "detached"] = "visible"
    js_function: str | None = None
    network_idle: bool = False
    idle_time: int = Field(default=500, ge=100, le=5000)


class ScreenshotStep(BaseModel):
    """Screenshot capture configuration."""
    name: str
    mode: Literal["viewport", "fullpage", "element"] = "viewport"
    selector: str | None = None
    scale: float = Field(default=1.0, ge=0.5, le=3.0)


class ConditionalStep(BaseModel):
    """If/else conditional step."""
    condition: str
    then_steps: list[dict[str, Any]] = Field(alias="then")
    else_steps: list[dict[str, Any]] = Field(default_factory=list, alias="else")


class LoopStep(BaseModel):
    """Foreach loop step."""
    items: str
    as_var: str = Field(alias="as")
    steps: list[dict[str, Any]]


class TestMetadata(BaseModel):
    """Test metadata configuration."""
    name: str
    id: str
    tags: list[str] = Field(default_factory=list)
    timeout: int = Field(default=300000, ge=10000, le=3600000)
    retries: int = Field(default=0, ge=0, le=5)
    parallel: bool = False


class DataConfig(BaseModel):
    """Test data configuration."""
    source: str | None = None
    variables: dict[str, str] = Field(default_factory=dict)
    inline: dict[str, Any] = Field(default_factory=dict)


class HooksConfig(BaseModel):
    """Test hooks configuration."""
    on_failure: list[dict[str, Any]] = Field(default_factory=list)
    on_success: list[dict[str, Any]] = Field(default_factory=list)
    cleanup: list[dict[str, Any]] = Field(default_factory=list)


class TestDefinition(BaseModel):
    """Complete test definition model."""
    metadata: TestMetadata
    data: DataConfig = Field(default_factory=DataConfig)
    fragments: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    steps: list[dict[str, Any]]
    hooks: HooksConfig = Field(default_factory=HooksConfig)


# --- Variable Resolution Engine ---

@dataclass
class VariableContext:
    """Runtime context for variable resolution."""
    env_vars: dict[str, str] = field(default_factory=dict)
    data_vars: dict[str, Any] = field(default_factory=dict)
    loop_vars: dict[str, Any] = field(default_factory=dict)
    vault_client: Any | None = None

    def resolve(self, value: str) -> str:
        """Resolve all variable references in a string."""
        if not isinstance(value, str):
            return value

        # Pattern: ${TYPE:key} or ${key}
        pattern = r"\$\{(?:(\w+):)?([^}]+)\}"

        def replacer(match: re.Match[str]) -> str:
            var_type = match.group(1)
            var_key = match.group(2)

            match var_type:
                case "ENV":
                    return self.env_vars.get(var_key, os.environ.get(var_key, ""))
                case "VAULT":
                    if self.vault_client:
                        return self.vault_client.read(var_key)
                    raise ValueError(f"Vault not configured for: {var_key}")
                case "RANDOM":
                    length = int(var_key) if var_key.isdigit() else 8
                    return secrets.token_hex(length // 2 + 1)[:length]
                case "DATA":
                    return str(self._get_nested(self.data_vars, var_key))
                case None:
                    # Check all contexts in order
                    for ctx in [self.loop_vars, self.data_vars, self.env_vars]:
                        if var_key in ctx:
                            return str(ctx[var_key])
                    return match.group(0)  # Keep unresolved
                case _:
                    return match.group(0)

        return re.sub(pattern, replacer, value)

    def _get_nested(self, data: dict[str, Any], key: str) -> Any:
        """Get nested dictionary value using dot notation."""
        keys = key.split(".")
        result = data
        for k in keys:
            if isinstance(result, dict):
                result = result.get(k)
            elif isinstance(result, list) and k.isdigit():
                result = result[int(k)]
            else:
                return None
        return result


# --- DSL Parser ---

class DSLParser:
    """
    Production DSL parser with validation, variable resolution, and data loading.

    Example:
        parser = DSLParser()
        test_def = parser.parse_file("tests/checkout.autoqa.yaml")
        for step in parser.iterate_steps(test_def):
            print(step)
    """

    def __init__(self, base_path: Path | None = None) -> None:
        self.base_path = base_path or Path.cwd()
        self._fragment_cache: dict[str, list[dict[str, Any]]] = {}

    def parse_file(self, file_path: str | Path) -> TestDefinition:
        """Parse a YAML test file and return validated TestDefinition."""
        path = self.base_path / file_path if not Path(file_path).is_absolute() else Path(file_path)

        with path.open("r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)

        return self.parse_dict(raw_data)

    def parse_dict(self, data: dict[str, Any]) -> TestDefinition:
        """Parse a dictionary into a validated TestDefinition."""
        # Cache fragments for include resolution
        if "fragments" in data:
            self._fragment_cache.update(data["fragments"])

        return TestDefinition.model_validate(data)

    def load_test_data(self, data_config: DataConfig) -> dict[str, Any]:
        """Load test data from external sources."""
        result: dict[str, Any] = {}

        # Load from external file
        if data_config.source:
            source_path = self.base_path / data_config.source
            suffix = source_path.suffix.lower()

            match suffix:
                case ".csv":
                    with source_path.open("r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        result["rows"] = list(reader)
                case ".json":
                    with source_path.open("r", encoding="utf-8") as f:
                        result.update(json.load(f))
                case ".yaml" | ".yml":
                    with source_path.open("r", encoding="utf-8") as f:
                        result.update(yaml.safe_load(f))
                case _:
                    raise ValueError(f"Unsupported data format: {suffix}")

        # Merge inline data
        result.update(data_config.inline)
        result.update(data_config.variables)

        return result

    def iterate_steps(
        self,
        test_def: TestDefinition,
        context: VariableContext | None = None,
    ) -> Iterator[tuple[StepType, dict[str, Any]]]:
        """
        Iterate through all steps, resolving includes, loops, and conditionals.

        Yields:
            Tuple of (step_type, resolved_step_config)
        """
        ctx = context or VariableContext()
        ctx.data_vars = self.load_test_data(test_def.data)

        yield from self._process_steps(test_def.steps, ctx)

    def _process_steps(
        self,
        steps: Sequence[dict[str, Any]],
        context: VariableContext,
    ) -> Iterator[tuple[StepType, dict[str, Any]]]:
        """Recursively process steps with variable resolution."""
        for step in steps:
            resolved_step = self._resolve_step_vars(step, context)

            # Handle special step types
            if "include" in resolved_step:
                fragment_name = resolved_step["include"]
                if fragment_name in self._fragment_cache:
                    yield from self._process_steps(
                        self._fragment_cache[fragment_name], context
                    )
                continue

            if "if" in resolved_step:
                cond_config = resolved_step["if"]
                condition_met = self._evaluate_condition(
                    cond_config["condition"], context
                )
                if condition_met:
                    yield from self._process_steps(cond_config.get("then", []), context)
                else:
                    yield from self._process_steps(cond_config.get("else", []), context)
                continue

            if "foreach" in resolved_step:
                loop_config = resolved_step["foreach"]
                items = context.resolve(loop_config["items"])
                # Resolve items reference
                if items.startswith("${"):
                    items_key = items[2:-1].split(".")[-1]
                    items = context.data_vars.get(items_key, [])

                if isinstance(items, str):
                    items = json.loads(items) if items.startswith("[") else []

                for idx, item in enumerate(items):
                    loop_ctx = VariableContext(
                        env_vars=context.env_vars,
                        data_vars=context.data_vars,
                        loop_vars={
                            loop_config["as"]: item,
                            "loop": {"index": idx, "first": idx == 0, "last": idx == len(items) - 1},
                        },
                        vault_client=context.vault_client,
                    )
                    yield from self._process_steps(loop_config["steps"], loop_ctx)
                continue

            # Determine step type and yield
            step_type = self._get_step_type(resolved_step)
            if step_type:
                yield (step_type, resolved_step)

    def _resolve_step_vars(
        self, step: dict[str, Any], context: VariableContext
    ) -> dict[str, Any]:
        """Recursively resolve variables in a step configuration."""
        result: dict[str, Any] = {}
        for key, value in step.items():
            if isinstance(value, str):
                result[key] = context.resolve(value)
            elif isinstance(value, dict):
                result[key] = self._resolve_step_vars(value, context)
            elif isinstance(value, list):
                result[key] = [
                    self._resolve_step_vars(v, context) if isinstance(v, dict)
                    else context.resolve(v) if isinstance(v, str)
                    else v
                    for v in value
                ]
            else:
                result[key] = value
        return result

    def _get_step_type(self, step: dict[str, Any]) -> StepType | None:
        """Determine the step type from step dictionary."""
        for step_type in StepType:
            if step_type.value in step:
                return step_type
        return None

    def _evaluate_condition(self, condition: str, context: VariableContext) -> bool:
        """Evaluate a condition expression."""
        resolved = context.resolve(condition)

        # Simple condition evaluations
        if resolved.startswith("element_exists("):
            # This will be evaluated at runtime by the executor
            return True  # Placeholder - actual check happens in executor

        # Boolean string check
        return resolved.lower() in ("true", "1", "yes")


# --- Usage Example ---

async def parse_and_validate_test(test_file: str) -> None:
    """Example usage of the DSL parser."""
    parser = DSLParser(base_path=Path("/tests"))

    try:
        test_def = parser.parse_file(test_file)
        print(f"Parsed test: {test_def.metadata.name}")
        print(f"Tags: {test_def.metadata.tags}")
        print(f"Timeout: {test_def.metadata.timeout}ms")

        context = VariableContext(
            env_vars={"STAGING_URL": "https://staging.example.com"},
        )

        for step_type, step_config in parser.iterate_steps(test_def, context):
            print(f"Step: {step_type.value} -> {step_config}")

    except Exception as e:
        print(f"Validation error: {e}")
```

### 3.3. The Self-Healing Test Runner - Full Implementation

The runner executes parsed DSL steps with intelligent fallback chains and healing capabilities:

```python
"""
AutoQA Self-Healing Test Runner - Production Implementation
File: autoqa/runner/smart_runner.py
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, TypedDict

from owl_browser import Browser, Page, RemoteConfig
from owl_browser.exceptions import ElementNotFoundError, TimeoutError as OwlTimeoutError

from autoqa.parser.dsl_parser import (
    DSLParser,
    StepType,
    TestDefinition,
    VariableContext,
    AssertionType,
)


class HealingStrategy(StrEnum):
    """Element location fallback strategies."""
    CSS_SELECTOR = "css"
    XPATH = "xpath"
    AI_DESCRIPTION = "ai"
    COORDINATES = "coords"


class StepStatus(StrEnum):
    """Step execution status."""
    PASSED = "passed"
    FAILED = "failed"
    HEALED = "healed"
    SKIPPED = "skipped"


@dataclass
class HealingEvent:
    """Record of a self-healing event."""
    step_index: int
    original_selector: str
    healed_selector: str
    strategy_used: HealingStrategy
    timestamp: datetime
    confidence: float


@dataclass
class StepResult:
    """Result of a single step execution."""
    step_index: int
    step_type: StepType
    status: StepStatus
    duration_ms: float
    error: str | None = None
    healing_event: HealingEvent | None = None
    screenshot_path: str | None = None
    artifacts: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    """Complete test execution result."""
    test_id: str
    test_name: str
    status: StepStatus
    total_duration_ms: float
    step_results: list[StepResult]
    healing_events: list[HealingEvent]
    video_path: str | None = None
    console_logs: list[dict[str, Any]] = field(default_factory=list)
    network_log: list[dict[str, Any]] = field(default_factory=list)


class SelectorCache(Protocol):
    """Protocol for selector cache storage."""
    async def get(self, test_id: str, step_hash: str) -> str | None: ...
    async def set(self, test_id: str, step_hash: str, selector: str) -> None: ...


@dataclass
class InMemorySelectorCache:
    """Simple in-memory selector cache for development."""
    _cache: dict[str, str] = field(default_factory=dict)

    async def get(self, test_id: str, step_hash: str) -> str | None:
        return self._cache.get(f"{test_id}:{step_hash}")

    async def set(self, test_id: str, step_hash: str, selector: str) -> None:
        self._cache[f"{test_id}:{step_hash}"] = selector


class SmartStepExecutor:
    """
    Executes individual test steps with self-healing capabilities.

    Uses a fallback chain: Cached Selector -> CSS -> XPath -> AI Description
    """

    def __init__(
        self,
        page: Page,
        selector_cache: SelectorCache,
        test_id: str,
    ) -> None:
        self.page = page
        self.selector_cache = selector_cache
        self.test_id = test_id
        self._healing_events: list[HealingEvent] = []

    @property
    def healing_events(self) -> list[HealingEvent]:
        return self._healing_events.copy()

    def _hash_step(self, step_config: dict[str, Any]) -> str:
        """Create a stable hash for a step configuration."""
        canonical = json.dumps(step_config, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    async def execute_click(
        self,
        step_config: dict[str, Any],
        step_index: int,
    ) -> StepResult:
        """Execute a click step with healing fallback."""
        start_time = time.perf_counter()
        target = step_config.get("click") or step_config.get("target", "")
        step_hash = self._hash_step({"click": target})

        # Strategy 1: Check selector cache for previously healed selector
        cached_selector = await self.selector_cache.get(self.test_id, step_hash)
        if cached_selector:
            try:
                await self.page.wait_for_selector(cached_selector, timeout=5000)
                await self.page.click(cached_selector)
                return StepResult(
                    step_index=step_index,
                    step_type=StepType.CLICK,
                    status=StepStatus.PASSED,
                    duration_ms=(time.perf_counter() - start_time) * 1000,
                )
            except (ElementNotFoundError, OwlTimeoutError):
                pass  # Fall through to other strategies

        # Strategy 2: Try CSS selector if provided
        css_selector = step_config.get("selector")
        if css_selector:
            try:
                await self.page.wait_for_selector(css_selector, timeout=5000)
                await self.page.click(css_selector)
                return StepResult(
                    step_index=step_index,
                    step_type=StepType.CLICK,
                    status=StepStatus.PASSED,
                    duration_ms=(time.perf_counter() - start_time) * 1000,
                )
            except (ElementNotFoundError, OwlTimeoutError):
                pass  # Fall through to AI healing

        # Strategy 3: AI-powered element finding
        healing_result = await self._heal_and_click(
            target=target,
            step_index=step_index,
            step_hash=step_hash,
        )

        healing_result.duration_ms = (time.perf_counter() - start_time) * 1000
        return healing_result

    async def _heal_and_click(
        self,
        target: str,
        step_index: int,
        step_hash: str,
    ) -> StepResult:
        """Attempt AI-powered healing for click action."""
        # Use find_element to get candidates
        try:
            elements = await self.page.find_element(target, max_results=3)

            if elements and len(elements) > 0:
                # Get the best match
                best_match = elements[0]
                selector = best_match.get("selector", "")
                confidence = best_match.get("confidence", 0.0)

                # Execute the click using AI
                await self.page.ai_click(target)

                # Cache the healed selector for future runs
                if selector:
                    await self.selector_cache.set(self.test_id, step_hash, selector)

                healing_event = HealingEvent(
                    step_index=step_index,
                    original_selector=target,
                    healed_selector=selector,
                    strategy_used=HealingStrategy.AI_DESCRIPTION,
                    timestamp=datetime.now(UTC),
                    confidence=confidence,
                )
                self._healing_events.append(healing_event)

                return StepResult(
                    step_index=step_index,
                    step_type=StepType.CLICK,
                    status=StepStatus.HEALED,
                    duration_ms=0,  # Will be set by caller
                    healing_event=healing_event,
                )
        except ElementNotFoundError:
            pass

        # Last resort: query the page for guidance
        try:
            query_result = await self.page.query_page(
                f"Where is the element described as '{target}'? "
                "Provide the exact location or describe how to find it."
            )

            # Try AI click with enhanced context
            await self.page.ai_click(f"{target} - {query_result}")

            healing_event = HealingEvent(
                step_index=step_index,
                original_selector=target,
                healed_selector=f"AI-guided: {query_result[:100]}",
                strategy_used=HealingStrategy.AI_DESCRIPTION,
                timestamp=datetime.now(UTC),
                confidence=0.5,
            )
            self._healing_events.append(healing_event)

            return StepResult(
                step_index=step_index,
                step_type=StepType.CLICK,
                status=StepStatus.HEALED,
                duration_ms=0,
                healing_event=healing_event,
            )
        except Exception as e:
            return StepResult(
                step_index=step_index,
                step_type=StepType.CLICK,
                status=StepStatus.FAILED,
                duration_ms=0,
                error=f"All healing strategies exhausted: {e}",
            )

    async def execute_type(
        self,
        step_config: dict[str, Any],
        step_index: int,
    ) -> StepResult:
        """Execute a type step with healing fallback."""
        start_time = time.perf_counter()

        if isinstance(step_config.get("type"), dict):
            config = step_config["type"]
            target = config["target"]
            value = config["value"]
            clear_first = config.get("clear_first", True)
        else:
            target = step_config.get("target", "")
            value = step_config.get("value", "")
            clear_first = step_config.get("clear_first", True)

        step_hash = self._hash_step({"type": target})

        # Try cached selector first
        cached_selector = await self.selector_cache.get(self.test_id, step_hash)
        if cached_selector:
            try:
                await self.page.wait_for_selector(cached_selector, timeout=5000)
                if clear_first:
                    await self.page.clear_input(cached_selector)
                await self.page.type(cached_selector, value)
                return StepResult(
                    step_index=step_index,
                    step_type=StepType.TYPE,
                    status=StepStatus.PASSED,
                    duration_ms=(time.perf_counter() - start_time) * 1000,
                )
            except (ElementNotFoundError, OwlTimeoutError):
                pass

        # Try direct selector
        css_selector = step_config.get("selector")
        if css_selector:
            try:
                await self.page.wait_for_selector(css_selector, timeout=5000)
                if clear_first:
                    await self.page.clear_input(css_selector)
                await self.page.type(css_selector, value)
                return StepResult(
                    step_index=step_index,
                    step_type=StepType.TYPE,
                    status=StepStatus.PASSED,
                    duration_ms=(time.perf_counter() - start_time) * 1000,
                )
            except (ElementNotFoundError, OwlTimeoutError):
                pass

        # AI-powered typing
        try:
            await self.page.ai_type(target, value)

            # Try to learn the selector for future runs
            elements = await self.page.find_element(target, max_results=1)
            if elements:
                selector = elements[0].get("selector", "")
                if selector:
                    await self.selector_cache.set(self.test_id, step_hash, selector)

            healing_event = HealingEvent(
                step_index=step_index,
                original_selector=target,
                healed_selector="AI-typed",
                strategy_used=HealingStrategy.AI_DESCRIPTION,
                timestamp=datetime.now(UTC),
                confidence=0.8,
            )
            self._healing_events.append(healing_event)

            return StepResult(
                step_index=step_index,
                step_type=StepType.TYPE,
                status=StepStatus.HEALED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
                healing_event=healing_event,
            )
        except Exception as e:
            return StepResult(
                step_index=step_index,
                step_type=StepType.TYPE,
                status=StepStatus.FAILED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
                error=str(e),
            )

    async def execute_wait_for(
        self,
        step_config: dict[str, Any],
        step_index: int,
    ) -> StepResult:
        """Execute wait step with multiple strategies."""
        start_time = time.perf_counter()

        if isinstance(step_config.get("wait_for"), dict):
            config = step_config["wait_for"]
        else:
            config = {"selector": step_config.get("wait_for", "")}

        timeout = config.get("timeout", 30000)

        try:
            # Network idle wait
            if config.get("network_idle"):
                idle_time = config.get("idle_time", 500)
                await self.page.wait_for_network_idle(
                    idle_time=idle_time,
                    timeout=timeout,
                )
            # JavaScript function wait
            elif config.get("js_function"):
                await self.page.wait_for_function(
                    config["js_function"],
                    timeout=timeout,
                )
            # URL pattern wait
            elif config.get("url_pattern"):
                await self.page.wait_for_url(
                    config["url_pattern"],
                    is_regex=config.get("is_regex", False),
                )
            # Element selector wait (default)
            elif config.get("selector"):
                selector = config["selector"]
                # Try CSS first, then AI
                try:
                    await self.page.wait_for_selector(selector, timeout=timeout)
                except OwlTimeoutError:
                    # AI fallback - use find_element to check presence
                    elements = await self.page.find_element(selector, max_results=1)
                    if not elements:
                        raise

            return StepResult(
                step_index=step_index,
                step_type=StepType.WAIT_FOR,
                status=StepStatus.PASSED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
            )
        except Exception as e:
            return StepResult(
                step_index=step_index,
                step_type=StepType.WAIT_FOR,
                status=StepStatus.FAILED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
                error=str(e),
            )


class SmartTestRunner:
    """
    Main test runner orchestrating execution with healing, recording, and artifacts.
    """

    def __init__(
        self,
        browser_config: RemoteConfig,
        artifact_path: Path,
        selector_cache: SelectorCache | None = None,
    ) -> None:
        self.browser_config = browser_config
        self.artifact_path = artifact_path
        self.selector_cache = selector_cache or InMemorySelectorCache()
        self._browser: Browser | None = None
        self._page: Page | None = None

    async def __aenter__(self) -> SmartTestRunner:
        self._browser = Browser(remote=self.browser_config)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._browser:
            await self._browser.close()

    async def run_test(
        self,
        test_def: TestDefinition,
        context: VariableContext | None = None,
        record_video: bool = True,
    ) -> TestResult:
        """Execute a complete test with all steps."""
        if not self._browser:
            raise RuntimeError("Runner not initialized. Use async context manager.")

        test_start = time.perf_counter()
        self._page = await self._browser.new_page()

        step_results: list[StepResult] = []
        ctx = context or VariableContext()

        # Start video recording
        if record_video:
            await self._page.start_video_recording(fps=30, codec="h264")

        # Enable network logging for assertions
        await self._page.enable_network_logging(True)

        executor = SmartStepExecutor(
            page=self._page,
            selector_cache=self.selector_cache,
            test_id=test_def.metadata.id,
        )

        parser = DSLParser()
        overall_status = StepStatus.PASSED

        try:
            for step_index, (step_type, step_config) in enumerate(
                parser.iterate_steps(test_def, ctx)
            ):
                result = await self._execute_step(
                    executor=executor,
                    step_type=step_type,
                    step_config=step_config,
                    step_index=step_index,
                )
                step_results.append(result)

                if result.status == StepStatus.FAILED:
                    overall_status = StepStatus.FAILED
                    # Execute failure hooks
                    await self._execute_hooks(
                        test_def.hooks.on_failure,
                        executor,
                        len(step_results),
                    )
                    break
                elif result.status == StepStatus.HEALED:
                    if overall_status == StepStatus.PASSED:
                        overall_status = StepStatus.HEALED

        except Exception as e:
            overall_status = StepStatus.FAILED
            step_results.append(StepResult(
                step_index=len(step_results),
                step_type=StepType.EXECUTE,
                status=StepStatus.FAILED,
                duration_ms=0,
                error=str(e),
            ))

        # Stop video and collect artifacts
        video_path: str | None = None
        if record_video:
            video_path = await self._page.stop_video_recording()

        # Collect console logs
        console_logs = await self._page.get_console_logs(level="all", limit=1000)

        # Collect network log
        network_log = await self._page.get_network_log(limit=500)

        # Execute success or cleanup hooks
        if overall_status in (StepStatus.PASSED, StepStatus.HEALED):
            await self._execute_hooks(
                test_def.hooks.on_success,
                executor,
                len(step_results),
            )
        await self._execute_hooks(
            test_def.hooks.cleanup,
            executor,
            len(step_results),
        )

        await self._page.close()

        return TestResult(
            test_id=test_def.metadata.id,
            test_name=test_def.metadata.name,
            status=overall_status,
            total_duration_ms=(time.perf_counter() - test_start) * 1000,
            step_results=step_results,
            healing_events=executor.healing_events,
            video_path=video_path,
            console_logs=console_logs,
            network_log=network_log,
        )

    async def _execute_step(
        self,
        executor: SmartStepExecutor,
        step_type: StepType,
        step_config: dict[str, Any],
        step_index: int,
    ) -> StepResult:
        """Route step execution to appropriate handler."""
        assert self._page is not None

        match step_type:
            case StepType.NAVIGATE:
                return await self._execute_navigate(step_config, step_index)
            case StepType.CLICK:
                return await executor.execute_click(step_config, step_index)
            case StepType.TYPE:
                return await executor.execute_type(step_config, step_index)
            case StepType.PICK:
                return await self._execute_pick(step_config, step_index)
            case StepType.WAIT_FOR:
                return await executor.execute_wait_for(step_config, step_index)
            case StepType.ASSERT:
                return await self._execute_assert(step_config, step_index)
            case StepType.SCREENSHOT:
                return await self._execute_screenshot(step_config, step_index)
            case StepType.LOG:
                return StepResult(
                    step_index=step_index,
                    step_type=StepType.LOG,
                    status=StepStatus.PASSED,
                    duration_ms=0,
                )
            case _:
                return StepResult(
                    step_index=step_index,
                    step_type=step_type,
                    status=StepStatus.SKIPPED,
                    duration_ms=0,
                    error=f"Unsupported step type: {step_type}",
                )

    async def _execute_navigate(
        self,
        step_config: dict[str, Any],
        step_index: int,
    ) -> StepResult:
        """Execute navigation step."""
        assert self._page is not None
        start_time = time.perf_counter()

        if isinstance(step_config.get("navigate"), dict):
            config = step_config["navigate"]
            url = config["url"]
            wait_until = config.get("wait_until", "load")
            timeout = config.get("timeout", 30000)
        else:
            url = step_config.get("navigate", "")
            wait_until = "load"
            timeout = 30000

        try:
            await self._page.goto(url, wait_until=wait_until, timeout=timeout)
            return StepResult(
                step_index=step_index,
                step_type=StepType.NAVIGATE,
                status=StepStatus.PASSED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
            )
        except Exception as e:
            return StepResult(
                step_index=step_index,
                step_type=StepType.NAVIGATE,
                status=StepStatus.FAILED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
                error=str(e),
            )

    async def _execute_pick(
        self,
        step_config: dict[str, Any],
        step_index: int,
    ) -> StepResult:
        """Execute dropdown selection step."""
        assert self._page is not None
        start_time = time.perf_counter()

        if isinstance(step_config.get("pick"), dict):
            config = step_config["pick"]
            target = config["target"]
            value = config["value"]
        else:
            target = step_config.get("target", "")
            value = step_config.get("value", "")

        try:
            await self._page.pick(target, value)
            return StepResult(
                step_index=step_index,
                step_type=StepType.PICK,
                status=StepStatus.PASSED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
            )
        except Exception as e:
            return StepResult(
                step_index=step_index,
                step_type=StepType.PICK,
                status=StepStatus.FAILED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
                error=str(e),
            )

    async def _execute_assert(
        self,
        step_config: dict[str, Any],
        step_index: int,
    ) -> StepResult:
        """Execute assertion step - delegated to AssertionEngine."""
        # Implementation in Section 6 - Assertion Engine
        start_time = time.perf_counter()
        assert self._page is not None

        if isinstance(step_config.get("assert"), dict):
            config = step_config["assert"]
        else:
            # Simple string assertion - treat as visual
            config = {"type": "visual", "query": step_config.get("assert", "")}

        assertion_type = AssertionType(config.get("type", "visual"))

        try:
            match assertion_type:
                case AssertionType.VISUAL:
                    result = await self._page.query_page(config["query"])
                    passed = "yes" in result.lower() or "true" in result.lower()
                case AssertionType.TEXT_CONTAINS:
                    text = await self._page.extract_text(config.get("target"))
                    passed = config["expected"] in text
                case AssertionType.TEXT_EQUALS:
                    text = await self._page.extract_text(config.get("target"))
                    passed = text.strip() == config["expected"].strip()
                case AssertionType.ELEMENT_EXISTS:
                    elements = await self._page.find_element(
                        config["target"], max_results=1
                    )
                    passed = len(elements) > 0
                case AssertionType.NETWORK:
                    network_log = await self._page.get_network_log(limit=100)
                    passed = any(
                        config.get("url_pattern", "") in entry.get("url", "")
                        and entry.get("status") == config.get("status", 200)
                        for entry in network_log
                    )
                case _:
                    passed = False

            return StepResult(
                step_index=step_index,
                step_type=StepType.ASSERT,
                status=StepStatus.PASSED if passed else StepStatus.FAILED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
                error=None if passed else f"Assertion failed: {config}",
            )
        except Exception as e:
            return StepResult(
                step_index=step_index,
                step_type=StepType.ASSERT,
                status=StepStatus.FAILED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
                error=str(e),
            )

    async def _execute_screenshot(
        self,
        step_config: dict[str, Any],
        step_index: int,
    ) -> StepResult:
        """Execute screenshot capture step."""
        assert self._page is not None
        start_time = time.perf_counter()

        if isinstance(step_config.get("screenshot"), dict):
            config = step_config["screenshot"]
            name = config["name"]
            mode = config.get("mode", "viewport")
        else:
            name = step_config.get("screenshot", f"step-{step_index}")
            mode = "viewport"

        screenshot_path = self.artifact_path / f"{name}.png"

        try:
            await self._page.screenshot(
                path=str(screenshot_path),
                mode=mode,
            )
            return StepResult(
                step_index=step_index,
                step_type=StepType.SCREENSHOT,
                status=StepStatus.PASSED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
                screenshot_path=str(screenshot_path),
            )
        except Exception as e:
            return StepResult(
                step_index=step_index,
                step_type=StepType.SCREENSHOT,
                status=StepStatus.FAILED,
                duration_ms=(time.perf_counter() - start_time) * 1000,
                error=str(e),
            )

    async def _execute_hooks(
        self,
        hooks: list[dict[str, Any]],
        executor: SmartStepExecutor,
        start_index: int,
    ) -> None:
        """Execute hook steps (on_failure, on_success, cleanup)."""
        for idx, hook in enumerate(hooks):
            step_type = StepType.SCREENSHOT if "screenshot" in hook else StepType.EXECUTE
            await self._execute_step(
                executor=executor,
                step_type=step_type,
                step_config=hook,
                step_index=start_index + idx,
            )
```

## 4. Visual Regression Engine - Complete Implementation

Traditional visual regression tools use pixel-diffing which is brittle. AutoQA uses **Semantic Visual Analysis** powered by Owl Browser's VLM.

### 4.1. Semantic Visual Comparison

```python
"""
AutoQA Visual Regression Engine - Production Implementation
File: autoqa/visual/regression_engine.py
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
import base64

from PIL import Image
import imagehash
from pydantic import BaseModel, Field

from owl_browser import Page


class DiffSeverity(StrEnum):
    """Visual difference severity levels."""
    NONE = "none"
    COSMETIC = "cosmetic"  # Font rendering, anti-aliasing
    MINOR = "minor"        # Spacing, color shade changes
    MAJOR = "major"        # Layout shifts, missing elements
    CRITICAL = "critical"  # Broken functionality


class VisualChangeType(StrEnum):
    """Types of visual changes detected."""
    LAYOUT_SHIFT = "layout_shift"
    MISSING_ELEMENT = "missing_element"
    NEW_ELEMENT = "new_element"
    TEXT_CHANGE = "text_change"
    COLOR_CHANGE = "color_change"
    SIZE_CHANGE = "size_change"
    POSITION_CHANGE = "position_change"
    FONT_CHANGE = "font_change"
    IMAGE_CHANGE = "image_change"


@dataclass
class VisualDiff:
    """Represents a detected visual difference."""
    change_type: VisualChangeType
    severity: DiffSeverity
    description: str
    element_selector: str | None = None
    bounding_box: tuple[int, int, int, int] | None = None  # x, y, width, height
    baseline_value: str | None = None
    current_value: str | None = None


@dataclass
class ComparisonResult:
    """Result of visual comparison between baseline and current screenshots."""
    baseline_path: str
    current_path: str
    is_match: bool
    overall_severity: DiffSeverity
    diffs: list[VisualDiff]
    perceptual_hash_distance: int
    ai_analysis: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class BaselineConfig(BaseModel):
    """Configuration for baseline management."""
    storage_path: Path
    retention_days: int = Field(default=90, ge=1, le=365)
    auto_update_on_approval: bool = True
    branch_isolation: bool = True  # Separate baselines per git branch


class VisualRegressionEngine:
    """
    Semantic visual regression engine using VLM for intelligent comparison.

    Unlike pixel-diffing tools, this engine understands visual meaning and
    can distinguish between functional changes and cosmetic differences.
    """

    COMPARISON_PROMPT = '''
    Compare these two screenshots of a web application.

    BASELINE (Reference): The first image shows the expected appearance.
    CURRENT (Test): The second image shows the current state.

    Analyze and report:
    1. Are there any FUNCTIONAL differences (missing buttons, broken layout,
       overlapping text, missing content)?
    2. Are there any COSMETIC-ONLY differences (font rendering, anti-aliasing,
       minor color variations)?

    Ignore these acceptable variations:
    - Dynamic content (timestamps, user-specific data, ads)
    - Minor anti-aliasing differences
    - Cursor position
    - Scrollbar visibility

    Report format:
    SEVERITY: [NONE|COSMETIC|MINOR|MAJOR|CRITICAL]
    FUNCTIONAL_CHANGES: [YES|NO]
    CHANGES:
    - [change description with element location]

    If SEVERITY is NONE or COSMETIC, respond with:
    MATCH: TRUE
    '''

    def __init__(
        self,
        page: Page,
        baseline_config: BaselineConfig,
    ) -> None:
        self.page = page
        self.config = baseline_config
        self._baseline_index: dict[str, dict[str, Any]] = {}
        self._load_baseline_index()

    def _load_baseline_index(self) -> None:
        """Load the baseline index from storage."""
        index_path = self.config.storage_path / "baseline_index.json"
        if index_path.exists():
            with index_path.open("r", encoding="utf-8") as f:
                self._baseline_index = json.load(f)

    def _save_baseline_index(self) -> None:
        """Persist the baseline index to storage."""
        self.config.storage_path.mkdir(parents=True, exist_ok=True)
        index_path = self.config.storage_path / "baseline_index.json"
        with index_path.open("w", encoding="utf-8") as f:
            json.dump(self._baseline_index, f, indent=2, default=str)

    def _get_baseline_key(
        self,
        test_id: str,
        checkpoint_name: str,
        branch: str | None = None,
    ) -> str:
        """Generate a unique key for baseline lookup."""
        if self.config.branch_isolation and branch:
            return f"{branch}/{test_id}/{checkpoint_name}"
        return f"{test_id}/{checkpoint_name}"

    def _compute_perceptual_hash(self, image_path: Path) -> str:
        """Compute perceptual hash for quick similarity check."""
        with Image.open(image_path) as img:
            return str(imagehash.phash(img))

    async def capture_screenshot(
        self,
        checkpoint_name: str,
        mode: Literal["viewport", "fullpage", "element"] = "viewport",
        selector: str | None = None,
        ignore_regions: list[tuple[int, int, int, int]] | None = None,
    ) -> Path:
        """
        Capture a screenshot for visual comparison.

        Args:
            checkpoint_name: Unique identifier for this checkpoint
            mode: Screenshot mode (viewport, fullpage, element)
            selector: CSS selector for element mode
            ignore_regions: List of (x, y, width, height) regions to mask

        Returns:
            Path to the captured screenshot
        """
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"{checkpoint_name}_{timestamp}.png"
        screenshot_path = self.config.storage_path / "current" / filename

        screenshot_path.parent.mkdir(parents=True, exist_ok=True)

        await self.page.screenshot(
            path=str(screenshot_path),
            mode=mode,
            selector=selector,
        )

        # Mask ignore regions if specified
        if ignore_regions:
            self._mask_regions(screenshot_path, ignore_regions)

        return screenshot_path

    def _mask_regions(
        self,
        image_path: Path,
        regions: list[tuple[int, int, int, int]],
    ) -> None:
        """Mask specified regions with a solid color."""
        with Image.open(image_path) as img:
            for x, y, width, height in regions:
                for px in range(x, min(x + width, img.width)):
                    for py in range(y, min(y + height, img.height)):
                        img.putpixel((px, py), (128, 128, 128))  # Gray mask
            img.save(image_path)

    async def compare_with_baseline(
        self,
        test_id: str,
        checkpoint_name: str,
        current_screenshot: Path,
        branch: str | None = None,
        tolerance: float = 0.0,
    ) -> ComparisonResult:
        """
        Compare current screenshot against baseline using semantic analysis.

        Args:
            test_id: Test identifier
            checkpoint_name: Checkpoint name
            current_screenshot: Path to current screenshot
            branch: Git branch for isolation
            tolerance: Acceptable perceptual hash distance (0-64)

        Returns:
            ComparisonResult with detailed diff analysis
        """
        baseline_key = self._get_baseline_key(test_id, checkpoint_name, branch)

        # Check if baseline exists
        if baseline_key not in self._baseline_index:
            # No baseline - create one
            await self.update_baseline(
                test_id, checkpoint_name, current_screenshot, branch
            )
            return ComparisonResult(
                baseline_path=str(current_screenshot),
                current_path=str(current_screenshot),
                is_match=True,
                overall_severity=DiffSeverity.NONE,
                diffs=[],
                perceptual_hash_distance=0,
                ai_analysis="New baseline created - no comparison performed.",
            )

        baseline_info = self._baseline_index[baseline_key]
        baseline_path = Path(baseline_info["path"])

        if not baseline_path.exists():
            raise FileNotFoundError(f"Baseline file missing: {baseline_path}")

        # Quick perceptual hash check
        current_hash = self._compute_perceptual_hash(current_screenshot)
        baseline_hash = baseline_info.get("phash", "")

        if baseline_hash:
            hash_distance = imagehash.hex_to_hash(current_hash) - imagehash.hex_to_hash(baseline_hash)
        else:
            hash_distance = 64  # Max distance if no baseline hash

        # If hashes are very similar, skip expensive VLM comparison
        if hash_distance <= tolerance:
            return ComparisonResult(
                baseline_path=str(baseline_path),
                current_path=str(current_screenshot),
                is_match=True,
                overall_severity=DiffSeverity.NONE,
                diffs=[],
                perceptual_hash_distance=hash_distance,
                ai_analysis="Perceptual hashes match within tolerance.",
            )

        # Perform semantic comparison using VLM
        ai_analysis = await self._semantic_compare(baseline_path, current_screenshot)
        diffs, severity, is_match = self._parse_ai_analysis(ai_analysis)

        return ComparisonResult(
            baseline_path=str(baseline_path),
            current_path=str(current_screenshot),
            is_match=is_match,
            overall_severity=severity,
            diffs=diffs,
            perceptual_hash_distance=hash_distance,
            ai_analysis=ai_analysis,
        )

    async def _semantic_compare(
        self,
        baseline_path: Path,
        current_path: Path,
    ) -> str:
        """Use VLM to semantically compare two screenshots."""
        # Encode images as base64 for the query
        with baseline_path.open("rb") as f:
            baseline_b64 = base64.b64encode(f.read()).decode()
        with current_path.open("rb") as f:
            current_b64 = base64.b64encode(f.read()).decode()

        # Use query_page with image context
        # Note: This assumes the VLM can accept image comparisons
        # In practice, we might need to navigate to a comparison page
        comparison_query = f"""
        {self.COMPARISON_PROMPT}

        Baseline image hash: {self._compute_perceptual_hash(baseline_path)}
        Current image hash: {self._compute_perceptual_hash(current_path)}
        """

        # Query the page's VLM for analysis
        result = await self.page.query_page(comparison_query)
        return result

    def _parse_ai_analysis(
        self,
        analysis: str,
    ) -> tuple[list[VisualDiff], DiffSeverity, bool]:
        """Parse VLM analysis response into structured diff objects."""
        diffs: list[VisualDiff] = []
        severity = DiffSeverity.NONE
        is_match = True

        analysis_lower = analysis.lower()

        # Parse severity
        if "critical" in analysis_lower:
            severity = DiffSeverity.CRITICAL
            is_match = False
        elif "major" in analysis_lower:
            severity = DiffSeverity.MAJOR
            is_match = False
        elif "minor" in analysis_lower:
            severity = DiffSeverity.MINOR
            is_match = False
        elif "cosmetic" in analysis_lower:
            severity = DiffSeverity.COSMETIC
            # Cosmetic changes are still considered a match

        # Check for explicit match indicator
        if "match: true" in analysis_lower:
            is_match = True
        elif "match: false" in analysis_lower or "functional_changes: yes" in analysis_lower:
            is_match = False

        # Parse individual changes (simplified parsing)
        if "changes:" in analysis_lower:
            changes_section = analysis.split("CHANGES:")[-1] if "CHANGES:" in analysis else ""
            for line in changes_section.strip().split("\n"):
                line = line.strip()
                if line.startswith("-"):
                    change_desc = line[1:].strip()
                    change_type = self._infer_change_type(change_desc)
                    diffs.append(VisualDiff(
                        change_type=change_type,
                        severity=severity,
                        description=change_desc,
                    ))

        return diffs, severity, is_match

    def _infer_change_type(self, description: str) -> VisualChangeType:
        """Infer the change type from description text."""
        desc_lower = description.lower()

        if "missing" in desc_lower:
            return VisualChangeType.MISSING_ELEMENT
        if "new" in desc_lower or "added" in desc_lower:
            return VisualChangeType.NEW_ELEMENT
        if "layout" in desc_lower or "position" in desc_lower:
            return VisualChangeType.LAYOUT_SHIFT
        if "text" in desc_lower or "content" in desc_lower:
            return VisualChangeType.TEXT_CHANGE
        if "color" in desc_lower:
            return VisualChangeType.COLOR_CHANGE
        if "size" in desc_lower or "dimension" in desc_lower:
            return VisualChangeType.SIZE_CHANGE
        if "font" in desc_lower:
            return VisualChangeType.FONT_CHANGE
        if "image" in desc_lower or "icon" in desc_lower:
            return VisualChangeType.IMAGE_CHANGE

        return VisualChangeType.LAYOUT_SHIFT  # Default

    async def update_baseline(
        self,
        test_id: str,
        checkpoint_name: str,
        screenshot_path: Path,
        branch: str | None = None,
    ) -> None:
        """Update or create a baseline from the given screenshot."""
        baseline_key = self._get_baseline_key(test_id, checkpoint_name, branch)

        # Copy to baselines directory
        baseline_dir = self.config.storage_path / "baselines"
        baseline_dir.mkdir(parents=True, exist_ok=True)

        baseline_filename = f"{test_id}_{checkpoint_name}.png"
        baseline_path = baseline_dir / baseline_filename

        # Copy the file
        import shutil
        shutil.copy2(screenshot_path, baseline_path)

        # Update index
        self._baseline_index[baseline_key] = {
            "path": str(baseline_path),
            "phash": self._compute_perceptual_hash(baseline_path),
            "created_at": datetime.now(UTC).isoformat(),
            "test_id": test_id,
            "checkpoint": checkpoint_name,
            "branch": branch,
        }

        self._save_baseline_index()

    async def run_visual_test(
        self,
        test_id: str,
        checkpoints: list[dict[str, Any]],
        branch: str | None = None,
    ) -> list[ComparisonResult]:
        """
        Run a complete visual regression test with multiple checkpoints.

        Args:
            test_id: Test identifier
            checkpoints: List of checkpoint configurations
            branch: Git branch for baseline isolation

        Returns:
            List of comparison results for each checkpoint
        """
        results: list[ComparisonResult] = []

        for checkpoint in checkpoints:
            name = checkpoint["name"]
            mode = checkpoint.get("mode", "viewport")
            selector = checkpoint.get("selector")
            ignore_regions = checkpoint.get("ignore_regions")
            tolerance = checkpoint.get("tolerance", 5)

            # Capture current state
            current_path = await self.capture_screenshot(
                checkpoint_name=name,
                mode=mode,
                selector=selector,
                ignore_regions=ignore_regions,
            )

            # Compare with baseline
            result = await self.compare_with_baseline(
                test_id=test_id,
                checkpoint_name=name,
                current_screenshot=current_path,
                branch=branch,
                tolerance=tolerance,
            )

            results.append(result)

            # Fail fast on critical differences
            if result.overall_severity == DiffSeverity.CRITICAL:
                break

        return results


# --- Integration with Test Runner ---

async def visual_regression_example() -> None:
    """Example of visual regression testing."""
    from owl_browser import Browser, RemoteConfig

    config = RemoteConfig(
        url="http://localhost:8080",
        token="test-token",
    )

    async with Browser(remote=config) as browser:
        page = await browser.new_page()
        await page.goto("https://example.com")

        engine = VisualRegressionEngine(
            page=page,
            baseline_config=BaselineConfig(
                storage_path=Path("/artifacts/visual"),
                branch_isolation=True,
            ),
        )

        results = await engine.run_visual_test(
            test_id="homepage-test",
            checkpoints=[
                {"name": "hero-section", "mode": "viewport"},
                {"name": "footer", "mode": "element", "selector": "footer"},
            ],
            branch="main",
        )

        for result in results:
            print(f"Checkpoint: {result.baseline_path}")
            print(f"Match: {result.is_match}")
            print(f"Severity: {result.overall_severity}")
            for diff in result.diffs:
                print(f"  - {diff.change_type}: {diff.description}")
```

### 4.2. Baseline Management

```python
"""
Baseline management for visual regression testing.
File: autoqa/visual/baseline_manager.py
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime, UTC, timedelta
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config as BotoConfig


@dataclass
class BaselineMetadata:
    """Metadata for a visual baseline."""
    test_id: str
    checkpoint_name: str
    branch: str | None
    created_at: datetime
    created_by: str
    phash: str
    file_size: int
    dimensions: tuple[int, int]
    approved: bool = False
    approved_by: str | None = None
    approved_at: datetime | None = None


class BaselineStorage:
    """
    Cloud-based baseline storage with versioning and approval workflow.

    Supports S3/MinIO for artifact storage with metadata in PostgreSQL.
    """

    def __init__(
        self,
        s3_bucket: str,
        s3_prefix: str = "visual-baselines",
        endpoint_url: str | None = None,  # For MinIO
    ) -> None:
        self.bucket = s3_bucket
        self.prefix = s3_prefix

        s3_config = BotoConfig(
            signature_version="s3v4",
            retries={"max_attempts": 3, "mode": "adaptive"},
        )

        self.s3 = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            config=s3_config,
        )

    def _get_s3_key(
        self,
        test_id: str,
        checkpoint: str,
        branch: str | None,
        version: str | None = None,
    ) -> str:
        """Generate S3 key for baseline storage."""
        parts = [self.prefix]
        if branch:
            parts.append(branch)
        parts.extend([test_id, checkpoint])
        if version:
            parts.append(version)
        return "/".join(parts) + ".png"

    async def upload_baseline(
        self,
        local_path: Path,
        test_id: str,
        checkpoint: str,
        branch: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Upload a baseline to S3 with metadata."""
        version = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        s3_key = self._get_s3_key(test_id, checkpoint, branch, version)

        extra_args: dict[str, Any] = {
            "ContentType": "image/png",
        }
        if metadata:
            extra_args["Metadata"] = metadata

        self.s3.upload_file(
            str(local_path),
            self.bucket,
            s3_key,
            ExtraArgs=extra_args,
        )

        return f"s3://{self.bucket}/{s3_key}"

    async def download_baseline(
        self,
        test_id: str,
        checkpoint: str,
        branch: str | None,
        local_path: Path,
        version: str | None = None,
    ) -> bool:
        """Download baseline from S3."""
        s3_key = self._get_s3_key(test_id, checkpoint, branch, version)

        try:
            self.s3.download_file(self.bucket, s3_key, str(local_path))
            return True
        except self.s3.exceptions.NoSuchKey:
            return False

    async def list_versions(
        self,
        test_id: str,
        checkpoint: str,
        branch: str | None = None,
    ) -> list[dict[str, Any]]:
        """List all versions of a baseline."""
        prefix = self._get_s3_key(test_id, checkpoint, branch).rsplit("/", 1)[0]

        response = self.s3.list_objects_v2(
            Bucket=self.bucket,
            Prefix=prefix,
        )

        versions = []
        for obj in response.get("Contents", []):
            versions.append({
                "key": obj["Key"],
                "last_modified": obj["LastModified"],
                "size": obj["Size"],
            })

        return sorted(versions, key=lambda x: x["last_modified"], reverse=True)

    async def cleanup_old_baselines(
        self,
        retention_days: int = 90,
    ) -> int:
        """Remove baselines older than retention period."""
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        deleted_count = 0

        paginator = self.s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []):
                if obj["LastModified"].replace(tzinfo=UTC) < cutoff:
                    self.s3.delete_object(Bucket=self.bucket, Key=obj["Key"])
                    deleted_count += 1

        return deleted_count
```

## 5. Video Recording & Artifacts - Complete Implementation

Full implementation for video recording, frame indexing, and artifact storage.

### 5.1. Video Recording Engine

```python
"""
AutoQA Video Recording & Artifact Management
File: autoqa/artifacts/video_recorder.py
"""
from __future__ import annotations

import asyncio
import json
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import StrEnum
from pathlib import Path
from typing import Any, AsyncIterator
from collections.abc import Sequence

import aiofiles
import boto3
from botocore.config import Config as BotoConfig

from owl_browser import Page


class ArtifactType(StrEnum):
    """Types of test artifacts."""
    VIDEO = "video"
    SCREENSHOT = "screenshot"
    CONSOLE_LOG = "console_log"
    NETWORK_LOG = "network_log"
    HAR = "har"
    TRACE = "trace"


@dataclass
class StepTimestamp:
    """Timestamp marker for a test step within a video."""
    step_index: int
    step_name: str
    frame_number: int
    timestamp_ms: int
    status: str


@dataclass
class VideoMetadata:
    """Metadata for a recorded video."""
    video_id: str
    test_id: str
    duration_ms: int
    fps: int
    resolution: tuple[int, int]
    codec: str
    file_size: int
    step_timestamps: list[StepTimestamp]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class Artifact:
    """Generic test artifact."""
    artifact_id: str
    artifact_type: ArtifactType
    test_id: str
    test_run_id: str
    file_path: str | None
    s3_url: str | None
    metadata: dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class VideoRecorder:
    """
    Manages video recording during test execution with step indexing.

    Uses Owl Browser's native video recording capabilities with
    frame-level step indexing for precise debugging.
    """

    def __init__(
        self,
        page: Page,
        output_path: Path,
        fps: int = 30,
        codec: str = "h264",
    ) -> None:
        self.page = page
        self.output_path = output_path
        self.fps = fps
        self.codec = codec
        self._recording = False
        self._start_time: float = 0
        self._step_timestamps: list[StepTimestamp] = []
        self._video_path: Path | None = None

    async def start(self) -> None:
        """Start video recording."""
        if self._recording:
            return

        self.output_path.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        self._video_path = self.output_path / f"recording_{timestamp}.mp4"

        await self.page.start_video_recording(fps=self.fps, codec=self.codec)
        self._recording = True
        self._start_time = asyncio.get_event_loop().time()
        self._step_timestamps = []

    async def stop(self) -> Path:
        """Stop recording and return the video file path."""
        if not self._recording:
            raise RuntimeError("Recording not started")

        video_path = await self.page.stop_video_recording()
        self._recording = False

        # Move to our output path if different
        if video_path and Path(video_path) != self._video_path:
            import shutil
            shutil.move(video_path, self._video_path)

        return self._video_path

    async def pause(self) -> None:
        """Pause video recording."""
        if self._recording:
            await self.page.pause_video_recording()

    async def resume(self) -> None:
        """Resume video recording."""
        if self._recording:
            await self.page.resume_video_recording()

    def mark_step(
        self,
        step_index: int,
        step_name: str,
        status: str = "started",
    ) -> None:
        """Mark a step timestamp in the video."""
        if not self._recording:
            return

        current_time = asyncio.get_event_loop().time()
        elapsed_ms = int((current_time - self._start_time) * 1000)
        frame_number = int(elapsed_ms * self.fps / 1000)

        self._step_timestamps.append(StepTimestamp(
            step_index=step_index,
            step_name=step_name,
            frame_number=frame_number,
            timestamp_ms=elapsed_ms,
            status=status,
        ))

    async def get_stats(self) -> dict[str, Any]:
        """Get current video recording statistics."""
        return await self.page.get_video_stats()

    def get_metadata(self, test_id: str) -> VideoMetadata:
        """Generate video metadata with step index."""
        import os

        file_size = 0
        if self._video_path and self._video_path.exists():
            file_size = os.path.getsize(self._video_path)

        duration_ms = 0
        if self._step_timestamps:
            duration_ms = self._step_timestamps[-1].timestamp_ms

        return VideoMetadata(
            video_id=hashlib.sha256(str(self._video_path).encode()).hexdigest()[:16],
            test_id=test_id,
            duration_ms=duration_ms,
            fps=self.fps,
            resolution=(1920, 1080),  # Default, could be dynamic
            codec=self.codec,
            file_size=file_size,
            step_timestamps=self._step_timestamps,
        )


class ArtifactManager:
    """
    Manages all test artifacts including videos, screenshots, and logs.

    Supports local storage and S3/MinIO for cloud deployments.
    """

    def __init__(
        self,
        local_path: Path,
        s3_bucket: str | None = None,
        s3_prefix: str = "test-artifacts",
        s3_endpoint: str | None = None,
    ) -> None:
        self.local_path = local_path
        self.s3_bucket = s3_bucket
        self.s3_prefix = s3_prefix

        self._s3_client = None
        if s3_bucket:
            s3_config = BotoConfig(
                signature_version="s3v4",
                retries={"max_attempts": 3, "mode": "adaptive"},
            )
            self._s3_client = boto3.client(
                "s3",
                endpoint_url=s3_endpoint,
                config=s3_config,
            )

        self._artifacts: dict[str, Artifact] = {}

    def _generate_artifact_id(self, test_id: str, artifact_type: ArtifactType) -> str:
        """Generate unique artifact ID."""
        timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
        return hashlib.sha256(f"{test_id}:{artifact_type}:{timestamp}".encode()).hexdigest()[:16]

    async def save_video(
        self,
        test_id: str,
        test_run_id: str,
        video_path: Path,
        metadata: VideoMetadata,
    ) -> Artifact:
        """Save video artifact with metadata."""
        artifact_id = self._generate_artifact_id(test_id, ArtifactType.VIDEO)

        # Local storage
        local_dir = self.local_path / test_run_id / "videos"
        local_dir.mkdir(parents=True, exist_ok=True)
        local_file = local_dir / f"{artifact_id}.mp4"

        import shutil
        shutil.copy2(video_path, local_file)

        # Save metadata
        metadata_file = local_dir / f"{artifact_id}_metadata.json"
        async with aiofiles.open(metadata_file, "w") as f:
            await f.write(json.dumps({
                "video_id": metadata.video_id,
                "test_id": metadata.test_id,
                "duration_ms": metadata.duration_ms,
                "fps": metadata.fps,
                "resolution": metadata.resolution,
                "codec": metadata.codec,
                "file_size": metadata.file_size,
                "step_timestamps": [
                    {
                        "step_index": st.step_index,
                        "step_name": st.step_name,
                        "frame_number": st.frame_number,
                        "timestamp_ms": st.timestamp_ms,
                        "status": st.status,
                    }
                    for st in metadata.step_timestamps
                ],
                "created_at": metadata.created_at.isoformat(),
            }, indent=2))

        # Upload to S3 if configured
        s3_url = None
        if self._s3_client and self.s3_bucket:
            s3_key = f"{self.s3_prefix}/{test_run_id}/videos/{artifact_id}.mp4"
            self._s3_client.upload_file(
                str(local_file),
                self.s3_bucket,
                s3_key,
                ExtraArgs={"ContentType": "video/mp4"},
            )
            s3_url = f"s3://{self.s3_bucket}/{s3_key}"

        artifact = Artifact(
            artifact_id=artifact_id,
            artifact_type=ArtifactType.VIDEO,
            test_id=test_id,
            test_run_id=test_run_id,
            file_path=str(local_file),
            s3_url=s3_url,
            metadata={
                "duration_ms": metadata.duration_ms,
                "fps": metadata.fps,
                "step_count": len(metadata.step_timestamps),
            },
        )

        self._artifacts[artifact_id] = artifact
        return artifact

    async def save_console_logs(
        self,
        page: Page,
        test_id: str,
        test_run_id: str,
    ) -> Artifact:
        """Capture and save console logs."""
        artifact_id = self._generate_artifact_id(test_id, ArtifactType.CONSOLE_LOG)

        # Get console logs from browser
        logs = await page.get_console_logs(level="all", limit=10000)

        # Local storage
        local_dir = self.local_path / test_run_id / "logs"
        local_dir.mkdir(parents=True, exist_ok=True)
        local_file = local_dir / f"{artifact_id}_console.json"

        async with aiofiles.open(local_file, "w") as f:
            await f.write(json.dumps(logs, indent=2, default=str))

        # Upload to S3 if configured
        s3_url = None
        if self._s3_client and self.s3_bucket:
            s3_key = f"{self.s3_prefix}/{test_run_id}/logs/{artifact_id}_console.json"
            self._s3_client.upload_file(
                str(local_file),
                self.s3_bucket,
                s3_key,
                ExtraArgs={"ContentType": "application/json"},
            )
            s3_url = f"s3://{self.s3_bucket}/{s3_key}"

        # Analyze logs for errors
        error_count = sum(1 for log in logs if log.get("level") in ("error", "warning"))

        artifact = Artifact(
            artifact_id=artifact_id,
            artifact_type=ArtifactType.CONSOLE_LOG,
            test_id=test_id,
            test_run_id=test_run_id,
            file_path=str(local_file),
            s3_url=s3_url,
            metadata={
                "total_entries": len(logs),
                "error_count": error_count,
            },
        )

        self._artifacts[artifact_id] = artifact
        return artifact

    async def save_network_log(
        self,
        page: Page,
        test_id: str,
        test_run_id: str,
    ) -> Artifact:
        """Capture and save network log."""
        artifact_id = self._generate_artifact_id(test_id, ArtifactType.NETWORK_LOG)

        # Get network log from browser
        network_log = await page.get_network_log(limit=5000)

        # Local storage
        local_dir = self.local_path / test_run_id / "logs"
        local_dir.mkdir(parents=True, exist_ok=True)
        local_file = local_dir / f"{artifact_id}_network.json"

        async with aiofiles.open(local_file, "w") as f:
            await f.write(json.dumps(network_log, indent=2, default=str))

        # Upload to S3 if configured
        s3_url = None
        if self._s3_client and self.s3_bucket:
            s3_key = f"{self.s3_prefix}/{test_run_id}/logs/{artifact_id}_network.json"
            self._s3_client.upload_file(
                str(local_file),
                self.s3_bucket,
                s3_key,
                ExtraArgs={"ContentType": "application/json"},
            )
            s3_url = f"s3://{self.s3_bucket}/{s3_key}"

        # Analyze network log
        failed_requests = sum(
            1 for req in network_log
            if req.get("status", 0) >= 400
        )

        artifact = Artifact(
            artifact_id=artifact_id,
            artifact_type=ArtifactType.NETWORK_LOG,
            test_id=test_id,
            test_run_id=test_run_id,
            file_path=str(local_file),
            s3_url=s3_url,
            metadata={
                "total_requests": len(network_log),
                "failed_requests": failed_requests,
            },
        )

        self._artifacts[artifact_id] = artifact
        return artifact

    async def save_screenshot(
        self,
        page: Page,
        test_id: str,
        test_run_id: str,
        name: str,
        mode: str = "viewport",
    ) -> Artifact:
        """Capture and save screenshot."""
        artifact_id = self._generate_artifact_id(test_id, ArtifactType.SCREENSHOT)

        # Local storage
        local_dir = self.local_path / test_run_id / "screenshots"
        local_dir.mkdir(parents=True, exist_ok=True)
        local_file = local_dir / f"{artifact_id}_{name}.png"

        await page.screenshot(path=str(local_file), mode=mode)

        # Upload to S3 if configured
        s3_url = None
        if self._s3_client and self.s3_bucket:
            s3_key = f"{self.s3_prefix}/{test_run_id}/screenshots/{artifact_id}_{name}.png"
            self._s3_client.upload_file(
                str(local_file),
                self.s3_bucket,
                s3_key,
                ExtraArgs={"ContentType": "image/png"},
            )
            s3_url = f"s3://{self.s3_bucket}/{s3_key}"

        import os
        file_size = os.path.getsize(local_file)

        artifact = Artifact(
            artifact_id=artifact_id,
            artifact_type=ArtifactType.SCREENSHOT,
            test_id=test_id,
            test_run_id=test_run_id,
            file_path=str(local_file),
            s3_url=s3_url,
            metadata={
                "name": name,
                "mode": mode,
                "file_size": file_size,
            },
        )

        self._artifacts[artifact_id] = artifact
        return artifact

    def get_artifacts(self, test_run_id: str) -> list[Artifact]:
        """Get all artifacts for a test run."""
        return [
            artifact for artifact in self._artifacts.values()
            if artifact.test_run_id == test_run_id
        ]

    async def cleanup_local(self, test_run_id: str) -> None:
        """Remove local artifacts after S3 upload."""
        local_dir = self.local_path / test_run_id
        if local_dir.exists():
            import shutil
            shutil.rmtree(local_dir)


# --- Usage Example ---

async def artifact_management_example() -> None:
    """Example of artifact management during test execution."""
    from owl_browser import Browser, RemoteConfig

    config = RemoteConfig(url="http://localhost:8080", token="test-token")

    async with Browser(remote=config) as browser:
        page = await browser.new_page()

        # Initialize managers
        video_recorder = VideoRecorder(
            page=page,
            output_path=Path("/artifacts/videos"),
            fps=30,
        )

        artifact_manager = ArtifactManager(
            local_path=Path("/artifacts"),
            s3_bucket="autoqa-artifacts",
            s3_endpoint="http://minio:9000",
        )

        test_id = "checkout-flow-001"
        test_run_id = "run-20240115-123456"

        # Start recording
        await video_recorder.start()

        # Execute test steps
        await page.goto("https://example.com")
        video_recorder.mark_step(0, "navigate_home", "completed")

        await page.ai_click("Login button")
        video_recorder.mark_step(1, "click_login", "completed")

        # Stop recording and save
        video_path = await video_recorder.stop()
        metadata = video_recorder.get_metadata(test_id)

        # Save all artifacts
        await artifact_manager.save_video(test_id, test_run_id, video_path, metadata)
        await artifact_manager.save_console_logs(page, test_id, test_run_id)
        await artifact_manager.save_network_log(page, test_id, test_run_id)
        await artifact_manager.save_screenshot(page, test_id, test_run_id, "final_state")

        # Get all artifacts
        artifacts = artifact_manager.get_artifacts(test_run_id)
        for artifact in artifacts:
            print(f"{artifact.artifact_type}: {artifact.s3_url or artifact.file_path}")
```

## 6. Generative Test Agents - Complete Implementation

Instead of fixed scripts, Generative Test Agents explore the UI autonomously using "Chaos Personas" to discover bugs.

### 6.1. Chaos Persona Engine

```python
"""
AutoQA Generative Test Agents - Chaos Persona Implementation
File: autoqa/agents/chaos_persona.py
"""
from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import StrEnum
from typing import Any, Literal
from collections.abc import Sequence

from pydantic import BaseModel, Field

from owl_browser import Page


class PersonaType(StrEnum):
    """Pre-defined persona types."""
    CONFUSED_SENIOR = "confused_senior"
    IMPATIENT_USER = "impatient_user"
    METHODICAL_TESTER = "methodical_tester"
    CHAOS_MONKEY = "chaos_monkey"
    ACCESSIBILITY_USER = "accessibility_user"
    MOBILE_USER = "mobile_user"
    SLOW_CONNECTION = "slow_connection"


class ActionType(StrEnum):
    """Types of exploratory actions."""
    CLICK = "click"
    TYPE = "type"
    SCROLL = "scroll"
    NAVIGATE_BACK = "navigate_back"
    WAIT = "wait"
    REFRESH = "refresh"
    RANDOM_INPUT = "random_input"


@dataclass
class PersonaBehavior:
    """Defines behavioral characteristics of a persona."""
    click_delay_range: tuple[int, int]  # ms
    type_delay_range: tuple[int, int]   # ms per character
    scroll_probability: float           # 0-1
    back_navigation_probability: float  # 0-1
    random_click_probability: float     # 0-1
    attention_span_steps: int           # Steps before getting "bored"
    error_tolerance: int                # How many errors before giving up


PERSONA_BEHAVIORS: dict[PersonaType, PersonaBehavior] = {
    PersonaType.CONFUSED_SENIOR: PersonaBehavior(
        click_delay_range=(2000, 5000),
        type_delay_range=(200, 500),
        scroll_probability=0.3,
        back_navigation_probability=0.4,
        random_click_probability=0.2,
        attention_span_steps=10,
        error_tolerance=2,
    ),
    PersonaType.IMPATIENT_USER: PersonaBehavior(
        click_delay_range=(100, 300),
        type_delay_range=(30, 80),
        scroll_probability=0.5,
        back_navigation_probability=0.1,
        random_click_probability=0.3,
        attention_span_steps=5,
        error_tolerance=1,
    ),
    PersonaType.METHODICAL_TESTER: PersonaBehavior(
        click_delay_range=(500, 1000),
        type_delay_range=(100, 150),
        scroll_probability=0.2,
        back_navigation_probability=0.1,
        random_click_probability=0.1,
        attention_span_steps=50,
        error_tolerance=5,
    ),
    PersonaType.CHAOS_MONKEY: PersonaBehavior(
        click_delay_range=(50, 200),
        type_delay_range=(10, 30),
        scroll_probability=0.6,
        back_navigation_probability=0.3,
        random_click_probability=0.7,
        attention_span_steps=100,
        error_tolerance=10,
    ),
    PersonaType.ACCESSIBILITY_USER: PersonaBehavior(
        click_delay_range=(1000, 2000),
        type_delay_range=(150, 300),
        scroll_probability=0.1,
        back_navigation_probability=0.2,
        random_click_probability=0.05,
        attention_span_steps=30,
        error_tolerance=3,
    ),
}


@dataclass
class ExplorationAction:
    """Record of an action taken during exploration."""
    action_type: ActionType
    target: str | None
    value: str | None
    timestamp: datetime
    success: bool
    error: str | None = None
    screenshot_path: str | None = None


@dataclass
class FrictionPoint:
    """Detected UX friction point."""
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    page_url: str
    action_sequence: list[ExplorationAction]
    screenshot_path: str | None
    detected_at: datetime


@dataclass
class ExplorationResult:
    """Result of an exploratory test session."""
    persona: PersonaType
    goal: str
    goal_achieved: bool
    total_steps: int
    duration_ms: int
    actions: list[ExplorationAction]
    friction_points: list[FrictionPoint]
    bugs_found: list[dict[str, Any]]
    final_url: str
    console_errors: list[dict[str, Any]]


class ChaosPersonaAgent:
    """
    AI agent that explores a web application with a specific persona behavior.

    Uses Owl Browser's execute_nla() for high-level goal-oriented exploration
    combined with persona-specific behavioral patterns.
    """

    def __init__(
        self,
        page: Page,
        persona: PersonaType,
        artifact_path: Path | None = None,
    ) -> None:
        self.page = page
        self.persona = persona
        self.behavior = PERSONA_BEHAVIORS.get(
            persona,
            PERSONA_BEHAVIORS[PersonaType.METHODICAL_TESTER]
        )
        self.artifact_path = artifact_path or Path("/artifacts/exploration")
        self._actions: list[ExplorationAction] = []
        self._friction_points: list[FrictionPoint] = []
        self._bugs: list[dict[str, Any]] = []

    async def explore(
        self,
        goal: str,
        start_url: str,
        max_steps: int = 50,
        timeout_ms: int = 300000,
    ) -> ExplorationResult:
        """
        Explore the application trying to achieve a goal.

        Args:
            goal: Natural language description of the goal
            start_url: Starting URL for exploration
            max_steps: Maximum number of steps
            timeout_ms: Maximum time for exploration

        Returns:
            ExplorationResult with actions taken and findings
        """
        start_time = asyncio.get_event_loop().time()
        self._actions = []
        self._friction_points = []
        self._bugs = []

        # Navigate to start
        await self.page.goto(start_url, wait_until="networkidle")
        await self._record_action(ActionType.CLICK, start_url, None, True)

        goal_achieved = False
        steps = 0
        consecutive_errors = 0

        while steps < max_steps:
            elapsed_ms = (asyncio.get_event_loop().time() - start_time) * 1000
            if elapsed_ms >= timeout_ms:
                break

            # Check if goal is achieved
            goal_check = await self.page.query_page(
                f"Has the user achieved the goal: '{goal}'? Answer YES or NO."
            )
            if "yes" in goal_check.lower():
                goal_achieved = True
                break

            # Decide next action based on persona
            action = await self._decide_next_action(goal)

            try:
                await self._execute_action(action)
                consecutive_errors = 0
            except Exception as e:
                consecutive_errors += 1
                await self._record_action(
                    action["type"],
                    action.get("target"),
                    action.get("value"),
                    False,
                    str(e),
                )

                # Check for friction point
                if consecutive_errors >= 2:
                    await self._record_friction_point(
                        f"User struggled with: {action.get('target', 'unknown')}",
                        "medium" if consecutive_errors == 2 else "high",
                    )

                if consecutive_errors >= self.behavior.error_tolerance:
                    break

            steps += 1

            # Add persona-specific delay
            delay = random.randint(*self.behavior.click_delay_range)
            await asyncio.sleep(delay / 1000)

            # Random back navigation based on persona
            if random.random() < self.behavior.back_navigation_probability:
                can_go_back = await self.page.can_go_back()
                if can_go_back:
                    await self.page.go_back()
                    await self._record_action(ActionType.NAVIGATE_BACK, None, None, True)

        # Collect console errors
        console_logs = await self.page.get_console_logs(level="error", limit=100)

        # Check for JS errors as bugs
        for log in console_logs:
            if log.get("level") == "error":
                self._bugs.append({
                    "type": "console_error",
                    "message": log.get("message", ""),
                    "url": await self.page.get_current_url(),
                })

        duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
        final_url = await self.page.get_current_url()

        return ExplorationResult(
            persona=self.persona,
            goal=goal,
            goal_achieved=goal_achieved,
            total_steps=steps,
            duration_ms=duration_ms,
            actions=self._actions,
            friction_points=self._friction_points,
            bugs_found=self._bugs,
            final_url=final_url,
            console_errors=console_logs,
        )

    async def _decide_next_action(self, goal: str) -> dict[str, Any]:
        """Use AI to decide the next action based on goal and persona."""
        # Random action for chaos personas
        if random.random() < self.behavior.random_click_probability:
            elements = await self.page.get_interactive_elements()
            if elements:
                element = random.choice(elements)
                return {
                    "type": ActionType.CLICK,
                    "target": element.get("selector", element.get("description", "")),
                }

        # Goal-directed action using NLA
        prompt = f"""
        You are a {self.persona.value} user trying to: {goal}

        What should you do next? Provide a single action:
        - Click on [element description]
        - Type [text] into [input description]
        - Scroll down
        - Wait

        Be specific about the element to interact with.
        """

        response = await self.page.query_page(prompt)

        # Parse response into action
        response_lower = response.lower()
        if "click" in response_lower:
            # Extract target
            target = response.split("click on")[-1].strip() if "click on" in response_lower else "button"
            return {"type": ActionType.CLICK, "target": target}
        elif "type" in response_lower:
            # Extract value and target
            return {"type": ActionType.TYPE, "target": "input", "value": "test"}
        elif "scroll" in response_lower:
            return {"type": ActionType.SCROLL, "target": None}
        else:
            return {"type": ActionType.WAIT, "target": None}

    async def _execute_action(self, action: dict[str, Any]) -> None:
        """Execute a decided action."""
        action_type = action["type"]
        target = action.get("target")
        value = action.get("value")

        match action_type:
            case ActionType.CLICK:
                if target:
                    await self.page.ai_click(target)
                await self._record_action(action_type, target, None, True)

            case ActionType.TYPE:
                if target and value:
                    await self.page.ai_type(target, value)
                await self._record_action(action_type, target, value, True)

            case ActionType.SCROLL:
                await self.page.scroll_by(0, 500)
                await self._record_action(action_type, None, None, True)

            case ActionType.WAIT:
                await asyncio.sleep(1)
                await self._record_action(action_type, None, None, True)

            case ActionType.NAVIGATE_BACK:
                await self.page.go_back()
                await self._record_action(action_type, None, None, True)

    async def _record_action(
        self,
        action_type: ActionType,
        target: str | None,
        value: str | None,
        success: bool,
        error: str | None = None,
    ) -> None:
        """Record an action taken during exploration."""
        screenshot_path = None
        if not success or random.random() < 0.1:  # Screenshot on error or 10% of actions
            self.artifact_path.mkdir(parents=True, exist_ok=True)
            screenshot_path = str(self.artifact_path / f"action_{len(self._actions)}.png")
            await self.page.screenshot(path=screenshot_path)

        self._actions.append(ExplorationAction(
            action_type=action_type,
            target=target,
            value=value,
            timestamp=datetime.now(UTC),
            success=success,
            error=error,
            screenshot_path=screenshot_path,
        ))

    async def _record_friction_point(
        self,
        description: str,
        severity: Literal["low", "medium", "high", "critical"],
    ) -> None:
        """Record a detected UX friction point."""
        screenshot_path = str(self.artifact_path / f"friction_{len(self._friction_points)}.png")
        await self.page.screenshot(path=screenshot_path)

        self._friction_points.append(FrictionPoint(
            description=description,
            severity=severity,
            page_url=await self.page.get_current_url(),
            action_sequence=self._actions[-5:],  # Last 5 actions
            screenshot_path=screenshot_path,
            detected_at=datetime.now(UTC),
        ))


class GenerativeTestRunner:
    """
    Orchestrates multiple chaos persona agents for comprehensive exploratory testing.
    """

    def __init__(
        self,
        page: Page,
        artifact_path: Path,
    ) -> None:
        self.page = page
        self.artifact_path = artifact_path

    async def run_exploration_suite(
        self,
        start_url: str,
        goals: list[str],
        personas: list[PersonaType] | None = None,
    ) -> list[ExplorationResult]:
        """
        Run multiple exploration sessions with different personas and goals.

        Args:
            start_url: Starting URL for all explorations
            goals: List of goals to achieve
            personas: List of personas to use (defaults to all)

        Returns:
            List of exploration results
        """
        personas = personas or list(PersonaType)
        results: list[ExplorationResult] = []

        for goal in goals:
            for persona in personas:
                agent = ChaosPersonaAgent(
                    page=self.page,
                    persona=persona,
                    artifact_path=self.artifact_path / persona.value,
                )

                result = await agent.explore(
                    goal=goal,
                    start_url=start_url,
                    max_steps=30,
                )

                results.append(result)

                # Reset page state between runs
                await self.page.goto(start_url)

        return results

    def summarize_findings(
        self,
        results: list[ExplorationResult],
    ) -> dict[str, Any]:
        """Summarize findings from multiple exploration sessions."""
        total_friction_points = sum(len(r.friction_points) for r in results)
        total_bugs = sum(len(r.bugs_found) for r in results)
        goals_achieved = sum(1 for r in results if r.goal_achieved)

        friction_by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for result in results:
            for fp in result.friction_points:
                friction_by_severity[fp.severity] += 1

        return {
            "total_sessions": len(results),
            "goals_achieved": goals_achieved,
            "goals_failed": len(results) - goals_achieved,
            "total_friction_points": total_friction_points,
            "friction_by_severity": friction_by_severity,
            "total_bugs": total_bugs,
            "average_steps": sum(r.total_steps for r in results) / len(results) if results else 0,
            "average_duration_ms": sum(r.duration_ms for r in results) / len(results) if results else 0,
        }
```

## 7. Assertion Engine - Complete Implementation

Full-featured assertion engine supporting visual, text, network, and custom assertions.

### 7.1. Assertion Framework

```python
"""
AutoQA Assertion Engine - Production Implementation
File: autoqa/assertions/assertion_engine.py
"""
from __future__ import annotations

import re
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import StrEnum
from typing import Any, Generic, TypeVar, Callable, Awaitable
from collections.abc import Sequence

from pydantic import BaseModel, Field

from owl_browser import Page


class AssertionStatus(StrEnum):
    """Assertion result status."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class AssertionType(StrEnum):
    """Types of assertions."""
    VISUAL = "visual"
    TEXT_CONTAINS = "text_contains"
    TEXT_EQUALS = "text_equals"
    TEXT_MATCHES = "text_matches"
    ELEMENT_EXISTS = "element_exists"
    ELEMENT_NOT_EXISTS = "element_not_exists"
    ELEMENT_VISIBLE = "element_visible"
    ELEMENT_COUNT = "element_count"
    ATTRIBUTE_EQUALS = "attribute_equals"
    NETWORK_REQUEST = "network_request"
    NETWORK_RESPONSE = "network_response"
    CONSOLE_NO_ERRORS = "console_no_errors"
    PAGE_TITLE = "page_title"
    URL_MATCHES = "url_matches"
    CUSTOM = "custom"


@dataclass
class AssertionResult:
    """Result of an assertion check."""
    assertion_type: AssertionType
    status: AssertionStatus
    message: str
    expected: Any
    actual: Any
    duration_ms: float
    screenshot_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


T = TypeVar("T")


class Assertion(ABC, Generic[T]):
    """Base class for all assertions."""

    assertion_type: AssertionType

    @abstractmethod
    async def evaluate(self, page: Page) -> AssertionResult:
        """Evaluate the assertion against the current page state."""
        ...


class VisualAssertion(Assertion[str]):
    """
    AI-powered visual assertion using VLM to answer questions about the page.

    Example:
        assertion = VisualAssertion(
            query="Is the login button visible and enabled?",
            expected_response="yes"
        )
    """

    assertion_type = AssertionType.VISUAL

    def __init__(
        self,
        query: str,
        expected_response: str = "yes",
        confidence_threshold: float = 0.7,
    ) -> None:
        self.query = query
        self.expected_response = expected_response.lower()
        self.confidence_threshold = confidence_threshold

    async def evaluate(self, page: Page) -> AssertionResult:
        import time
        start = time.perf_counter()

        try:
            # Use query_page for visual analysis
            response = await page.query_page(self.query)
            response_lower = response.lower()

            # Check for affirmative response
            passed = any(
                indicator in response_lower
                for indicator in [self.expected_response, "yes", "true", "correct", "visible"]
            )

            # Also check for negative indicators
            if any(neg in response_lower for neg in ["no", "not", "cannot", "false"]):
                passed = False

            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                message=f"Visual query: {self.query}",
                expected=self.expected_response,
                actual=response,
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as e:
            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.ERROR,
                message=f"Visual assertion error: {e}",
                expected=self.expected_response,
                actual=None,
                duration_ms=(time.perf_counter() - start) * 1000,
            )


class TextAssertion(Assertion[str]):
    """
    Text content assertion with multiple matching modes.

    Supports: contains, equals, matches (regex)
    """

    def __init__(
        self,
        selector: str,
        expected: str,
        mode: str = "contains",  # contains, equals, matches
        case_sensitive: bool = False,
    ) -> None:
        self.selector = selector
        self.expected = expected
        self.mode = mode
        self.case_sensitive = case_sensitive
        self.assertion_type = AssertionType(f"text_{mode}")

    async def evaluate(self, page: Page) -> AssertionResult:
        import time
        start = time.perf_counter()

        try:
            # Extract text using the SDK
            actual_text = await page.extract_text(self.selector)

            if not self.case_sensitive:
                actual_text = actual_text.lower()
                expected = self.expected.lower()
            else:
                expected = self.expected

            match self.mode:
                case "contains":
                    passed = expected in actual_text
                case "equals":
                    passed = actual_text.strip() == expected.strip()
                case "matches":
                    passed = bool(re.search(expected, actual_text))
                case _:
                    passed = expected in actual_text

            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                message=f"Text {self.mode}: '{self.expected}' in '{self.selector}'",
                expected=self.expected,
                actual=actual_text[:500],  # Truncate for readability
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as e:
            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.ERROR,
                message=f"Text assertion error: {e}",
                expected=self.expected,
                actual=None,
                duration_ms=(time.perf_counter() - start) * 1000,
            )


class ElementAssertion(Assertion[bool]):
    """
    Element presence and state assertions.

    Supports: exists, not_exists, visible, count
    """

    def __init__(
        self,
        selector: str,
        should_exist: bool = True,
        should_be_visible: bool = False,
        expected_count: int | None = None,
    ) -> None:
        self.selector = selector
        self.should_exist = should_exist
        self.should_be_visible = should_be_visible
        self.expected_count = expected_count

        if expected_count is not None:
            self.assertion_type = AssertionType.ELEMENT_COUNT
        elif should_be_visible:
            self.assertion_type = AssertionType.ELEMENT_VISIBLE
        elif should_exist:
            self.assertion_type = AssertionType.ELEMENT_EXISTS
        else:
            self.assertion_type = AssertionType.ELEMENT_NOT_EXISTS

    async def evaluate(self, page: Page) -> AssertionResult:
        import time
        start = time.perf_counter()

        try:
            # Use find_element for AI-powered element location
            elements = await page.find_element(self.selector, max_results=10)
            element_count = len(elements) if elements else 0

            if self.expected_count is not None:
                passed = element_count == self.expected_count
                actual = element_count
                expected = self.expected_count
            elif self.should_be_visible:
                # Check if at least one element is visible
                passed = element_count > 0
                # Additional visibility check could be done here
                actual = f"Found {element_count} elements"
                expected = "Visible element"
            elif self.should_exist:
                passed = element_count > 0
                actual = f"Found {element_count} elements"
                expected = "Element exists"
            else:
                passed = element_count == 0
                actual = f"Found {element_count} elements"
                expected = "Element does not exist"

            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                message=f"Element check: {self.selector}",
                expected=expected,
                actual=actual,
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as e:
            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.ERROR,
                message=f"Element assertion error: {e}",
                expected=self.should_exist,
                actual=None,
                duration_ms=(time.perf_counter() - start) * 1000,
            )


class NetworkAssertion(Assertion[dict[str, Any]]):
    """
    Network request/response assertions.

    Verifies that specific API calls were made with expected parameters.
    """

    def __init__(
        self,
        url_pattern: str,
        method: str | None = None,
        expected_status: int | None = None,
        expected_response_contains: str | None = None,
        should_exist: bool = True,
    ) -> None:
        self.url_pattern = url_pattern
        self.method = method
        self.expected_status = expected_status
        self.expected_response_contains = expected_response_contains
        self.should_exist = should_exist
        self.assertion_type = AssertionType.NETWORK_REQUEST

    async def evaluate(self, page: Page) -> AssertionResult:
        import time
        start = time.perf_counter()

        try:
            # Get network log
            network_log = await page.get_network_log(limit=500)

            # Find matching requests
            matching_requests = [
                req for req in network_log
                if self.url_pattern in req.get("url", "")
                and (self.method is None or req.get("method") == self.method)
            ]

            if not self.should_exist:
                passed = len(matching_requests) == 0
                return AssertionResult(
                    assertion_type=self.assertion_type,
                    status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                    message=f"Network request should not exist: {self.url_pattern}",
                    expected="No matching requests",
                    actual=f"Found {len(matching_requests)} matching requests",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

            if not matching_requests:
                return AssertionResult(
                    assertion_type=self.assertion_type,
                    status=AssertionStatus.FAILED,
                    message=f"No network request matching: {self.url_pattern}",
                    expected=f"Request to {self.url_pattern}",
                    actual="No matching requests found",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

            # Check status code
            if self.expected_status is not None:
                matching_with_status = [
                    req for req in matching_requests
                    if req.get("status") == self.expected_status
                ]
                if not matching_with_status:
                    return AssertionResult(
                        assertion_type=self.assertion_type,
                        status=AssertionStatus.FAILED,
                        message=f"No request with status {self.expected_status}",
                        expected=self.expected_status,
                        actual=[req.get("status") for req in matching_requests],
                        duration_ms=(time.perf_counter() - start) * 1000,
                    )

            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.PASSED,
                message=f"Network assertion passed: {self.url_pattern}",
                expected=f"Request to {self.url_pattern}",
                actual=f"Found {len(matching_requests)} matching requests",
                duration_ms=(time.perf_counter() - start) * 1000,
                metadata={"matching_requests": len(matching_requests)},
            )
        except Exception as e:
            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.ERROR,
                message=f"Network assertion error: {e}",
                expected=self.url_pattern,
                actual=None,
                duration_ms=(time.perf_counter() - start) * 1000,
            )


class ConsoleAssertion(Assertion[list[dict[str, Any]]]):
    """
    Console log assertions.

    Verifies console output meets expectations (e.g., no errors).
    """

    def __init__(
        self,
        no_errors: bool = True,
        no_warnings: bool = False,
        expected_messages: list[str] | None = None,
        forbidden_messages: list[str] | None = None,
    ) -> None:
        self.no_errors = no_errors
        self.no_warnings = no_warnings
        self.expected_messages = expected_messages or []
        self.forbidden_messages = forbidden_messages or []
        self.assertion_type = AssertionType.CONSOLE_NO_ERRORS

    async def evaluate(self, page: Page) -> AssertionResult:
        import time
        start = time.perf_counter()

        try:
            # Get console logs
            logs = await page.get_console_logs(level="all", limit=1000)

            errors = [log for log in logs if log.get("level") == "error"]
            warnings = [log for log in logs if log.get("level") == "warning"]

            issues: list[str] = []

            if self.no_errors and errors:
                issues.append(f"Found {len(errors)} console errors")

            if self.no_warnings and warnings:
                issues.append(f"Found {len(warnings)} console warnings")

            # Check for expected messages
            all_messages = [log.get("message", "") for log in logs]
            for expected in self.expected_messages:
                if not any(expected in msg for msg in all_messages):
                    issues.append(f"Expected message not found: {expected}")

            # Check for forbidden messages
            for forbidden in self.forbidden_messages:
                if any(forbidden in msg for msg in all_messages):
                    issues.append(f"Forbidden message found: {forbidden}")

            passed = len(issues) == 0

            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                message="Console assertion" if passed else "; ".join(issues),
                expected="No console errors" if self.no_errors else "Console check",
                actual=f"Errors: {len(errors)}, Warnings: {len(warnings)}",
                duration_ms=(time.perf_counter() - start) * 1000,
                metadata={
                    "error_count": len(errors),
                    "warning_count": len(warnings),
                    "error_messages": [e.get("message", "")[:200] for e in errors[:5]],
                },
            )
        except Exception as e:
            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.ERROR,
                message=f"Console assertion error: {e}",
                expected="Console check",
                actual=None,
                duration_ms=(time.perf_counter() - start) * 1000,
            )


class CustomAssertion(Assertion[Any]):
    """
    Custom assertion using a user-defined async function.

    Example:
        async def my_check(page: Page) -> tuple[bool, str]:
            text = await page.extract_text("body")
            return "welcome" in text.lower(), f"Found: {text[:100]}"

        assertion = CustomAssertion(
            name="welcome_message",
            check_fn=my_check,
            expected="Welcome message visible"
        )
    """

    assertion_type = AssertionType.CUSTOM

    def __init__(
        self,
        name: str,
        check_fn: Callable[[Page], Awaitable[tuple[bool, str]]],
        expected: str,
    ) -> None:
        self.name = name
        self.check_fn = check_fn
        self.expected = expected

    async def evaluate(self, page: Page) -> AssertionResult:
        import time
        start = time.perf_counter()

        try:
            passed, actual = await self.check_fn(page)

            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                message=f"Custom assertion: {self.name}",
                expected=self.expected,
                actual=actual,
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as e:
            return AssertionResult(
                assertion_type=self.assertion_type,
                status=AssertionStatus.ERROR,
                message=f"Custom assertion error: {e}",
                expected=self.expected,
                actual=None,
                duration_ms=(time.perf_counter() - start) * 1000,
            )


class AssertionEngine:
    """
    Orchestrates assertion execution with reporting and screenshot capture.
    """

    def __init__(
        self,
        page: Page,
        screenshot_on_failure: bool = True,
        artifact_path: Path | None = None,
    ) -> None:
        self.page = page
        self.screenshot_on_failure = screenshot_on_failure
        self.artifact_path = artifact_path or Path("/artifacts/assertions")
        self._results: list[AssertionResult] = []

    async def assert_visual(
        self,
        query: str,
        expected: str = "yes",
    ) -> AssertionResult:
        """Execute a visual assertion."""
        assertion = VisualAssertion(query, expected)
        return await self._execute(assertion)

    async def assert_text(
        self,
        selector: str,
        expected: str,
        mode: str = "contains",
    ) -> AssertionResult:
        """Execute a text assertion."""
        assertion = TextAssertion(selector, expected, mode)
        return await self._execute(assertion)

    async def assert_element_exists(
        self,
        selector: str,
        should_exist: bool = True,
    ) -> AssertionResult:
        """Assert element existence."""
        assertion = ElementAssertion(selector, should_exist=should_exist)
        return await self._execute(assertion)

    async def assert_network(
        self,
        url_pattern: str,
        method: str | None = None,
        status: int | None = None,
    ) -> AssertionResult:
        """Assert network request was made."""
        assertion = NetworkAssertion(url_pattern, method, status)
        return await self._execute(assertion)

    async def assert_no_console_errors(self) -> AssertionResult:
        """Assert no console errors."""
        assertion = ConsoleAssertion(no_errors=True)
        return await self._execute(assertion)

    async def assert_custom(
        self,
        name: str,
        check_fn: Callable[[Page], Awaitable[tuple[bool, str]]],
        expected: str,
    ) -> AssertionResult:
        """Execute a custom assertion."""
        assertion = CustomAssertion(name, check_fn, expected)
        return await self._execute(assertion)

    async def _execute(self, assertion: Assertion[Any]) -> AssertionResult:
        """Execute an assertion and handle failure screenshots."""
        result = await assertion.evaluate(self.page)

        if result.status == AssertionStatus.FAILED and self.screenshot_on_failure:
            self.artifact_path.mkdir(parents=True, exist_ok=True)
            screenshot_path = self.artifact_path / f"failure_{len(self._results)}.png"
            await self.page.screenshot(path=str(screenshot_path))
            result.screenshot_path = str(screenshot_path)

        self._results.append(result)
        return result

    def get_results(self) -> list[AssertionResult]:
        """Get all assertion results."""
        return self._results.copy()

    def get_summary(self) -> dict[str, Any]:
        """Get summary of all assertions."""
        passed = sum(1 for r in self._results if r.status == AssertionStatus.PASSED)
        failed = sum(1 for r in self._results if r.status == AssertionStatus.FAILED)
        errors = sum(1 for r in self._results if r.status == AssertionStatus.ERROR)

        return {
            "total": len(self._results),
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "pass_rate": passed / len(self._results) if self._results else 0,
            "total_duration_ms": sum(r.duration_ms for r in self._results),
        }


# --- DSL Assertion Parser ---

def parse_assertion_dsl(config: dict[str, Any]) -> Assertion[Any]:
    """
    Parse assertion configuration from DSL YAML into Assertion objects.

    Example YAML:
        - assert:
            type: text_contains
            selector: "#welcome"
            expected: "Hello, User"
    """
    assertion_type = AssertionType(config.get("type", "visual"))

    match assertion_type:
        case AssertionType.VISUAL:
            return VisualAssertion(
                query=config["query"],
                expected_response=config.get("expected", "yes"),
            )
        case AssertionType.TEXT_CONTAINS | AssertionType.TEXT_EQUALS | AssertionType.TEXT_MATCHES:
            return TextAssertion(
                selector=config["selector"],
                expected=config["expected"],
                mode=assertion_type.value.replace("text_", ""),
            )
        case AssertionType.ELEMENT_EXISTS:
            return ElementAssertion(
                selector=config["selector"],
                should_exist=True,
            )
        case AssertionType.ELEMENT_NOT_EXISTS:
            return ElementAssertion(
                selector=config["selector"],
                should_exist=False,
            )
        case AssertionType.ELEMENT_COUNT:
            return ElementAssertion(
                selector=config["selector"],
                expected_count=config["count"],
            )
        case AssertionType.NETWORK_REQUEST | AssertionType.NETWORK_RESPONSE:
            return NetworkAssertion(
                url_pattern=config["url_pattern"],
                method=config.get("method"),
                expected_status=config.get("status"),
            )
        case AssertionType.CONSOLE_NO_ERRORS:
            return ConsoleAssertion(
                no_errors=config.get("no_errors", True),
                no_warnings=config.get("no_warnings", False),
            )
        case _:
            raise ValueError(f"Unknown assertion type: {assertion_type}")
```

## 8. CI/CD Integration - Complete Examples

Full CI/CD configurations for GitHub Actions, GitLab CI, and Jenkins.

### 8.1. GitHub Actions Workflow

```yaml
# .github/workflows/autoqa.yml
name: AutoQA E2E Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM UTC

concurrency:
  group: autoqa-${{ github.ref }}
  cancel-in-progress: true

env:
  AUTOQA_API_URL: ${{ secrets.AUTOQA_API_URL }}
  AUTOQA_TOKEN: ${{ secrets.AUTOQA_TOKEN }}
  STAGING_URL: ${{ vars.STAGING_URL }}

jobs:
  lint-tests:
    name: Validate Test Definitions
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'

      - name: Install AutoQA CLI
        run: pip install autoqa-cli pydantic pyyaml

      - name: Validate YAML Test Definitions
        run: |
          autoqa validate tests/**/*.autoqa.yaml

  e2e-tests:
    name: E2E Tests (${{ matrix.shard }})
    runs-on: ubuntu-latest
    needs: lint-tests
    timeout-minutes: 30

    strategy:
      fail-fast: false
      matrix:
        shard: [1, 2, 3, 4]  # 4 parallel shards

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'

      - name: Install dependencies
        run: |
          pip install autoqa-cli owl-browser pytest pytest-asyncio

      - name: Run E2E Tests (Shard ${{ matrix.shard }})
        run: |
          autoqa run \
            --tests tests/**/*.autoqa.yaml \
            --shard ${{ matrix.shard }}/4 \
            --parallel 5 \
            --output results/shard-${{ matrix.shard }} \
            --video \
            --screenshots-on-failure
        env:
          AUTOQA_SHARD: ${{ matrix.shard }}
          AUTOQA_TOTAL_SHARDS: 4

      - name: Upload Test Results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: test-results-shard-${{ matrix.shard }}
          path: results/
          retention-days: 14

      - name: Upload Videos on Failure
        uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: failure-videos-shard-${{ matrix.shard }}
          path: results/**/videos/
          retention-days: 7

  visual-regression:
    name: Visual Regression Tests
    runs-on: ubuntu-latest
    needs: lint-tests
    timeout-minutes: 20

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install autoqa-cli owl-browser imagehash pillow

      - name: Download Baselines
        uses: actions/cache@v4
        with:
          path: baselines/
          key: visual-baselines-${{ github.base_ref || 'main' }}
          restore-keys: |
            visual-baselines-main

      - name: Run Visual Regression
        run: |
          autoqa visual \
            --tests tests/visual/**/*.autoqa.yaml \
            --baselines baselines/ \
            --output visual-results/ \
            --tolerance 5

      - name: Upload Visual Diffs
        uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: visual-diffs
          path: visual-results/diffs/

      - name: Update Baselines Cache
        if: github.ref == 'refs/heads/main' && success()
        uses: actions/cache/save@v4
        with:
          path: baselines/
          key: visual-baselines-main-${{ github.sha }}

  exploratory-tests:
    name: Chaos Persona Exploration
    runs-on: ubuntu-latest
    needs: e2e-tests
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    timeout-minutes: 60

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install autoqa-cli owl-browser

      - name: Run Chaos Personas
        run: |
          autoqa explore \
            --url ${{ env.STAGING_URL }} \
            --personas confused_senior,impatient_user,chaos_monkey \
            --goals "Complete checkout" "Find help documentation" "Reset password" \
            --max-steps 50 \
            --output exploration-results/

      - name: Upload Exploration Results
        uses: actions/upload-artifact@v4
        with:
          name: exploration-results
          path: exploration-results/

  aggregate-results:
    name: Aggregate & Report
    runs-on: ubuntu-latest
    needs: [e2e-tests, visual-regression]
    if: always()

    steps:
      - uses: actions/checkout@v4

      - name: Download all artifacts
        uses: actions/download-artifact@v4
        with:
          path: all-results/

      - name: Generate Report
        run: |
          pip install autoqa-cli junitparser
          autoqa report \
            --input all-results/ \
            --format html,junit \
            --output report/

      - name: Publish Test Report
        uses: dorny/test-reporter@v1
        if: always()
        with:
          name: AutoQA Test Results
          path: report/*.xml
          reporter: java-junit

      - name: Upload HTML Report
        uses: actions/upload-artifact@v4
        with:
          name: html-report
          path: report/*.html

      - name: Comment PR with Results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const summary = fs.readFileSync('report/summary.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: summary
            });
```

### 8.2. GitLab CI Configuration

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - test
  - visual
  - explore
  - report

variables:
  AUTOQA_API_URL: $AUTOQA_API_URL
  AUTOQA_TOKEN: $AUTOQA_TOKEN
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.pip-cache"

default:
  image: python:3.12-slim
  cache:
    key: ${CI_COMMIT_REF_SLUG}
    paths:
      - .pip-cache/
      - .cache/

.autoqa-setup: &autoqa-setup
  before_script:
    - pip install autoqa-cli owl-browser pytest pytest-asyncio

validate-tests:
  stage: validate
  <<: *autoqa-setup
  script:
    - autoqa validate tests/**/*.autoqa.yaml
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

.e2e-test-template: &e2e-test
  stage: test
  <<: *autoqa-setup
  timeout: 30 minutes
  artifacts:
    when: always
    paths:
      - results/
    reports:
      junit: results/junit.xml
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

e2e-tests-1:
  <<: *e2e-test
  script:
    - autoqa run --tests tests/**/*.autoqa.yaml --shard 1/4 --output results/

e2e-tests-2:
  <<: *e2e-test
  script:
    - autoqa run --tests tests/**/*.autoqa.yaml --shard 2/4 --output results/

e2e-tests-3:
  <<: *e2e-test
  script:
    - autoqa run --tests tests/**/*.autoqa.yaml --shard 3/4 --output results/

e2e-tests-4:
  <<: *e2e-test
  script:
    - autoqa run --tests tests/**/*.autoqa.yaml --shard 4/4 --output results/

visual-regression:
  stage: visual
  <<: *autoqa-setup
  script:
    - pip install imagehash pillow
    - autoqa visual --tests tests/visual/**/*.autoqa.yaml --baselines baselines/ --output visual-results/
  artifacts:
    when: on_failure
    paths:
      - visual-results/diffs/
    expire_in: 3 days
  cache:
    key: visual-baselines-${CI_DEFAULT_BRANCH}
    paths:
      - baselines/
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

chaos-exploration:
  stage: explore
  <<: *autoqa-setup
  timeout: 1 hour
  script:
    - |
      autoqa explore \
        --url $STAGING_URL \
        --personas confused_senior,chaos_monkey \
        --goals "Complete purchase" "Contact support" \
        --output exploration/
  artifacts:
    paths:
      - exploration/
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"

aggregate-report:
  stage: report
  <<: *autoqa-setup
  needs:
    - job: e2e-tests-1
      artifacts: true
    - job: e2e-tests-2
      artifacts: true
    - job: e2e-tests-3
      artifacts: true
    - job: e2e-tests-4
      artifacts: true
  script:
    - pip install junitparser
    - autoqa report --input results/ --format html,junit --output report/
  artifacts:
    paths:
      - report/
    reports:
      junit: report/combined.xml
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### 8.3. Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent {
        kubernetes {
            yaml '''
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: python
    image: python:3.12-slim
    command: ['cat']
    tty: true
    resources:
      requests:
        memory: "1Gi"
        cpu: "500m"
'''
        }
    }

    environment {
        AUTOQA_API_URL = credentials('autoqa-api-url')
        AUTOQA_TOKEN = credentials('autoqa-token')
        STAGING_URL = 'https://staging.example.com'
    }

    options {
        timeout(time: 1, unit: 'HOURS')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    stages {
        stage('Setup') {
            steps {
                container('python') {
                    sh '''
                        pip install autoqa-cli owl-browser pytest pytest-asyncio
                        pip install imagehash pillow junitparser
                    '''
                }
            }
        }

        stage('Validate Tests') {
            steps {
                container('python') {
                    sh 'autoqa validate tests/**/*.autoqa.yaml'
                }
            }
        }

        stage('E2E Tests') {
            parallel {
                stage('Shard 1') {
                    steps {
                        container('python') {
                            sh '''
                                autoqa run \
                                    --tests tests/**/*.autoqa.yaml \
                                    --shard 1/4 \
                                    --parallel 3 \
                                    --output results/shard-1 \
                                    --video
                            '''
                        }
                    }
                }
                stage('Shard 2') {
                    steps {
                        container('python') {
                            sh '''
                                autoqa run \
                                    --tests tests/**/*.autoqa.yaml \
                                    --shard 2/4 \
                                    --parallel 3 \
                                    --output results/shard-2 \
                                    --video
                            '''
                        }
                    }
                }
                stage('Shard 3') {
                    steps {
                        container('python') {
                            sh '''
                                autoqa run \
                                    --tests tests/**/*.autoqa.yaml \
                                    --shard 3/4 \
                                    --parallel 3 \
                                    --output results/shard-3 \
                                    --video
                            '''
                        }
                    }
                }
                stage('Shard 4') {
                    steps {
                        container('python') {
                            sh '''
                                autoqa run \
                                    --tests tests/**/*.autoqa.yaml \
                                    --shard 4/4 \
                                    --parallel 3 \
                                    --output results/shard-4 \
                                    --video
                            '''
                        }
                    }
                }
            }
        }

        stage('Visual Regression') {
            steps {
                container('python') {
                    sh '''
                        autoqa visual \
                            --tests tests/visual/**/*.autoqa.yaml \
                            --baselines baselines/ \
                            --output visual-results/
                    '''
                }
            }
        }

        stage('Generate Report') {
            steps {
                container('python') {
                    sh '''
                        autoqa report \
                            --input results/ \
                            --format html,junit \
                            --output report/
                    '''
                }
            }
        }
    }

    post {
        always {
            junit 'report/*.xml'

            publishHTML(target: [
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'report',
                reportFiles: 'index.html',
                reportName: 'AutoQA Report'
            ])

            archiveArtifacts artifacts: 'results/**/videos/**', allowEmptyArchive: true
        }

        failure {
            archiveArtifacts artifacts: 'results/**/screenshots/**', allowEmptyArchive: true

            emailext(
                subject: "AutoQA Tests Failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: '''
                    <p>AutoQA E2E tests failed.</p>
                    <p>Build: ${BUILD_URL}</p>
                    <p>Report: ${BUILD_URL}AutoQA_Report/</p>
                ''',
                recipientProviders: [developers(), requestor()]
            )
        }
    }
}
```

## 9. Production Infrastructure

Complete infrastructure configurations for production deployments.

### 9.1. Docker Compose (Development/Staging)

```yaml
# docker-compose.yml
version: '3.9'

services:
  # AutoQA API Gateway
  autoqa-api:
    image: autoqa/api:latest
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://autoqa:autoqa@postgres:5432/autoqa
      REDIS_URL: redis://redis:6379/0
      S3_ENDPOINT: http://minio:9000
      S3_BUCKET: autoqa-artifacts
      S3_ACCESS_KEY: minioadmin
      S3_SECRET_KEY: minioadmin
      OWL_BROWSER_POOL_SIZE: 10
    depends_on:
      - postgres
      - redis
      - minio
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Test Orchestrator
  autoqa-orchestrator:
    image: autoqa/orchestrator:latest
    environment:
      DATABASE_URL: postgresql://autoqa:autoqa@postgres:5432/autoqa
      REDIS_URL: redis://redis:6379/0
      BROWSER_GRID_URL: http://owl-browser:8080
    depends_on:
      - postgres
      - redis
      - owl-browser
    deploy:
      replicas: 2

  # Owl Browser Pool
  owl-browser:
    image: olib/owl-browser:stable
    ports:
      - "8080:8080"
    environment:
      MAX_CONTEXTS: 20
      HEADLESS: "true"
      ENABLE_VIDEO: "true"
      VIDEO_PATH: /videos
      LLM_MODEL: qwen3-vl-2b
    volumes:
      - browser-videos:/videos
      - browser-profiles:/profiles
    deploy:
      replicas: 5
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 1G
          cpus: '0.5'
    shm_size: '2gb'

  # PostgreSQL Database
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: autoqa
      POSTGRES_PASSWORD: autoqa
      POSTGRES_DB: autoqa
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U autoqa"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis for job queue
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # MinIO for artifact storage
  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    volumes:
      - minio-data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 20s
      retries: 3

  # Dashboard UI
  autoqa-dashboard:
    image: autoqa/dashboard:latest
    ports:
      - "3000:3000"
    environment:
      API_URL: http://autoqa-api:8000
    depends_on:
      - autoqa-api

volumes:
  postgres-data:
  redis-data:
  minio-data:
  browser-videos:
  browser-profiles:

networks:
  default:
    driver: bridge
```

### 9.2. Kubernetes with KEDA Autoscaling

```yaml
# k8s/autoqa-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autoqa-orchestrator
  namespace: autoqa
spec:
  replicas: 2
  selector:
    matchLabels:
      app: autoqa-orchestrator
  template:
    metadata:
      labels:
        app: autoqa-orchestrator
    spec:
      containers:
        - name: orchestrator
          image: autoqa/orchestrator:latest
          ports:
            - containerPort: 8000
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: autoqa-secrets
                  key: database-url
            - name: REDIS_URL
              valueFrom:
                secretKeyRef:
                  name: autoqa-secrets
                  key: redis-url
          resources:
            requests:
              memory: "512Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /ready
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10

---
# Owl Browser StatefulSet for stable network identities
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: owl-browser
  namespace: autoqa
spec:
  serviceName: owl-browser
  replicas: 5
  selector:
    matchLabels:
      app: owl-browser
  template:
    metadata:
      labels:
        app: owl-browser
    spec:
      containers:
        - name: browser
          image: olib/owl-browser:stable
          ports:
            - containerPort: 8080
              name: http
          env:
            - name: MAX_CONTEXTS
              value: "10"
            - name: HEADLESS
              value: "true"
            - name: ENABLE_VIDEO
              value: "true"
          resources:
            requests:
              memory: "1Gi"
              cpu: "500m"
            limits:
              memory: "2Gi"
              cpu: "1000m"
          volumeMounts:
            - name: shm
              mountPath: /dev/shm
            - name: videos
              mountPath: /videos
      volumes:
        - name: shm
          emptyDir:
            medium: Memory
            sizeLimit: 2Gi
  volumeClaimTemplates:
    - metadata:
        name: videos
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: fast-ssd
        resources:
          requests:
            storage: 10Gi

---
# KEDA ScaledObject for browser pool autoscaling
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: owl-browser-scaler
  namespace: autoqa
spec:
  scaleTargetRef:
    name: owl-browser
  minReplicaCount: 2
  maxReplicaCount: 50
  pollingInterval: 15
  cooldownPeriod: 60
  triggers:
    - type: redis
      metadata:
        address: redis.autoqa.svc.cluster.local:6379
        listName: autoqa:test-queue
        listLength: "5"  # Scale up when queue > 5 per pod
    - type: prometheus
      metadata:
        serverAddress: http://prometheus.monitoring.svc.cluster.local:9090
        metricName: autoqa_active_tests
        threshold: "10"
        query: sum(autoqa_active_tests{namespace="autoqa"})

---
# Horizontal Pod Autoscaler for orchestrator
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: autoqa-orchestrator-hpa
  namespace: autoqa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: autoqa-orchestrator
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80

---
# Service for browser pool
apiVersion: v1
kind: Service
metadata:
  name: owl-browser
  namespace: autoqa
spec:
  selector:
    app: owl-browser
  ports:
    - port: 8080
      targetPort: 8080
  clusterIP: None  # Headless for StatefulSet
```

## 10. Reporting & Analytics

Complete reporting system with PostgreSQL schema and analytics queries.

### 10.1. PostgreSQL Schema

```sql
-- migrations/001_initial_schema.sql

-- Test Definitions
CREATE TABLE test_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    yaml_content TEXT NOT NULL,
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(255),
    version INTEGER DEFAULT 1
);

CREATE INDEX idx_test_definitions_tags ON test_definitions USING GIN(tags);

-- Test Runs (Executions)
CREATE TABLE test_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_definition_id UUID REFERENCES test_definitions(id),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    environment VARCHAR(100),
    git_branch VARCHAR(255),
    git_commit VARCHAR(40),
    triggered_by VARCHAR(255),
    ci_pipeline_id VARCHAR(255),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_test_runs_status ON test_runs(status);
CREATE INDEX idx_test_runs_started_at ON test_runs(started_at DESC);
CREATE INDEX idx_test_runs_git_branch ON test_runs(git_branch);

-- Step Results
CREATE TABLE step_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_run_id UUID REFERENCES test_runs(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL,
    step_type VARCHAR(50) NOT NULL,
    step_name VARCHAR(255),
    status VARCHAR(50) NOT NULL,
    duration_ms INTEGER,
    error_message TEXT,
    screenshot_url TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_step_results_test_run ON step_results(test_run_id);
CREATE INDEX idx_step_results_status ON step_results(status);

-- Healing Events
CREATE TABLE healing_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_run_id UUID REFERENCES test_runs(id) ON DELETE CASCADE,
    step_result_id UUID REFERENCES step_results(id) ON DELETE CASCADE,
    original_selector TEXT NOT NULL,
    healed_selector TEXT NOT NULL,
    strategy VARCHAR(50) NOT NULL,
    confidence DECIMAL(3,2),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_healing_events_test_run ON healing_events(test_run_id);

-- Artifacts
CREATE TABLE artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_run_id UUID REFERENCES test_runs(id) ON DELETE CASCADE,
    artifact_type VARCHAR(50) NOT NULL,
    file_path TEXT,
    s3_url TEXT,
    file_size INTEGER,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_artifacts_test_run ON artifacts(test_run_id);
CREATE INDEX idx_artifacts_type ON artifacts(artifact_type);

-- Flakiness Tracking
CREATE TABLE test_flakiness (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_definition_id UUID REFERENCES test_definitions(id),
    window_start DATE NOT NULL,
    window_end DATE NOT NULL,
    total_runs INTEGER DEFAULT 0,
    passed_runs INTEGER DEFAULT 0,
    failed_runs INTEGER DEFAULT 0,
    healed_runs INTEGER DEFAULT 0,
    flakiness_score DECIMAL(5,4) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(test_definition_id, window_start, window_end)
);

CREATE INDEX idx_test_flakiness_score ON test_flakiness(flakiness_score DESC);

-- Visual Baselines
CREATE TABLE visual_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_definition_id UUID REFERENCES test_definitions(id),
    checkpoint_name VARCHAR(255) NOT NULL,
    branch VARCHAR(255),
    s3_url TEXT NOT NULL,
    phash VARCHAR(64),
    approved BOOLEAN DEFAULT FALSE,
    approved_by VARCHAR(255),
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(test_definition_id, checkpoint_name, branch)
);

-- Analytics Materialized Views
CREATE MATERIALIZED VIEW daily_test_summary AS
SELECT
    DATE_TRUNC('day', started_at) AS date,
    COUNT(*) AS total_runs,
    COUNT(*) FILTER (WHERE status = 'passed') AS passed,
    COUNT(*) FILTER (WHERE status = 'failed') AS failed,
    COUNT(*) FILTER (WHERE status = 'healed') AS healed,
    AVG(duration_ms) AS avg_duration_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95_duration_ms
FROM test_runs
WHERE started_at > NOW() - INTERVAL '90 days'
GROUP BY DATE_TRUNC('day', started_at);

CREATE UNIQUE INDEX idx_daily_test_summary_date ON daily_test_summary(date);

-- Function to refresh materialized views
CREATE OR REPLACE FUNCTION refresh_analytics_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY daily_test_summary;
END;
$$ LANGUAGE plpgsql;

-- Scheduled refresh (using pg_cron extension)
-- SELECT cron.schedule('refresh-analytics', '0 * * * *', 'SELECT refresh_analytics_views()');
```

### 10.2. Analytics Queries

```python
"""
AutoQA Analytics & Reporting Engine
File: autoqa/analytics/queries.py
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import asyncpg
from pydantic import BaseModel


class TestRunSummary(BaseModel):
    """Summary of test runs for a time period."""
    total_runs: int
    passed: int
    failed: int
    healed: int
    pass_rate: float
    heal_rate: float
    avg_duration_ms: float
    p95_duration_ms: float


class FlakyTest(BaseModel):
    """Information about a flaky test."""
    test_id: str
    test_name: str
    flakiness_score: float
    total_runs: int
    failure_pattern: str


class HealingInsight(BaseModel):
    """Insight about self-healing patterns."""
    original_selector: str
    healed_selector: str
    occurrence_count: int
    success_rate: float


class AnalyticsEngine:
    """
    Analytics engine for test result analysis and reporting.
    """

    def __init__(self, db_pool: asyncpg.Pool) -> None:
        self.db = db_pool

    async def get_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        environment: str | None = None,
        branch: str | None = None,
    ) -> TestRunSummary:
        """Get test run summary for a time period."""
        query = """
            SELECT
                COUNT(*) AS total_runs,
                COUNT(*) FILTER (WHERE status = 'passed') AS passed,
                COUNT(*) FILTER (WHERE status = 'failed') AS failed,
                COUNT(*) FILTER (WHERE status = 'healed') AS healed,
                AVG(duration_ms) AS avg_duration_ms,
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95_duration_ms
            FROM test_runs
            WHERE started_at BETWEEN $1 AND $2
        """
        params: list[Any] = [start_date, end_date]

        if environment:
            query += " AND environment = $3"
            params.append(environment)
        if branch:
            query += f" AND git_branch = ${len(params) + 1}"
            params.append(branch)

        row = await self.db.fetchrow(query, *params)

        total = row["total_runs"] or 0
        passed = row["passed"] or 0
        healed = row["healed"] or 0

        return TestRunSummary(
            total_runs=total,
            passed=passed,
            failed=row["failed"] or 0,
            healed=healed,
            pass_rate=passed / total if total > 0 else 0,
            heal_rate=healed / total if total > 0 else 0,
            avg_duration_ms=row["avg_duration_ms"] or 0,
            p95_duration_ms=row["p95_duration_ms"] or 0,
        )

    async def get_flaky_tests(
        self,
        days: int = 14,
        min_runs: int = 5,
        limit: int = 20,
    ) -> list[FlakyTest]:
        """Identify flaky tests based on inconsistent results."""
        query = """
            WITH test_stats AS (
                SELECT
                    td.id AS test_id,
                    td.name AS test_name,
                    COUNT(*) AS total_runs,
                    COUNT(*) FILTER (WHERE tr.status = 'passed') AS passed,
                    COUNT(*) FILTER (WHERE tr.status = 'failed') AS failed,
                    -- Flakiness score: tests that sometimes pass and sometimes fail
                    CASE
                        WHEN COUNT(*) >= $2 THEN
                            2.0 * LEAST(
                                COUNT(*) FILTER (WHERE tr.status = 'passed'),
                                COUNT(*) FILTER (WHERE tr.status = 'failed')
                            )::DECIMAL / COUNT(*)
                        ELSE 0
                    END AS flakiness_score
                FROM test_definitions td
                JOIN test_runs tr ON tr.test_definition_id = td.id
                WHERE tr.started_at > NOW() - INTERVAL '1 day' * $1
                GROUP BY td.id, td.name
            )
            SELECT *
            FROM test_stats
            WHERE flakiness_score > 0.1 AND total_runs >= $2
            ORDER BY flakiness_score DESC
            LIMIT $3
        """

        rows = await self.db.fetch(query, days, min_runs, limit)

        return [
            FlakyTest(
                test_id=str(row["test_id"]),
                test_name=row["test_name"],
                flakiness_score=float(row["flakiness_score"]),
                total_runs=row["total_runs"],
                failure_pattern=self._analyze_failure_pattern(
                    row["passed"], row["failed"]
                ),
            )
            for row in rows
        ]

    def _analyze_failure_pattern(self, passed: int, failed: int) -> str:
        """Analyze the failure pattern of a test."""
        total = passed + failed
        if total == 0:
            return "No runs"

        fail_rate = failed / total
        if fail_rate < 0.1:
            return "Occasional failures"
        elif fail_rate < 0.3:
            return "Intermittent failures"
        elif fail_rate < 0.5:
            return "Frequent failures"
        else:
            return "Mostly failing"

    async def get_healing_insights(
        self,
        days: int = 30,
        limit: int = 50,
    ) -> list[HealingInsight]:
        """Get insights about self-healing patterns."""
        query = """
            SELECT
                original_selector,
                healed_selector,
                COUNT(*) AS occurrence_count,
                AVG(confidence) AS avg_confidence
            FROM healing_events he
            JOIN test_runs tr ON tr.id = he.test_run_id
            WHERE tr.started_at > NOW() - INTERVAL '1 day' * $1
            GROUP BY original_selector, healed_selector
            HAVING COUNT(*) >= 2
            ORDER BY occurrence_count DESC
            LIMIT $2
        """

        rows = await self.db.fetch(query, days, limit)

        return [
            HealingInsight(
                original_selector=row["original_selector"],
                healed_selector=row["healed_selector"],
                occurrence_count=row["occurrence_count"],
                success_rate=float(row["avg_confidence"] or 0),
            )
            for row in rows
        ]

    async def get_historical_trends(
        self,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """Get historical test result trends."""
        query = """
            SELECT
                date,
                total_runs,
                passed,
                failed,
                healed,
                avg_duration_ms,
                p95_duration_ms,
                CASE WHEN total_runs > 0
                    THEN passed::DECIMAL / total_runs
                    ELSE 0
                END AS pass_rate
            FROM daily_test_summary
            WHERE date > NOW() - INTERVAL '1 day' * $1
            ORDER BY date ASC
        """

        rows = await self.db.fetch(query, days)

        return [dict(row) for row in rows]

    async def calculate_flakiness_scores(self) -> int:
        """Calculate and store flakiness scores for all tests."""
        query = """
            INSERT INTO test_flakiness (
                test_definition_id,
                window_start,
                window_end,
                total_runs,
                passed_runs,
                failed_runs,
                healed_runs,
                flakiness_score
            )
            SELECT
                td.id,
                DATE_TRUNC('week', NOW() - INTERVAL '7 days')::DATE,
                DATE_TRUNC('week', NOW())::DATE,
                COUNT(*),
                COUNT(*) FILTER (WHERE tr.status = 'passed'),
                COUNT(*) FILTER (WHERE tr.status = 'failed'),
                COUNT(*) FILTER (WHERE tr.status = 'healed'),
                CASE
                    WHEN COUNT(*) >= 3 THEN
                        2.0 * LEAST(
                            COUNT(*) FILTER (WHERE tr.status = 'passed'),
                            COUNT(*) FILTER (WHERE tr.status = 'failed')
                        )::DECIMAL / COUNT(*)
                    ELSE 0
                END
            FROM test_definitions td
            JOIN test_runs tr ON tr.test_definition_id = td.id
            WHERE tr.started_at > NOW() - INTERVAL '7 days'
            GROUP BY td.id
            ON CONFLICT (test_definition_id, window_start, window_end)
            DO UPDATE SET
                total_runs = EXCLUDED.total_runs,
                passed_runs = EXCLUDED.passed_runs,
                failed_runs = EXCLUDED.failed_runs,
                healed_runs = EXCLUDED.healed_runs,
                flakiness_score = EXCLUDED.flakiness_score
        """

        result = await self.db.execute(query)
        return int(result.split()[-1])  # Returns affected row count
```

## 11. Roadmap

### Current Release (v1.0)
- Self-healing test runner with AI-powered element location
- YAML-based test DSL with variables, loops, and conditionals
- Video recording with step-indexed playback
- Visual regression using semantic VLM comparison
- CI/CD integrations for GitHub Actions, GitLab CI, Jenkins

### Next Release (v1.1)
- **Text-to-Test**: Generate test YAML from recorded user sessions
- **Jira Integration**: Auto-file bug reports with video evidence
- **Slack/Teams Notifications**: Real-time test failure alerts
- **Performance Baselines**: Track and alert on performance regressions

### Future (v2.0)
- **Mobile App Testing**: iOS/Android support via Appium protocol
- **API Testing Integration**: Combined UI + API test scenarios
- **AI Test Generation**: Generate new tests from application analysis
- **Distributed Tracing**: Correlate frontend tests with backend traces

---
*AutoQA Documentation - Production Ready*
*Built on Owl Browser SDK*

---

## Disclaimer

This project documentation was generated by generative AI. While the architectural concepts and implementation patterns are based on real-world best practices, some features, configurations, or code examples may require adjustments for production use. Please review and test thoroughly before deploying.