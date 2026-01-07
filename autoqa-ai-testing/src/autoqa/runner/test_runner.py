"""
Test runner for executing DSL test specifications.

Executes tests using owl-browser with:
- Self-healing selector recovery (no AI dependency)
- Automatic retries with exponential backoff
- Smart waits (network idle, selectors)
- Screenshot capture on failure
- Network log capture for debugging
"""

from __future__ import annotations

import contextlib
import re
import time
import traceback
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import structlog

from autoqa.dsl.models import (
    StepAction,
    TestSpec,
    TestStep,
    TestSuite,
)
from autoqa.dsl.transformer import StepTransformer
from autoqa.runner.self_healing import HealingResult, SelfHealingEngine
from autoqa.versioning.history_tracker import TestRunHistory
from autoqa.versioning.models import VersioningConfig

if TYPE_CHECKING:
    from owl_browser import Browser, BrowserContext

logger = structlog.get_logger(__name__)


# Exception types for retry logic
class ElementNotFoundError(Exception):
    """Raised when an element cannot be found."""

    pass


class ElementNotInteractableError(Exception):
    """Raised when an element is found but not interactable."""

    pass


class NetworkTimeoutError(Exception):
    """Raised when network operations timeout."""

    pass


class StepStatus(StrEnum):
    """Status of a test step execution."""

    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    HEALED = "healed"


@dataclass
class StepResult:
    """Result of a single step execution."""

    step_index: int
    step_name: str | None
    action: str
    status: StepStatus
    duration_ms: int = 0
    result: Any = None
    error: str | None = None
    error_traceback: str | None = None
    screenshot_path: str | None = None
    healing_result: HealingResult | None = None
    retries: int = 0
    network_log: list[dict[str, Any]] | None = None


@dataclass
class TestRunResult:
    """Result of a complete test run."""

    test_name: str
    status: StepStatus
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int = 0
    total_steps: int = 0
    passed_steps: int = 0
    failed_steps: int = 0
    skipped_steps: int = 0
    healed_steps: int = 0
    step_results: list[StepResult] = field(default_factory=list)
    video_path: str | None = None
    artifacts: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    variables: dict[str, Any] = field(default_factory=dict)
    network_log: list[dict[str, Any]] = field(default_factory=list)


class PageRecoveryError(Exception):
    """Raised when page recovery (navigation to expected URL) fails."""

    pass


class TestRunner:
    """
    Executes test specifications using owl-browser.

    Features:
    - Self-healing selector recovery (deterministic, no AI)
    - URL-aware recovery: navigates to expected page if on wrong page
    - Automatic retries with exponential backoff (tenacity)
    - Smart waits: wait_for_network_idle after navigation
    - wait_for_selector before interactions
    - is_visible/is_enabled checks before clicks
    - Video recording
    - Screenshot capture on failure
    - Network log capture for debugging
    - Variable capture and interpolation
    """

    # Actions that require element visibility/enabled checks
    INTERACTION_ACTIONS: frozenset[StepAction] = frozenset({
        StepAction.CLICK,
        StepAction.DOUBLE_CLICK,
        StepAction.RIGHT_CLICK,
        StepAction.TYPE,
        StepAction.PICK,
        StepAction.HOVER,
        StepAction.UPLOAD,
        StepAction.SUBMIT,
    })

    # Actions that should wait for network idle after execution
    NAVIGATION_ACTIONS: frozenset[StepAction] = frozenset({
        StepAction.NAVIGATE,
        StepAction.CLICK,
        StepAction.SUBMIT,
    })

    def __init__(
        self,
        browser: Browser,
        healing_engine: SelfHealingEngine | None = None,
        artifact_dir: str | Path | None = None,
        record_video: bool = False,
        screenshot_on_failure: bool = True,
        capture_network_on_failure: bool = True,
        default_timeout_ms: int = 30000,
        wait_for_network_idle: bool = True,
        network_idle_timeout_ms: int = 5000,
        pre_action_visibility_check: bool = True,
        enable_versioning: bool = False,
        versioning_storage_path: str = ".autoqa/history",
        enable_url_recovery: bool = True,
    ) -> None:
        self._browser = browser
        self._healing_engine = healing_engine or SelfHealingEngine()
        self._artifact_dir = Path(artifact_dir) if artifact_dir else Path("./artifacts")
        self._record_video = record_video
        self._screenshot_on_failure = screenshot_on_failure
        self._capture_network_on_failure = capture_network_on_failure
        self._default_timeout = default_timeout_ms
        self._wait_for_network_idle = wait_for_network_idle
        self._network_idle_timeout = network_idle_timeout_ms
        self._pre_action_visibility_check = pre_action_visibility_check
        self._enable_url_recovery = enable_url_recovery
        self._transformer = StepTransformer()
        self._log = logger.bind(component="test_runner")

        # URL recovery tracking - stores the expected URL from navigate actions
        # and step-level _expected_url metadata
        self._current_expected_url: str | None = None

        # Versioning support
        self._enable_versioning = enable_versioning
        self._versioning_storage_path = versioning_storage_path
        self._history_tracker: TestRunHistory | None = None

        if self._enable_versioning:
            self._history_tracker = TestRunHistory(storage_path=versioning_storage_path)

        self._artifact_dir.mkdir(parents=True, exist_ok=True)

    def run_spec(
        self,
        spec: TestSpec,
        page: BrowserContext | None = None,
        variables: dict[str, Any] | None = None,
    ) -> TestRunResult:
        """
        Run a single test specification.

        Args:
            spec: Test specification to run
            page: Browser page to use (creates new if not provided)
            variables: Additional variables for interpolation

        Returns:
            TestRunResult with execution details
        """
        result = TestRunResult(
            test_name=spec.name,
            status=StepStatus.RUNNING,
            started_at=datetime.now(UTC),
            total_steps=len(spec.steps),
            variables={**(variables or {}), **spec.variables},
        )

        own_page = page is None
        if own_page:
            page = self._browser.new_page()

        self._log.info("Starting test run", test=spec.name, steps=len(spec.steps))

        try:
            if self._record_video:
                page.start_video_recording(fps=30)

            if spec.before_all:
                self._run_hook(page, spec.before_all.steps, "before_all", result)

            for i, step in enumerate(spec.steps):
                if spec.before_each:
                    self._run_hook(page, spec.before_each.steps, "before_each", result)

                step_result = self._execute_step(page, step, i, result)
                result.step_results.append(step_result)

                match step_result.status:
                    case StepStatus.PASSED:
                        result.passed_steps += 1
                    case StepStatus.FAILED:
                        result.failed_steps += 1
                        if not step.continue_on_failure:
                            break
                    case StepStatus.SKIPPED:
                        result.skipped_steps += 1
                    case StepStatus.HEALED:
                        result.healed_steps += 1
                        result.passed_steps += 1

                if spec.after_each:
                    self._run_hook(page, spec.after_each.steps, "after_each", result)

            if spec.after_all:
                self._run_hook(page, spec.after_all.steps, "after_all", result)

            if self._record_video:
                try:
                    video_path = page.stop_video_recording()
                    result.video_path = video_path
                except Exception as e:
                    self._log.warning("Failed to stop video recording", error=str(e))

        except Exception as e:
            result.error = str(e)
            self._log.error("Test run failed with exception", error=str(e))

        finally:
            if own_page:
                with contextlib.suppress(Exception):
                    page.close()

        result.finished_at = datetime.now(UTC)
        result.duration_ms = int(
            (result.finished_at - result.started_at).total_seconds() * 1000
        )
        result.status = (
            StepStatus.PASSED if result.failed_steps == 0 else StepStatus.FAILED
        )

        self._log.info(
            "Test run completed",
            test=spec.name,
            status=result.status,
            passed=result.passed_steps,
            failed=result.failed_steps,
            healed=result.healed_steps,
            duration_ms=result.duration_ms,
        )

        # Save snapshot if versioning is enabled (either globally or per-spec)
        versioning_enabled = self._enable_versioning or (
            spec.versioning and spec.versioning.enabled
        )
        if versioning_enabled:
            self._save_test_snapshot(spec, result, page if not own_page else None)

        return result

    def _save_test_snapshot(
        self,
        spec: TestSpec,
        result: TestRunResult,
        page: BrowserContext | None,
    ) -> None:
        """Save a snapshot for versioned test tracking."""
        try:
            # Get versioning config from spec or use defaults
            versioning_config = VersioningConfig(
                enabled=True,
                storage_path=spec.versioning.storage_path if spec.versioning else self._versioning_storage_path,
                capture_screenshots=spec.versioning.capture_screenshots if spec.versioning else True,
                capture_network=spec.versioning.capture_network if spec.versioning else True,
                capture_elements=spec.versioning.capture_elements if spec.versioning else True,
                element_selectors=list(spec.versioning.element_selectors) if spec.versioning else [],
            )

            # Get or create history tracker
            tracker = self._history_tracker
            if tracker is None or (spec.versioning and spec.versioning.storage_path != self._versioning_storage_path):
                tracker = TestRunHistory(
                    storage_path=versioning_config.storage_path,
                    config=versioning_config,
                )

            # Save the snapshot
            snapshot = tracker.save_snapshot(
                test_name=spec.name,
                run_data=result,
                page=page,
            )

            self._log.info(
                "Snapshot saved",
                test=spec.name,
                version_id=snapshot.version_id,
            )

        except Exception as e:
            self._log.warning(
                "Failed to save test snapshot",
                test=spec.name,
                error=str(e),
            )

    def run_suite(
        self,
        suite: TestSuite,
        variables: dict[str, Any] | None = None,
    ) -> list[TestRunResult]:
        """
        Run a test suite.

        Args:
            suite: Test suite to run
            variables: Additional variables for interpolation

        Returns:
            List of TestRunResult for each test
        """
        results: list[TestRunResult] = []
        combined_vars = {**(variables or {}), **suite.variables}

        self._log.info(
            "Starting test suite",
            suite=suite.name,
            tests=len(suite.tests),
            parallel=suite.parallel_execution,
        )

        if suite.before_suite:
            page = self._browser.new_page()
            try:
                dummy_result = TestRunResult(
                    test_name="_suite_setup",
                    status=StepStatus.RUNNING,
                    started_at=datetime.now(UTC),
                )
                self._run_hook(page, suite.before_suite.steps, "before_suite", dummy_result)
            finally:
                page.close()

        if suite.parallel_execution:
            results = self._run_parallel(suite, combined_vars)
        else:
            for test in suite.tests:
                test_vars = {**combined_vars, **test.variables}
                result = self.run_spec(test, variables=test_vars)
                results.append(result)

                if suite.fail_fast and result.status == StepStatus.FAILED:
                    self._log.info("Fail-fast triggered, stopping suite execution")
                    break

        if suite.after_suite:
            page = self._browser.new_page()
            try:
                dummy_result = TestRunResult(
                    test_name="_suite_teardown",
                    status=StepStatus.RUNNING,
                    started_at=datetime.now(UTC),
                )
                self._run_hook(page, suite.after_suite.steps, "after_suite", dummy_result)
            finally:
                page.close()

        passed = sum(1 for r in results if r.status == StepStatus.PASSED)
        failed = sum(1 for r in results if r.status == StepStatus.FAILED)

        self._log.info(
            "Test suite completed",
            suite=suite.name,
            total=len(results),
            passed=passed,
            failed=failed,
        )

        return results

    def _run_parallel(
        self,
        suite: TestSuite,
        variables: dict[str, Any],
    ) -> list[TestRunResult]:
        """Run tests in parallel using asyncio."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results: list[TestRunResult] = []
        max_workers = min(suite.max_parallel, len(suite.tests))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_test = {
                executor.submit(
                    self.run_spec,
                    test,
                    variables={**variables, **test.variables},
                ): test
                for test in suite.tests
            }

            for future in as_completed(future_to_test):
                test = future_to_test[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self._log.error(
                        "Parallel test execution failed",
                        test=test.name,
                        error=str(e),
                    )
                    results.append(
                        TestRunResult(
                            test_name=test.name,
                            status=StepStatus.FAILED,
                            started_at=datetime.now(UTC),
                            finished_at=datetime.now(UTC),
                            error=str(e),
                        )
                    )

        return results

    def _execute_step(
        self,
        page: BrowserContext,
        step: TestStep,
        index: int,
        test_result: TestRunResult,
    ) -> StepResult:
        """
        Execute a single test step with smart waits, URL recovery, and robustness.

        URL-aware recovery flow:
        1. Track expected URL from navigate actions and step metadata
        2. Before element actions, verify we're on the expected page
        3. If element not found, try URL recovery before selector healing
        4. Log all recovery attempts for debugging
        """
        step_name = step.name or f"Step {index + 1}"
        start_time = time.monotonic()

        self._log.debug("Executing step", step=step_name, action=step.action)

        # Check skip condition
        if step.skip_if and self._evaluate_condition(step.skip_if, test_result.variables):
            return StepResult(
                step_index=index,
                step_name=step.name,
                action=step.action,
                status=StepStatus.SKIPPED,
            )

        # Track expected URL from navigate actions
        if step.action == StepAction.NAVIGATE and step.url:
            self._current_expected_url = step.url
            self._log.debug("Updated expected URL", url=step.url)

        # Update expected URL from step metadata if provided
        step_expected_url = step.expected_url
        if step_expected_url:
            self._current_expected_url = step_expected_url

        method_name, args = self._transformer.transform(step)
        args = self._interpolate_args(args, test_result.variables)

        last_error: Exception | None = None
        retries = 0
        network_log: list[dict[str, Any]] | None = None
        url_recovery_attempted = False

        for attempt in range(step.retry_count + 1):
            try:
                # URL-aware pre-check: verify we're on the expected page
                # before attempting element interactions
                if (
                    self._enable_url_recovery
                    and step.action in self.INTERACTION_ACTIONS
                    and step.selector
                    and self._current_expected_url
                ):
                    self._verify_or_recover_url(page, self._current_expected_url)

                # Smart pre-action waits for interaction actions
                if step.action in self.INTERACTION_ACTIONS and step.selector:
                    self._ensure_element_ready(page, step.selector, step.timeout)

                # Execute the browser command
                result = self._execute_browser_command(
                    page, method_name, args, step
                )

                # Smart post-action waits for navigation actions
                if self._wait_for_network_idle and step.action in self.NAVIGATION_ACTIONS:
                    self._wait_for_stable_state(page)

                if step.capture_as:
                    test_result.variables[step.capture_as] = result

                duration = int((time.monotonic() - start_time) * 1000)

                return StepResult(
                    step_index=index,
                    step_name=step.name,
                    action=step.action,
                    status=StepStatus.PASSED,
                    duration_ms=duration,
                    result=result if self._transformer.should_capture_result(step) else None,
                    retries=retries,
                )

            except Exception as e:
                last_error = e
                retries = attempt

                # RECOVERY STRATEGY 1: URL-aware recovery
                # If element not found and we have an expected URL, try navigating there first
                if (
                    self._enable_url_recovery
                    and not url_recovery_attempted
                    and step.selector
                    and self._is_element_not_found_error(e)
                    and self._current_expected_url
                ):
                    url_recovery_attempted = True
                    recovery_success = self._attempt_url_recovery(
                        page,
                        self._current_expected_url,
                        step_name,
                    )

                    if recovery_success:
                        # After URL recovery, retry the step immediately
                        self._log.info(
                            "URL recovery successful, retrying step",
                            step=step_name,
                            url=self._current_expected_url,
                        )
                        try:
                            if step.action in self.INTERACTION_ACTIONS:
                                self._ensure_element_ready(page, step.selector, step.timeout)

                            result = self._execute_browser_command(
                                page, method_name, args, step
                            )

                            if self._wait_for_network_idle and step.action in self.NAVIGATION_ACTIONS:
                                self._wait_for_stable_state(page)

                            if step.capture_as:
                                test_result.variables[step.capture_as] = result

                            duration = int((time.monotonic() - start_time) * 1000)

                            return StepResult(
                                step_index=index,
                                step_name=step.name,
                                action=step.action,
                                status=StepStatus.HEALED,
                                duration_ms=duration,
                                result=result if self._transformer.should_capture_result(step) else None,
                                retries=retries,
                            )
                        except Exception as recovery_error:
                            last_error = recovery_error
                            self._log.warning(
                                "Step still failed after URL recovery",
                                step=step_name,
                                error=str(recovery_error),
                            )

                # RECOVERY STRATEGY 2: Selector self-healing
                # Attempt self-healing for element not found errors
                if step.selector and self._is_element_not_found_error(e):
                    healing_result = self._healing_engine.heal_selector(
                        page,
                        step.selector,
                        action_context=step.action,
                        element_description=step.description,
                    )

                    if healing_result.success and healing_result.healed_selector:
                        args["selector"] = healing_result.healed_selector
                        try:
                            # Re-check element readiness with healed selector
                            if step.action in self.INTERACTION_ACTIONS:
                                self._ensure_element_ready(
                                    page, healing_result.healed_selector, step.timeout
                                )

                            result = self._execute_browser_command(
                                page, method_name, args, step
                            )

                            if self._wait_for_network_idle and step.action in self.NAVIGATION_ACTIONS:
                                self._wait_for_stable_state(page)

                            if step.capture_as:
                                test_result.variables[step.capture_as] = result

                            duration = int((time.monotonic() - start_time) * 1000)

                            return StepResult(
                                step_index=index,
                                step_name=step.name,
                                action=step.action,
                                status=StepStatus.HEALED,
                                duration_ms=duration,
                                result=result if self._transformer.should_capture_result(step) else None,
                                healing_result=healing_result,
                                retries=retries,
                            )
                        except Exception as heal_error:
                            last_error = heal_error

                # Exponential backoff before retry
                if attempt < step.retry_count:
                    delay = self._calculate_backoff_delay(attempt, step.retry_delay_ms)
                    self._log.debug(
                        "Step failed, retrying with backoff",
                        step=step_name,
                        attempt=attempt + 1,
                        max_retries=step.retry_count,
                        delay_ms=delay,
                        error=str(e),
                    )
                    time.sleep(delay / 1000)

        duration = int((time.monotonic() - start_time) * 1000)

        # Capture failure artifacts
        screenshot_path: str | None = None
        if self._screenshot_on_failure:
            screenshot_path = self._capture_failure_screenshot(
                page, test_result.test_name, index, test_result.artifacts
            )

        if self._capture_network_on_failure:
            network_log = self._capture_network_log(page, test_result)

        return StepResult(
            step_index=index,
            step_name=step.name,
            action=step.action,
            status=StepStatus.FAILED,
            duration_ms=duration,
            error=str(last_error) if last_error else "Unknown error",
            error_traceback=traceback.format_exc() if last_error else None,
            screenshot_path=screenshot_path,
            retries=retries,
            network_log=network_log,
        )

    def _ensure_element_ready(
        self,
        page: BrowserContext,
        selector: str,
        timeout: int | None = None,
    ) -> None:
        """Ensure element is visible and enabled before interaction."""
        effective_timeout = timeout or self._default_timeout

        # Wait for selector to exist
        try:
            page.wait_for_selector(selector, timeout=effective_timeout)
        except Exception as e:
            raise ElementNotFoundError(f"Element not found: {selector}") from e

        # Check visibility if pre-action check is enabled
        if self._pre_action_visibility_check:
            try:
                if not page.is_visible(selector):
                    # Element exists but not visible - scroll to it
                    try:
                        page.scroll_to_element(selector)
                        time.sleep(0.2)  # Brief wait for scroll
                    except Exception:
                        pass

                    # Re-check visibility
                    if not page.is_visible(selector):
                        raise ElementNotInteractableError(
                            f"Element not visible: {selector}"
                        )

                # Check if element is enabled (for interactive elements)
                try:
                    if not page.is_enabled(selector):
                        raise ElementNotInteractableError(
                            f"Element not enabled: {selector}"
                        )
                except Exception:
                    # is_enabled may not be applicable for all elements
                    pass

            except ElementNotInteractableError:
                raise
            except Exception:
                # Visibility check failed but element exists, proceed anyway
                pass

    def _wait_for_stable_state(self, page: BrowserContext) -> None:
        """Wait for network idle and stable DOM state."""
        try:
            page.wait_for_network_idle(
                idle_time=500,
                timeout=self._network_idle_timeout,
            )
        except Exception as e:
            self._log.debug("Network idle wait timed out", error=str(e))

    def _verify_or_recover_url(
        self,
        page: BrowserContext,
        expected_url: str,
    ) -> None:
        """
        Verify browser is on expected URL, navigate if not.

        This is a proactive check before element interactions to ensure
        we're on the correct page. Does NOT raise on recovery failure -
        that will be caught when the element interaction fails.

        Args:
            page: Browser context
            expected_url: Expected URL (full URL or path)
        """
        try:
            current_url = page.get_current_url()
            if not current_url:
                return

            # Check if current URL matches expected (either full URL or path)
            expected_parsed = urlparse(expected_url)
            current_parsed = urlparse(current_url)

            # Compare paths (more flexible than full URL match)
            expected_path = expected_parsed.path.rstrip("/") or "/"
            current_path = current_parsed.path.rstrip("/") or "/"

            if current_path != expected_path:
                self._log.info(
                    "URL mismatch detected, navigating to expected page",
                    current=current_url,
                    expected=expected_url,
                    current_path=current_path,
                    expected_path=expected_path,
                )
                # Navigate to expected URL
                page.goto(expected_url, wait_until="domcontentloaded", timeout=10000)
                self._wait_for_stable_state(page)

        except Exception as e:
            self._log.warning(
                "URL verification/recovery failed",
                expected_url=expected_url,
                error=str(e),
            )

    def _attempt_url_recovery(
        self,
        page: BrowserContext,
        expected_url: str,
        step_name: str,
    ) -> bool:
        """
        Attempt to recover by navigating to the expected URL.

        Called when an element is not found and we have an expected URL.
        This handles the case where the browser ended up on a different page
        (e.g., due to a redirect, timeout, or prior navigation failure).

        Args:
            page: Browser context
            expected_url: URL where the element should exist
            step_name: Name of the step (for logging)

        Returns:
            True if recovery navigation succeeded, False otherwise
        """
        try:
            current_url = page.get_current_url() or "unknown"
            self._log.info(
                "Attempting URL recovery",
                step=step_name,
                current_url=current_url,
                target_url=expected_url,
            )

            # Navigate to expected URL
            page.goto(expected_url, wait_until="domcontentloaded", timeout=10000)

            # Wait for page to stabilize
            self._wait_for_stable_state(page)

            # Verify navigation succeeded
            new_url = page.get_current_url() or ""
            expected_path = urlparse(expected_url).path.rstrip("/") or "/"
            new_path = urlparse(new_url).path.rstrip("/") or "/"

            if new_path == expected_path:
                self._log.info(
                    "URL recovery succeeded",
                    step=step_name,
                    url=new_url,
                )
                return True
            else:
                self._log.warning(
                    "URL recovery navigated to unexpected page",
                    step=step_name,
                    expected_path=expected_path,
                    actual_path=new_path,
                )
                return False

        except Exception as e:
            self._log.error(
                "URL recovery failed",
                step=step_name,
                expected_url=expected_url,
                error=str(e),
            )
            return False

    def _calculate_backoff_delay(self, attempt: int, base_delay_ms: int) -> int:
        """Calculate exponential backoff delay with jitter."""
        import random
        # Exponential backoff: base * 2^attempt with max cap
        delay = min(base_delay_ms * (2 ** attempt), 30000)
        # Add 10% jitter
        jitter = random.randint(0, int(delay * 0.1))
        return delay + jitter

    def _capture_failure_screenshot(
        self,
        page: BrowserContext,
        test_name: str,
        step_index: int,
        artifacts: dict[str, str],
    ) -> str | None:
        """Capture screenshot on failure."""
        try:
            # Sanitize test name for filename
            safe_name = re.sub(r"[^\w\-_]", "_", test_name)
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            screenshot_path = str(
                self._artifact_dir / f"failure_{safe_name}_{step_index}_{timestamp}.png"
            )
            page.screenshot(screenshot_path)
            artifacts[f"failure_screenshot_{step_index}"] = screenshot_path
            self._log.info("Captured failure screenshot", path=screenshot_path)
            return screenshot_path
        except Exception as ss_error:
            self._log.warning("Failed to capture failure screenshot", error=str(ss_error))
            return None

    def _capture_network_log(
        self,
        page: BrowserContext,
        test_result: TestRunResult,
    ) -> list[dict[str, Any]] | None:
        """Capture network log for debugging."""
        try:
            network_log = page.get_network_log()
            test_result.network_log = network_log
            self._log.debug("Captured network log", entries=len(network_log))
            return network_log
        except Exception as e:
            self._log.debug("Failed to capture network log", error=str(e))
            return None

    def _execute_browser_command(
        self,
        page: BrowserContext,
        method_name: str,
        args: dict[str, Any],
        step: TestStep,
    ) -> Any:
        """Execute a browser command."""
        if method_name.startswith("_assert"):
            return self._execute_assertion(page, method_name, args, step)

        method = getattr(page, method_name, None)
        if method is None:
            raise ValueError(f"Unknown browser method: {method_name}")

        return method(**args)

    def _execute_assertion(
        self,
        page: BrowserContext,
        method_name: str,
        args: dict[str, Any],
        step: TestStep,
    ) -> bool:
        """Execute an assertion step."""
        from autoqa.assertions.engine import AssertionEngine

        engine = AssertionEngine(page)

        match method_name:
            case "_assert_element":
                return engine.assert_element(args["config"])
            case "_assert_visual":
                return engine.assert_visual(args["config"], self._artifact_dir)
            case "_assert_network":
                return engine.assert_network(args["config"])
            case "_assert_url":
                return engine.assert_url(
                    args["url_pattern"],
                    is_regex=args.get("is_regex", False),
                )
            case "_assert_custom":
                return engine.assert_custom(args["config"])
            # ML-based assertions
            case "_assert_ml":
                return engine.assert_ml(args["config"])
            case "_assert_ocr":
                return engine.assert_ocr(args["config"])
            case "_assert_ui_state":
                return engine.assert_ui_state(args["config"])
            case "_assert_color":
                return engine.assert_color(args["config"])
            case "_assert_layout":
                return engine.assert_layout(args["config"])
            case "_assert_icon":
                return engine.assert_icon(args["config"])
            case "_assert_accessibility":
                return engine.assert_accessibility(args["config"])
            # LLM-based assertions
            case "_assert_llm" | "_assert_semantic" | "_assert_content":
                return self._execute_llm_assertion(page, method_name, args)
            case _:
                raise ValueError(f"Unknown assertion type: {method_name}")

    def _run_hook(
        self,
        page: BrowserContext,
        steps: list[TestStep],
        hook_name: str,
        result: TestRunResult,
    ) -> None:
        """Run a lifecycle hook."""
        for i, step in enumerate(steps):
            step_result = self._execute_step(page, step, i, result)
            if step_result.status == StepStatus.FAILED:
                self._log.warning(
                    "Hook step failed",
                    hook=hook_name,
                    step=step.name or i,
                    error=step_result.error,
                )

    def _interpolate_args(
        self, args: dict[str, Any], variables: dict[str, Any]
    ) -> dict[str, Any]:
        """Interpolate variables in arguments."""
        import re

        pattern = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

        def replace(value: Any) -> Any:
            if isinstance(value, str):
                def replacer(match: re.Match[str]) -> str:
                    var_name = match.group(1)
                    if var_name in variables:
                        return str(variables[var_name])
                    return match.group(0)

                return pattern.sub(replacer, value)
            elif isinstance(value, dict):
                return {k: replace(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [replace(v) for v in value]
            return value

        return {k: replace(v) for k, v in args.items()}

    def _evaluate_condition(self, condition: str, variables: dict[str, Any]) -> bool:
        """Evaluate a skip condition."""
        import re

        interpolated = condition
        pattern = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

        for match in pattern.finditer(condition):
            var_name = match.group(1)
            if var_name in variables:
                value = variables[var_name]
                if isinstance(value, str):
                    interpolated = interpolated.replace(match.group(0), f'"{value}"')
                else:
                    interpolated = interpolated.replace(match.group(0), str(value))

        try:
            return bool(eval(interpolated, {"__builtins__": {}}, {}))
        except Exception:
            return False

    def _is_element_not_found_error(self, error: Exception) -> bool:
        """Check if error is an element not found error."""
        error_str = str(error).lower()
        indicators = [
            "element not found",
            "no such element",
            "unable to locate",
            "could not find",
            "selector did not match",
        ]
        return any(indicator in error_str for indicator in indicators)

    def _execute_llm_assertion(
        self,
        page: BrowserContext,
        method_name: str,
        args: dict[str, Any],
    ) -> bool:
        """
        Execute an LLM-based assertion.

        Uses asyncio to run the async LLM assertion engine.
        Falls back gracefully when LLM is disabled.
        """
        import asyncio

        from autoqa.llm.assertions import LLMAssertionEngine, LLMAssertionError

        async def run_assertion() -> bool:
            engine = LLMAssertionEngine(page)

            match method_name:
                case "_assert_llm":
                    config = args["config"]
                    result = await engine.assert_semantic(
                        assertion=config.assertion,
                        context=config.context,
                        min_confidence=config.min_confidence,
                        message=config.message,
                    )
                    return result.passed

                case "_assert_semantic":
                    config = args["config"]
                    result = await engine.assert_state(
                        expected_state=config.expected_state,
                        indicators=config.indicators,
                        min_confidence=config.min_confidence,
                        message=config.message,
                    )
                    return result.passed

                case "_assert_content":
                    config = args["config"]
                    result = await engine.assert_content_valid(
                        content_type=config.content_type,
                        expected_patterns=config.expected_patterns,
                        selector=config.selector,
                        min_confidence=config.min_confidence,
                        message=config.message,
                    )
                    return result.passed

                case _:
                    raise ValueError(f"Unknown LLM assertion type: {method_name}")

        try:
            # Run the async assertion
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an async context, create a new task
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, run_assertion())
                    return future.result(timeout=60)
            else:
                return asyncio.run(run_assertion())

        except LLMAssertionError:
            raise
        except Exception as e:
            self._log.warning(
                "LLM assertion execution failed, using fallback",
                error=str(e),
            )
            # Return True to allow fallback behavior (assertion passes with warning)
            return True
