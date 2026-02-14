"""Core stress test runner - executes flows concurrently using Owl Browser SDK v2."""

import asyncio
import time
import logging

from owl_browser import OwlBrowser, RemoteConfig, FlowExecutor
from owl_browser import FlowResult as SdkFlowResult, Flow as SdkFlow

from .config import StressConfig
from .flow_loader import load_flow, validate_flow
from .metrics import (
    StepResult, FlowResult, BatchResult, StressTestResult,
)

logger = logging.getLogger("owl_stress")


def _convert_sdk_result(
    sdk_result: SdkFlowResult,
    flow_id: int,
    batch_size: int,
    context_id: str,
) -> FlowResult:
    """Convert SDK FlowResult to our metrics FlowResult."""
    steps = []
    for s in sdk_result.steps:
        steps.append(StepResult(
            step_index=s.step_index,
            tool_name=s.tool_name,
            success=s.success,
            duration_ms=s.duration_ms,
            error=s.error or "",
        ))

    return FlowResult(
        flow_id=flow_id,
        batch_size=batch_size,
        success=sdk_result.success,
        total_duration_ms=sdk_result.total_duration_ms,
        steps=steps,
        error=sdk_result.error or "",
        context_id=context_id,
    )


async def _execute_single_flow(
    browser: OwlBrowser,
    sdk_flow: SdkFlow,
    flow_id: int,
    batch_size: int,
) -> FlowResult:
    """Execute a single flow in its own isolated browser context."""
    context_id = ""

    try:
        # Create isolated browser context with unique fingerprint
        ctx = await browser.create_context()
        context_id = ctx["context_id"]

        # Use the SDK's FlowExecutor which handles variable resolution,
        # expectations, conditional branching, and context_id injection
        executor = FlowExecutor(browser, context_id)
        sdk_result = await executor.execute(sdk_flow)

        return _convert_sdk_result(sdk_result, flow_id, batch_size, context_id)

    except Exception as e:
        return FlowResult(
            flow_id=flow_id,
            batch_size=batch_size,
            success=False,
            total_duration_ms=0,
            error=f"Flow execution error: {e}",
            context_id=context_id,
        )
    finally:
        if context_id:
            try:
                await browser.close_context(context_id=context_id)
            except Exception:
                pass


async def run_batch(
    browser: OwlBrowser,
    sdk_flow: SdkFlow,
    batch_size: int,
    config: StressConfig,
) -> BatchResult:
    """Run a batch of concurrent flows."""
    batch = BatchResult(batch_size=batch_size)
    batch.start_time = time.monotonic()

    logger.info(f"Starting batch: {batch_size} concurrent flows")

    # Launch all flows concurrently with minimal stagger.
    # The SDK's built-in semaphore (max_concurrent) and connection pool
    # handle throttling — stagger only prevents burst of context creation.
    tasks = []
    for i in range(batch_size):
        task = asyncio.create_task(
            _execute_single_flow(browser, sdk_flow, flow_id=i, batch_size=batch_size)
        )
        tasks.append(task)
        if config.cooldown_between_flows > 0 and i < batch_size - 1:
            await asyncio.sleep(config.cooldown_between_flows)

    logger.info(f"All {batch_size} flows launched, waiting for completion...")

    # Wait for all flows to complete
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            batch.flow_results.append(FlowResult(
                flow_id=i, batch_size=batch_size,
                success=False, total_duration_ms=0,
                error=str(result),
            ))
        else:
            batch.flow_results.append(result)

    batch.end_time = time.monotonic()

    logger.info(
        f"Batch {batch_size} complete: {batch.successful_flows}/{batch.total_flows} succeeded "
        f"({batch.success_rate:.1f}%) in {batch.wall_time_ms:.0f}ms"
    )

    return batch


async def run_stress_test(config: StressConfig) -> StressTestResult:
    """Execute a full stress test across all batch sizes."""
    # Load and validate via our loader (for warnings)
    flow = load_flow(config.flow_path)
    warnings = validate_flow(flow)
    for w in warnings:
        logger.warning(f"Flow validation: {w}")

    # Load via SDK for execution
    sdk_flow = FlowExecutor.load_flow(config.flow_path)

    remote_config = RemoteConfig(
        url=config.owl_endpoint,
        token=config.owl_token,
        max_concurrent=config.max_concurrent,
    )

    result = StressTestResult(
        target_name=config.target_name,
        target_url=config.target_url,
        flow_name=flow.name,
    )
    result.start_time = time.monotonic()

    logger.info(f"Starting stress test: {config.target_name}")
    logger.info(f"Flow: {flow.name} ({flow.step_count} steps)")
    logger.info(f"Batch sizes: {config.batch_sizes}")

    async with OwlBrowser(remote_config) as browser:
        for batch_size in config.batch_sizes:
            batch_result = await run_batch(browser, sdk_flow, batch_size, config)
            result.batch_results.append(batch_result)

            # Cooldown between batches
            if batch_size != config.batch_sizes[-1]:
                logger.info(f"Cooling down {config.delay_between_batches}s before next batch...")
                await asyncio.sleep(config.delay_between_batches)

    result.end_time = time.monotonic()
    logger.info(
        f"Stress test complete: {result.total_flows_executed} flows, "
        f"{result.overall_success_rate:.1f}% success rate, "
        f"{result.total_wall_time_s:.1f}s total"
    )

    return result
