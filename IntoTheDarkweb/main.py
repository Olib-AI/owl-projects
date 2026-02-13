"""
Into The Darkweb - Tor & Onion Access via Owl Browser

Apify actor providing two modes of access to the Tor network:
- Easy Access: One-shot page fetch returning HTML content.
- Browser Experience: Full interactive session with sequential browser actions.

Environment Variables (set via Apify actor settings):
    OWL_BROWSER_US_URL:   Owl Browser US region endpoint URL
    OWL_BROWSER_US_TOKEN: Owl Browser US region API token
    OWL_BROWSER_EU_URL:   Owl Browser EU region endpoint URL
    OWL_BROWSER_EU_TOKEN: Owl Browser EU region API token
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
from datetime import datetime, timezone
from typing import Any
import random

from apify import Actor
from owl_browser import OwlBrowser, RemoteConfig

logger = logging.getLogger("into-the-darkweb")

# ---------------------------------------------------------------------------
# Valid actions for Browser Experience mode and their required/optional params
# ---------------------------------------------------------------------------
VALID_ACTIONS: dict[str, dict[str, list[str]]] = {
    "navigate": {"required": ["url"], "optional": ["wait_until", "timeout"]},
    "reload": {"required": [], "optional": ["wait_until", "timeout"]},
    "go_back": {"required": [], "optional": ["wait_until", "timeout"]},
    "go_forward": {"required": [], "optional": ["wait_until", "timeout"]},
    "click": {"required": ["selector"], "optional": []},
    "type": {"required": ["selector", "text"], "optional": []},
    "pick": {"required": ["selector", "value"], "optional": []},
    "submit_form": {"required": [], "optional": ["selector"]},
    "extract_text": {"required": [], "optional": ["selector"]},
    "screenshot": {"required": [], "optional": []},
    "get_html": {"required": [], "optional": []},
    "scroll_by": {"required": [], "optional": ["x", "y"]},
    "scroll_to_element": {"required": ["selector"], "optional": []},
    "scroll_to_top": {"required": [], "optional": []},
    "scroll_to_bottom": {"required": [], "optional": []},
    "wait_for_selector": {"required": ["selector"], "optional": ["timeout"]},
    "wait_for_text": {"required": ["text"], "optional": ["selector", "timeout"]},
    "get_page_info": {"required": [], "optional": []},
    "get_cookies": {"required": [], "optional": []},
    "set_cookie": {"required": ["name", "value"], "optional": ["domain", "path"]},
    "delete_cookies": {"required": [], "optional": []},
    "evaluate": {"required": ["script"], "optional": []},
    "save_content": {"required": ["key"], "optional": ["value"]},
}


GLOBAL_OPTIONAL_PARAMS = {
    "retries",
    "retry_delay",
    "on_error",
    "if_selector",
    "pre_delay",
    "post_delay",
}


def get_browser_config(region: str) -> RemoteConfig:
    """Build Owl Browser RemoteConfig for the selected region.

    Args:
        region: "US" or "EU".

    Returns:
        Configured RemoteConfig for the OwlBrowser connection.

    Raises:
        ValueError: If required environment variables are missing.
    """
    if region == "EU":
        url = os.environ.get("OWL_BROWSER_EU_URL", "")
        token = os.environ.get("OWL_BROWSER_EU_TOKEN", "")
    else:
        url = os.environ.get("OWL_BROWSER_US_URL", "")
        token = os.environ.get("OWL_BROWSER_US_TOKEN", "")

    if not url or not token:
        raise ValueError(
            f"Missing Owl Browser configuration for region {region}. "
            f"Ensure OWL_BROWSER_{region}_URL and OWL_BROWSER_{region}_TOKEN "
            f"environment variables are set in actor settings."
        )

    return RemoteConfig(url=url, token=token, api_prefix="")


def _utc_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _extract_screenshot_bytes(result: Any) -> bytes | None:
    """Extract raw PNG bytes from a screenshot result.

    The SDK may return the screenshot as:
    - A base64-encoded string directly.
    - A dict with a 'data' or 'screenshot' or 'image' key containing base64.

    Returns:
        PNG bytes if extraction succeeds, None otherwise.
    """
    b64_data: str | None = None

    if isinstance(result, str):
        b64_data = result
    elif isinstance(result, dict):
        for key in ("data", "screenshot", "image", "base64"):
            if key in result and isinstance(result[key], str):
                b64_data = result[key]
                break

    if not b64_data:
        return None

    try:
        return base64.b64decode(b64_data)
    except Exception:
        logger.warning("Failed to decode base64 screenshot data")
        return None


def _calculate_delay(delay_config: int | list[int] | None) -> int:
    """Calculate delay in milliseconds from config.

    Args:
        delay_config: Either a fixed integer (ms) or a [min, max] list.

    Returns:
        Delay in milliseconds.
    """
    if not delay_config:
        return 0

    if isinstance(delay_config, list) and len(delay_config) == 2:
        return random.randint(delay_config[0], delay_config[1])

    if isinstance(delay_config, int):
        return delay_config

    return 0


def _validate_action(action_config: dict[str, Any], index: int) -> str | None:
    """Validate a single action config from the actions array.

    Args:
        action_config: The action dict from user input.
        index: Zero-based index in the actions array (for error messages).

    Returns:
        Error message string if validation fails, None if valid.
    """
    action_name = action_config.get("action")
    if not action_name or not isinstance(action_name, str):
        return f"Action at index {index} is missing the 'action' field."

    if action_name not in VALID_ACTIONS:
        return (
            f"Action '{action_name}' at index {index} is not recognized. "
            f"Valid actions: {', '.join(sorted(VALID_ACTIONS.keys()))}"
        )

    schema = VALID_ACTIONS[action_name]
    for param in schema["required"]:
        if param not in action_config:
            return (
                f"Action '{action_name}' at index {index} is missing "
                f"required parameter '{param}'."
            )

    return None


async def run_easy_access(browser: OwlBrowser, input_data: dict[str, Any]) -> dict[str, Any]:
    """Easy Access mode -- single page fetch via the browser_go tool.

    Args:
        browser: Connected OwlBrowser instance.
        input_data: Validated actor input.

    Returns:
        Result dict for the Apify dataset.
    """
    url: str = input_data["url"]

    params: dict[str, Any] = {"url": url, "use_tor": True}

    if os_val := input_data.get("os"):
        params["os"] = os_val

    # camelCase -> snake_case mapping for waitUntil
    if wait_until := input_data.get("waitUntil"):
        params["wait_until"] = wait_until

    if timeout := input_data.get("timeout"):
        params["timeout"] = int(timeout)

    output_format: str = input_data.get("outputFormat", "html")
    if output_format in ("html", "text", "markdown"):
        params["output"] = output_format

    # Charge for page fetch
    await Actor.charge(event_name="page-fetch")

    logger.info("Easy Access: fetching %s via Tor (output=%s)", url, output_format)
    result = await browser.execute("browser_go", **params)

    content: str
    if isinstance(result, str):
        content = result
    elif isinstance(result, dict):
        content = str(
            result.get("html")
            or result.get("text")
            or result.get("markdown")
            or result.get("content")
            or result.get("result")
            or result
        )
    else:
        content = str(result)

    return {
        "url": url,
        "content": content,
        "outputFormat": output_format,
        "status": "success",
        "region": input_data["region"],
        "timestamp": _utc_iso(),
    }


async def run_browser_experience(
    browser: OwlBrowser, input_data: dict[str, Any]
) -> dict[str, Any]:
    """Browser Experience mode -- interactive session with sequential actions.

    Creates a Tor-enabled browser context, executes each action from the user's
    actions array, collects results, and ensures the context is closed on exit.

    Args:
        browser: Connected OwlBrowser instance.
        input_data: Validated actor input.

    Returns:
        Result dict for the Apify dataset.
    """
    # Build context creation params with Tor proxy
    ctx_params: dict[str, Any] = {
        "proxy_type": "socks5h",
        "proxy_host": "127.0.0.1",
        "proxy_port": 9050,
        "is_tor": True,
        "tor_control_port": 9051,
    }

    if os_val := input_data.get("os"):
        ctx_params["os"] = os_val

    if tz_val := input_data.get("timezone"):
        ctx_params["timezone"] = tz_val

    # Charge for browser session
    await Actor.charge(event_name="browser-session")

    # Create browser context
    ctx_result = await browser.execute("browser_create_context", **ctx_params)

    context_id: str
    if isinstance(ctx_result, dict):
        context_id = ctx_result.get("context_id", ctx_result.get("contextId", ""))
    else:
        context_id = str(ctx_result)

    if not context_id:
        raise RuntimeError(
            "Failed to create browser context: no context_id returned from SDK."
        )

    logger.info("Created Tor browser context: %s", context_id)

    actions: list[dict[str, Any]] = input_data.get("actions", [])
    results: list[dict[str, Any]] = []
    screenshot_count = 0
    kvs = await Actor.open_key_value_store()

    try:
        for i, action_config in enumerate(actions):
            action_name: str = action_config["action"]

            # ---- Extract Control Parameters ----
            retries = int(action_config.get("retries", 0))
            retry_delay = int(action_config.get("retry_delay", 1000))
            on_error = action_config.get("on_error", "throw")  # throw, continue, break
            if_selector = action_config.get("if_selector")

            # Human-like delays
            pre_delay = action_config.get("pre_delay")
            post_delay = action_config.get("post_delay")

            # Validate extraction
            if on_error not in ("throw", "continue", "break"):
                logger.warning(
                    "Invalid on_error '%s' at step %d. Defaulting to 'throw'.",
                    on_error,
                    i + 1,
                )
                on_error = "throw"

            # ---- Conditional Execution ----
            if if_selector:
                logger.info("Checking condition: if_selector='%s'", if_selector)
                try:
                    exists = await browser.execute(
                        "browser_evaluate",
                        script=f"document.querySelector('{if_selector}') !== null",
                        context_id=context_id,
                    )
                    if not exists:
                        logger.info(
                            "Condition failed (element not found). Skipping step %d (%s).",
                            i + 1,
                            action_name,
                        )
                        results.append({
                            "step": i + 1,
                            "action": action_name,
                            "status": "skipped",
                            "reason": f"if_selector '{if_selector}' not found",
                        })
                        continue
                except Exception as cond_err:
                    logger.warning(
                        "Failed to evaluate if_selector at step %d: %s. Proceeding.",
                        i + 1,
                        cond_err,
                    )

            # ---- Pre-Delay ----
            if pre_delay:
                delay_ms = _calculate_delay(pre_delay)
                if delay_ms > 0:
                    logger.info("Pre-delay: sleeping %dms", delay_ms)
                    await asyncio.sleep(delay_ms / 1000)

            # ---- Build Action Params ----
            # Exclude control params so we don't send garbage to the SDK
            params: dict[str, Any] = {
                k: v
                for k, v in action_config.items()
                if k not in GLOBAL_OPTIONAL_PARAMS and k != "action"
            }
            params["context_id"] = context_id

            # Ensure integer types for timeout fields
            if "timeout" in params:
                params["timeout"] = int(params["timeout"])

            tool_name = f"browser_{action_name}"

            # ---- Execution with Retry ----
            attempt = 0
            max_attempts = retries + 1
            step_result: dict[str, Any] | None = None
            step_error: Exception | None = None

            start_time = datetime.now(timezone.utc)

            while attempt < max_attempts:
                attempt += 1
                try:
                    if action_name == "save_content":
                        # Local client-side action
                        key = params.get("key")
                        val = params.get("value")
                        if not key:
                            raise ValueError("save_content requires 'key'")
                        # If value not provided, use last result? Or explicit value.
                        # For simplicity, require explicit value or maybe use variable store later.
                        # For now, let's assume value is passed.
                        await kvs.set_value(key, val)
                        result = {"key": key, "size": len(str(val))}
                    else:
                        # Remote browser action
                        result = await browser.execute(tool_name, **params)

                    duration_ms = int(
                        (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                    )

                    step_result = {
                        "step": i + 1,
                        "action": action_name,
                        "status": "success",
                        "result": result,
                        "durationMs": duration_ms,
                        "attempts": attempt,
                    }

                    # Handle screenshot saving
                    if action_name == "screenshot" and result is not None:
                        png_bytes = _extract_screenshot_bytes(result)
                        if png_bytes:
                            screenshot_count += 1
                            key = f"screenshot_{screenshot_count}"
                            await kvs.set_value(key, png_bytes, content_type="image/png")
                            step_result["screenshotKey"] = key
                            step_result["result"] = {
                                "screenshotKey": key,
                                "sizeBytes": len(png_bytes),
                            }
                            logger.info(
                                "Screenshot saved: %s (%d bytes)", key, len(png_bytes)
                            )
                    
                    logger.info(
                        "Action %d/%d '%s' succeeded (attempt %d/%d)",
                        i + 1,
                        len(actions),
                        action_name,
                        attempt,
                        max_attempts,
                    )
                    results.append(step_result)
                    step_error = None
                    break  # Success, exit retry loop

                except Exception as e:
                    step_error = e
                    logger.warning(
                        "Action %d/%d '%s' failed (attempt %d/%d): %s",
                        i + 1,
                        len(actions),
                        action_name,
                        attempt,
                        max_attempts,
                        e,
                    )
                    if attempt < max_attempts:
                        await asyncio.sleep(retry_delay / 1000)

            # ---- Failure Handling ----
            if step_error:
                duration_ms = int(
                    (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                )
                results.append({
                    "step": i + 1,
                    "action": action_name,
                    "status": "error",
                    "error": str(step_error),
                    "durationMs": duration_ms,
                    "attempts": attempt,
                })

                if on_error == "throw":
                    raise step_error
                elif on_error == "break":
                    logger.info("on_error='break': stopping execution.")
                    break
                elif on_error == "continue":
                    logger.info("on_error='continue': proceeding to next step.")

            # ---- Post-Delay ----
            if not step_error and post_delay:
                delay_ms = _calculate_delay(post_delay)
                if delay_ms > 0:
                    logger.info("Post-delay: sleeping %dms", delay_ms)
                    await asyncio.sleep(delay_ms / 1000)

    finally:
        # Always close the context to free server resources
        try:
            await browser.execute("browser_close_context", context_id=context_id)
            logger.info("Closed browser context: %s", context_id)
        except Exception as close_err:
            logger.warning(
                "Failed to close context %s: %s", context_id, close_err
            )

    failed_count = sum(1 for r in results if r["status"] == "error")
    total_count = len(results)

    if failed_count == 0:
        overall_status = "success"
    elif failed_count < total_count:
        overall_status = "partial"
    else:
        overall_status = "error"

    return {
        "status": overall_status,
        "region": input_data["region"],
        "contextId": context_id,
        "actionsTotal": len(actions),
        "actionsSucceeded": total_count - failed_count,
        "actionsFailed": failed_count,
        "results": results,
        "timestamp": _utc_iso(),
    }


async def apify_main() -> None:
    """Apify actor entry point.

    Reads input, validates parameters, connects to Owl Browser,
    and dispatches to the appropriate mode handler.
    """
    async with Actor:
        input_data: dict[str, Any] = await Actor.get_input() or {}

        mode: str = input_data.get("mode", "easy")
        region: str = input_data.get("region", "US").upper()

        # ---- Input validation ----
        if mode not in ("easy", "browser"):
            await Actor.fail(
                status_message=f"Invalid mode '{mode}'. Must be 'easy' or 'browser'."
            )
            return

        if region not in ("US", "EU"):
            await Actor.fail(
                status_message=f"Invalid region '{region}'. Must be 'US' or 'EU'."
            )
            return

        if mode == "easy" and not input_data.get("url"):
            await Actor.fail(
                status_message="URL is required for Easy Access mode. "
                "Provide a 'url' field in the input."
            )
            return

        if mode == "browser":
            actions = input_data.get("actions")
            if not actions or not isinstance(actions, list) or len(actions) == 0:
                await Actor.fail(
                    status_message="Actions array is required for Browser Experience mode. "
                    "Provide a non-empty 'actions' array in the input."
                )
                return

            # Validate each action before starting the browser session
            for idx, action_cfg in enumerate(actions):
                if not isinstance(action_cfg, dict):
                    await Actor.fail(
                        status_message=f"Action at index {idx} must be a JSON object."
                    )
                    return
                validation_error = _validate_action(action_cfg, idx)
                if validation_error:
                    await Actor.fail(status_message=validation_error)
                    return

        # ---- Build browser config ----
        try:
            config = get_browser_config(region)
        except ValueError as config_err:
            await Actor.fail(status_message=str(config_err))
            return

        logger.info(
            "Starting actor: mode=%s, region=%s", mode, region
        )

        # ---- Execute ----
        try:
            async with OwlBrowser(config) as browser:
                if mode == "easy":
                    result = await run_easy_access(browser, input_data)
                else:
                    result = await run_browser_experience(browser, input_data)

                await Actor.push_data(result)
                logger.info("Actor completed. Status: %s", result.get("status"))

        except Exception as runtime_err:
            logger.error("Actor execution failed: %s", runtime_err, exc_info=True)
            error_result: dict[str, Any] = {
                "status": "error",
                "error": str(runtime_err),
                "mode": mode,
                "region": region,
                "timestamp": _utc_iso(),
            }
            await Actor.push_data(error_result)
            await Actor.fail(status_message=f"Actor failed: {runtime_err}")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    asyncio.run(apify_main())
