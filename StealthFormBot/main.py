"""
StealthFormBot - Enterprise Form Submission with Anti-Detection

Apify Actor for robust form automation that works with ANY form type.

This actor integrates with the Apify platform using the official Apify SDK,
providing proper input handling, dataset storage, and key-value store support.

Usage:
    # On Apify platform:
    apify run

    # Local testing:
    python main.py

Environment Variables:
    OWL_BROWSER_URL: Remote browser URL (default: http://localhost:8080)
    OWL_BROWSER_TOKEN: Authentication token for browser
    APIFY_TOKEN: Apify API token (set automatically on Apify platform)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Add parent directory to path for SDK import (local development)
SDK_PATH = Path(__file__).parent.parent / "python-sdk"
if SDK_PATH.exists():
    sys.path.insert(0, str(SDK_PATH))

from dotenv import load_dotenv

# Load environment variables from .env file (local development)
env_file = Path(__file__).parent.parent / ".env"
if env_file.exists():
    load_dotenv(env_file)

# Apify SDK imports
from apify import Actor

from owl_browser import (
    Browser,
    RemoteConfig,
    ProxyConfig as OwlProxyConfig,
    ProxyType,
    DialogType,
    DialogAction,
)

from models import (
    ActorInput,
    ActorOutput,
    ApifyProxyConfig,
    FormField,
    FormStep,
    FormSubmissionStatus,
    FieldType,
    LoginConfig,
    ProxyConfig,
    RetryConfig,
    WaitCondition,
)
from form_handler import FormHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def get_browser_config(input_data: dict[str, Any] | None = None) -> tuple[str, str]:
    """
    Get browser URL and token from input or environment.

    Args:
        input_data: Optional input data that may contain browser config

    Returns:
        Tuple of (browser_url, browser_token)
    """
    # Check input first, then fall back to environment variables
    if input_data:
        url = input_data.get("owlBrowserUrl") or os.environ.get("OWL_BROWSER_URL", "http://localhost:8080")
        token = input_data.get("owlBrowserToken") or os.environ.get("OWL_BROWSER_TOKEN", "")
    else:
        url = os.environ.get("OWL_BROWSER_URL", "http://localhost:8080")
        token = os.environ.get("OWL_BROWSER_TOKEN", "")

    if not token:
        logger.warning("OWL_BROWSER_TOKEN not set - browser may reject connection")

    return url, token


def parse_input(input_data: dict[str, Any]) -> ActorInput:
    """
    Parse raw input JSON into ActorInput.
    
    Args:
        input_data: Raw JSON input from Apify
        
    Returns:
        Parsed ActorInput
    """
    # Parse field configs
    field_configs = []
    for fc in input_data.get("fieldConfigs", []):
        field_configs.append(FormField(
            selector=fc["selector"],
            value=fc["value"],
            field_type=FieldType(fc.get("fieldType", "text")),
            wait_before=fc.get("waitBefore", 0),
            clear_first=fc.get("clearFirst", True),
            required=fc.get("required", True),
            retry_count=fc.get("retryCount", 2),
            file_paths=fc.get("filePaths", []),
            custom_handler=fc.get("customHandler"),
        ))
    
    # Parse steps
    steps = []
    for step in input_data.get("steps", []):
        step_fields = []
        for fc in step.get("fields", []):
            step_fields.append(FormField(
                selector=fc["selector"],
                value=fc["value"],
                field_type=FieldType(fc.get("fieldType", "text")),
                wait_before=fc.get("waitBefore", 0),
                clear_first=fc.get("clearFirst", True),
                required=fc.get("required", True),
                retry_count=fc.get("retryCount", 2),
            ))
        
        steps.append(FormStep(
            name=step["name"],
            fields=step_fields,
            next_selector=step.get("nextSelector"),
            wait_condition=WaitCondition(step.get("waitCondition", "networkidle")),
            wait_selector=step.get("waitSelector"),
            wait_url_pattern=step.get("waitUrlPattern"),
            wait_timeout=step.get("waitTimeout", 10000),
            pre_actions=step.get("preActions", []),
            post_actions=step.get("postActions", []),
        ))
    
    # Parse login config
    login = None
    if login_data := input_data.get("login"):
        login = LoginConfig(
            url=login_data["url"],
            username_selector=login_data["usernameSelector"],
            password_selector=login_data["passwordSelector"],
            username=login_data["username"],
            password=login_data["password"],
            submit_selector=login_data.get("submitSelector", "button[type='submit']"),
            success_indicator=login_data.get("successIndicator"),
            wait_timeout=login_data.get("waitTimeout", 15000),
        )
    
    # Parse custom proxy config
    proxy = None
    if proxy_data := input_data.get("proxy"):
        proxy = ProxyConfig(
            type=proxy_data["type"],
            host=proxy_data["host"],
            port=proxy_data["port"],
            username=proxy_data.get("username"),
            password=proxy_data.get("password"),
            timezone_override=proxy_data.get("timezoneOverride"),
            language_override=proxy_data.get("languageOverride"),
        )

    # Parse Apify proxy config
    use_apify_proxy = input_data.get("useApifyProxy", False)
    apify_proxy = None
    if use_apify_proxy:
        apify_proxy = ApifyProxyConfig(
            groups=input_data.get("apifyProxyGroups", []),
            country_code=input_data.get("apifyProxyCountry"),
            session_id=input_data.get("apifyProxySessionId"),
        )
    
    # Parse retry config
    retry_data = input_data.get("retry", {})
    retry = RetryConfig(
        max_retries=retry_data.get("maxRetries", 3),
        retry_delay=retry_data.get("retryDelay", 1000),
        exponential_backoff=retry_data.get("exponentialBackoff", True),
        retry_on=retry_data.get("retryOn", ["timeout", "element_not_found"]),
    )
    
    return ActorInput(
        target_url=input_data["targetUrl"],
        form_data=input_data.get("formData", {}),
        field_configs=field_configs,
        steps=steps,
        submit_selector=input_data.get("submitSelector"),
        login=login,
        file_uploads=[],  # TODO: Parse file uploads
        proxy=proxy,
        use_apify_proxy=use_apify_proxy,
        apify_proxy=apify_proxy,
        profile_path=input_data.get("profilePath"),
        retry=retry,
        navigation_timeout=input_data.get("navigationTimeout", 30000),
        field_timeout=input_data.get("fieldTimeout", 5000),
        screenshot_before_submit=input_data.get("screenshotBeforeSubmit", True),
        screenshot_after_submit=input_data.get("screenshotAfterSubmit", True),
        screenshot_on_error=input_data.get("screenshotOnError", True),
        auto_accept_alerts=input_data.get("autoAcceptAlerts", True),
        auto_accept_confirms=input_data.get("autoAcceptConfirms", True),
        success_indicator=input_data.get("successIndicator"),
        success_url_pattern=input_data.get("successUrlPattern"),
        verbose=input_data.get("verbose", False),
    )


def parse_apify_proxy_url(proxy_url: str) -> OwlProxyConfig:
    """
    Parse Apify proxy URL into OwlProxyConfig.

    Apify proxy URLs follow the format:
    http://username:password@proxy.apify.com:8000

    Args:
        proxy_url: Full proxy URL from Apify

    Returns:
        OwlProxyConfig configured for the Apify proxy
    """
    from urllib.parse import urlparse

    parsed = urlparse(proxy_url)

    # Use minimal proxy config for compatibility with OwlBrowser trial
    # Advanced features like block_webrtc may not be available on all tiers
    return OwlProxyConfig(
        type=ProxyType.HTTP,
        host=parsed.hostname or "proxy.apify.com",
        port=parsed.port or 8000,
        username=parsed.username,
        password=parsed.password,
        stealth=True,
        block_webrtc=False,  # Not supported on trial tier
        spoof_timezone=False,  # Not supported on trial tier
        spoof_language=False,  # Not supported on trial tier
    )


def run_actor(
    input_data: dict[str, Any],
    apify_proxy_url: str | None = None,
) -> dict[str, Any]:
    """
    Main actor entry point.

    Args:
        input_data: Raw JSON input
        apify_proxy_url: Pre-resolved Apify proxy URL (from async context)

    Returns:
        Output as dict
    """
    # Parse input
    config = parse_input(input_data)

    if config.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info(f"StealthFormBot starting - Target: {config.target_url}")

    # Get browser configuration
    browser_url, browser_token = get_browser_config(input_data)
    logger.info(f"Connecting to browser at {browser_url}")

    # Configure remote connection
    remote_config = RemoteConfig(
        url=browser_url,
        token=browser_token,
        timeout=config.navigation_timeout * 2,  # Allow extra time
    )

    # Build proxy config - priority: Apify proxy > Custom proxy > No proxy
    owl_proxy: OwlProxyConfig | None = None

    if apify_proxy_url:
        # Use Apify proxy (resolved from async context)
        logger.info("Using Apify proxy service")
        owl_proxy = parse_apify_proxy_url(apify_proxy_url)
    elif config.proxy:
        # Use custom proxy
        logger.info(f"Using custom proxy: {config.proxy.host}:{config.proxy.port}")
        proxy_type_map = {
            "http": ProxyType.HTTP,
            "https": ProxyType.HTTPS,
            "socks5": ProxyType.SOCKS5,
            "socks5h": ProxyType.SOCKS5H,
        }
        # Use minimal proxy config for compatibility with OwlBrowser trial
        owl_proxy = OwlProxyConfig(
            type=proxy_type_map.get(config.proxy.type, ProxyType.HTTP),
            host=config.proxy.host,
            port=config.proxy.port,
            username=config.proxy.username,
            password=config.proxy.password,
            stealth=True,
            block_webrtc=False,  # Not supported on trial tier
            spoof_timezone=False,  # Not supported on trial tier
            spoof_language=False,  # Not supported on trial tier
            timezone_override=config.proxy.timezone_override,
            language_override=config.proxy.language_override,
        )
    else:
        logger.info("No proxy configured")
    
    # Execute with browser
    output: ActorOutput
    try:
        with Browser(remote=remote_config, verbose=config.verbose) as browser:
            logger.info(f"Browser connected in {browser.mode} mode")
            
            # Create page with proxy and profile if configured
            page = browser.new_page(
                proxy=owl_proxy,
                profile_path=config.profile_path,
            )
            
            try:
                # Create and run form handler
                handler = FormHandler(page, config)
                output = handler.execute()
                
            finally:
                # Always close page
                page.close()
                
    except Exception as e:
        logger.error(f"Browser error: {e}")
        output = ActorOutput(
            success=False,
            status=FormSubmissionStatus.FAILED,
            target_url=config.target_url,
            errors=[f"Browser error: {e}"],
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
    
    # Convert output to dict
    result = asdict(output)
    
    # Log summary
    logger.info(f"StealthFormBot completed - Success: {output.success}, Status: {output.status.value}")
    if output.errors:
        for error in output.errors:
            logger.error(f"  Error: {error}")
    
    return result


async def apify_main() -> None:
    """
    Main entry point for Apify platform.

    Uses the Apify SDK to:
    - Get input from the Apify platform
    - Configure Apify proxy if requested
    - Store results in the default dataset
    - Save screenshots to key-value store
    """
    async with Actor:
        # Get input from Apify platform
        actor_input = await Actor.get_input() or {}

        logger.info("=" * 60)
        logger.info("StealthFormBot - Apify Actor")
        logger.info("=" * 60)

        # Validate required input
        if not actor_input.get("targetUrl"):
            await Actor.fail(status_message="Missing required input: targetUrl")
            return

        # Resolve Apify proxy URL if enabled
        apify_proxy_url: str | None = None
        if actor_input.get("useApifyProxy"):
            try:
                proxy_groups = actor_input.get("apifyProxyGroups", [])
                country_code = actor_input.get("apifyProxyCountry")
                session_id = actor_input.get("apifyProxySessionId")

                # Generate a session ID if not provided to ensure consistent IP
                # Session IDs must be max 50 chars, alphanumeric with underscore, dot, tilde
                if not session_id:
                    session_id = f"stealthformbot_{secrets.token_hex(8)}"

                logger.info(
                    f"Configuring Apify proxy - Groups: {proxy_groups or 'default'}, "
                    f"Country: {country_code or 'any'}, Session: {session_id}"
                )

                proxy_config = await Actor.create_proxy_configuration(
                    groups=proxy_groups if proxy_groups else None,
                    country_code=country_code,
                )

                if proxy_config:
                    # Use session_id for proxy session persistence (same IP across requests)
                    apify_proxy_url = await proxy_config.new_url(session_id=session_id)
                    logger.info(f"Apify proxy URL obtained: {apify_proxy_url[:50]}...")
                else:
                    logger.warning("Failed to create Apify proxy configuration")

            except Exception as e:
                logger.error(f"Error configuring Apify proxy: {e}")
                # Continue without proxy rather than failing

        # Run the form submission
        result = run_actor(actor_input, apify_proxy_url=apify_proxy_url)

        # Store result in the default dataset
        await Actor.push_data(result)

        # Save screenshots to key-value store if present
        kvs = await Actor.open_key_value_store()

        if result.get("screenshot_before"):
            screenshot_path = Path(result["screenshot_before"])
            if screenshot_path.exists():
                await kvs.set_value(
                    "screenshot_before",
                    screenshot_path.read_bytes(),
                    content_type="image/png",
                )

        if result.get("screenshot_after"):
            screenshot_path = Path(result["screenshot_after"])
            if screenshot_path.exists():
                await kvs.set_value(
                    "screenshot_after",
                    screenshot_path.read_bytes(),
                    content_type="image/png",
                )

        if result.get("screenshot_error"):
            screenshot_path = Path(result["screenshot_error"])
            if screenshot_path.exists():
                await kvs.set_value(
                    "screenshot_error",
                    screenshot_path.read_bytes(),
                    content_type="image/png",
                )

        # Set exit status based on result
        if result.get("success"):
            logger.info("Form submission completed successfully")
        else:
            logger.warning(f"Form submission failed: {result.get('status')}")
            # Don't fail the actor, just log - the result is still useful


def main_local() -> None:
    """Local testing entry point (not using Apify platform)."""
    # Test input - simple contact form
    test_input = {
        "targetUrl": "https://httpbin.org/forms/post",
        "formData": {
            "custname": "John Doe",
            "custtel": "+1-555-0123",
            "custemail": "john.doe@example.com",
            "size": "medium",
            "topping": "bacon",
            "comments": "This is a test submission from StealthFormBot.",
        },
        "submitSelector": "button[type='submit']",
        "screenshotBeforeSubmit": True,
        "screenshotAfterSubmit": True,
        "verbose": True,
    }

    logger.info("=" * 60)
    logger.info("StealthFormBot Test Run (Local)")
    logger.info("=" * 60)

    # Run actor
    result = run_actor(test_input)

    # Pretty print result
    print("\n" + "=" * 60)
    print("RESULT:")
    print("=" * 60)
    print(json.dumps(result, indent=2, default=str))


def main() -> None:
    """
    Main entry point - detects environment and runs appropriately.

    On Apify platform: Uses Actor.main() pattern
    Locally: Runs test configuration
    """
    # Check if running on Apify platform
    if os.environ.get("APIFY_IS_AT_HOME") or os.environ.get("APIFY_TOKEN"):
        # Running on Apify platform - use async main
        asyncio.run(apify_main())
    else:
        # Local development - use sync test mode
        main_local()


if __name__ == "__main__":
    main()
