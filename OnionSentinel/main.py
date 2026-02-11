"""
OnionSentinel - Automated Dark Web Threat Intelligence Monitor

Monitor .onion sites for keywords, leaks, and threats using Owl Browser.
Features:
- TOR connectivity with circuit isolation per target.
- Concurrent monitoring of multiple targets.
- Keyword-based threat detection.
- Visual evidence capture (Screenshots/Video).
- Multi-region support (US/EU).
"""

import asyncio
import base64
import logging
import os
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List

from apify import Actor
from owl_browser import OwlBrowser, RemoteConfig

logger = logging.getLogger("onion-sentinel")

def get_browser_config(region: str) -> RemoteConfig:
    """Build Owl Browser RemoteConfig for the selected region."""
    region = region.upper()
    if region == "EU":
        url = os.environ.get("OWL_BROWSER_EU_URL", "")
        token = os.environ.get("OWL_BROWSER_EU_TOKEN", "")
    else:
        url = os.environ.get("OWL_BROWSER_US_URL", "")
        token = os.environ.get("OWL_BROWSER_US_TOKEN", "")

    if not url or not token:
        raise ValueError(
            f"Missing Owl Browser configuration for region {region}. "
            f"Ensure OWL_BROWSER_{region}_URL and OWL_BROWSER_{region}_TOKEN are set."
        )

    return RemoteConfig(url=url, token=token, api_prefix="")

def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _extract_screenshot_bytes(result: Any) -> bytes | None:
    """Extract raw PNG bytes from a screenshot result."""
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

async def process_target(
    browser: OwlBrowser, 
    target: Dict[str, Any], 
    keywords: List[str], 
    input_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Process a single monitoring target."""
    url = target.get("url")
    label = target.get("label", url)
    target_type = target.get("type", "generic")
    
    logger.info("Processing target: %s (%s)", label, url)
    
    # Context params for TOR access
    ctx_params = {
        "proxy_type": "socks5h",
        "proxy_host": "127.0.0.1",
        "proxy_port": 9050,
        "is_tor": True,
        "proxy_stealth": input_data.get("proxyStealth", True),
        "tor_control_port": 9051,
    }
    
    if os_val := input_data.get("os"):
        ctx_params["os"] = os_val

    # Create isolated TOR context
    ctx_result = await browser.execute("browser_create_context", **ctx_params)
    context_id = ctx_result.get("context_id") if isinstance(ctx_result, dict) else str(ctx_result)
    
    findings = []
    processed_pages = 0
    max_pages = input_data.get("maxPagesPerTarget", 10)
    
    try:
        # 1. Start session video if requested
        if input_data.get("saveVideo"):
            await browser.execute("browser_start_video_recording", context_id=context_id)

        # 2. Navigate to root
        nav_result = await browser.execute("browser_navigate", context_id=context_id, url=url, wait_until="load")
        if isinstance(nav_result, dict) and not nav_result.get("success", True):
            error_msg = nav_result.get("message", "Navigation failed")
            logger.warning("Failed to navigate to %s: %s", url, error_msg)
            return {"url": url, "error": error_msg, "status": "error"}
        
        # 3. Content extraction (using raw HTML and cleaning)
        logger.info("Extracting content from %s", url)
        html_result = await browser.execute("browser_get_html", context_id=context_id, clean_level="basic")
        html_content = html_result if isinstance(html_result, str) else html_result.get("html", "") if isinstance(html_result, dict) else ""
        
        # Strip HTML tags for keyword matching
        clean_content = re.sub(r'<[^>]+>', ' ', html_content)
        content = clean_content

        found_keywords = [k for k in keywords if k.lower() in content.lower()]
        if found_keywords:
            logger.info("Match found on %s: %s", url, found_keywords)
            
            finding = {
                "url": url,
                "keywords": found_keywords,
                "timestamp": _utc_iso(),
                "snippet": content[:1000] + "..." if len(content) > 1000 else content
            }
            
            # Take screenshot of findings if requested
            if input_data.get("saveScreenshots"):
                ss_result = await browser.execute("browser_screenshot", context_id=context_id, mode="fullpage")
                
                png_bytes = _extract_screenshot_bytes(ss_result)
                if png_bytes:
                    kvs = await Actor.open_key_value_store()
                    ss_key = f"ss_{context_id}_{processed_pages}"
                    await kvs.set_value(ss_key, png_bytes, content_type="image/png")
                    finding["screenshotKey"] = ss_key

            findings.append(finding)
        
        processed_pages = 1

        # 4. Stop video and get URL if requested
        if input_data.get("saveVideo"):
            await browser.execute("browser_stop_video_recording", context_id=context_id)
            video_info = await browser.execute("browser_download_video_recording", context_id=context_id)
            if isinstance(video_info, dict) and "url" in video_info:
                findings_summary = {
                    "target_label": label,
                    "target_url": url,
                    "video_url": video_info["url"],
                    "timestamp": _utc_iso(),
                    "findings_count": len(findings)
                }
                # We could also download the video and save to KVS, but for now we provide the URL
                logger.info("Video available at: %s", video_info["url"])
                # Add video info to the result
                results_extra = {"videoUrl": video_info["url"]}
            else:
                results_extra = {}
        else:
            results_extra = {}

    except Exception as e:
        logger.error("Error processing %s: %s", label, e)
        return {"url": url, "error": str(e), "status": "error"}
    finally:
        await browser.execute("browser_close_context", context_id=context_id)

    res = {
        "url": url,
        "label": label,
        "type": target_type,
        "findings": findings,
        "findingsCount": len(findings),
        "pagesProcessed": processed_pages,
        "status": "success",
        "timestamp": _utc_iso()
    }
    res.update(results_extra)
    return res

async def process_uptime_target(
    browser: OwlBrowser, 
    target: Dict[str, Any], 
    input_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Check if a single .onion target is online."""
    url = target.get("url")
    label = target.get("label", url)
    
    logger.info("Checking uptime for: %s", url)
    
    ctx_params = {
        "proxy_type": "socks5h",
        "proxy_host": "127.0.0.1",
        "proxy_port": 9050,
        "is_tor": True,
        "tor_control_port": 9051,
    }
    
    if os_val := input_data.get("os"):
        ctx_params["os"] = os_val

    # Create isolated TOR context
    ctx_result = await browser.execute("browser_create_context", **ctx_params)
    context_id = ctx_result.get("context_id") if isinstance(ctx_result, dict) else str(ctx_result)
    
    try:
        start_time = datetime.now(timezone.utc)
        # Navigate and wait for load
        nav_result = await browser.execute("browser_navigate", context_id=context_id, url=url, wait_until="load", timeout=60000)
        end_time = datetime.now(timezone.utc)
        
        # Check if navigation actually succeeded
        if isinstance(nav_result, dict) and not nav_result.get("success", True):
            logger.warning("Target %s is offline: %s", url, nav_result.get("message"))
            return {
                "url": url,
                "label": label,
                "status": "offline",
                "error": nav_result.get("message", "Navigation failed"),
                "timestamp": _utc_iso()
            }

        return {
            "url": url,
            "label": label,
            "status": "online",
            "responseTime": (end_time - start_time).total_seconds(),
            "timestamp": _utc_iso()
        }
    except Exception as e:
        logger.warning("Target %s is offline or failed to load: %s", url, e)
        return {
            "url": url,
            "label": label,
            "status": "offline",
            "error": str(e),
            "timestamp": _utc_iso()
        }
    finally:
        await browser.execute("browser_close_context", context_id=context_id)

async def run_discovery(browser: OwlBrowser, query: str, input_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Discover new .onion sites using Ahmia step-by-step process."""
    ahmia_base = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
    all_discovered = []
    
    # Context params for TOR access
    ctx_params = {
        "proxy_type": "socks5h",
        "proxy_host": "127.0.0.1",
        "proxy_port": 9050,
        "is_tor": True,
        "tor_control_port": 9051,
        "resource_blocking": False,
    }
    
    ctx_result = await browser.execute("browser_create_context", **ctx_params)
    context_id = ctx_result.get("context_id") if isinstance(ctx_result, dict) else str(ctx_result)
    
    try:
        # Step 1: Visit Ahmia root to get hidden token
        logger.info("Visiting Ahmia root to obtain search tokens")
        await browser.execute("browser_navigate", context_id=context_id, url=ahmia_base, wait_until="networkidle")
        
        # Get minimal HTML to find hidden inputs
        html_res = await browser.execute("browser_get_html", context_id=context_id, clean_level="minimal")
        html_content = html_res if isinstance(html_res, str) else html_res.get("html", "")
        
        # Regex to find <input type="hidden" name="XXXX" value="YYYY">
        hidden_match = re.search(r'<input type="hidden" name="([^"]+)" value="([^"]+)">', html_content)
        
        if not hidden_match:
            logger.error("Could not find hidden search token on Ahmia")
            return []
            
        token_name = hidden_match.group(1)
        token_value = hidden_match.group(2)
        logger.info("Found token: %s=%s", token_name, token_value)
        
        # Step 2: Construct search URL and navigate
        encoded_query = urllib.parse.quote(query)
        search_url = f"{ahmia_base}/search/?q={encoded_query}&{token_name}={token_value}"
        
        logger.info("Searching Ahmia for '%s'", query)
        await browser.execute("browser_navigate", context_id=context_id, url=search_url, wait_until="networkidle")
        
        # Get HTML of results
        results_res = await browser.execute("browser_get_html", context_id=context_id, clean_level="minimal")
        results_html = results_res if isinstance(results_res, str) else results_res.get("html", "")
        
        # Step 3: Parse results using regex
        # Results are in <li class="result"> blocks
        result_blocks = re.findall(r'<li class="result">.*?</li>', results_html, re.DOTALL)
        logger.info("Found %d raw result blocks", len(result_blocks))
        
        for block in result_blocks:
            # Extract onion domain from <cite>
            cite_match = re.search(r'<cite>([^<]+)</cite>', block)
            if not cite_match:
                continue
                
            onion_domain = cite_match.group(1).strip()
            url = f"http://{onion_domain}" if not onion_domain.startswith("http") else onion_domain
            
            # Extract title (look for the link in h4)
            title_match = re.search(r'<h4>.*?<a[^>]*>(.*?)</a>.*?</h4>', block, re.DOTALL)
            title = title_match.group(1).strip() if title_match else "No Title"
            # Clean HTML tags from title
            title = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', title)).strip()
            
            # Extract description (look for p tag)
            desc_match = re.search(r'<p>(.*?)</p>', block, re.DOTALL)
            description = desc_match.group(1).strip() if desc_match else "No Description"
            description = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', description)).strip()
            
            if url not in [d["url"] for d in all_discovered]:
                all_discovered.append({
                    "url": url,
                    "title": title,
                    "description": description,
                    "engine": "Ahmia"
                })
                    
    finally:
        await browser.execute("browser_close_context", context_id=context_id)
        
    return all_discovered

async def main():
    async with Actor:
        input_data = await Actor.get_input() or {}
        mode = input_data.get("mode", "monitoring")
        targets = input_data.get("targets", [])
        keywords = input_data.get("keywords", [])
        query = input_data.get("query", "")
        region = input_data.get("region", "US")
        concurrency = input_data.get("concurrency", 1)
        
        config = get_browser_config(region)
        
        async with OwlBrowser(config) as browser:
            logger.info("Starting OnionSentinel in %s mode (Region: %s)", mode, region)
            
            if mode == "discovery":
                if not query:
                    await Actor.fail("Query is required for discovery mode.")
                    return
                
                await Actor.charge(event_name="darkweb-discovery")
                discovered = await run_discovery(browser, query, input_data)
                
                # Push results as a single summary record or multiple items
                await Actor.push_data({
                    "mode": "discovery",
                    "query": query,
                    "discoveredCount": len(discovered),
                    "results": discovered,
                    "timestamp": _utc_iso()
                })
                
            elif mode == "uptime-check":
                if not targets:
                    await Actor.fail("No targets provided for uptime-check mode.")
                    return
                
                # Limit to max 10 targets for performance
                if len(targets) > 10:
                    logger.warning("Target list truncated to 10 URLs for performance.")
                    targets = targets[:10]
                
                semaphore = asyncio.Semaphore(concurrency)
                
                async def bounded_check(target):
                    async with semaphore:
                        # Charge for uptime event
                        await Actor.charge(event_name="darkweb-uptime")
                        return await process_uptime_target(browser, target, input_data)

                tasks = [bounded_check(t) for t in targets]
                results = await asyncio.gather(*tasks)
                
                for result in results:
                    await Actor.push_data(result)

            else:
                if not targets:
                    await Actor.fail("No targets provided for monitoring mode.")
                    return
                
                # Limit to max 10 targets for performance
                if len(targets) > 10:
                    logger.warning("Target list truncated to 10 URLs for performance.")
                    targets = targets[:10]
                
                # Use semaphore for concurrency control
                semaphore = asyncio.Semaphore(concurrency)
                
                async def bounded_process(target):
                    async with semaphore:
                        # Charge for monitoring event
                        await Actor.charge(event_name="darkweb-scan")
                        return await process_target(browser, target, keywords, input_data)

                tasks = [bounded_process(t) for t in targets]
                results = await asyncio.gather(*tasks)
                
                for result in results:
                    await Actor.push_data(result)
                
            logger.info("OnionSentinel task complete.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
