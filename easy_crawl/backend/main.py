"""
Easy Crawl API - FastAPI backend for browser automation.

Migrated to Owl Browser Python SDK v2 with async-first architecture.
"""

from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os

from owl_browser import OwlBrowser, RemoteConfig

load_dotenv()

# Configuration
REMOTE_BROWSER_URL = os.getenv("OWL_BROWSER_URL", "http://localhost:8080")
REMOTE_BROWSER_TOKEN = os.getenv("OWL_BROWSER_TOKEN", "your-access-token")

# RemoteConfig with api_prefix="" for direct connection (no /api prefix)
remote_config = RemoteConfig(
    url=REMOTE_BROWSER_URL,
    token=REMOTE_BROWSER_TOKEN,
    api_prefix=""
)

# Shared browser instance for async crawl jobs
_browser: OwlBrowser | None = None
_shared_context_id: str | None = None

# Track job_id -> context_id mapping for cleanup
_job_contexts: dict[str, str] = {}


async def get_browser() -> OwlBrowser:
    """Get or create shared browser instance."""
    global _browser
    if _browser is None:
        _browser = OwlBrowser(remote_config)
        await _browser.connect()
    return _browser


async def get_shared_context_id() -> str:
    """Get a shared context for job status queries (progress/result)."""
    global _shared_context_id
    if _shared_context_id is None:
        browser = await get_browser()
        ctx = await browser.create_context()
        _shared_context_id = ctx["context_id"]
    return _shared_context_id


async def close_job_context(job_id: str) -> None:
    """Close the browser context associated with a job."""
    global _job_contexts
    if job_id in _job_contexts:
        context_id = _job_contexts.pop(job_id)
        try:
            browser = await get_browser()
            await browser.close_context(context_id=context_id)
            print(f"[CLEANUP] Closed context {context_id} for job {job_id}")
        except Exception as e:
            print(f"[CLEANUP] Failed to close context for job {job_id}: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown."""
    yield
    # Cleanup on shutdown
    global _browser, _shared_context_id
    if _browser is not None:
        await _browser.close()
        _browser = None
        _shared_context_id = None


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScrapeRequest(BaseModel):
    url: str
    output_format: str = "markdown" # markdown, json, text

class SearchRequest(BaseModel):
    query: str

class CrawlRequest(BaseModel):
    url: str
    depth: int = 2
    max_pages: int = 5
    follow_external: bool = False
    output_format: str = "markdown"
    include_images: bool = True
    include_metadata: bool = True
    exclude_patterns: list[str] | None = None
    timeout_per_page: int = 10000

@app.get("/")
async def read_root() -> dict[str, str]:
    """Health check endpoint."""
    return {"message": "Easy Crawl API is running"}


@app.post("/scrape")
async def scrape_url(request: ScrapeRequest) -> dict[str, Any]:
    """
    Scrape a single URL and return content in the specified format.

    Args:
        request: Scrape request with URL and output format.

    Returns:
        Dictionary with content and format.
    """
    async with OwlBrowser(remote_config) as browser:
        ctx = await browser.create_context()
        context_id = ctx["context_id"]

        try:
            await browser.navigate(context_id=context_id, url=request.url)

            if request.output_format == "json":
                # Using extract_json with auto-detection (no template provided)
                content = await browser.extract_json(context_id=context_id)
            elif request.output_format == "text":
                content = await browser.extract_text(context_id=context_id)
            else:  # markdown
                content = await browser.get_markdown(context_id=context_id)

            return {"content": content, "format": request.output_format}
        finally:
            await browser.close_context(context_id=context_id)


@app.post("/search")
async def search_google(request: SearchRequest) -> dict[str, Any]:
    """
    Search Google and return structured results.

    Args:
        request: Search request with query.

    Returns:
        Dictionary with search results, success status, and optional error message.
    """
    try:
        async with OwlBrowser(remote_config) as browser:
            ctx = await browser.create_context()
            context_id = ctx["context_id"]

            try:
                # Google search - use networkidle to wait for dynamic content
                q = request.query.replace(" ", "+")
                await browser.navigate(
                    context_id=context_id,
                    url=f"https://www.google.com/search?q={q}",
                    wait_until="networkidle"
                )

                # Small additional wait to ensure results are rendered
                await browser.wait(context_id=context_id, timeout=500)

                # Extract results using built-in google_search template (no LLM required)
                results = await browser.extract_json(context_id=context_id, template="google_search")

                # Check for empty results
                if not results or (isinstance(results, list) and len(results) == 0):
                    return {
                        "success": False,
                        "results": [],
                        "error": "No search results found. This may be due to a proxy issue or the search returned no matches.",
                    }

                return {"success": True, "results": results}
            finally:
                await browser.close_context(context_id=context_id)
    except Exception as e:
        error_msg = str(e)
        # Provide user-friendly message for common issues
        if "proxy" in error_msg.lower() or "connection" in error_msg.lower() or "timeout" in error_msg.lower():
            return {
                "success": False,
                "results": [],
                "error": "Search failed due to a connection or proxy issue. Please try again later.",
            }
        return {
            "success": False,
            "results": [],
            "error": f"Search failed: {error_msg}",
        }

@app.post("/crawl/start")
async def start_crawl(request: CrawlRequest) -> dict[str, Any]:
    """
    Start an async crawl job.

    Args:
        request: Crawl request with URL and configuration.

    Returns:
        Dictionary with job_id for tracking progress.
    """
    global _job_contexts

    # Use shared browser - don't close context while async job runs
    browser = await get_browser()
    ctx = await browser.create_context()
    context_id = ctx["context_id"]

    # Build kwargs, only include exclude_patterns if it's a non-empty list
    extract_kwargs: dict[str, Any] = {
        "context_id": context_id,
        "url": request.url,
        "depth": request.depth,
        "max_pages": request.max_pages,
        "follow_external": request.follow_external,
        "output_format": request.output_format,
        "include_images": request.include_images,
        "include_metadata": request.include_metadata,
        "timeout_per_page": request.timeout_per_page,
    }
    if request.exclude_patterns:
        extract_kwargs["exclude_patterns"] = request.exclude_patterns

    job = await browser.extract_site(**extract_kwargs)

    # Track context_id for cleanup when result is fetched
    if job.get("job_id"):
        _job_contexts[job["job_id"]] = context_id
        print(f"[CRAWL] Started job {job['job_id']} with context {context_id}")

    return job


@app.get("/crawl/{job_id}/progress")
async def get_crawl_progress(job_id: str) -> dict[str, Any]:
    """
    Get progress of a crawl job.

    Args:
        job_id: The job ID to check.

    Returns:
        Progress dictionary with crawled pages, total, etc.
    """
    browser = await get_browser()
    progress = await browser.extract_site_progress(job_id=job_id)
    return progress


@app.get("/crawl/{job_id}/result")
async def get_crawl_result(job_id: str) -> dict[str, Any]:
    """
    Get the result of a completed crawl job.

    Args:
        job_id: The job ID to get results for.

    Returns:
        Crawl result with pages and content.
    """
    browser = await get_browser()
    result = await browser.extract_site_result(job_id=job_id)

    # Close the context associated with this job
    await close_job_context(job_id)

    return result


@app.delete("/crawl/{job_id}")
async def cancel_crawl(job_id: str) -> dict[str, str]:
    """
    Cancel a crawl job and close its context.

    Args:
        job_id: The job ID to cancel.

    Returns:
        Status dictionary.
    """
    if job_id in _job_contexts:
        await close_job_context(job_id)
        return {"status": "cancelled", "job_id": job_id}
    return {"status": "not_found", "job_id": job_id}


@app.get("/crawl/jobs/active")
async def list_active_jobs() -> dict[str, dict[str, str]]:
    """
    List all active crawl jobs with their context IDs.

    Returns:
        Dictionary mapping job_id to context_id.
    """
    return {"active_jobs": _job_contexts.copy()}
