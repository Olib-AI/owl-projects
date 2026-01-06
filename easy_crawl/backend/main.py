from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from owl_browser import Browser, RemoteConfig, ProxyConfig, ProxyType
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
REMOTE_BROWSER_URL = os.getenv("OWL_BROWSER_URL", "http://localhost:8080")
REMOTE_BROWSER_TOKEN = os.getenv("OWL_BROWSER_TOKEN", "your-access-token")

remote_config = RemoteConfig(
    url=REMOTE_BROWSER_URL,
    token=REMOTE_BROWSER_TOKEN
)

# Shared browser instance for async operations (extract_site)
# Don't use 'with' for async jobs - the context must stay alive during extraction
_browser: Optional[Browser] = None
_shared_page = None  # Reusable page for job status queries

# Track job_id -> page object mapping for cleanup
_job_pages: Dict[str, Any] = {}

def get_browser() -> Browser:
    """Get or create shared browser instance."""
    global _browser
    if _browser is None:
        _browser = Browser(remote=remote_config)
        _browser.launch()  # Must call launch() before using
    return _browser

def get_shared_page():
    """Get a shared page for job status queries (progress/result)."""
    global _shared_page
    if _shared_page is None:
        _shared_page = get_browser().new_page()
    return _shared_page

def close_job_context(job_id: str):
    """Close the browser context associated with a job."""
    global _job_pages
    if job_id in _job_pages:
        page = _job_pages.pop(job_id)
        try:
            page.close()
            print(f"[CLEANUP] Closed context for job {job_id}")
        except Exception as e:
            print(f"[CLEANUP] Failed to close context for job {job_id}: {e}")

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
    exclude_patterns: Optional[List[str]] = None
    timeout_per_page: int = 10000

@app.get("/")
def read_root():
    return {"message": "Easy Crawl API is running"}

@app.post("/scrape")
def scrape_url(request: ScrapeRequest):
    with Browser(remote=remote_config) as browser:
        page = browser.new_page()
        page.goto(request.url)
        
        if request.output_format == "json":
            # Using extract_json with auto-detection (no template provided)
            content = page.extract_json()
        elif request.output_format == "text":
            content = page.extract_text()
        else: # markdown
            content = page.get_markdown()
            
        return {"content": content, "format": request.output_format}

@app.post("/search")
def search_google(request: SearchRequest):

    with Browser(remote=remote_config) as browser:
        # Create context with proxy
        page = browser.new_page()

        # Google search - use networkidle to wait for dynamic content
        q = request.query.replace(" ", "+")
        page.goto(f"https://www.google.com/search?q={q}", wait_until="networkidle")

        # Small additional wait to ensure results are rendered
        page.wait(500)

        # Extract results using built-in google_search template (no LLM required)
        results = page.extract_json(template="google_search")

        return {"results": results}

@app.post("/crawl/start")
def start_crawl(request: CrawlRequest):
    global _job_pages
    # Use shared browser - don't close context while async job runs
    browser = get_browser()
    page = browser.new_page()
    job = page.extract_site(
        url=request.url,
        depth=request.depth,
        max_pages=request.max_pages,
        follow_external=request.follow_external,
        output_format=request.output_format,
        include_images=request.include_images,
        include_metadata=request.include_metadata,
        exclude_patterns=request.exclude_patterns,
        timeout_per_page=request.timeout_per_page
    )
    # Track page object for cleanup when result is fetched
    if job.get("job_id"):
        _job_pages[job["job_id"]] = page
        print(f"[CRAWL] Started job {job['job_id']} with context {page.id}")
    return job

@app.get("/crawl/{job_id}/progress")
def get_crawl_progress(job_id: str):
    # Use shared page - job operations only need job_id, not the original context
    page = get_shared_page()
    progress = page.extract_site_progress(job_id)
    return progress

@app.get("/crawl/{job_id}/result")
def get_crawl_result(job_id: str):
    import time

    t0 = time.time()
    # Use shared page - job operations only need job_id, not the original context
    page = get_shared_page()
    t1 = time.time()
    print(f"[TIMING] get_shared_page: {(t1-t0)*1000:.0f}ms")

    result = page.extract_site_result(job_id)
    t2 = time.time()
    print(f"[TIMING] extract_site_result: {(t2-t1)*1000:.0f}ms")

    # Close the context associated with this job
    close_job_context(job_id)

    return result

@app.delete("/crawl/{job_id}")
def cancel_crawl(job_id: str):
    """Cancel a crawl job and close its context."""
    if job_id in _job_pages:
        close_job_context(job_id)
        return {"status": "cancelled", "job_id": job_id}
    return {"status": "not_found", "job_id": job_id}

@app.get("/crawl/jobs/active")
def list_active_jobs():
    """List all active crawl jobs with their context IDs."""
    return {"active_jobs": {job_id: page.id for job_id, page in _job_pages.items()}}
