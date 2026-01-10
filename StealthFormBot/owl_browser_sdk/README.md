# Owl Browser SDK for Python

AI-first browser automation SDK with on-device vision model, natural language selectors, and comprehensive stealth features.

## Features

- **Natural Language Selectors** - Click, type, and interact using descriptions like "search button" or "login form"
- **On-Device Vision Model** - Built-in Qwen 3 model for page understanding and CAPTCHA solving
- **Stealth Mode** - Proxy support with timezone spoofing, WebRTC blocking, and anti-detection
- **Thread-Safe** - Designed for concurrent usage with multiple pages
- **Simple API** - Minimal code required for common tasks
- **Dual Mode** - Connect to local browser binary OR remote HTTP server

## Installation

```bash
pip install owl-browser
```

**Note:** You must also build the Owl Browser binary. See the main project README for build instructions.

## Quick Start

```python
from owl_browser import Browser

# Simple usage with context manager
with Browser() as browser:
    page = browser.new_page()
    page.goto("https://example.com")

    # Natural language selectors
    page.click("search button")
    page.type("search input", "hello world")

    # Take screenshot
    page.screenshot("screenshot.png")
```

## Remote Mode (HTTP Server)

The SDK supports connecting to a remote Owl Browser HTTP server, enabling:

- **Cloud deployment** - Run browser on remote servers
- **Distributed scraping** - Connect multiple clients to one browser
- **Resource optimization** - Share browser resources across applications

### Basic Remote Usage

```python
from owl_browser import Browser, RemoteConfig

# Connect to remote browser server
browser = Browser(remote=RemoteConfig(
    url="http://192.168.1.100:8080",
    token="your-secret-token"
))
browser.launch()

# API is identical to local mode!
page = browser.new_page()
page.goto("https://example.com")
page.click("search button")
page.type("search input", "hello world")
page.screenshot("screenshot.png")

browser.close()
```

### Remote with Context Manager

```python
from owl_browser import Browser, RemoteConfig

with Browser(remote=RemoteConfig(
    url="http://localhost:8080",
    token="secret-token"
)) as browser:
    page = browser.new_page()
    page.goto("https://example.com")
    page.screenshot("screenshot.png")
```

### Async Remote Usage

```python
import asyncio
from owl_browser import AsyncBrowser, RemoteConfig

async def main():
    async with AsyncBrowser(remote=RemoteConfig(
        url="http://192.168.1.100:8080",
        token="your-secret-token"
    )) as browser:
        page = await browser.new_page()
        await page.goto("https://example.com")
        await page.screenshot("screenshot.png")

asyncio.run(main())
```

### JWT Authentication

For enhanced security, the SDK supports JWT (JSON Web Token) authentication with RSA signing. The SDK can automatically generate and refresh JWT tokens using your private key:

```python
from owl_browser import Browser, RemoteConfig, JWTConfig, AuthMode

# Connect with JWT authentication (auto-generated tokens)
browser = Browser(remote=RemoteConfig(
    url="http://192.168.1.100:8080",
    auth_mode=AuthMode.JWT,
    jwt=JWTConfig(
        private_key="/path/to/private.pem",  # RSA private key
        expires_in=3600,                      # Token validity (1 hour)
        refresh_threshold=300,                # Refresh 5 min before expiry
        issuer="my-app",                      # Optional claims
        subject="user-123"
    )
))
browser.launch()
```

You can also use the JWT utilities directly:

```python
from owl_browser import generate_jwt, decode_jwt, JWTManager, generate_key_pair

# Generate a single token
token = generate_jwt('/path/to/private.pem', expires_in=7200, issuer='my-app')

# Decode a token (without verification)
decoded = decode_jwt(token)
print(f"Expires at: {decoded['payload']['exp']}")

# Use JWTManager for auto-refresh
jwt_manager = JWTManager('/path/to/private.pem', expires_in=3600, refresh_threshold=300)
token = jwt_manager.get_token()  # Auto-refreshes when needed

# Generate new RSA key pair
private_key, public_key = generate_key_pair()
with open('private.pem', 'w') as f:
    f.write(private_key)
with open('public.pem', 'w') as f:
    f.write(public_key)
```

### WebSocket Transport

For lower latency and persistent connections, use WebSocket transport instead of HTTP:

```python
from owl_browser import Browser, RemoteConfig, TransportMode, ReconnectConfig

# WebSocket mode - real-time communication
browser = Browser(remote=RemoteConfig(
    url="http://192.168.1.100:8080",
    token="your-secret-token",
    transport=TransportMode.WEBSOCKET,  # Use WebSocket instead of HTTP
    reconnect=ReconnectConfig(
        enabled=True,
        max_attempts=5,
        initial_delay_ms=1000,
        max_delay_ms=30000
    )
))
browser.launch()
```

### High-Performance Configuration

For high-concurrency workloads, configure retry, and concurrency limits:

```python
from owl_browser import Browser, RemoteConfig, RetryConfig, ConcurrencyConfig

# High-performance HTTP configuration
browser = Browser(remote=RemoteConfig(
    url="http://192.168.1.100:8080",
    token="your-secret-token",
    timeout=30000,
    # Retry configuration with exponential backoff
    retry=RetryConfig(
        max_retries=5,
        initial_delay_ms=100,
        max_delay_ms=10000,
        backoff_multiplier=2.0,
        jitter_factor=0.1
    ),
    # Concurrency limiting
    concurrency=ConcurrencyConfig(
        max_concurrent=50
    )
))
browser.launch()
```

### RemoteConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `url` | str | *required* | Base URL of HTTP server (e.g., `http://localhost:8080`) |
| `token` | str | - | Bearer token (required for TOKEN mode) |
| `auth_mode` | AuthMode | TOKEN | Authentication mode (TOKEN or JWT) |
| `jwt` | JWTConfig | - | JWT configuration (required for JWT mode) |
| `transport` | TransportMode | HTTP | Transport mode (HTTP or WEBSOCKET) |
| `timeout` | int | 30000 | Request timeout in milliseconds |
| `verify_ssl` | bool | True | Verify SSL certificates |
| `retry` | RetryConfig | - | Retry configuration for HTTP transport |
| `reconnect` | ReconnectConfig | - | Reconnection config for WebSocket |
| `concurrency` | ConcurrencyConfig | - | Concurrency limiting config |

### JWTConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `private_key` | str | *required* | Path to RSA private key or PEM string |
| `expires_in` | int | 3600 | Token validity in seconds |
| `refresh_threshold` | int | 300 | Seconds before expiry to refresh |
| `issuer` | str | - | Issuer claim (iss) |
| `subject` | str | - | Subject claim (sub) |
| `audience` | str | - | Audience claim (aud) |
| `claims` | dict | - | Additional custom claims |

### RetryConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_retries` | int | 3 | Maximum number of retry attempts |
| `initial_delay_ms` | int | 100 | Initial delay in milliseconds |
| `max_delay_ms` | int | 10000 | Maximum delay cap in milliseconds |
| `backoff_multiplier` | float | 2.0 | Multiplier for exponential backoff |
| `jitter_factor` | float | 0.1 | Random jitter factor (0-1) |

### ReconnectConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | True | Whether auto-reconnection is enabled |
| `max_attempts` | int | 5 | Maximum reconnection attempts (0 = infinite) |
| `initial_delay_ms` | int | 1000 | Initial delay in milliseconds |
| `max_delay_ms` | int | 30000 | Maximum delay cap in milliseconds |
| `backoff_multiplier` | float | 2.0 | Multiplier for exponential backoff |
| `jitter_factor` | float | 0.1 | Random jitter factor (0-1) |

### ConcurrencyConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_concurrent` | int | 10 | Maximum concurrent requests |

### Checking Connection Mode

```python
from owl_browser import Browser, RemoteConfig, ConnectionMode

browser = Browser(remote=RemoteConfig(url="...", token="..."))
browser.launch()

# Check the connection mode
print(f"Mode: {browser.mode}")  # ConnectionMode.REMOTE
print(f"Is Remote: {browser.is_remote}")  # True

browser.close()
```

### Setting Up the HTTP Server

See `http-server/README.md` for instructions on deploying the Owl Browser HTTP server.

```bash
# Start the HTTP server
./owl_browser --http --port 8080 --token "your-secret-token"
```

## Usage Examples

### Basic Navigation and Interaction

```python
from owl_browser import Browser

browser = Browser()
browser.launch()

page = browser.new_page()
page.goto("https://example.com")

# Click using various selector types
page.click("#submit")           # CSS selector
page.click("100x200")           # Coordinates
page.click("login button")      # Natural language

# Type into inputs
page.type("#email", "user@example.com")
page.type("password field", "secret123")

# Select from dropdowns
page.pick("country dropdown", "United States")

# Press special keys
from owl_browser import KeyName
page.press_key(KeyName.ENTER)

# Human-like mouse movement (anti-bot detection)
page.mouse_move(100, 100, 500, 300)  # Move from (100,100) to (500,300)
page.mouse_move(100, 100, 500, 300, steps=50)  # With 50 intermediate steps
page.mouse_move(100, 100, 500, 300, stop_points=[  # With stop points
    [200, 150],
    [350, 250]
])

browser.close()
```

### AI-Powered Features

```python
from owl_browser import Browser

with Browser() as browser:
    page = browser.new_page()
    page.goto("https://news.example.com")

    # Query the page using LLM
    summary = page.query_page("What are the main headlines?")
    print(summary)

    # Get structured page summary
    summary = page.summarize_page()
    print(summary)

    # Execute natural language commands
    page.execute_nla("scroll down and click the first article")

    # Auto-solve CAPTCHAs
    result = page.solve_captcha()
    if result.get("success"):
        print("CAPTCHA solved!")
```

### Concurrent Scraping

```python
from owl_browser import Browser
from concurrent.futures import ThreadPoolExecutor

browser = Browser()
browser.launch()

def scrape_url(url):
    """Scrape a single URL - each call gets its own isolated page."""
    page = browser.new_page()
    try:
        page.goto(url)
        return {
            "url": url,
            "title": page.get_title(),
            "text": page.extract_text("main content")
        }
    finally:
        page.close()

urls = [
    "https://example1.com",
    "https://example2.com",
    "https://example3.com",
]

# Scrape 5 pages concurrently
with ThreadPoolExecutor(max_workers=5) as executor:
    results = list(executor.map(scrape_url, urls))

browser.close()

for result in results:
    print(f"{result['title']}: {result['text'][:100]}...")
```

### Proxy with Stealth

```python
from owl_browser import Browser, ProxyConfig, ProxyType

with Browser() as browser:
    # Create page with proxy and timezone spoofing
    page = browser.new_page(proxy=ProxyConfig(
        type=ProxyType.SOCKS5H,  # SOCKS5 with remote DNS
        host="proxy.example.com",
        port=1080,
        username="user",
        password="pass",
        stealth=True,           # Block WebRTC leaks
        timezone_override="America/New_York"  # Match proxy location
    ))

    page.goto("https://whatismyip.com")
    page.screenshot("proxy-test.png")

    # Check proxy status
    status = page.get_proxy_status()
    print(f"Proxy connected: {status.connected}")
```

### Cookie Management

```python
from owl_browser import Browser

with Browser() as browser:
    page = browser.new_page()
    page.goto("https://example.com")

    # Get all cookies
    cookies = page.get_cookies()
    for cookie in cookies:
        print(f"{cookie.name}: {cookie.value}")

    # Set a cookie
    page.set_cookie(
        url="https://example.com",
        name="session",
        value="abc123",
        secure=True,
        http_only=True
    )

    # Delete specific cookie
    page.delete_cookies("https://example.com", "session")

    # Delete all cookies
    page.delete_cookies()
```

### Video Recording

```python
from owl_browser import Browser

with Browser() as browser:
    page = browser.new_page()

    # Start recording
    page.start_video_recording(fps=30)

    page.goto("https://example.com")
    page.click("some button")
    page.type("input field", "test data")

    # Stop and get video path
    video_path = page.stop_video_recording()
    print(f"Video saved to: {video_path}")
```

### Content Extraction

```python
from owl_browser import Browser, CleanLevel, ExtractionTemplate

with Browser() as browser:
    page = browser.new_page()
    page.goto("https://example.com")

    # Extract text
    text = page.extract_text()
    article = page.extract_text("main article")

    # Get as Markdown
    markdown = page.get_markdown(include_links=True, include_images=False)

    # Get clean HTML
    html = page.get_html(CleanLevel.AGGRESSIVE)

    # Extract structured JSON (auto-detects template)
    data = page.extract_json()

    # Use specific template
    data = page.extract_json(ExtractionTemplate.GOOGLE_SEARCH)
```

### Test Execution

Run tests exported from the Developer Playground:

```python
from owl_browser import Browser

with Browser() as browser:
    page = browser.new_page()

    # Run test from JSON file
    result = page.run_test("my-test.json", verbose=True)

    # Or define inline
    result = page.run_test({
        "name": "Login Test",
        "steps": [
            {"type": "navigate", "url": "https://example.com/login"},
            {"type": "type", "selector": "#email", "text": "user@example.com"},
            {"type": "type", "selector": "#password", "text": "password123"},
            {"type": "click", "selector": "button[type='submit']"},
            {"type": "wait", "duration": 2000},
            {"type": "screenshot", "filename": "logged-in.png"}
        ]
    })

    print(f"Test: {result.test_name}")
    print(f"Success: {result.successful_steps}/{result.total_steps}")
    print(f"Time: {result.execution_time}ms")
```

### Quick Utilities

For simple one-off operations:

```python
from owl_browser import quick_screenshot, quick_extract, quick_query

# Take a quick screenshot
quick_screenshot("https://example.com", "example.png")

# Extract text quickly
text = quick_extract("https://example.com", "main content")

# Query a page
answer = quick_query("https://news.com", "What is the top headline?")
```

### Async/Await Usage

For asyncio-based applications:

```python
import asyncio
from owl_browser import AsyncBrowser

async def main():
    async with AsyncBrowser() as browser:
        page = await browser.new_page()
        await page.goto("https://example.com")

        # All methods are async
        await page.click("search button")
        await page.type("search input", "hello world")

        text = await page.extract_text()
        await page.screenshot("screenshot.png")

asyncio.run(main())
```

#### Concurrent Async Scraping

```python
import asyncio
from owl_browser import AsyncBrowser, ProxyConfig, ProxyType

async def scrape_url(browser, url):
    """Scrape a single URL."""
    page = await browser.new_page()
    try:
        await page.goto(url)
        return {
            "url": url,
            "title": await page.get_title(),
            "text": await page.extract_text("main")
        }
    finally:
        await page.close()

async def main():
    urls = [
        "https://example1.com",
        "https://example2.com",
        "https://example3.com",
    ]

    async with AsyncBrowser() as browser:
        # Scrape all URLs concurrently
        results = await asyncio.gather(*[
            scrape_url(browser, url) for url in urls
        ])

    for result in results:
        print(f"{result['title']}: {result['text'][:50]}...")

asyncio.run(main())
```

#### Quick Async Utilities

```python
import asyncio
from owl_browser import async_screenshot, async_extract, async_query

async def main():
    # Quick screenshot
    await async_screenshot("https://example.com", "example.png")

    # Quick extraction
    text = await async_extract("https://example.com", "main content")

    # Quick LLM query
    answer = await async_query("https://news.com", "What is the top headline?")

asyncio.run(main())
```

## API Reference

### Browser

| Method | Description |
|--------|-------------|
| `launch()` | Start the browser process |
| `new_page(proxy?, llm?)` | Create a new page (context) |
| `pages()` | Get all active pages |
| `get_llm_status()` | Check LLM availability |
| `get_demographics()` | Get location, time, weather |
| `close()` | Close browser and all pages |

### BrowserContext (Page)

#### Navigation
| Method | Description |
|--------|-------------|
| `goto(url)` | Navigate to URL |
| `reload(ignore_cache?)` | Reload page |
| `go_back()` | Navigate back |
| `go_forward()` | Navigate forward |

#### Interaction
| Method | Description |
|--------|-------------|
| `click(selector)` | Click element |
| `type(selector, text)` | Type into input |
| `pick(selector, value)` | Select from dropdown |
| `press_key(key)` | Press special key |
| `submit_form()` | Submit focused form |
| `highlight(selector)` | Highlight element |
| `hover(selector, duration?)` | Hover over element |
| `double_click(selector)` | Double-click element |
| `right_click(selector)` | Right-click (context menu) |
| `clear_input(selector)` | Clear input field |
| `focus(selector)` | Focus on element |
| `blur(selector)` | Remove focus from element |
| `select_all(selector)` | Select all text in input |
| `keyboard_combo(key, modifiers)` | Press key combination (Ctrl+A, etc.) |
| `drag_drop(start_x, start_y, end_x, end_y)` | Drag and drop |
| `mouse_move(start_x, start_y, end_x, end_y, steps?, stop_points?)` | Human-like mouse movement |

#### Element State
| Method | Description |
|--------|-------------|
| `is_visible(selector)` | Check if element is visible |
| `is_enabled(selector)` | Check if element is enabled |
| `is_checked(selector)` | Check if checkbox/radio is checked |
| `get_attribute(selector, attr)` | Get element attribute value |
| `get_bounding_box(selector)` | Get element position and size |

#### File Upload
| Method | Description |
|--------|-------------|
| `upload_file(selector, file_paths)` | Upload files to input |

#### Frame/Iframe Handling
| Method | Description |
|--------|-------------|
| `list_frames()` | List all frames on page |
| `switch_to_frame(selector)` | Switch to iframe |
| `switch_to_main_frame()` | Switch back to main frame |

#### JavaScript Evaluation
| Method | Description |
|--------|-------------|
| `evaluate(script, args?)` | Execute JavaScript in page context |

#### Content
| Method | Description |
|--------|-------------|
| `extract_text(selector?)` | Extract text content |
| `get_html(clean_level?)` | Get HTML |
| `get_markdown(...)` | Get as Markdown |
| `extract_json(template?)` | Extract structured JSON |
| `summarize_page()` | Get LLM page summary |

#### AI Features
| Method | Description |
|--------|-------------|
| `query_page(query)` | Ask LLM about page |
| `execute_nla(command)` | Execute NL command |
| `solve_captcha()` | Auto-solve CAPTCHA |

#### Screenshot & Video
| Method | Description |
|--------|-------------|
| `screenshot(path?)` | Take screenshot |
| `start_video_recording(fps?)` | Start recording |
| `stop_video_recording()` | Stop and save video |

#### Cookies & Proxy
| Method | Description |
|--------|-------------|
| `get_cookies(url?)` | Get cookies |
| `set_cookie(...)` | Set a cookie |
| `delete_cookies(...)` | Delete cookies |
| `set_proxy(config)` | Configure proxy |
| `get_proxy_status()` | Get proxy status |
| `connect_proxy()` | Enable proxy |
| `disconnect_proxy()` | Disable proxy |

#### Network Interception
| Method | Description |
|--------|-------------|
| `add_network_rule(rule)` | Add interception rule (block, mock, redirect) |
| `remove_network_rule(rule_id)` | Remove a rule |
| `set_network_interception(enabled)` | Enable/disable interception |
| `get_network_log(limit?)` | Get network request log |
| `clear_network_log()` | Clear the log |

#### File Downloads
| Method | Description |
|--------|-------------|
| `set_download_path(path)` | Set download directory |
| `get_downloads()` | Get list of downloads |
| `wait_for_download(id?, timeout?)` | Wait for download to complete |
| `cancel_download(download_id)` | Cancel a download |

#### Dialog Handling
| Method | Description |
|--------|-------------|
| `set_dialog_action(type, action, text?)` | Configure auto-handling policy |
| `get_pending_dialog()` | Get pending dialog info |
| `handle_dialog(id, accept, text?)` | Accept/dismiss dialog |
| `wait_for_dialog(timeout?)` | Wait for dialog to appear |

#### Tab/Window Management
| Method | Description |
|--------|-------------|
| `new_tab(url?)` | Create new tab |
| `get_tabs()` | List all tabs |
| `switch_tab(tab_id)` | Switch to tab |
| `get_active_tab()` | Get active tab |
| `close_tab(tab_id)` | Close a tab |
| `get_tab_count()` | Get tab count |
| `set_popup_policy(policy)` | Configure popup handling |
| `get_blocked_popups()` | Get blocked popup URLs |

## New Features

### Network Interception

Block, mock, or redirect network requests:

```python
from owl_browser import Browser, NetworkRule, NetworkAction

with Browser() as browser:
    page = browser.new_page()

    # Block ads
    rule_id = page.add_network_rule(NetworkRule(
        url_pattern='https://ads.example.com/*',
        action=NetworkAction.BLOCK
    ))

    # Mock API response
    page.add_network_rule(NetworkRule(
        url_pattern='https://api.example.com/data',
        action=NetworkAction.MOCK,
        mock_body='{"status": "ok"}',
        mock_status=200,
        mock_content_type='application/json'
    ))

    # Redirect requests
    page.add_network_rule(NetworkRule(
        url_pattern='https://old-api.example.com/*',
        action=NetworkAction.REDIRECT,
        redirect_url='https://new-api.example.com/'
    ))

    # Enable interception
    page.set_network_interception(True)

    # Navigate and check log
    page.goto("https://example.com")
    log = page.get_network_log()

    # Remove rule
    page.remove_network_rule(rule_id)
```

### File Downloads

Handle file downloads:

```python
from owl_browser import Browser

with Browser() as browser:
    page = browser.new_page()
    page.goto("https://example.com/files")

    # Set download directory
    page.set_download_path('/tmp/downloads')

    # Click a download link
    page.click('a[download]')

    # Wait for download to complete
    download = page.wait_for_download()
    print(f"Downloaded: {download.filename} to {download.path}")

    # Or get all downloads
    downloads = page.get_downloads()

    # Cancel a download
    page.cancel_download(download.id)
```

### Dialog Handling

Handle JavaScript dialogs (alert, confirm, prompt):

```python
from owl_browser import Browser, DialogType, DialogAction

with Browser() as browser:
    page = browser.new_page()

    # Auto-accept alerts
    page.set_dialog_action(DialogType.ALERT, DialogAction.ACCEPT)

    # Auto-respond to prompts
    page.set_dialog_action(
        DialogType.PROMPT,
        DialogAction.ACCEPT_WITH_TEXT,
        "My answer"
    )

    # Dismiss confirms
    page.set_dialog_action(DialogType.CONFIRM, DialogAction.DISMISS)

    page.goto("https://example.com")

    # Or handle manually
    dialog = page.wait_for_dialog()
    print(f"Dialog message: {dialog.message}")
    page.handle_dialog(dialog.id, accept=True, response_text="response")
```

### Multi-Tab Management

Work with multiple tabs:

```python
from owl_browser import Browser, PopupPolicy

with Browser() as browser:
    page = browser.new_page()
    page.goto("https://example.com")

    # Create new tab
    tab = page.new_tab('https://google.com')
    print(f"Tab ID: {tab.tab_id}")

    # List all tabs
    tabs = page.get_tabs()
    for t in tabs:
        print(f"Tab: {t.title} - {t.url}")

    # Switch to a tab
    page.switch_tab(tabs[0].tab_id)

    # Get active tab
    active = page.get_active_tab()

    # Get tab count
    count = page.get_tab_count()

    # Close a tab
    page.close_tab(tab.tab_id)

    # Configure popup handling
    page.set_popup_policy(PopupPolicy.BLOCK)

    # Get blocked popups
    blocked = page.get_blocked_popups()
```

## Error Handling

The SDK provides specific exception types for different error scenarios:

```python
from owl_browser import (
    Browser, RemoteConfig, JWTConfig, AuthMode,
    AuthenticationError, RateLimitError, IPBlockedError,
    LicenseError, BrowserInitializationError, FirewallError,
    ActionError, ActionStatus, ActionResult,
    ElementNotFoundError, NavigationError, ContextError
)

try:
    browser = Browser(remote=RemoteConfig(
        url="http://localhost:8080",
        auth_mode=AuthMode.JWT,
        jwt=JWTConfig(private_key="/path/to/private.pem")
    ))
    browser.launch()

    page = browser.new_page()
    page.goto("https://example.com")

    # This will raise ElementNotFoundError if element doesn't exist
    page.click("non-existent button")

except ElementNotFoundError as e:
    # Element was not found on the page
    print(f"Element not found: {e}")

except NavigationError as e:
    # Navigation failed (timeout, page load error, etc.)
    print(f"Navigation failed: {e}")

except ActionError as e:
    # Generic action error with detailed status
    print(f"Action failed: {e.message}")
    print(f"Status: {e.status}")
    print(f"Selector: {e.selector}")
    # Check specific error types
    if e.is_element_not_found():
        print("Could not find element")
    elif e.is_navigation_error():
        print("Navigation issue")
    elif e.is_timeout():
        print("Operation timed out")

except FirewallError as e:
    # Web firewall/bot protection detected
    print(f"Firewall detected: {e.provider}")
    print(f"Challenge type: {e.challenge_type}")
    print(f"URL: {e.url}")

except AuthenticationError as e:
    # 401 - Invalid or expired token
    print(f"Auth failed: {e.message}")
    print(f"Reason: {e.reason}")

except RateLimitError as e:
    # 429 - Too many requests
    print(f"Rate limited. Retry after: {e.retry_after} seconds")

except IPBlockedError as e:
    # 403 - IP not whitelisted
    print(f"IP blocked: {e.ip_address}")

except LicenseError as e:
    # License validation failed
    print(f"License error: {e.status}")

except BrowserInitializationError as e:
    print(f"Failed to start browser: {e}")

finally:
    browser.close()
```

### Action Result Validation

The browser returns structured `ActionResult` responses for browser actions, providing detailed information about success or failure:

```python
from owl_browser import (
    ActionStatus, ActionResult, ActionError,
    is_action_result, throw_if_action_failed
)

# ActionStatus enum values (common ones)
ActionStatus.OK                      # Action succeeded
ActionStatus.ELEMENT_NOT_FOUND       # Element not found on page
ActionStatus.ELEMENT_NOT_VISIBLE     # Element exists but not visible
ActionStatus.ELEMENT_NOT_INTERACTABLE # Element not interactable
ActionStatus.NAVIGATION_FAILED       # Navigation failed
ActionStatus.NAVIGATION_TIMEOUT      # Navigation timed out
ActionStatus.PAGE_LOAD_ERROR         # Page failed to load
ActionStatus.FIREWALL_DETECTED       # Web firewall/bot protection detected
ActionStatus.CAPTCHA_DETECTED        # CAPTCHA challenge detected
ActionStatus.CLICK_FAILED            # Click action failed
ActionStatus.CLICK_INTERCEPTED       # Click intercepted by another element
ActionStatus.TYPE_FAILED             # Type action failed
ActionStatus.TYPE_PARTIAL            # Partial text entered
ActionStatus.PICK_FAILED             # Dropdown selection failed
ActionStatus.UPLOAD_FAILED           # File upload failed
ActionStatus.FRAME_SWITCH_FAILED     # Failed to switch to frame
ActionStatus.TAB_SWITCH_FAILED       # Failed to switch to tab
ActionStatus.CONTEXT_NOT_FOUND       # Browser context not found
ActionStatus.INVALID_SELECTOR        # Invalid selector provided
ActionStatus.TIMEOUT                 # Operation timed out
ActionStatus.VERIFICATION_TIMEOUT    # Verification timed out

# ActionResult dataclass
@dataclass
class ActionResult:
    success: bool
    status: str
    message: str
    selector: Optional[str] = None      # The selector that failed
    url: Optional[str] = None           # URL involved (navigation errors)
    http_status: Optional[int] = None   # HTTP status code
    error_code: Optional[str] = None    # Browser error code
    element_count: Optional[int] = None # Elements found (multiple_elements)

# Helper functions
if is_action_result(result):
    throw_if_action_failed(result)  # Raises appropriate exception
```

### Exception Types

| Exception | HTTP Code | Description |
|-----------|-----------|-------------|
| `ActionError` | - | Browser action failed with status code and details |
| `ElementNotFoundError` | - | Element not found on page |
| `NavigationError` | - | Navigation failed (timeout, load error) |
| `FirewallError` | - | Web firewall/bot protection detected (Cloudflare, Akamai, etc.) |
| `ContextError` | - | Browser context not found |
| `AuthenticationError` | 401 | Invalid/expired token or JWT signature mismatch |
| `RateLimitError` | 429 | Too many requests, includes `retry_after` in seconds |
| `IPBlockedError` | 403 | Client IP not in whitelist |
| `LicenseError` | 503 | Browser license validation failed |
| `BrowserInitializationError` | - | Failed to start/connect to browser |
| `CommandTimeoutError` | - | Operation timed out |

### FirewallError Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `url` | `str` | The URL where the firewall was detected |
| `provider` | `str` | Firewall provider (Cloudflare, Akamai, Imperva, etc.) |
| `challenge_type` | `str?` | Type of challenge (JS Challenge, CAPTCHA, etc.) |

The browser automatically detects web firewalls including Cloudflare, Akamai, Imperva, PerimeterX, DataDome, and AWS WAF.

### ActionError Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `status` | `str` | Status code (e.g., `element_not_found`) |
| `message` | `str` | Human-readable error message |
| `selector` | `str?` | The selector that failed |
| `url` | `str?` | URL involved in navigation errors |
| `http_status` | `int?` | HTTP status code |
| `error_code` | `str?` | Browser error code |
| `element_count` | `int?` | Number of elements found |

## Thread Safety

The SDK is designed for concurrent usage:

- **Browser** instance can be shared across threads
- Each **BrowserContext** (page) is isolated
- Multiple pages can run operations simultaneously
- IPC communication is thread-safe with proper locking

Best practice for concurrent scraping:
1. Create one `Browser` instance
2. Create separate pages for each concurrent task
3. Close pages when done to free resources

## Requirements

- Python 3.8+
- macOS or Linux
- Built Owl Browser binary

## License

MIT License - see the main project for details.
