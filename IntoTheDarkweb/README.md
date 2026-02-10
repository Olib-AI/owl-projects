# Into The Darkweb

Access .onion sites and the darkweb through the Tor network using [Owl Browser](https://www.owlbrowser.net).

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

Into The Darkweb is an [Apify](https://apify.com) actor that provides programmatic access to the Tor network through Owl Browser's anti-detection browser infrastructure. It offers two modes of operation:

- **Easy Access** — Fetch any .onion page in a single call. Pass a URL, get back HTML. No context management needed.
- **Browser Experience** — Run a full interactive browsing session over Tor with a sequence of actions: navigate, click, type, take screenshots, extract data, and more.

All traffic is routed through Tor with unique exit node IPs per session. Browser fingerprints are randomized for each context.

---

## Quick Start

### Easy Access — Fetch a page

```json
{
    "mode": "easy",
    "region": "US",
    "url": "http://2gzyxa5ihm7nsber64qvit6eraokhlmr6scarvb5xqi6hx4i7flrcbad.onion"
}
```

Returns the full HTML content of the page.

### Browser Experience — Interactive session

```json
{
    "mode": "browser",
    "region": "EU",
    "os": "linux",
    "actions": [
        {"action": "navigate", "url": "http://2gzyxa5ihm7nsber64qvit6eraokhlmr6scarvb5xqi6hx4i7flrcbad.onion"},
        {"action": "wait_for_selector", "selector": "#content", "timeout": 15000},
        {"action": "screenshot"},
        {"action": "extract_text"},
        {"action": "get_html"}
    ]
}
```

Creates a Tor-enabled browser context, runs each action sequentially, collects all results, and auto-closes the context when done.

---

## Input Parameters

### General Settings

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `mode` | string | Yes | `"easy"` | `"easy"` for one-shot page fetch, `"browser"` for interactive session |
| `region` | string | Yes | `"US"` | Browser instance region: `"US"` (United States) or `"EU"` (Europe) |
| `os` | string | No | — | OS fingerprint: `"windows"`, `"macos"`, or `"linux"` |

### Easy Access Options

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `url` | string | Yes (easy mode) | — | The .onion URL or any URL to fetch |
| `outputFormat` | string | No | `"html"` | Output format: `"html"` (raw HTML), `"text"` (extracted plain text), `"markdown"` (markdown conversion) |
| `waitUntil` | string | No | — | When navigation is complete: `"load"`, `"domcontentloaded"`, `"networkidle"`, `"fullscroll"` |
| `timeout` | integer | No | `30000` | Navigation timeout in milliseconds (5000–120000) |

### Browser Experience Options

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `timezone` | string | No | — | IANA timezone (e.g. `"America/New_York"`, `"Europe/London"`) |
| `actions` | array | Yes (browser mode) | — | Sequence of browser actions to execute |

---

## Available Browser Actions

Each action in the `actions` array is a JSON object with an `action` field and action-specific parameters. The browser context ID is injected automatically.

### Navigation

| Action | Parameters | Description |
|--------|-----------|-------------|
| `navigate` | `url` (required), `wait_until`, `timeout` | Navigate to a URL |
| `reload` | `wait_until`, `timeout` | Reload the current page |
| `go_back` | `wait_until`, `timeout` | Navigate back in history |
| `go_forward` | `wait_until`, `timeout` | Navigate forward in history |

### Interaction

| Action | Parameters | Description |
|--------|-----------|-------------|
| `click` | `selector` (required) | Click an element. Accepts CSS selectors, XY coordinates (`"100x200"`), or natural language (`"Login button"`) |
| `type` | `selector` (required), `text` (required) | Type text into an input field |
| `pick` | `selector` (required), `value` (required) | Select a dropdown option |
| `submit_form` | `selector` | Submit a form |

### Data Extraction

| Action | Parameters | Description |
|--------|-----------|-------------|
| `extract_text` | `selector` | Extract text content from the page or a specific element |
| `get_html` | — | Get the full page HTML |
| `screenshot` | — | Take a screenshot (saved to key-value store as PNG) |
| `get_page_info` | — | Get current URL, title, and page metadata |
| `evaluate` | `script` (required) | Execute JavaScript and return the result |

### Scrolling

| Action | Parameters | Description |
|--------|-----------|-------------|
| `scroll_by` | `x`, `y` | Scroll by pixel offset |
| `scroll_to_element` | `selector` (required) | Scroll to a specific element |
| `scroll_to_top` | — | Scroll to the top of the page |
| `scroll_to_bottom` | — | Scroll to the bottom of the page |

### Waiting

| Action | Parameters | Description |
|--------|-----------|-------------|
| `wait_for_selector` | `selector` (required), `timeout` | Wait for an element to appear |

### Cookies

| Action | Parameters | Description |
|--------|-----------|-------------|
| `get_cookies` | — | Get all cookies for the current page |
| `set_cookie` | `name` (required), `value` (required), `domain`, `path` | Set a cookie |
| `delete_cookies` | — | Delete all cookies |

---

## Output

### Easy Access Output

```json
{
    "url": "http://example.onion",
    "content": "<!DOCTYPE html>...",
    "outputFormat": "html",
    "status": "success",
    "region": "US",
    "timestamp": "2025-01-15T12:00:00+00:00"
}
```

### Browser Experience Output

```json
{
    "status": "success",
    "region": "EU",
    "contextId": "ctx_000001",
    "actionsTotal": 5,
    "actionsSucceeded": 5,
    "actionsFailed": 0,
    "results": [
        {
            "step": 1,
            "action": "navigate",
            "status": "success",
            "result": { "url": "http://example.onion", "title": "..." },
            "durationMs": 8500
        },
        {
            "step": 2,
            "action": "screenshot",
            "status": "success",
            "result": { "screenshotKey": "screenshot_1", "sizeBytes": 245760 },
            "durationMs": 1200
        }
    ],
    "timestamp": "2025-01-15T12:00:05+00:00"
}
```

Screenshots are stored in the Apify key-value store as PNG files, accessible via the `screenshotKey` in the results.

**Status values:** `"success"` (all actions passed), `"partial"` (some actions failed), `"error"` (all actions failed or actor-level error).

---

## Examples

### Scrape an onion site

```json
{
    "mode": "easy",
    "region": "US",
    "url": "http://2gzyxa5ihm7nsber64qvit6eraokhlmr6scarvb5xqi6hx4i7flrcbad.onion",
    "waitUntil": "networkidle",
    "timeout": 60000
}
```

### Login and extract data from a .onion site

```json
{
    "mode": "browser",
    "region": "EU",
    "os": "linux",
    "timezone": "Europe/Berlin",
    "actions": [
        {"action": "navigate", "url": "http://example.onion/login"},
        {"action": "type", "selector": "#username", "text": "myuser"},
        {"action": "type", "selector": "#password", "text": "mypass"},
        {"action": "click", "selector": "button[type='submit']"},
        {"action": "wait_for_selector", "selector": ".dashboard", "timeout": 15000},
        {"action": "screenshot"},
        {"action": "navigate", "url": "http://example.onion/data"},
        {"action": "extract_text", "selector": ".results"},
        {"action": "get_html"}
    ]
}
```

### Take a screenshot of a darkweb page

```json
{
    "mode": "browser",
    "region": "US",
    "actions": [
        {"action": "navigate", "url": "http://2gzyxa5ihm7nsber64qvit6eraokhlmr6scarvb5xqi6hx4i7flrcbad.onion"},
        {"action": "wait_for_selector", "selector": "body", "timeout": 30000},
        {"action": "screenshot"},
        {"action": "get_page_info"}
    ]
}
```

---

## Environment Variables

These are configured in the Apify actor settings (not user input):

| Variable | Description |
|----------|-------------|
| `OWL_BROWSER_US_URL` | Owl Browser US region endpoint URL |
| `OWL_BROWSER_US_TOKEN` | Owl Browser US region API token |
| `OWL_BROWSER_EU_URL` | Owl Browser EU region endpoint URL |
| `OWL_BROWSER_EU_TOKEN` | Owl Browser EU region API token |

---

## How It Works

1. The actor reads user input and selects the Owl Browser instance for the chosen region (US or EU).
2. All connections are routed through the Tor network with unique exit node IPs per session.
3. Browser fingerprints (User-Agent, OS, WebGL, Canvas, etc.) are randomized using Owl Browser's anti-detection engine.

**Easy Access** uses the `browser_go` tool, which handles context creation, Tor-routed navigation, HTML extraction, and cleanup in a single call.

**Browser Experience** creates a dedicated Tor-enabled browser context with SOCKS5h proxy (`127.0.0.1:9050`) and Tor circuit isolation. Each action runs sequentially against this context. The context is always closed when the session ends, even if errors occur.

---

## Technology

Built with:

- **[Owl Browser](https://www.owlbrowser.net)** — Anti-detection browser with Tor integration, fingerprint spoofing, and remote automation APIs.
- **[Owl Browser Python SDK v2](https://www.owlbrowser.net)** — Async-first Python client for Owl Browser (`owl-browser` on PyPI).
- **[Apify SDK](https://apify.com)** — Actor runtime, dataset storage, and key-value store for screenshots.

---

## License

MIT License - see LICENSE file for details.

---

## Links

- **Owl Browser**: [https://www.owlbrowser.net](https://www.owlbrowser.net)
- **Olib AI**: [https://www.olib.ai](https://www.olib.ai)
- **Owl Browser Docs**: [https://www.owlbrowser.net/docs](https://www.owlbrowser.net/docs)
- **Repository**: [https://github.com/Olib-AI/owl-projects](https://github.com/Olib-AI/owl-projects)

---

## Keywords

darkweb, dark web, tor, tor browser, onion, .onion, hidden services, tor network, onion routing, darknet, deep web, anonymous browsing, tor proxy, socks5, onion scraper, darkweb scraper, tor scraping, onion crawler, darkweb crawler, darkweb monitoring, threat intelligence, OSINT, open source intelligence, darknet monitoring, tor automation, onion access, hidden service scraper, anti-detection browser, browser fingerprinting, fingerprint spoofing, stealth browser, web scraping, browser automation, headless browser, remote browser, apify actor, owl browser
