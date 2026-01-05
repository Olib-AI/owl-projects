# Owl Browser - Partner Guide

Welcome to the Owl Browser platform. This guide is designed for partners building SaaS platforms, high-scale automation tools, and AI agents using our technology.

## 1. Introduction

Owl Browser is an **AI-First, High-Scale Automation Browser** built on top of Chromium. Unlike traditional automation tools (Selenium, Puppeteer, Playwright) that rely on brittle CSS selectors and DOM structures, Owl Browser integrates **native AI capabilities** directly into the browser core.

### Key Value Propositions

*   **AI-Native Interaction:** Click, type, and interact using natural language (e.g., `page.click("login button")`) instead of complex CSS selectors. The browser understands the UI like a human.
*   **Built-in LLM:** Features an on-device vision-language model (Qwen3-VL-2B) for visual understanding, CAPTCHA solving, and page summarization without external API costs.
*   **Unmatched Stealth:** Built from the ground up for stealth. Includes native fingerprint management, anti-detection (Canvas/WebGL noise), and timezone spoofing to bypass sophisticated bot protections.
*   **High Performance:** C++ native architecture with off-screen rendering, optimized for high-density containerized deployments.
*   **Standardized API:** All capabilities are exposed via a standardized HTTP API and a user-friendly Python SDK.

## 2. Architecture

For SaaS integrations, we recommend the **Remote Server Architecture**. This allows you to decouple your application logic (running the Python SDK) from the browser execution nodes (running the HTTP Server).

```
┌─────────────────────────────┐      HTTP / JSON      ┌─────────────────────────────┐
│  Partner Application        │   (REST + WebSocket)  │  Owl Browser Node          │
│  (Python SDK)               │ ◄───────────────────► │  (HTTP Server + Browser)    │
│                             │                       │                             │
│  browser = Browser(         │                       │  [ API Gateway ]            │
│    remote=RemoteConfig(...) │                       │       │                     │
│  )                          │                       │  [ Native Browser Core ]    │
└─────────────────────────────┘                       │     ├── AI Model            │
                                                      │     ├── Stealth Engine      │
                                                      │     └── Rendering Engine    │
                                                      └─────────────────────────────┘
```

*   **Python SDK:** A lightweight client that sends commands to the server. It is thread-safe and supports async/await for high-concurrency scraping.
*   **HTTP Server:** A stateless container that manages browser instances, handles authentication (Bearer Token/JWT), and executes automation commands.

## 3. Getting Started

### Prerequisites

*   **Python 3.8+**
*   Access to an Owl Browser HTTP Server endpoint (provided by Olib or self-hosted via Docker).

### Installation

Install the partner SDK:

```bash
pip install owl-browser
```

### Basic Usage

Connect to the HTTP server and perform a simple automation task:

```python
from owl_browser import Browser, RemoteConfig

# Configuration for the remote browser node
remote_config = RemoteConfig(
    url="http://your-browser-node:8080",
    token="your-access-token"
)

# Initialize and launch connection
with Browser(remote=remote_config) as browser:
    # Create a new isolated context (like a fresh incognito window)
    page = browser.new_page()
    
    # Navigate
    page.goto("https://example.com")
    
    # AI Interaction: No CSS selectors needed!
    page.click("get started button")
    page.type("email input", "partner@example.com")
    
    # Visual Verification
    page.screenshot("confirmation.png")
```

## 4. Key Features & Tools

Owl Browser offers a rich set of tools divided into several categories. All tools are accessible via the Python SDK.

### 4.1. Navigation & Interaction

Traditional automation breaks when layouts change. Owl Browser uses a **Semantic Matcher** to find elements based on their meaning.

*   **`page.goto(url)`**: Navigate to a URL. Supports `wait_until` strategies (`load`, `networkidle`).
*   **`page.click(selector)`**: Click elements using:
    *   **Natural Language:** `"login button"`, `"search icon"`
    *   **CSS Selectors:** `"#submit-btn"`
    *   **Coordinates:** `"100x200"`
*   **`page.type(selector, text)`**: Human-like typing with variable keystroke delays.
*   **`page.pick(selector, value)`**: Smart dropdown selection. Works with standard `<select>` and complex JS dropdowns.
*   **`page.drag_drop(start, end)`**: Simulate drag-and-drop interactions (e.g., for sliders or puzzles).

### 4.2. AI & Intelligence

Leverage the built-in Vision-Language Model (VLM) for advanced tasks.

*   **`page.query_page(query)`**: Ask natural language questions about the page content.
    *   *Example:* `page.query_page("What is the price of the enterprise plan?")`
*   **`page.summarize_page()`**: Get a structured summary of the page's main content.
*   **`page.execute_nla(command)` (Natural Language Actions)**: Execute multi-step complex instructions.
    *   *Example:* `page.execute_nla("Find the contact form and fill it with test data")`
*   **`page.solve_captcha()`**: Auto-detect and solve CAPTCHAs using the on-device vision model.

### 4.3. Data Extraction

Extract clean data from any website.

*   **`page.extract_text(selector)`**: Get clean text from specific elements or the whole page.
*   **`page.extract_json(template)`**: Extract structured data using pre-built templates or auto-detection.
*   **`page.screenshot(path)`**: Capture pixel-perfect screenshots. Modes: `viewport`, `fullpage`, or `element`.

### 4.4. Stealth & Identity

Manage browser fingerprints to stay undetected.

*   **`browser.new_page(...)`**: The entry point for every session. Supports:
    *   **Proxies:** HTTP, SOCKS5, SOCKS5H (Remote DNS).
    *   **Stealth Mode:** Automatically patches WebDriver flags, WebGL/Canvas fingerprints.
    *   **Profile Path:** Load persistent cookies and storage.
*   **`page.set_proxy(config)`**: Dynamically switch proxies for an active context.
*   **Demographics**: The browser can automatically spoof timezone and geolocation to match your proxy IP via `browser.get_demographics()`.

### 4.5. Network Control

Full control over the network layer for scraping and testing.

*   **`page.add_network_rule(rule)`**: Intercept requests.
    *   **Block:** Stop ads/trackers loading (`*.google-analytics.com`).
    *   **Mock:** Return fake JSON responses for APIs.
    *   **Redirect:** Point requests to different URLs.
*   **`page.get_network_log()`**: Audit all network traffic (headers, payloads) for debugging.

## 5. SDK Reference

### Context Management
| Method | Description |
| :--- | :--- |
| `browser.new_page(proxy=...)` | Creates an isolated browser environment (cookies/storage). |
| `browser.close()` | Terminates the connection and frees resources. |

### Page Actions
| Method | Description |
| :--- | :--- |
| `page.goto(url)` | Navigates to a specific URL. |
| `page.click(selector)` | Smart click on an element. |
| `page.type(selector, text)` | Types text into an input field. |
| `page.press_key(key)` | Simulates special keys (Enter, Tab, Esc). |
| `page.scroll_to_bottom()` | Scrolls to the bottom of the page (infinite scroll). |
| `page.wait_for_selector(sel)` | Waits for an element to appear. |

### Intelligence
| Method | Description |
| :--- | :--- |
| `page.solve_captcha()` | Attempts to solve any visible CAPTCHA. |
| `page.query_page(query)` | Asks the LLM a question about the page. |
| `page.summarize_page()` | Returns a JSON summary of the page. |

### Data & Media
| Method | Description |
| :--- | :--- |
| `page.screenshot(path)` | Saves a screenshot to disk. |
| `page.extract_text(sel)` | Returns text content. |
| `page.start_video_recording()`| Begins recording the session to MP4. |
| `page.stop_video_recording()` | Stops recording and returns the file path. |

## 6. Best Practices for Partners

1.  **Context Isolation:** Always use `browser.new_page()` for every new user session or task. This ensures cookies and local storage do not bleed between sessions.
2.  **Resource Management:** Explicitly call `page.close()` or use the context manager (`with Browser()...`) to ensure memory is freed on the server.
3. **Proxy Strategy:** For high-scale scraping, use the `ProxyConfig` with `ProxyType.SOCKS5H` to prevent DNS leaks and enable `timezone_override` to match the proxy location.
4. **Error Handling:** The SDK raises specific exceptions (`ElementNotFoundError`, `FirewallError`, `CaptchaDetectedError`). Wrap critical actions in try/except blocks to handle these gracefully.

## 7. Complete SDK Reference

This section provides a detailed reference for the available methods in the Python SDK (`owl-browser`). Most automation actions are performed on a `Page` object (returned by `browser.new_page()`).

### 7.1. Context & Lifecycle

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **browser.new_page** | `proxy` (ProxyConfig), `llm` (LLMConfig), `profile_path` (str) | Creates a new isolated browser page (context). |
| **browser.pages** | (none) | Returns a list of all active pages. |
| **browser.list_contexts** | (none) | List all active context IDs. |
| **browser.close** | (none) | Closes the browser connection and all pages. |
| **page.close** | (none) | Closes the specific page/context. |
| **page.load_profile** | `profile_path` (str, **req**) | Loads a browser profile into the current context. |
| **browser.create_profile** | `name` (str) | Creates a new browser profile with randomized fingerprint. |

### 7.2. Navigation & History

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **page.goto** | `url` (str, **req**), `wait_until` (str), `timeout` (int) | Navigates to a URL. |
| **page.reload** | `ignore_cache` (bool), `wait_until` (str), `timeout` (int) | Reloads the current page. |
| **page.go_back** | `wait_until` (str), `timeout` (int) | Navigates back in history. |
| **page.go_forward** | `wait_until` (str), `timeout` (int) | Navigates forward in history. |
| **page.can_go_back** | (none) | Checks if navigation back is possible. |
| **page.can_go_forward** | (none) | Checks if navigation forward is possible. |
| **page.get_current_url** | (none) | Returns the current URL. |
| **page.get_title** | (none) | Returns the page title. |
| **page.get_page_info** | (none) | Returns info like URL, title, and nav state. |

### 7.3. User Interaction

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **page.click** | `selector` (str, **req**) | Clicks an element. |
| **page.type** | `selector` (str, **req**), `text` (str, **req**) | Types text into an input field. |
| **page.pick** | `selector` (str, **req**), `value` (str, **req**) | Selects an option from a dropdown. |
| **page.press_key** | `key` (KeyName, **req**) | Presses a special key (Enter, Tab, Esc, etc.). |
| **page.submit_form** | (none) | Submits the currently focused form. |
| **page.clear_input** | `selector` (str, **req**) | Clears text from an input field. |
| **page.focus** | `selector` (str, **req**) | Sets focus to an element. |
| **page.blur** | `selector` (str, **req**) | Removes focus from an element. |
| **page.select_all** | `selector` (str, **req**) | Selects all text in an input. |
| **page.hover** | `selector` (str, **req**), `duration` (int) | Hovers over an element. |
| **page.double_click** | `selector` (str, **req**) | Double-clicks an element. |
| **page.right_click** | `selector` (str, **req**) | Right-clicks an element. |
| **page.keyboard_combo** | `key` (str, **req**), `modifiers` (list, **req**) | Presses key combinations (e.g., Ctrl+A). |
| **page.drag_drop** | `start_x`, `start_y`, `end_x`, `end_y`, `mid_points` | Drags from start coordinates to end coordinates. |
| **page.html5_drag_drop** | `source_selector`, `target_selector` | HTML5 drag and drop between elements. |
| **page.mouse_move** | `start_x`, `start_y`, `end_x`, `end_y`, `steps`, `stop_points` | Simulates human-like mouse movement. |
| **page.upload_file** | `selector` (str), `file_paths` (list) | Uploads files to a file input. |
| **page.highlight** | `selector`, `border_color`, `background_color` | Highlights an element for debugging. |
| **page.show_grid_overlay** | `horizontal_lines`, `vertical_lines`, ... | Shows a coordinate grid overlay. |

### 7.4. AI & Intelligence

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **page.query_page** | `query` (str, **req**) | Asks a question about the page content. |
| **page.summarize_page** | `force_refresh` (bool) | Returns a structured AI summary of the page. |
| **page.execute_nla** | `command` (str, **req**) | Executes a multi-step Natural Language Action. |
| **page.ai_click** | `description` (str, **req**) | Clicks an element described by natural language. |
| **page.ai_type** | `description` (str, **req**), `text` (str, **req**) | Types into an element described by natural language. |
| **page.ai_extract** | `what` (str, **req**) | Extracts specific data described by natural language. |
| **page.ai_query** | `query` (str, **req**) | Asks a question using the vision model. |
| **page.ai_analyze** | (none) | Returns comprehensive page analysis. |
| **page.find_element** | `description` (str, **req**), `max_results` (int) | Finds elements by natural language description. |
| **page.llm_status** | (none) | Checks if the on-device LLM is ready. |

### 7.5. Content Extraction

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **page.extract_text** | `selector` (str) | Extracts text from the page or specific element. |
| **page.extract_json** | `template` (ExtractionTemplate) | Extracts structured data (auto-detects if no template). |
| **page.get_html** | `clean_level` (CleanLevel) | Gets the page HTML (Minimal, Basic, or Aggressive). |
| **page.get_markdown** | `include_links`, `include_images`, `max_length` | Converts page content to Markdown. |
| **page.detect_website_type** | (none) | Detects the website type for extraction templates. |
| **page.list_templates** | (none) | Lists available extraction templates. |
| **page.extract_site** | `url`, `depth`, `max_pages`, ... | Starts a multi-page crawling and extraction job. |
| **page.extract_site_and_wait** | `url`, `depth`, ... | Crawls a site and waits for result. |

### 7.6. Visual & Media

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **page.screenshot** | `path` (str), `mode`, `selector`, `scale` | Takes a screenshot (viewport, element, or fullpage). |
| **page.start_video_recording** | `fps` (int), `codec` (str) | Starts recording a video of the session. |
| **page.stop_video_recording** | (none) | Stops recording and returns file path. |
| **page.pause_video_recording** | (none) | Pauses video recording. |
| **page.resume_video_recording** | (none) | Resumes video recording. |
| **page.get_video_stats** | (none) | Returns video recording statistics. |
| **page.start_live_stream** | `fps` (int), `quality` (int) | Starts a live MJPEG stream. |
| **page.stop_live_stream** | (none) | Stops the live stream. |
| **page.get_live_frame** | (none) | Gets a single frame from the live stream. |

### 7.7. Network & Security

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **page.set_proxy** | `config` (ProxyConfig, **req**) | Sets the proxy for the current page. |
| **page.get_proxy_status** | (none) | Returns current proxy connection status. |
| **page.connect_proxy** | (none) | Connects to the configured proxy. |
| **page.disconnect_proxy** | (none) | Disconnects from the proxy. |
| **page.add_network_rule** | `rule` (NetworkRule, **req**) | Adds a rule to Block, Mock, or Redirect requests. |
| **page.remove_network_rule** | `rule_id` (str, **req**) | Removes a network interception rule. |
| **page.set_network_interception**| `enabled` (bool) | Toggles network interception on/off. |
| **page.enable_network_logging** | `enable` (bool) | Enables/disables network request logging. |
| **page.get_network_log** | `limit` (int) | Returns the history of network requests. |
| **page.clear_network_log** | (none) | Clears the network log. |
| **page.get_blocker_stats** | (none) | Returns stats on blocked ads/trackers. |

### 7.8. Cookies & Profile

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **page.get_cookies** | `url` (str) | Returns a list of cookies. |
| **page.set_cookie** | `url`, `name`, `value`, ... | Sets a cookie. |
| **page.delete_cookies** | `url`, `name` | Deletes specific or all cookies. |
| **page.save_profile** | `profile_path` (str) | Saves current state (cookies, fingerprint) to file. |
| **page.get_profile** | (none) | Returns current profile state in memory. |
| **page.update_profile_cookies**| (none) | Updates the profile file with current cookies. |
| **page.get_context_info** | (none) | Returns context info including VM and fingerprints. |

### 7.9. Captcha Solving

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **page.detect_captcha** | (none) | Detects if a CAPTCHA is present. |
| **page.classify_captcha** | (none) | Classifies the CAPTCHA type. |
| **page.solve_captcha** | `max_attempts` (int), `provider` (str) | Auto-detects and solves CAPTCHAs. |
| **page.solve_text_captcha** | `max_attempts` (int) | Solves text-based CAPTCHAs. |
| **page.solve_image_captcha** | `max_attempts` (int), `provider` (str) | Solves image selection CAPTCHAs. |

### 7.10. Waiting & Scrolling

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **page.wait_for_selector** | `selector` (str, **req**), `timeout` (int) | Waits for an element to appear. |
| **page.wait_for_network_idle** | `idle_time` (int), `timeout` (int) | Waits for network activity to settle. |
| **page.wait_for_function** | `js_function` (str, **req**), `timeout` (int) | Waits for JS function to return truthy. |
| **page.wait_for_url** | `url_pattern` (str, **req**), `is_regex` (bool) | Waits for URL to match pattern. |
| **page.wait** | `timeout` (int, **req**) | Waits for specified milliseconds. |
| **page.scroll_by** | `x` (int), `y` (int) | Scrolls by specified pixels. |
| **page.scroll_to** | `x` (int), `y` (int) | Scrolls to absolute position. |
| **page.scroll_to_element** | `selector` (str, **req**) | Scrolls element into view. |
| **page.scroll_to_top** | (none) | Scrolls to top of page. |
| **page.scroll_to_bottom** | (none) | Scrolls to bottom of page. |

### 7.11. Other Features

| SDK Method | Parameters | Description |
| :--- | :--- | :--- |
| **page.evaluate** | `script` (str, **req**), `args`, `return_value` | Executes JavaScript in the page context. |
| **page.expression** | `expression` (str, **req**) | Evaluates a JS expression and returns value. |
| **page.set_viewport** | `width` (int), `height` (int) | Resizes the browser viewport. |
| **page.get_viewport** | (none) | Returns current viewport size. |
| **page.zoom_in** | (none) | Zooms in page content. |
| **page.zoom_out** | (none) | Zooms out page content. |
| **page.zoom_reset** | (none) | Resets zoom to 100%. |
| **page.set_download_path** | `path` (str, **req**) | Sets the directory for file downloads. |
| **page.get_downloads** | (none) | Lists all downloads. |
| **page.wait_for_download** | `download_id`, `timeout` | Waits for a download to complete. |
| **page.set_dialog_action** | `dialog_type`, `action`, `prompt_text` | Configures auto-handling for dialogs. |
| **page.handle_dialog** | `dialog_id`, `accept`, `response_text` | Manually handles a pending dialog. |
| **page.new_tab** | `url` (str) | Opens a new tab. |
| **page.switch_tab** | `tab_id` (str, **req**) | Switches focus to a specific tab. |
| **page.get_element_at_position**| `x` (int), `y` (int) | Gets element details at coordinates. |
| **page.get_interactive_elements**| (none) | Lists all interactive elements on page. |
| **page.get_console_logs** | `level`, `filter`, `limit` | Returns browser console logs. |
| **page.get_demographics** | (none) | Returns geolocation and weather info. |
| **page.run_test** | `test` (str/dict, **req**) | Executes a pre-defined test scenario. |

---
**Olib AI** | [Documentation](https://olib.ai/docs) | [Support](mailto:partners@olib.ai)
