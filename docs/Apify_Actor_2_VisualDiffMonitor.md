# VisualDiffMonitor: Website Change Detection Actor

## Actor Name
**VisualDiffMonitor** - Visual Website Change Detection & Alerting

## Description
VisualDiffMonitor is an Apify actor that monitors websites for visual changes by capturing screenshots at scheduled intervals and detecting pixel-level differences. Unlike text-based change detectors, it captures actual visual rendering including CSS changes, layout shifts, image updates, and dynamic content that text comparison misses.

The actor supports authenticated sessions, viewport customization, element-specific monitoring, and integrates with webhooks for real-time alerts when changes are detected.

---

## Use Case and Market Demand

### Problem Statement
Businesses need to monitor websites for changes but existing solutions fail when:
1. **Visual-only changes** - CSS updates, color changes, image swaps
2. **JavaScript-rendered content** - SPAs, dynamic dashboards, charts
3. **Layout changes** - Element repositioning without text changes
4. **Authenticated pages** - Behind-login dashboards, portals
5. **Competitor monitoring** - Pricing pages, product displays

### Real-World Use Cases

| Industry | Use Case | Why Visual Matters |
|----------|----------|-------------------|
| **E-commerce** | Competitor price monitoring | Prices may be in images/SVGs |
| **Legal/Compliance** | Regulatory page monitoring | PDF links, visual notices |
| **Brand Protection** | Trademark monitoring | Logo misuse, visual assets |
| **Marketing** | Competitor campaign tracking | Ad creatives, landing pages |
| **IT Operations** | Status page monitoring | Dashboard visualizations |
| **Real Estate** | Listing availability | Property images, virtual tours |
| **Finance** | Trading interface monitoring | Chart changes, real-time data |

### Competitive Gap on Apify
Current website monitoring actors on Apify:
- Focus on text/HTML diff (miss visual changes)
- Lack authenticated session support
- No element-specific monitoring
- Limited screenshot comparison algorithms
- No viewport/device simulation

---

## SDK Features Used (Browser-Only, No AI)

### Screenshot Capture
```python
# Full viewport screenshot
page.screenshot(path="viewport.png")

# Full page screenshot (scrollable content)
page.screenshot(path="fullpage.png", mode="fullpage")

# Element-specific screenshot
page.screenshot(path="element.png", mode="element", selector="#price-table")

# Scaled screenshot (reduce storage)
page.screenshot(path="scaled.png", scale=50)  # 50% size
```

### Viewport Configuration for Device Simulation
```python
# Desktop viewport
page.set_viewport(width=1920, height=1080)

# Tablet viewport
page.set_viewport(width=768, height=1024)

# Mobile viewport
page.set_viewport(width=375, height=812)

# Get current viewport
viewport = page.get_viewport()
print(f"Width: {viewport.width}, Height: {viewport.height}")
```

### Session Management for Authenticated Pages
```python
# Restore session cookies
page.set_cookie(
    url="https://dashboard.example.com",
    name="auth_token",
    value="jwt_token_here",
    secure=True,
    http_only=True,
    expires=int(time.time()) + 3600
)

# Navigate after authentication
page.goto("https://dashboard.example.com/analytics")

# Or use saved profile
page = browser.new_page(profile_path="/profiles/dashboard_session.json")
```

### Scrolling for Full Page Capture
```python
# Scroll to load lazy content before screenshot
page.scroll_to_bottom()
page.wait(500)  # Allow images to load
page.scroll_to_top()

# Scroll to specific element
page.scroll_to_element("#target-section")
```

### Wait Conditions for Dynamic Content
```python
# Wait for network to settle (images loaded)
page.wait_for_network_idle(idle_time=500, timeout=30000)

# Wait for specific element
page.wait_for_selector(".chart-loaded", timeout=10000)

# Wait for JavaScript condition
page.wait_for_function("return window.chartRendered === true")
```

### Network Interception for Clean Screenshots
```python
# Block ads and trackers for cleaner comparison
from owl_browser import NetworkRule, NetworkAction

page.enable_network_interception(True)

# Block common ad domains
page.add_network_rule(NetworkRule(
    url_pattern="*://ads.*",
    action=NetworkAction.BLOCK
))
page.add_network_rule(NetworkRule(
    url_pattern="*://analytics.*",
    action=NetworkAction.BLOCK
))
page.add_network_rule(NetworkRule(
    url_pattern="*://tracking.*",
    action=NetworkAction.BLOCK
))
```

### Element Hiding for Focused Comparison
```python
# Hide dynamic elements that cause false positives
page.evaluate("""
    document.querySelectorAll('.timestamp, .ad-banner, .cookie-popup')
        .forEach(el => el.style.display = 'none');
""")
```

### Content Extraction for Change Summary
```python
# Get text content for change summary
text_content = page.extract_text("#main-content")

# Get structured HTML for detailed diff
html_content = page.get_html(clean_level="basic")

# Get markdown for readable summary
markdown = page.get_markdown(include_links=True, include_images=True)
```

### Element Bounding Box for Region Monitoring
```python
# Get element position for region-specific comparison
bbox = page.get_bounding_box("#price-display")
print(f"Position: ({bbox.x}, {bbox.y}), Size: {bbox.width}x{bbox.height}")

# Check if element is visible before capture
if page.is_visible("#content-area"):
    page.screenshot(path="content.png", mode="element", selector="#content-area")
```

### Console Log Capture for Error Detection
```python
# Capture JavaScript errors as change indicators
page.goto(url)
logs = page.get_console_logs(level="error")
if logs:
    print(f"Page has {len(logs)} JavaScript errors")
```

---

## Suggested Apify Payment Model

### Subscription Tiers

| Plan | Price/Month | URLs Monitored | Check Frequency | Storage |
|------|-------------|----------------|-----------------|---------|
| **Basic** | $19 | 10 | Hourly | 1 GB |
| **Professional** | $79 | 100 | 15 min | 10 GB |
| **Enterprise** | $249 | Unlimited | 5 min | 100 GB |

### Per-Check Costs (Pay-as-you-go)
- Standard check: $0.005 per URL
- Full-page screenshot: +$0.002
- Authenticated session: +$0.003
- Multi-viewport check: +$0.002 per viewport
- Storage: $0.01 per GB/month

### Why This Model Works
1. **Predictable monitoring costs** - Fixed per-check pricing
2. **Frequency flexibility** - Higher frequency = higher value
3. **Storage bundled** - Screenshots can accumulate

---

## High-Level Architecture

```
+------------------+     +-------------------+     +------------------+
|   Scheduled      |     |  VisualDiffMonitor|     |   Owl Browser    |
|   Trigger        | --> |      Actor        | --> |  Screenshot API  |
+------------------+     +-------------------+     +------------------+
        |                        |                        |
        v                        v                        v
+------------------+     +-------------------+     +------------------+
| - Cron Schedule  |     | - URL Queue       |     | - Render Page    |
| - Webhook        |     | - Session Mgmt    |     | - Viewport Set   |
| - Manual Run     |     | - Image Compare   |     | - Wait Conditions|
+------------------+     +-------------------+     +------------------+
        |                        |                        |
        v                        v                        v
+------------------+     +-------------------+     +------------------+
|   Apify Storage  |     |  Diff Analysis    |     |   Alert System   |
| - Screenshots    |     | - Pixel Compare   |     | - Webhook        |
| - Diff Images    |     | - Region Analysis |     | - Email          |
| - History        |     | - Threshold Check |     | - Slack/Discord  |
+------------------+     +-------------------+     +------------------+
```

### Actor Input Schema
```json
{
  "monitors": [
    {
      "url": "https://competitor.com/pricing",
      "name": "Competitor Pricing",
      "viewport": {"width": 1920, "height": 1080},
      "fullPage": true,
      "regions": [
        {"selector": "#price-table", "name": "Price Table"},
        {"selector": ".hero-banner", "name": "Hero Banner"}
      ],
      "excludeSelectors": [".timestamp", ".ad-slot"],
      "authentication": {
        "cookies": [
          {"name": "session", "value": "abc123", "domain": "competitor.com"}
        ]
      },
      "waitCondition": {
        "type": "networkIdle",
        "timeout": 30000
      },
      "threshold": {
        "pixelDiffPercent": 1.0,
        "ignoreColors": false,
        "ignoreAntiAliasing": true
      }
    }
  ],
  "notifications": {
    "webhook": "https://hooks.slack.com/services/...",
    "email": "alerts@company.com",
    "minSeverity": "medium"
  },
  "storage": {
    "keepHistory": 30,
    "generateDiffImages": true
  }
}
```

### Output Schema
```json
{
  "url": "https://competitor.com/pricing",
  "name": "Competitor Pricing",
  "checkTime": "2024-01-09T12:00:00Z",
  "changeDetected": true,
  "severity": "high",
  "diffPercentage": 12.5,
  "regions": [
    {
      "name": "Price Table",
      "changed": true,
      "diffPercentage": 45.2,
      "diffImageUrl": "https://storage.apify.com/diff_price_table.png"
    },
    {
      "name": "Hero Banner",
      "changed": false,
      "diffPercentage": 0.1
    }
  ],
  "screenshotUrl": "https://storage.apify.com/current.png",
  "previousScreenshotUrl": "https://storage.apify.com/previous.png",
  "diffImageUrl": "https://storage.apify.com/diff.png",
  "textChanges": {
    "added": ["New price: $99"],
    "removed": ["Old price: $149"]
  }
}
```

### Key Implementation Details

1. **Screenshot Storage Strategy**
   - Store current + previous for each URL
   - Generate diff images on change detection
   - Automatic cleanup of old screenshots

2. **Image Comparison Algorithm**
   - Pixel-level diff with configurable threshold
   - Perceptual hashing for similar image detection
   - Region-specific comparison for targeted monitoring
   - Anti-aliasing tolerance to reduce false positives

3. **Change Severity Calculation**
   ```
   Severity = Low (< 1% diff), Medium (1-5%), High (> 5%)
   + Weight by region importance
   + Consider historical change frequency
   ```

4. **Session Persistence**
   - Store authentication cookies between runs
   - Automatic re-authentication on session expiry
   - Support for OAuth token refresh

5. **Notification System**
   - Webhook with diff image attachment
   - Email with visual comparison
   - Slack/Discord integration
   - Severity-based filtering

---

## Technical Requirements

- **Owl Browser SDK**: Screenshot API, session management
- **Image Processing**: Pillow/OpenCV for diff calculation
- **Apify SDK**: Storage, webhooks, scheduling
- **Python 3.12+**: Async processing

---

## Differentiation from Competitors

| Feature | VisualDiffMonitor | Text-Based Monitors |
|---------|-------------------|---------------------|
| CSS changes | Yes | No |
| Image changes | Yes | No |
| Layout shifts | Yes | No |
| JS-rendered content | Yes | Limited |
| Authenticated pages | Yes | Rarely |
| Region monitoring | Yes | No |
| Viewport simulation | Yes | No |
| Anti-aliasing tolerance | Yes | N/A |
| Diff image generation | Yes | No |
