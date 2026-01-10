# StealthFormBot: Anti-Detection Form Automation Actor

## Actor Name
**StealthFormBot** - Enterprise Form Submission with Anti-Detection

## Description
StealthFormBot is an Apify actor that automates form submissions across websites with sophisticated anti-detection measures. It handles complex multi-step forms, file uploads, CAPTCHAs (via third-party services), and dynamic JavaScript forms while evading bot detection systems like Cloudflare, PerimeterX, and DataDome.

Unlike simple HTTP-based form submitters, StealthFormBot renders pages like a real browser, handles JavaScript-generated form fields, manages sessions with cookies, and rotates fingerprints to avoid pattern detection.

---

## Use Case and Market Demand

### Problem Statement
Many legitimate business operations require automated form submissions:
- Job applications across multiple job boards
- Business registration forms across government portals
- Lead generation forms for sales teams
- Warranty/rebate claim submissions at scale
- Survey and feedback form completion
- Account creation for testing purposes

Traditional HTTP-based automation fails because:
1. Modern forms use JavaScript to generate fields dynamically
2. Anti-bot systems detect automation by fingerprinting
3. Multi-step wizards require session state
4. File uploads need browser-level handling
5. CAPTCHAs block automated submissions

### Target Market
- **HR/Recruitment agencies** - Posting jobs across 50+ job boards
- **Legal/Compliance firms** - Filing regulatory forms
- **Marketing agencies** - Managing client lead forms
- **E-commerce brands** - Submitting product listings
- **QA teams** - Testing form workflows
- **Data entry service providers** - Processing high-volume form submissions

### Competitive Gap on Apify
Current Apify actors for form filling are basic HTTP-based or lack:
- Sophisticated fingerprint rotation
- Multi-step form wizard support
- Dynamic field detection
- File upload handling
- Session persistence across runs

---

## SDK Features Used (Browser-Only, No AI)

### Core Navigation & Interaction
```python
# Navigation with wait conditions
page.goto(url, wait_until="networkidle", timeout=30000)
page.reload(ignore_cache=True)

# Form interactions
page.click(selector)  # CSS or coordinate selectors
page.type(selector, text)  # Input fields
page.pick(selector, value)  # Dropdowns/select elements
page.press_key(KeyName.TAB)  # Navigation between fields
page.keyboard_combo("Ctrl+A")  # Select all, copy, paste
page.clear_input(selector)  # Clear existing values
page.submit_form()  # Press Enter to submit
```

### File Upload Handling
```python
page.upload_file(selector, ["/path/to/resume.pdf", "/path/to/cover.docx"])
```

### Multi-Step Form Handling
```python
# Wait for next step to load
page.wait_for_selector(".step-2-content", timeout=10000)
page.wait_for_url("*/step2*")
page.wait_for_network_idle(idle_time=500)
```

### Anti-Detection Features
```python
# Fingerprint-aware context creation
browser = Browser(remote=RemoteConfig(url=BROWSER_URL, token=TOKEN))
page = browser.new_page(
    proxy=ProxyConfig(
        type=ProxyType.SOCKS5H,
        host=proxy_host,
        port=proxy_port,
        stealth=True,               # Block WebRTC leaks
        block_webrtc=True,          # Prevent IP leakage
        spoof_timezone=True,        # Match proxy timezone
        spoof_language=True,        # Match proxy locale
        timezone_override="America/New_York",
        language_override="en-US"
    ),
    profile_path="/profiles/user_123.json"  # Persistent identity
)

# Get context fingerprint info
info = page.get_context_info()
print(f"VM Profile: {info.vm_profile.user_agent}")
print(f"Canvas Hash: {info.canvas.hash_seed}")
```

### Session & Cookie Management
```python
# Restore session cookies
page.set_cookie(
    url="https://target.com",
    name="session_id",
    value="abc123",
    secure=True,
    http_only=True,
    same_site=CookieSameSite.LAX,
    expires=int(time.time()) + 86400
)

# Save session for reuse
profile = page.save_profile("session_user123")
# Download for external storage
content = page.download_profile("session_user123.json")
```

### Element State Verification
```python
# Pre-submission checks
if page.is_visible("submit button"):
    if page.is_enabled("submit button"):
        page.click("submit button")

# Verify checkbox state
if not page.is_checked("#terms"):
    page.click("#terms")
```

### JavaScript Execution for Dynamic Forms
```python
# Handle dynamically generated form fields
page.evaluate("document.querySelector('#dynamic-field').value = 'test'")
page.wait_for_function("return document.querySelector('.success') !== null")
```

### Dialog Handling
```python
# Auto-accept confirmation dialogs
page.set_dialog_action(DialogType.CONFIRM, DialogAction.ACCEPT)
page.set_dialog_action(DialogType.ALERT, DialogAction.ACCEPT)
```

### Screenshot for Verification
```python
# Capture submission confirmation
page.screenshot(path="confirmation.png", mode="fullpage")
```

---

## Suggested Apify Payment Model

### Pricing Tiers

| Plan | Price/Month | Included Runs | Form Fields/Run | Features |
|------|-------------|---------------|-----------------|----------|
| **Starter** | $29 | 500 | 20 | Basic forms, no file upload |
| **Professional** | $99 | 2,000 | 50 | File uploads, proxy rotation |
| **Enterprise** | $299 | 10,000 | Unlimited | Custom profiles, priority support |

### Per-Run Costs (Pay-as-you-go)
- Base cost: $0.02 per form submission
- File upload: +$0.01 per file
- CAPTCHA solving: +$0.05 per solve (pass-through)
- Proxy usage: +$0.005 per request

### Why This Model Works
1. **Predictable costs** - Customers know cost per submission
2. **Scalable** - Enterprises can submit thousands of forms
3. **Value-based** - Pricing reflects complexity (files, CAPTCHAs)

---

## High-Level Architecture

```
+------------------+     +-------------------+     +------------------+
|   Apify Input    |     |  StealthFormBot   |     |   Owl Browser    |
|   (JSON Schema)  | --> |      Actor        | --> |  (Remote Mode)   |
+------------------+     +-------------------+     +------------------+
        |                        |                        |
        v                        v                        v
+------------------+     +-------------------+     +------------------+
| - Target URL     |     | - Profile Mgmt    |     | - Stealth Mode   |
| - Form Fields    |     | - Proxy Rotation  |     | - Fingerprinting |
| - File Paths     |     | - Retry Logic     |     | - JS Rendering   |
| - Proxy Config   |     | - Error Handling  |     | - Cookie Storage |
+------------------+     +-------------------+     +------------------+
        |                        |                        |
        v                        v                        v
+------------------+     +-------------------+     +------------------+
|   Apify Storage  | <-- |  Output Dataset   | <-- |  Submission Proof|
| - Screenshots    |     | - Status          |     | - Confirmation   |
| - Profiles       |     | - Confirmation ID |     | - Screenshots    |
+------------------+     +-------------------+     +------------------+
```

### Actor Input Schema
```json
{
  "targetUrl": "https://example.com/apply",
  "formData": {
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "phone": "+1-555-0123"
  },
  "fileUploads": [
    {"fieldSelector": "#resume", "fileUrl": "https://storage.apify.com/resume.pdf"}
  ],
  "multiStep": {
    "enabled": true,
    "stepSelectors": [".next-btn", ".submit-btn"],
    "stepWaitConditions": ["networkidle", "selector:.confirmation"]
  },
  "proxyConfig": {
    "useApifyProxy": true,
    "proxyGroup": "RESIDENTIAL"
  },
  "captchaConfig": {
    "service": "2captcha",
    "apiKey": "{{CAPTCHA_API_KEY}}"
  },
  "retryConfig": {
    "maxRetries": 3,
    "retryOnErrors": ["timeout", "captcha_failed"]
  }
}
```

### Output Schema
```json
{
  "success": true,
  "targetUrl": "https://example.com/apply",
  "confirmationId": "APP-2024-12345",
  "submittedAt": "2024-01-09T12:00:00Z",
  "screenshotUrl": "https://storage.apify.com/screenshots/confirm.png",
  "cookies": [...],
  "errors": []
}
```

### Key Implementation Details

1. **Profile Rotation**
   - Maintain pool of browser profiles with distinct fingerprints
   - Rotate profiles to avoid pattern detection
   - Persist sessions for sites requiring login

2. **Proxy Integration**
   - Support Apify Proxy with residential/datacenter groups
   - Automatic retry on proxy failures
   - IP rotation per submission or session

3. **Error Recovery**
   - Screenshot on failure for debugging
   - Automatic retry with different profile/proxy
   - Detailed error logging for troubleshooting

4. **Compliance Features**
   - Rate limiting to respect target site policies
   - Configurable delays between submissions
   - Audit trail with timestamps and screenshots

---

## Technical Requirements

- **Owl Browser SDK**: Remote mode connection
- **Apify SDK**: Actor framework, storage, proxy integration
- **Python 3.12+**: Type-safe implementation
- **External Services**: 2captcha/Anti-Captcha for CAPTCHA solving (optional)

---

## Differentiation from Competitors

| Feature | StealthFormBot | Generic Form Actors |
|---------|----------------|---------------------|
| JavaScript forms | Yes | Limited |
| Fingerprint rotation | Yes | No |
| Multi-step wizards | Yes | Rarely |
| File uploads | Yes | Sometimes |
| Session persistence | Yes | No |
| Anti-detection | Advanced | Basic |
| Proxy stealth | Yes (WebRTC, TZ, Lang) | Basic |
