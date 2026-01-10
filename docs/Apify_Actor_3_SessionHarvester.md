# SessionHarvester: Authenticated Session Extraction Actor

## Actor Name
**SessionHarvester** - Automated Login & Session Cookie Extraction

## Description
SessionHarvester is an Apify actor that automates login flows across websites and extracts authenticated session data (cookies, localStorage, sessionStorage) for use in downstream scraping and automation tasks. It handles complex login scenarios including multi-factor authentication prompts, CAPTCHAs, OAuth flows, and multi-step verification.

The actor outputs portable session data that can be injected into other actors, enabling authenticated scraping without embedding credentials in every actor.

---

## Use Case and Market Demand

### Problem Statement
Scraping authenticated content is challenging because:
1. **Session management complexity** - Cookies, tokens, storage APIs
2. **Login flow variations** - OAuth, SAML, MFA, magic links
3. **Anti-bot on login pages** - CAPTCHAs, rate limiting, fingerprinting
4. **Session expiration** - Need periodic refresh
5. **Credential security** - Storing passwords in actors is risky

### Why Separate Login from Scraping
- **Single Responsibility** - Login actor handles auth, scraping actors use sessions
- **Credential Isolation** - Only one actor has access to passwords
- **Session Reuse** - One login serves multiple downstream actors
- **MFA Handling** - Human-in-the-loop for 2FA when needed
- **Rate Limit Avoidance** - Avoid repeated logins that trigger security

### Target Market

| Industry | Use Case | Session Targets |
|----------|----------|-----------------|
| **E-commerce** | Seller portal scraping | Amazon Seller Central, Shopify Admin |
| **Finance** | Banking data aggregation | Bank portals, Investment dashboards |
| **HR/Recruiting** | ATS data extraction | LinkedIn Recruiter, Greenhouse |
| **Social Media** | Analytics dashboards | Instagram Insights, Twitter Analytics |
| **Travel** | Booking management | Airline portals, Hotel extranets |
| **Legal** | Court record access | PACER, State court systems |
| **Healthcare** | Patient portal data | MyChart, Hospital portals |

### Competitive Gap on Apify
Current Apify login solutions:
- Embedded in individual actors (code duplication)
- Limited MFA support
- No session export/import standard
- Poor handling of complex OAuth flows
- Lack fingerprint rotation for anti-detection

---

## SDK Features Used (Browser-Only, No AI)

### Login Form Interaction
```python
# Navigate to login page
page.goto("https://example.com/login")
page.wait_for_selector("#username")

# Fill login form
page.type("#username", credentials.username)
page.type("#password", credentials.password)

# Click login button
page.click("button[type='submit']")

# Or submit via keyboard
page.press_key(KeyName.ENTER)
```

### Wait for Authentication Success
```python
# Wait for redirect to dashboard
page.wait_for_url("*/dashboard*", timeout=30000)

# Wait for authenticated element
page.wait_for_selector(".user-profile", timeout=15000)

# Wait for specific cookie
import time
for _ in range(30):
    cookies = page.get_cookies()
    if any(c.name == "session_id" for c in cookies):
        break
    page.wait(1000)
```

### Cookie Extraction
```python
# Get all cookies
all_cookies = page.get_cookies()

# Get cookies for specific domain
site_cookies = page.get_cookies("https://example.com")

# Export as serializable format
exported_cookies = [
    {
        "name": c.name,
        "value": c.value,
        "domain": c.domain,
        "path": c.path,
        "secure": c.secure,
        "httpOnly": c.http_only,
        "sameSite": c.same_site.value,
        "expires": c.expires
    }
    for c in site_cookies
]
```

### Profile Management for Complete Session State
```python
# Save complete browser profile (cookies + fingerprint)
profile = page.save_profile("user_session_123")
print(f"Profile ID: {profile.profile_id}")
print(f"Cookies saved: {len(profile.cookies)}")

# Download profile as portable JSON
profile_bytes = page.download_profile("user_session_123.json")

# Later, restore session
page = browser.new_page(profile_path="user_session_123.json")
page.goto("https://example.com/dashboard")  # Already authenticated!
```

### JavaScript Storage Extraction
```python
# Extract localStorage
local_storage = page.evaluate("""
    const storage = {};
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        storage[key] = localStorage.getItem(key);
    }
    return storage;
""")

# Extract sessionStorage
session_storage = page.evaluate("""
    const storage = {};
    for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        storage[key] = sessionStorage.getItem(key);
    }
    return storage;
""")
```

### MFA/2FA Handling
```python
# Wait for MFA prompt
page.wait_for_selector(".mfa-input", timeout=10000)

# Option 1: Auto-fill from authenticator (if TOTP secret available)
import pyotp
totp = pyotp.TOTP(mfa_secret)
code = totp.now()
page.type(".mfa-input", code)
page.click(".mfa-submit")

# Option 2: Pause and wait for manual entry (human-in-the-loop)
# Actor sends webhook notification, human enters code, actor continues
page.wait_for_url("*/dashboard*", timeout=120000)  # 2 min timeout for manual
```

### OAuth Flow Handling
```python
# Click OAuth login button
page.click("button.google-login")

# Handle popup for OAuth
# Wait for redirect back to main site
page.wait_for_url("*example.com*", timeout=60000)

# OAuth may open new tab
tabs = page.get_tabs()
if len(tabs) > 1:
    # Switch to OAuth tab
    page.switch_tab(tabs[1].tab_id)
    # Complete OAuth flow
    page.type("#email", google_email)
    page.click("#next")
    page.wait(1000)
    page.type("#password", google_password)
    page.click("#submit")
    # Switch back to main tab
    page.switch_tab(tabs[0].tab_id)
```

### Dialog Handling for Login Prompts
```python
# Handle JavaScript alerts during login
page.set_dialog_action(DialogType.ALERT, DialogAction.ACCEPT)

# Handle confirmation dialogs
page.set_dialog_action(DialogType.CONFIRM, DialogAction.ACCEPT)
```

### Anti-Detection for Login Pages
```python
# Use stealth proxy configuration
page = browser.new_page(
    proxy=ProxyConfig(
        type=ProxyType.SOCKS5H,
        host=proxy_host,
        port=proxy_port,
        stealth=True,
        block_webrtc=True,
        spoof_timezone=True,
        timezone_override="America/Los_Angeles"
    )
)

# Get fingerprint info to verify stealth
info = page.get_context_info()
print(f"User Agent: {info.vm_profile.user_agent}")
print(f"Timezone: {info.vm_profile.timezone}")
```

### Network Interception for Token Capture
```python
# Enable network logging to capture auth tokens
page.enable_network_logging(True)

# Perform login
page.goto("https://example.com/login")
page.type("#email", email)
page.type("#password", password)
page.click("#submit")
page.wait_for_url("*/dashboard*")

# Get network log to find auth tokens
network_log = page.get_network_log()
auth_requests = [
    entry for entry in network_log 
    if "auth" in entry.url or "token" in entry.url
]
```

### Screenshot for Verification & Debugging
```python
# Capture login page state
page.screenshot(path="login_page.png")

# Capture success state
page.screenshot(path="logged_in.png")

# Capture failure state for debugging
page.screenshot(path="login_error.png")
```

---

## Suggested Apify Payment Model

### Subscription Tiers

| Plan | Price/Month | Sessions/Month | Sites | Features |
|------|-------------|----------------|-------|----------|
| **Starter** | $39 | 100 | 5 | Basic login, cookies only |
| **Professional** | $149 | 500 | 25 | OAuth, MFA, full storage |
| **Enterprise** | $499 | 2,500 | Unlimited | Custom flows, priority |

### Per-Session Costs (Pay-as-you-go)
- Standard login: $0.10 per session
- OAuth flow: $0.15 per session
- MFA handling: $0.20 per session
- Session refresh: $0.05 per refresh
- Profile storage: $0.01 per profile/day

### Why This Model Works
1. **Value-based pricing** - Authentication is high-value operation
2. **Complexity tiers** - OAuth/MFA require more resources
3. **Storage as recurring** - Profiles need persistent storage

---

## High-Level Architecture

```
+------------------+     +-------------------+     +------------------+
|   Credentials    |     |  SessionHarvester |     |   Owl Browser    |
|   (Encrypted)    | --> |      Actor        | --> |  Login Flow      |
+------------------+     +-------------------+     +------------------+
        |                        |                        |
        v                        v                        v
+------------------+     +-------------------+     +------------------+
| - Username/Pass  |     | - Site Handlers   |     | - Form Fill      |
| - MFA Secrets    |     | - OAuth Flows     |     | - Cookie Extract |
| - API Keys       |     | - Session Export  |     | - Storage Read   |
+------------------+     +-------------------+     +------------------+
        |                        |                        |
        v                        v                        v
+------------------+     +-------------------+     +------------------+
|   Apify Secrets  |     |  Session Store    |     |  Downstream Use  |
| - Encrypted KV   |     | - Cookies JSON    |     | - Other Actors   |
| - Vault          |     | - Profiles        |     | - API Clients    |
+------------------+     +-------------------+     +------------------+
```

### Actor Input Schema
```json
{
  "site": "amazon_seller_central",
  "credentials": {
    "username": "{{USERNAME}}",
    "password": "{{PASSWORD}}"
  },
  "mfa": {
    "type": "totp",
    "secret": "{{MFA_SECRET}}"
  },
  "proxyConfig": {
    "useApifyProxy": true,
    "proxyGroup": "RESIDENTIAL",
    "country": "US"
  },
  "output": {
    "format": "full_profile",
    "storage": "key_value_store",
    "keyName": "amazon_session"
  },
  "validation": {
    "checkUrl": "https://sellercentral.amazon.com/home",
    "successSelector": ".myo-dashboard"
  }
}
```

### Output Schema
```json
{
  "success": true,
  "site": "amazon_seller_central",
  "sessionCreatedAt": "2024-01-09T12:00:00Z",
  "sessionExpiresAt": "2024-01-10T12:00:00Z",
  "cookies": [
    {
      "name": "session-id",
      "value": "xxx-xxxxxxx-xxxxxxx",
      "domain": ".amazon.com",
      "path": "/",
      "secure": true,
      "httpOnly": true,
      "sameSite": "lax",
      "expires": 1704888000
    }
  ],
  "localStorage": {
    "user_preferences": "{...}"
  },
  "sessionStorage": {},
  "profile": {
    "profileId": "amazon_user_123",
    "fingerprint": {
      "userAgent": "Mozilla/5.0...",
      "platform": "Win32"
    }
  },
  "validationPassed": true,
  "screenshotUrl": "https://storage.apify.com/logged_in.png"
}
```

### Supported Site Handlers

| Site | Handler | Features |
|------|---------|----------|
| Amazon Seller Central | `amazon_seller_central` | MFA, CAPTCHA |
| LinkedIn | `linkedin` | CAPTCHA, verification |
| Instagram | `instagram` | 2FA, suspicious login |
| Twitter/X | `twitter` | OAuth, 2FA |
| Facebook | `facebook` | 2FA, checkpoint |
| Google | `google` | OAuth, 2FA, device trust |
| GitHub | `github` | 2FA, SSH key |
| Custom | `custom` | Configurable flow |

### Key Implementation Details

1. **Credential Security**
   - Never log or expose credentials
   - Use Apify Secrets for credential storage
   - Clear credentials from memory after use

2. **Session Validation**
   - Navigate to protected URL after login
   - Check for authenticated elements
   - Verify session cookie presence

3. **Error Recovery**
   - Screenshot on failure
   - Retry with different proxy on block
   - Handle common error patterns (wrong password, locked account)

4. **Session Refresh Strategy**
   - Track session expiration
   - Automatic re-login before expiry
   - Preserve fingerprint across refreshes

5. **Site-Specific Handlers**
   - Pre-built handlers for common sites
   - Custom handler configuration for new sites
   - Community-contributed handlers

---

## Technical Requirements

- **Owl Browser SDK**: Remote mode, profile management
- **Apify SDK**: Secrets, KV Store, Webhooks
- **Python 3.12+**: Async, type-safe
- **pyotp**: TOTP MFA code generation

---

## Differentiation from Competitors

| Feature | SessionHarvester | Embedded Login |
|---------|------------------|----------------|
| Credential isolation | Yes | No |
| Session export | Standardized | Ad-hoc |
| MFA handling | Built-in | Rarely |
| OAuth flows | Supported | Complex |
| Profile persistence | Yes | No |
| Multi-actor reuse | Yes | No |
| Fingerprint consistency | Yes | No |
| Site handlers library | Yes | No |

---

## Security Considerations

1. **Credential Encryption** - All credentials encrypted at rest
2. **Audit Logging** - Track all session creation attempts
3. **IP Binding** - Optional session-to-IP binding
4. **Rate Limiting** - Prevent brute force attempts
5. **Anomaly Detection** - Alert on unusual login patterns
