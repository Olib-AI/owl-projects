# Apify Actor Ideas Backlog

Future actor ideas leveraging Owl Browser's full capabilities (158 tools, 22 categories).

> **Reference implementation:** Follow `IntoTheDarkweb/` as the template for all new actors.
> It uses the current SDK (`owl-browser` v2.0.1), Apify SDK v3, Pay Per Event monetization,
> and is fully deployed and validated on the `olibai` org account.

---

## Current State

### Shipped Actors
| Actor | Status | SDK | Monetization |
|-------|--------|-----|-------------|
| **IntoTheDarkweb** | Live on `olibai` org | owl-browser 2.0.1 (SDK v2) | PPE ($0.05/page-fetch, $0.10/browser-session) |
| **StealthFormBot** | Live on personal account | Old bundled SDK (v1) | Not monetized |

### Implementation Notes
- All new actors should use `owl-browser>=2.0.1` from PyPI (not bundled SDK)
- Use `RemoteConfig(url=..., token=..., api_prefix="")` for direct connection
- Use `OwlBrowser` async client with `browser.execute("tool_name", **params)`
- Set default memory to 256 MB from the Apify web console (actor Settings > Default run configuration). The `minMemoryMbytes`/`maxMemoryMbytes` in `actor.json` do NOT control the default — you must set it manually. Most actors need only 128-512 MB since heavy lifting is on the browser instance
- Use Pay Per Event (PPE) monetization with `Actor.charge(event_name=...)` — avoid Rental model (excluded from Apify MCP/AI search)
- Apify takes 20% of PPE revenue; profit = (0.8 * revenue) - platform costs
- ENV vars for browser instances: `OWL_BROWSER_{US,EU}_{URL,TOKEN}`

---

## Idea 1: StealthScraper — AI-Powered Anti-Detection Web Scraping

**Priority: HIGH | Effort: Medium | Market: Massive**

General-purpose scraping actor where users provide URLs and extraction instructions in natural language (e.g., "extract all product names and prices"). Returns structured JSON. Handles JS rendering, infinite scroll, pagination, CAPTCHAs, and anti-bot systems automatically.

### Owl Browser Tools Used
- `browser_ai_extract` — Natural language extraction without CSS selectors
- `browser_extract_site` — Multi-page crawling with depth/page limits
- `browser_extract_json` — Structured extraction with built-in templates (Amazon, Google, Wikipedia, GitHub, Twitter, Reddit)
- `browser_solve_captcha` — Auto CAPTCHA solving (on-device, no API cost)
- `browser_detect_site` — Adaptive extraction based on site type
- Fingerprint rotation per request, `fullscroll` for lazy-loaded content, network interception for ad/tracker blocking

### Why Us
- "Describe what you want" is a paradigm shift from CSS selectors
- Anti-detection layer means it works on sites that block every other scraper
- On-device CAPTCHA solving = no external API costs
- Built-in templates for major sites reduce development time

### Suggested Pricing (PPE)
- `page-extract`: $0.03-0.05 per page extracted
- `site-crawl`: $0.01 per page in multi-page crawl

---

## Idea 2: AI Price Tracker — Stealth E-commerce Price Monitoring

**Priority: HIGH | Effort: Medium | Market: Large**

Monitors product prices across Amazon, Walmart, Target, Best Buy, eBay. Scheduled runs detect price drops, track history, return structured data.

### Owl Browser Tools Used
- `browser_extract_json` with `amazon_product` template
- `browser_ai_extract` for sites without templates
- `browser_solve_captcha` for Cloudflare challenges on retailers
- Profile persistence for consistent identities across monitoring sessions
- Timezone/language spoofing for regional pricing accuracy

### Why Us
- Amazon/Walmart/Target have aggressive bot detection — Owl's native fingerprinting bypasses it
- Most existing Apify price trackers break constantly due to blocking
- Human-like mouse movements prevent behavioral detection

### Suggested Pricing (PPE)
- `price-check`: $0.02-0.03 per product checked

---

## Idea 3: CAPTCHA Bypass Proxy — Universal CAPTCHA Wall Remover

**Priority: HIGH | Effort: LOW | Market: Large**

Users provide a URL + actions. Actor navigates, auto-detects and solves any CAPTCHA (reCAPTCHA, Cloudflare Turnstile, hCaptcha, text CAPTCHAs), returns the post-CAPTCHA page content.

### Owl Browser Tools Used
- `browser_detect_captcha` — Heuristic detection with confidence score
- `browser_classify_captcha` — Type identification (text, image, checkbox, puzzle, audio)
- `browser_solve_captcha` — Auto-solve with on-device vision model
- `browser_solve_text_captcha` / `browser_solve_image_captcha` — Specialized solvers
- Fingerprint spoofing reduces CAPTCHA frequency in the first place

### Why Us
- On-device solving = no 2Captcha/Anti-Captcha API fees, no round-trip latency
- Anti-detection layer reduces how often CAPTCHAs appear
- Supports all major CAPTCHA providers in a single actor

### Suggested Pricing (PPE)
- `captcha-solve`: $0.005-0.01 per solve (competitive with 2Captcha at $1-3/1000)

---

## Idea 4: LeadHarvester — AI B2B Lead Generation

**Priority: HIGH | Effort: High | Market: Large (highest willingness-to-pay)**

Search LinkedIn, Crunchbase, industry directories, company websites. Extract contacts, company details, funding, tech stack, employee count, recent news. Structured leads with confidence scores.

### Owl Browser Tools Used
- `browser_nla` — Natural language navigation ("search for CTOs in fintech in SF")
- `browser_ai_extract` — Diverse page layouts across data sources
- Profile persistence with cookies for maintaining LinkedIn sessions
- Proxy rotation with timezone/language matching
- Human-like interactions (bezier mouse, keystroke timing) for LinkedIn's behavioral analysis

### Why Us
- LinkedIn has the most sophisticated anti-bot detection — Owl's engine-level fingerprinting is essential
- LinkedIn scrapers are the most requested and most broken actors on Apify
- NLA handles complex search flows without brittle CSS selectors

### Suggested Pricing (PPE)
- `lead-extract`: $0.05-0.10 per lead

---

## Idea 5: SiteMapper — Website Crawler & Knowledge Base Builder

**Priority: MEDIUM | Effort: LOW | Market: Medium-Large**

Given a root URL, crawls entire website and produces: Markdown docs, JSON sitemap with metadata, CSV of pages, AI-generated site summary. Output ready for RAG/LLM pipelines.

### Owl Browser Tools Used
- `browser_extract_site` — Multi-page async crawling with progress tracking
- `browser_get_markdown` — Clean Markdown from any page
- `browser_detect_site` — Page type identification
- `browser_summarize_page` — AI summaries per page
- `fullscroll` wait strategy for lazy-loaded content
- Network interception for cleaner extraction

### Why Us
- AI summarization goes beyond simple crawling
- Markdown output is directly usable for RAG/AI chatbot knowledge bases
- Anti-detection enables crawling sites that block standard crawlers

### Suggested Pricing (PPE)
- `page-crawl`: $0.01-0.02 per page crawled

---

## Idea 6: GeoScraper — Multi-Region Location-Aware Data Collection

**Priority: MEDIUM | Effort: Medium | Market: Medium**

Same URL visited from multiple geographic locations. Captures localized content: pricing, product availability, search results, ad placements. Comparison across regions.

### Owl Browser Tools Used
- `browser_set_proxy` with `spoof_timezone=true`, `spoof_language=true`
- `browser_get_demographics` — Confirm detected location
- `browser_ai_extract` — Handle locale-specific formatting
- Per-region profile generation for consistent fingerprints
- Network interception to block geo-detection scripts

### Why Us
- Engine-level timezone + language + locale spoofing (not JS shims that get detected)
- Automatic geolocation matching with proxy

### Suggested Pricing (PPE)
- `geo-fetch`: $0.03-0.05 per URL per region

---

## Idea 7: FormFiller Pro — Universal AI Form Completion

**Priority: MEDIUM | Effort: Medium | Market: Medium**

Evolution of StealthFormBot. Users provide URL + data. AI identifies fields, fills with human-like typing, handles multi-step wizards, solves CAPTCHAs, submits. Zero configuration for new forms.

### Owl Browser Tools Used
- `browser_nla` — Natural language form completion
- `browser_ai_type` — Find fields by description, not CSS selectors
- `browser_pick` — Native and custom dropdowns
- `browser_drag_drop` — Slider CAPTCHAs, date pickers
- CAPTCHA solving, human-like keystroke timing
- Profile persistence for multi-step forms

### Why Us
- AI field identification = zero config for any form (vs StealthFormBot's selector-based approach)
- Works across Typeform, Jotform, Formstack, Google Forms without custom code

### Suggested Pricing (PPE)
- `form-submit`: $0.05-0.10 per submission

---

## Idea 8: BrandShield — Anti-Counterfeiting & Brand Monitor

**Priority: MEDIUM | Effort: High | Market: Medium (high per-customer value)**

Monitors marketplaces (Amazon, eBay, AliExpress, Etsy) and darkweb for counterfeits, unauthorized sellers, trademark abuse. Takes evidentiary screenshots and video. Compliance reports.

### Owl Browser Tools Used
- `browser_ai_extract` — "Extract all listings matching brand X"
- `browser_screenshot` — Evidentiary captures
- `browser_start_video_recording` — Video evidence for legal proceedings
- `browser_extract_json` with Amazon template
- CAPTCHA solving, Tor access for darkweb monitoring (reuse IntoTheDarkweb patterns)

### Why Us
- Combines surface web + dark web monitoring in one actor
- Video evidence capability is unique
- AI adapts to marketplace layout changes

### Suggested Pricing (PPE)
- `marketplace-scan`: $0.05 per marketplace page scanned
- `darkweb-scan`: $0.10 per .onion page scanned

---

## Idea 9: VisualQA — AI Visual Regression Testing

**Priority: LOW | Effort: Medium | Market: Medium**

Takes full-page screenshots across viewport sizes, AI analyzes for visual issues (broken layouts, missing images, overlapping text, accessibility). Compares against baselines. AI-annotated diff reports.

### Owl Browser Tools Used
- `browser_screenshot` — Fullpage capture
- `browser_ai_analyze` — Structured page analysis
- `browser_ai_query` — "Are there visual issues on this page?"
- `browser_set_viewport` — Multi-device testing
- `browser_start_video_recording` — Session recordings for debugging

### Suggested Pricing (PPE)
- `visual-check`: $0.03-0.05 per URL per viewport

---

## Idea 10: AccountGuard — Automated Security Auditor

**Priority: LOW | Effort: High | Market: Small-Medium (enterprise niche)**

Logs into user accounts, checks 2FA status, recovery options, active sessions, connected apps. Produces security audit reports.

### Owl Browser Tools Used
- `browser_nla` — Complex multi-step login and navigation
- `browser_ai_query` — "Is 2FA enabled on this page?"
- CAPTCHA solving for login challenges
- Profile persistence for session state
- Proxy stealth to avoid unusual-location alerts

### Suggested Pricing (PPE)
- `account-audit`: $0.10-0.20 per account audited

---

## Unused Owl Browser Capabilities Worth Exploring

These tools haven't been mapped to an actor yet but have potential:

| Capability | Tools | Potential Use |
|-----------|-------|---------------|
| **Video recording** | `browser_start_video_recording`, `browser_stop_video_recording`, `browser_download_video_recording` | Session replay, evidence capture, demo generation |
| **Live streaming** | `browser_start_live_stream`, `browser_get_live_frame` | Real-time monitoring dashboards |
| **Network interception** | `browser_add_network_rule`, `browser_get_network_log` | API testing, request mocking, performance analysis |
| **Frame handling** | `browser_list_frames`, `browser_switch_to_frame` | Iframe-heavy sites (ads, embeds, banking portals) |
| **Clipboard** | `browser_clipboard_read`, `browser_clipboard_write` | Copy-paste workflows, data transfer |
| **Demographics** | `browser_get_demographics`, `browser_get_location`, `browser_get_weather` | Location verification, geo-conditional testing |
| **Console logs** | `browser_get_console_log` | Error monitoring, JS debugging |
| **Download management** | `browser_wait_for_download`, `browser_get_downloads` | File scraping, document harvesting |

---

## Development Checklist for New Actors

When building a new actor, follow this pattern (based on IntoTheDarkweb):

1. **Project structure**: `.actor/actor.json`, `.actor/input_schema.json`, `.actor/output_schema.json`, `main.py`, `Dockerfile`, `requirements.txt`, `pyproject.toml`, `.env`, `README.md`
2. **SDK**: `owl-browser>=2.0.1` from PyPI, async with `OwlBrowser` + `RemoteConfig(api_prefix="")`
3. **ENV vars**: `OWL_BROWSER_{US,EU}_{URL,TOKEN}` from `os.environ` (set in Apify actor settings)
4. **Memory**: Set default memory (256 MB) from the Apify web console under actor Settings. `minMemoryMbytes`/`maxMemoryMbytes` in actor.json only set limits, not the default — Apify defaults to 4 GB if you don't manually change it
5. **Monetization**: PPE with `Actor.charge(event_name=...)` — charge before the expensive operation
6. **Validation**: Validate all input before connecting to browser (fail-fast)
7. **Cleanup**: Always close contexts in `finally` blocks
8. **Screenshots**: Save to KVS, put lightweight references in dataset (not raw base64)
9. **Push**: `apify login -t <ORG_TOKEN>` then `apify push`
10. **Test**: Run via API, verify billing events fire correctly
