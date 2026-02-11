# OnionSentinel

Automated Dark Web Threat Intelligence & Monitoring through [Owl Browser](https://www.owlbrowser.net).

OnionSentinel is an [Apify](https://apify.com) actor designed for automated scanning, discovery, and status verification of the dark web (.onion sites). It leverages Owl Browser's secure Tor infrastructure with engine-level anti-detection.

---

## Operating Modes

1. **Monitoring (Default):** Scans specific target URLs for keywords and threats. Supports up to 10 targets per run.
2. **Discovery:** Finds new .onion sites based on a search query using a reliable two-step search process on Ahmia.
3. **Uptime Check:** Verifies if a list of .onion links are currently active and responsive. Supports up to 10 targets per run.

---

## Features

- **Reliable Discovery:** Uses Ahmia's internal search tokens to bypass protection and retrieve thousands of hidden service links.
- **Robust Uptime Verification:** Specifically checks for navigation success and captures exact Tor error codes (e.g., `ERR_SOCKS_CONNECTION_FAILED`) to distinguish between dead sites and temporary timeouts.
- **Performance Optimized:** Enforces a 10-URL limit per scan to ensure fast completion and high reliability.
- **Keyword Detection:** Scans raw HTML content for specific keywords (emails, brands, leaks) with high-fidelity extraction.
- **Evidence Capture:** Automatically saves full-page screenshots where threats are detected.
- **Video Recording:** Record the entire browsing session for compliance, auditing, and legal evidence.
- **Tor Circuit Isolation:** Every target can be processed in an isolated context with unique Tor exit IPs.

---

## Input

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `mode` | string | Yes | `"monitoring"` | `"monitoring"`, `"discovery"`, or `"uptime-check"` |
| `query` | string | Yes (discovery) | — | Search query for Discovery mode (e.g., 'marketplaces') |
| `targets` | array | Yes (monitoring/uptime) | — | List of .onion objects `{"url": "...", "label": "..."}`. **Max 10 per run.** |
| `keywords` | array | Yes (monitoring) | — | Keywords or phrases to detect in page content. |
| `region` | string | Yes | `"US"` | Browser region: `"US"` or `"EU"`. |
| `concurrency` | integer | No | `1` | Number of targets to process in parallel (Max 5). |
| `saveScreenshots` | boolean | No | `true` | Capture and store screenshots of findings. |
| `saveVideo` | boolean | No | `false` | Record session video (may increase run time). |
| `maxPagesPerTarget` | integer | No | `10` | Limit sub-pages crawled per root URL. |

---

## Example Inputs

### Discovery Mode
```json
{
    "mode": "discovery",
    "query": "financial leaks 2026",
    "region": "US"
}
```

### Monitoring Mode
```json
{
    "mode": "monitoring",
    "targets": [
        {"url": "http://vww6ybal4bd7szmgncyruucpgfkqahzddi37ktce53ab47mre5msosyd.onion", "label": "Dread Forum"}
    ],
    "keywords": ["database dump", "admin@mycompany.com"],
    "region": "EU",
    "saveScreenshots": true
}
```

### Uptime Check Mode
```json
{
    "mode": "uptime-check",
    "targets": [
        {"url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion", "label": "Ahmia Search"},
        {"url": "http://deadlinkexample.onion", "label": "Old Market"}
    ],
    "region": "US"
}
```

---

## Charging & Events

This actor uses pay-per-event charging for specific actions:
- `darkweb-discovery`: Charged per discovery run.
- `darkweb-scan`: Charged per target monitored.
- `darkweb-uptime`: Charged per link checked.

---

## Technology

- **[Owl Browser](https://www.owlbrowser.net)** — Secure anti-detection browser with Tor and automation.
- **[Apify SDK](https://apify.com)** — Actor runtime and data storage.
- **[Python SDK](https://www.owlbrowser.net)** — Owl Browser async Python client.

---

## License

MIT