# Owl Browser — Project Portfolio

A collection of open-source projects built on the [Owl Browser](https://owlbrowser.com) platform, demonstrating the power of AI-native browser automation across security, testing, data extraction, and web intelligence domains. Each project leverages the Owl Browser SDK for stealth browsing, CAPTCHA solving, fingerprint management, and AI-driven page understanding.

> **Getting Started:** Install the SDK with `pip install owl-browser` and check the [SDK documentation](https://www.owlbrowser.com/docs) for setup instructions.

---

## Projects

### [AutoQA — AI Test Automation](./autoqa-ai-testing/)

AutoQA is a production-ready test automation framework that replaces brittle Selenium/Playwright scripts with human-readable YAML test definitions. It can auto-generate test suites by crawling a website, with optional vision-AI enhancement for richer element detection. Tests self-heal deterministically when selectors break — no AI guessing. The framework includes visual regression testing with anti-aliasing tolerance, ML-based assertions (OCR, color analysis, layout validation, accessibility checks), and parallel execution with resource-aware concurrency. It integrates with CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins) and provides both CLI and REST API interfaces. Built on Python 3.12+ with Owl Browser SDK v2 as the core browser engine. See the [project README](./autoqa-ai-testing/README.md) for the full DSL reference and setup guide.

### [Easy Crawl — AI Web Scraper](./easy_crawl/)

Easy Crawl is a minimalist web data extraction platform that demonstrates the "Browser-as-Backend" architecture — delivering production-grade scraping, crawling, and search with under 200 lines of backend code. It offers three core capabilities: a Universal Scraper that converts any URL into clean Markdown or structured JSON (handling SPAs and JavaScript-heavy pages natively), an Intelligent Crawler that navigates websites to configurable depth for building knowledge bases, and a Live Search API returning structured results for AI agents. The frontend is React 18 + TypeScript + Tailwind CSS, and the backend is a lightweight FastAPI wrapper around the Owl Browser SDK. Ideal for developers building RAG pipelines, data scientists needing quick datasets, and teams integrating web data into LLM workflows. See the [project README](./easy_crawl/README.md) for API reference and deployment instructions.

### [Owl Stress — Browser Stress Testing](./stress_test/)

Owl Stress is a load testing framework that executes JSON-defined user journeys across escalating concurrency levels (1–100 concurrent users) using real browser sessions. Each virtual user gets an isolated browser context with a unique fingerprint. The tool collects per-step timing, success/failure rates, and percentile latencies (p95, p99), then generates professional PDF reports with charts and tables. Test flows are defined declaratively in JSON — no Python code required — covering navigation, form filling, waiting, and clicking. Built on Python 3.12+ with the Owl Browser SDK for session management and flow execution. See the [project README](./stress_test/README.md) for flow template examples and CLI usage.

### [IntoTheDarkweb — Tor Network Access](./IntoTheDarkweb/)

IntoTheDarkweb is an Apify actor providing programmatic access to the Tor network and .onion sites through Owl Browser's anti-detection infrastructure. Users can build and deploy their own instance on the Apify platform. It offers two modes: **Easy Access** for quick one-shot page fetching (returning HTML, text, or markdown) and **Browser Experience** for full interactive sessions with sequential actions like navigation, clicking, typing, screenshot capture, and data extraction. All traffic routes through Tor with unique exit node IPs per session, and browser fingerprints are randomized per context. Built with Python 3.12+, the Apify SDK, and Owl Browser SDK v2, supporting US/EU regional deployment. See the [project README](./IntoTheDarkweb/README.md) for input schemas and deployment guide.

### [OnionSentinel — Dark Web Monitoring](./OnionSentinel/)

OnionSentinel is an automated dark web threat intelligence solution built as an Apify actor — users can build and deploy their own instance on the Apify platform. It provides three operational modes: **Monitoring** (scanning .onion sites for keywords and threats with evidence capture), **Discovery** (finding new hidden services via Ahmia search), and **Uptime Check** (verifying site availability). Features include keyword-based threat detection with screenshot/video evidence, BFS site crawling with configurable depth, Tor circuit isolation per target for anonymity, and concurrent processing of up to 10 targets per run. It uses real-time Tor error detection to distinguish dead sites from temporary failures. Built with Python 3.12+, Apify SDK, BeautifulSoup, and the Owl Browser SDK. See the [project README](./OnionSentinel/README.md) for configuration options and alert formats.

### [SecureProbe — Web Vulnerability Scanner](./SecureProbe/)

SecureProbe is a web vulnerability scanner combining browser automation with 19 specialized security analyzers for comprehensive attack simulation. It performs CVSS-aligned severity ratings with CWE references for every finding, supporting both passive (observation-only) and active (test payload) scan modes. The modular analyzer system covers TLS configuration, cookie security, CSRF/XSS, input validation, API security, session management, cryptography, and advanced attack patterns. It features async/concurrent execution, intelligent rate limiting, deduplication, and multi-format reporting (JSON/HTML). Built on Python 3.12+ with structlog for detailed logging, providing both CLI and programmatic interfaces. See the [project README](./SecureProbe/README.md) for analyzer details and scan configuration.

### [SecureEmbed — Secure Third-Party Script Embedding](./SecureEmbed/)

SecureEmbed is an npm package that solves the security challenge of embedding third-party scripts (chat widgets, analytics, forms) without exposing API keys in source code. It combines Service Workers with WebAssembly to provide runtime credential injection with domain-bound AES-256-GCM encryption. Keys are derived via PBKDF2 with 100K iterations, and the security logic compiles to Wasm — immune to JavaScript reverse engineering. Supported providers include Intercom, Crisp, HubSpot, Drift, Google Analytics, Mixpanel, Segment, Typeform, JotForm, and custom integrations. Ships with React components (`<SecureEmbed>`, `useSecureEmbed` hook), a vanilla JS API, and CLI tools for config encryption, all in a 30KB footprint. See the [project README](./SecureEmbed/README.md) for integration guides and encryption setup.

### [StealthFormBot — Automated Form Submission](./StealthFormBot/)

StealthFormBot is an Apify actor that automates form submissions across websites with advanced anti-detection measures. It renders pages in a real browser, handles JavaScript-generated fields, manages cookies and sessions, and rotates fingerprints to evade bot detection. Supported scenarios include simple contact forms, multi-step wizards, dynamic forms, file uploads, login flows, and CAPTCHA-protected pages. Features include automatic retry with exponential backoff, proxy support (custom or Apify-integrated), stealth mode fingerprint rotation, and screenshot capture at each step. Output includes session cookies, confirmation IDs, and submission confirmation screenshots. Built on Python 3.12+ with the Apify SDK and Owl Browser SDK. See the [project README](./StealthFormBot/README.md) for input configuration and deployment options.

---

## Documentation

The [`docs/`](./docs/) directory contains solution architecture blueprints and design documents for larger-scale systems built on Owl Browser, including a distributed search engine (CrawlForge), dark web monitoring platform (DarkWatch), e-commerce intelligence engine (PriceGuard), and social media analysis system (TrendScope). These serve as reference architectures for building production systems with the SDK.

---

*Built with [Owl Browser](https://owlbrowser.com) | Powered by Open Source*
