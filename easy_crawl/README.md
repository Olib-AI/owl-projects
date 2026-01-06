# Easy Crawl

### The AI-Native Web Data Platform

**Access the chaotic web as clean, structured data. Powered by Owl Browser.**

---

Easy Crawl is a production-grade web scraping, searching, and crawling solution. It transforms complex, dynamic websites into LLM-ready formats (Markdown, JSON) with zero friction.

### ⚡ Radical Efficiency

Easy Crawl demonstrates how the right foundation simplifies complex engineering. 

While typical web data extraction often requires significant infrastructure—headless browser clusters, proxy rotation, and manual CAPTCHA solving—Easy Crawl achieves production-grade results with a backend of less than 200 lines of Python.

This efficiency is made possible by **Owl Browser**, an AI-native browser engine designed to handle rendering, extraction, and anti-detection natively. By offloading these complexities to the browser engine, we've eliminated the need for hundreds of lines of boilerplate and infrastructure management.

---

## 🚀 Capabilities

### 1. Universal Scraper
**"If you can see it, you can scrape it."**
Stop fighting with `beautifulsoup` or broken selectors. Easy Crawl renders pages in a real browser, executes all JavaScript, waits for hydration, and uses on-device AI to extract the *actual* content.
- **Perfect for RAG:** Outputs clean, semantic Markdown optimized for Vector Databases.
- **SPA Ready:** Handles React, Vue, Angular, and dynamic content effortlessly.

![Scrape Action](git_assets/scrape.png)

### 2. Intelligent Crawler
**Map the unknown.**
Give Easy Crawl a starting point and watch it map out a website. It autonomously navigates links, respecting your depth and page limits, to build comprehensive knowledge bases.
- **Smart Navigation:** Follows links like a human user.
- **Context Aware:** Maintains session state across the crawl.

![Crawl Action](git_assets/crawl.png)

### 3. Live Search API
**Real-time knowledge for AI Agents.**
Perform live web searches and receive parsed, structured results instantly. Bypass the noise of search engine results pages and get straight to the data.

![Search Action](git_assets/search.png)

---

## 🛠️ Architecture

This project demonstrates the **"Browser-as-Backend"** architecture:

*   **Engine:** [Owl Browser SDK](https://www.owlbrowser.net) (Handles rendering, AI extraction, Anti-bot)
*   **Backend:** Python FastAPI (Lightweight orchestration)
*   **Frontend:** React + Tailwind CSS (Modern, responsive UI)

## 🤖 Agentic Extensibility

Beyond simple scraping and crawling, Easy Crawl is designed for the era of AI agents. Because **Owl Browser** natively supports integration with LLM models, you can easily extend this tool with agentic capabilities:

- **Self-Healing Workflows:** Agents that can navigate through UI changes autonomously.
- **Semantic Actions:** "Find the checkout button and tell me the total" instead of hardcoded selectors.
- **Real-time Reasoning:** Analyzing page content on-the-fly to make navigation decisions.

The combination of a real browser engine and native LLM support makes Easy Crawl a foundation for building sophisticated web-based AI agents.

## 📦 Quick Start

Run the entire stack with a single command:

```bash
./start.sh
```

This will:
1.  Launch the **Python FastAPI** backend on port `8000`.
2.  Launch the **React Frontend** on port `5173`.
3.  Open `http://localhost:5173` to start crawling.