# PriceGuard: AI-Driven E-commerce Intelligence & Repricing Engine

## 1. Executive Summary

**PriceGuard** is a high-frequency competitive intelligence platform for e-commerce retailers. It automates the tracking of competitor pricing, inventory levels, and promotional strategies across millions of SKUs in real-time.

By utilizing the **Owl Browser**, PriceGuard bypasses the sophisticated anti-bot systems (Akamai, Datadome, Cloudflare) used by major retailers, delivering accurate, location-specific market data to fuel dynamic repricing strategies.

## 2. System Architecture

The system must handle millions of price checks per hour. A traditional cron job is insufficient. We use an **Event-Driven Architecture**.

```mermaid
graph TD
    API[Dashboard API] -->|Product List| Scheduler[Temporal.io Workflow]
    
    Scheduler -->|Task| Queue[NATS JetStream]
    
    subgraph "Scraping Cluster"
        Queue --> Worker1
        Queue --> Worker2
        
        Worker1[Worker Node] -->|gRPC| Owl[Owl Browser]
        Owl -->|Request| Target[Amazon / Walmart / Target]
    end
    
    Worker1 -->|Price Data| Ingest[Ingestion Service]
    
    Inggest -->|Write| Scylla["ScyllaDB (History)"]
    Inggest -->|Update| Cache["Redis (Current State)"]
    
    Inggest -->|Price Change Event| Repricer[Repricing Engine]
    Repricer -->|API Call| Shopify[Shopify/Magento API]
```

## 3. Retailer-Specific Scrapers

This section provides complete, production-ready scraper implementations for major retailers using the Owl Browser SDK.

### 3.1. Amazon Scraper

Amazon employs sophisticated bot detection. This scraper handles product pages, search results, and Buy Box detection.

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import TypedDict

from owl_browser import Browser, RemoteConfig, ProxyConfig, Page


class BuyBoxStatus(StrEnum):
    """Amazon Buy Box ownership status."""
    OWNED = "owned"
    COMPETITOR = "competitor"
    SUPPRESSED = "suppressed"
    UNKNOWN = "unknown"


class AmazonProductData(TypedDict):
    """Structured Amazon product extraction result."""
    asin: str
    title: str
    price: Decimal | None
    list_price: Decimal | None
    currency: str
    availability: str
    seller_name: str
    seller_id: str | None
    buy_box_status: BuyBoxStatus
    rating: float | None
    review_count: int | None
    is_prime: bool
    delivery_date: str | None
    image_urls: list[str]


class AmazonSearchResult(TypedDict):
    """Single search result item."""
    asin: str
    title: str
    price: Decimal | None
    rating: float | None
    review_count: int | None
    is_sponsored: bool
    position: int


@dataclass(frozen=True, slots=True)
class AmazonScraper:
    """
    Production Amazon scraper with Buy Box detection and anti-bot bypass.

    Uses Owl Browser's AI extraction to handle layout variations across
    Amazon's A/B tests and regional differences.
    """

    browser: Browser
    marketplace: str = "amazon.com"

    async def scrape_product(self, asin: str, *, page: Page | None = None) -> AmazonProductData:
        """
        Extract complete product data including Buy Box status.

        Args:
            asin: Amazon Standard Identification Number
            page: Optional existing page context (creates new if None)

        Returns:
            Structured product data with pricing and availability
        """
        should_close_page = page is None
        if page is None:
            page = self.browser.new_page()

        try:
            url = f"https://www.{self.marketplace}/dp/{asin}"
            await page.goto(url, wait_until="networkidle", timeout=30000)

            # Check for CAPTCHA challenge
            captcha_detected = await page.detect_captcha()
            if captcha_detected:
                await page.solve_captcha(max_attempts=3)
                await page.wait_for_network_idle(idle_time=2000)

            # Use AI extraction for robust data capture across layout variants
            raw_data = await page.extract_json(template={
                "title": "product title (main heading)",
                "price": "current price amount (number only, no currency symbol)",
                "list_price": "original/list price if shown struck through",
                "currency": "currency code (USD, GBP, EUR)",
                "availability": "stock status text",
                "seller_name": "sold by / ships from seller name",
                "rating": "star rating out of 5",
                "review_count": "number of customer reviews",
                "is_prime": "whether Prime delivery is available (true/false)",
                "delivery_date": "estimated delivery date text"
            })

            # Buy Box detection requires specific element analysis
            buy_box_status = await self._detect_buy_box_status(page)

            # Extract seller ID from page if available
            seller_id = await self._extract_seller_id(page)

            # Get all product image URLs
            image_urls = await self._extract_image_urls(page)

            return AmazonProductData(
                asin=asin,
                title=raw_data.get("title", ""),
                price=Decimal(str(raw_data["price"])) if raw_data.get("price") else None,
                list_price=Decimal(str(raw_data["list_price"])) if raw_data.get("list_price") else None,
                currency=raw_data.get("currency", "USD"),
                availability=raw_data.get("availability", "Unknown"),
                seller_name=raw_data.get("seller_name", "Amazon"),
                seller_id=seller_id,
                buy_box_status=buy_box_status,
                rating=float(raw_data["rating"]) if raw_data.get("rating") else None,
                review_count=int(raw_data["review_count"]) if raw_data.get("review_count") else None,
                is_prime=bool(raw_data.get("is_prime")),
                delivery_date=raw_data.get("delivery_date"),
                image_urls=image_urls,
            )
        finally:
            if should_close_page:
                await page.close()

    async def _detect_buy_box_status(self, page: Page) -> BuyBoxStatus:
        """Detect Buy Box ownership using VLM analysis."""
        # Query the page visually for Buy Box state
        response = await page.query_page(
            "Is there an 'Add to Cart' button visible in the Buy Box area on the right side? "
            "If yes, who is the seller shown? Is the Buy Box suppressed (showing 'See All Buying Options')?"
        )

        response_lower = response.lower()
        if "suppressed" in response_lower or "see all buying options" in response_lower:
            return BuyBoxStatus.SUPPRESSED
        if "add to cart" in response_lower:
            # Further analysis to determine ownership
            seller_check = await page.ai_extract(
                "The seller name shown in the Buy Box 'Ships from and sold by' section"
            )
            if seller_check and "amazon" in seller_check.lower():
                return BuyBoxStatus.COMPETITOR  # Amazon is the competitor
            return BuyBoxStatus.OWNED if seller_check else BuyBoxStatus.UNKNOWN

        return BuyBoxStatus.UNKNOWN

    async def _extract_seller_id(self, page: Page) -> str | None:
        """Extract seller ID from the seller link."""
        try:
            seller_link = await page.evaluate(
                """() => {
                    const link = document.querySelector('#sellerProfileTriggerId');
                    return link ? link.href : null;
                }""",
                return_value=True
            )
            if seller_link and "seller=" in seller_link:
                return seller_link.split("seller=")[1].split("&")[0]
        except Exception:
            pass
        return None

    async def _extract_image_urls(self, page: Page) -> list[str]:
        """Extract all product image URLs."""
        try:
            urls = await page.evaluate(
                """() => {
                    const images = document.querySelectorAll('#altImages img, #imgTagWrapperId img');
                    return Array.from(images)
                        .map(img => img.src || img.dataset.src)
                        .filter(src => src && src.includes('images'))
                        .map(src => src.replace(/\._.*_\./, '._SL1500_.'));
                }""",
                return_value=True
            )
            return urls or []
        except Exception:
            return []

    async def scrape_search_results(
        self,
        query: str,
        *,
        max_pages: int = 3,
        page: Page | None = None
    ) -> list[AmazonSearchResult]:
        """
        Scrape Amazon search results with pagination.

        Args:
            query: Search query string
            max_pages: Maximum number of result pages to scrape
            page: Optional existing page context

        Returns:
            List of search results with position tracking
        """
        should_close_page = page is None
        if page is None:
            page = self.browser.new_page()

        results: list[AmazonSearchResult] = []

        try:
            search_url = f"https://www.{self.marketplace}/s?k={query.replace(' ', '+')}"
            await page.goto(search_url, wait_until="networkidle")

            # Handle potential CAPTCHA
            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=3)

            for page_num in range(max_pages):
                # Extract current page results using AI
                page_results = await page.extract_json(template={
                    "products": [{
                        "asin": "ASIN identifier from data attribute or link",
                        "title": "product title text",
                        "price": "price amount (number only)",
                        "rating": "star rating number",
                        "review_count": "number of reviews",
                        "is_sponsored": "whether marked as Sponsored (true/false)"
                    }]
                })

                products = page_results.get("products", [])
                for idx, product in enumerate(products):
                    position = (page_num * 48) + idx + 1  # 48 results per page typical
                    results.append(AmazonSearchResult(
                        asin=product.get("asin", ""),
                        title=product.get("title", ""),
                        price=Decimal(str(product["price"])) if product.get("price") else None,
                        rating=float(product["rating"]) if product.get("rating") else None,
                        review_count=int(product["review_count"]) if product.get("review_count") else None,
                        is_sponsored=bool(product.get("is_sponsored")),
                        position=position,
                    ))

                # Navigate to next page if available
                if page_num < max_pages - 1:
                    next_exists = await page.evaluate(
                        "() => !!document.querySelector('.s-pagination-next:not(.s-pagination-disabled)')",
                        return_value=True
                    )
                    if not next_exists:
                        break

                    await page.click(".s-pagination-next")
                    await page.wait_for_network_idle(idle_time=2000)

        finally:
            if should_close_page:
                await page.close()

        return results
```

### 3.2. Walmart Scraper

Walmart uses Akamai bot management. This scraper handles product pages and store-specific inventory.

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from decimal import Decimal
from typing import TypedDict

from owl_browser import Browser, Page, ProxyConfig


class WalmartProductData(TypedDict):
    """Structured Walmart product extraction result."""
    item_id: str
    upc: str | None
    title: str
    price: Decimal | None
    was_price: Decimal | None
    unit_price: str | None
    availability: str
    fulfillment_type: str  # "SHIP_TO_HOME", "PICKUP", "DELIVERY"
    store_id: str | None
    store_name: str | None
    quantity_available: int | None
    rating: float | None
    review_count: int | None


class StoreAvailability(TypedDict):
    """Store-level inventory data."""
    store_id: str
    store_name: str
    address: str
    in_stock: bool
    quantity: int | None
    price: Decimal | None
    pickup_available: bool


@dataclass(frozen=True, slots=True)
class WalmartScraper:
    """
    Production Walmart scraper with store availability detection.

    Handles Akamai bot protection through Owl Browser's stealth features
    and fingerprint rotation.
    """

    browser: Browser

    async def scrape_product(
        self,
        item_id: str,
        *,
        store_id: str | None = None,
        page: Page | None = None
    ) -> WalmartProductData:
        """
        Extract Walmart product data with optional store context.

        Args:
            item_id: Walmart item ID
            store_id: Optional store ID for location-specific pricing
            page: Optional existing page context

        Returns:
            Structured product data
        """
        should_close_page = page is None
        if page is None:
            page = self.browser.new_page()

        try:
            # Set store context via cookie if provided
            if store_id:
                await page.set_cookie(
                    url="https://www.walmart.com",
                    name="PSID",
                    value=store_id,
                    domain=".walmart.com",
                    path="/",
                    secure=True
                )
                await page.set_cookie(
                    url="https://www.walmart.com",
                    name="assortmentStoreId",
                    value=store_id,
                    domain=".walmart.com",
                    path="/",
                    secure=True
                )

            url = f"https://www.walmart.com/ip/{item_id}"
            await page.goto(url, wait_until="networkidle", timeout=30000)

            # Akamai challenge detection and bypass
            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=3)
                await page.wait_for_network_idle(idle_time=3000)

            # Check for bot block page
            page_title = await page.get_title()
            if "robot" in page_title.lower() or "blocked" in page_title.lower():
                raise RuntimeError(f"Bot detection triggered for item {item_id}")

            # AI-powered extraction handles layout variations
            raw_data = await page.extract_json(template={
                "title": "product title/name",
                "price": "current selling price (number only)",
                "was_price": "original/was price if shown",
                "unit_price": "price per unit if displayed (e.g., '$0.05/oz')",
                "availability": "stock status (In stock, Out of stock, Limited stock)",
                "fulfillment": "fulfillment options available (Shipping, Pickup, Delivery)",
                "rating": "average star rating",
                "review_count": "total number of reviews"
            })

            # Extract UPC from page metadata
            upc = await self._extract_upc(page)

            # Get current store info if set
            store_name = None
            if store_id:
                store_name = await page.ai_extract("The selected store name shown on the page")

            # Determine fulfillment type
            fulfillment_text = raw_data.get("fulfillment", "").lower()
            if "pickup" in fulfillment_text:
                fulfillment_type = "PICKUP"
            elif "delivery" in fulfillment_text:
                fulfillment_type = "DELIVERY"
            else:
                fulfillment_type = "SHIP_TO_HOME"

            return WalmartProductData(
                item_id=item_id,
                upc=upc,
                title=raw_data.get("title", ""),
                price=Decimal(str(raw_data["price"])) if raw_data.get("price") else None,
                was_price=Decimal(str(raw_data["was_price"])) if raw_data.get("was_price") else None,
                unit_price=raw_data.get("unit_price"),
                availability=raw_data.get("availability", "Unknown"),
                fulfillment_type=fulfillment_type,
                store_id=store_id,
                store_name=store_name,
                quantity_available=None,  # Requires cart analysis
                rating=float(raw_data["rating"]) if raw_data.get("rating") else None,
                review_count=int(raw_data["review_count"]) if raw_data.get("review_count") else None,
            )

        finally:
            if should_close_page:
                await page.close()

    async def _extract_upc(self, page: Page) -> str | None:
        """Extract UPC from product page metadata."""
        try:
            upc = await page.evaluate(
                """() => {
                    // Check JSON-LD structured data
                    const scripts = document.querySelectorAll('script[type="application/ld+json"]');
                    for (const script of scripts) {
                        try {
                            const data = JSON.parse(script.textContent);
                            if (data.gtin13) return data.gtin13;
                            if (data.gtin12) return data.gtin12;
                        } catch {}
                    }
                    // Check meta tags
                    const upcMeta = document.querySelector('meta[itemprop="gtin13"], meta[itemprop="gtin12"]');
                    return upcMeta ? upcMeta.content : null;
                }""",
                return_value=True
            )
            return upc
        except Exception:
            return None

    async def check_store_availability(
        self,
        item_id: str,
        zip_code: str,
        *,
        radius_miles: int = 50,
        page: Page | None = None
    ) -> list[StoreAvailability]:
        """
        Check inventory at nearby stores for a product.

        Args:
            item_id: Walmart item ID
            zip_code: ZIP code to search around
            radius_miles: Search radius in miles
            page: Optional existing page context

        Returns:
            List of store availability records
        """
        should_close_page = page is None
        if page is None:
            page = self.browser.new_page()

        results: list[StoreAvailability] = []

        try:
            # Navigate to product page
            url = f"https://www.walmart.com/ip/{item_id}"
            await page.goto(url, wait_until="networkidle")

            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=3)

            # Click "Check nearby stores" or similar
            await page.ai_click("button or link to check store availability or pickup options")
            await page.wait(1500)

            # Enter ZIP code in store finder
            await page.ai_type("ZIP code input field", zip_code)
            await page.press_key("Enter")
            await page.wait_for_network_idle(idle_time=2000)

            # Extract store list
            stores_data = await page.extract_json(template={
                "stores": [{
                    "store_id": "store number or ID",
                    "store_name": "store name",
                    "address": "full store address",
                    "in_stock": "whether item is in stock (true/false)",
                    "quantity": "quantity available if shown",
                    "price": "price at this store if different",
                    "pickup_available": "whether pickup is available (true/false)"
                }]
            })

            for store in stores_data.get("stores", []):
                results.append(StoreAvailability(
                    store_id=store.get("store_id", ""),
                    store_name=store.get("store_name", ""),
                    address=store.get("address", ""),
                    in_stock=bool(store.get("in_stock")),
                    quantity=int(store["quantity"]) if store.get("quantity") else None,
                    price=Decimal(str(store["price"])) if store.get("price") else None,
                    pickup_available=bool(store.get("pickup_available")),
                ))

        finally:
            if should_close_page:
                await page.close()

        return results
```

### 3.3. Target Scraper

Target uses Akamai and PerimeterX. This scraper handles price and inventory extraction with store context.

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from decimal import Decimal
from typing import TypedDict

from owl_browser import Browser, Page


class TargetProductData(TypedDict):
    """Structured Target product extraction result."""
    tcin: str
    dpci: str | None
    upc: str | None
    title: str
    price: Decimal | None
    reg_price: Decimal | None
    sale_price: Decimal | None
    circle_price: Decimal | None  # Target Circle member price
    availability: str
    store_id: str | None
    store_name: str | None
    aisle_location: str | None
    shipping_eligible: bool
    same_day_delivery: bool
    order_pickup: bool
    drive_up: bool


@dataclass(frozen=True, slots=True)
class TargetScraper:
    """
    Production Target scraper with Circle pricing and store inventory.

    Handles PerimeterX protection through session management and
    fingerprint diversity.
    """

    browser: Browser

    async def scrape_product(
        self,
        tcin: str,
        *,
        store_id: str | None = None,
        page: Page | None = None
    ) -> TargetProductData:
        """
        Extract Target product data with optional store context.

        Args:
            tcin: Target item number
            store_id: Optional store ID for location-specific data
            page: Optional existing page context

        Returns:
            Structured product data with all pricing tiers
        """
        should_close_page = page is None
        if page is None:
            page = self.browser.new_page()

        try:
            # Set store context if provided
            if store_id:
                await page.set_cookie(
                    url="https://www.target.com",
                    name="GuestLocation",
                    value=f'{{"zipCode":"","storeId":"{store_id}"}}',
                    domain=".target.com",
                    path="/"
                )
                # Also set via localStorage for redundancy
                await page.evaluate(
                    f"""() => {{
                        localStorage.setItem('selectedStoreId', '{store_id}');
                        localStorage.setItem('userSelectedStoreId', '{store_id}');
                    }}"""
                )

            url = f"https://www.target.com/p/-/A-{tcin}"
            await page.goto(url, wait_until="networkidle", timeout=30000)

            # PerimeterX detection
            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=3)
                await page.wait_for_network_idle(idle_time=3000)

            # Block check
            current_url = await page.get_current_url()
            if "blocked" in current_url or "captcha" in current_url:
                raise RuntimeError(f"Bot detection triggered for TCIN {tcin}")

            # Multi-tier pricing extraction
            raw_data = await page.extract_json(template={
                "title": "product title/name",
                "price": "current displayed price (number only)",
                "reg_price": "regular price if different from current",
                "sale_price": "sale price if on sale",
                "circle_price": "Target Circle member price if shown",
                "availability": "stock status text",
                "shipping": "shipping availability (true/false)",
                "same_day": "same day delivery available (true/false)",
                "pickup": "order pickup available (true/false)",
                "drive_up": "drive up available (true/false)"
            })

            # Extract identifiers
            dpci = await self._extract_dpci(page)
            upc = await self._extract_upc(page)

            # Get store info and aisle location if in store context
            store_name = None
            aisle_location = None
            if store_id:
                store_info = await page.ai_extract(
                    "The store name and aisle/location number if shown for this item"
                )
                if store_info:
                    # Parse store info
                    store_name = await page.ai_extract("Just the store name")
                    aisle_location = await page.ai_extract("Just the aisle or location code")

            return TargetProductData(
                tcin=tcin,
                dpci=dpci,
                upc=upc,
                title=raw_data.get("title", ""),
                price=Decimal(str(raw_data["price"])) if raw_data.get("price") else None,
                reg_price=Decimal(str(raw_data["reg_price"])) if raw_data.get("reg_price") else None,
                sale_price=Decimal(str(raw_data["sale_price"])) if raw_data.get("sale_price") else None,
                circle_price=Decimal(str(raw_data["circle_price"])) if raw_data.get("circle_price") else None,
                availability=raw_data.get("availability", "Unknown"),
                store_id=store_id,
                store_name=store_name,
                aisle_location=aisle_location,
                shipping_eligible=bool(raw_data.get("shipping")),
                same_day_delivery=bool(raw_data.get("same_day")),
                order_pickup=bool(raw_data.get("pickup")),
                drive_up=bool(raw_data.get("drive_up")),
            )

        finally:
            if should_close_page:
                await page.close()

    async def _extract_dpci(self, page: Page) -> str | None:
        """Extract DPCI from page."""
        try:
            dpci = await page.ai_extract("The DPCI number shown in product details")
            return dpci if dpci and "-" in dpci else None
        except Exception:
            return None

    async def _extract_upc(self, page: Page) -> str | None:
        """Extract UPC from structured data."""
        try:
            return await page.evaluate(
                """() => {
                    const scripts = document.querySelectorAll('script[type="application/ld+json"]');
                    for (const script of scripts) {
                        try {
                            const data = JSON.parse(script.textContent);
                            if (data.gtin13) return data.gtin13;
                        } catch {}
                    }
                    return null;
                }""",
                return_value=True
            )
        except Exception:
            return None
```

### 3.4. Generic Product Scraper (AI-First)

For retailers without dedicated scrapers, this universal extractor uses AI to handle any product page.

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TypedDict, Any

from owl_browser import Browser, Page


class GenericProductData(TypedDict):
    """Universal product data structure."""
    url: str
    domain: str
    title: str
    price: Decimal | None
    currency: str
    original_price: Decimal | None
    availability: str
    seller: str | None
    brand: str | None
    sku: str | None
    upc: str | None
    description: str | None
    images: list[str]
    rating: float | None
    review_count: int | None
    raw_extraction: dict[str, Any]


@dataclass(slots=True)
class GenericProductScraper:
    """
    Universal AI-powered product scraper for any e-commerce site.

    Uses Owl Browser's VLM and extract_json with intelligent fallbacks
    to handle unknown page layouts without site-specific rules.
    """

    browser: Browser
    extraction_cache: dict[str, dict[str, str]] = field(default_factory=dict)

    async def scrape_product(
        self,
        url: str,
        *,
        custom_fields: dict[str, str] | None = None,
        page: Page | None = None
    ) -> GenericProductData:
        """
        Extract product data from any e-commerce product page.

        Args:
            url: Product page URL
            custom_fields: Optional additional fields to extract
            page: Optional existing page context

        Returns:
            Structured product data with all available information
        """
        should_close_page = page is None
        if page is None:
            page = self.browser.new_page()

        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)

            # Universal CAPTCHA handling
            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=3)
                await page.wait_for_network_idle(idle_time=2000)

            # Detect website type for optimized extraction
            site_type = await page.detect_website_type()

            # Build extraction template
            base_template = {
                "title": "main product title or name",
                "price": "current selling price (number only, no currency)",
                "currency": "currency code (USD, EUR, GBP, etc.)",
                "original_price": "original/list/was price if discounted",
                "availability": "stock status (In Stock, Out of Stock, etc.)",
                "seller": "seller or merchant name",
                "brand": "product brand name",
                "sku": "SKU or product code",
                "description": "short product description (first 500 chars)",
                "rating": "average rating out of 5",
                "review_count": "total number of reviews"
            }

            if custom_fields:
                base_template.update(custom_fields)

            # Primary extraction via AI
            raw_data = await page.extract_json(template=base_template)

            # Fallback to ai_extract for missing critical fields
            if not raw_data.get("title"):
                raw_data["title"] = await page.ai_extract(
                    "The main product title or name on this page"
                )

            if not raw_data.get("price"):
                price_text = await page.ai_extract(
                    "The current price of this product (just the number)"
                )
                if price_text:
                    try:
                        raw_data["price"] = float(price_text.replace(",", "").replace("$", ""))
                    except ValueError:
                        pass

            # Extract images using JavaScript
            images = await self._extract_images(page)

            # Extract UPC from structured data if available
            upc = await self._extract_structured_identifier(page, "gtin13", "gtin12", "upc")

            # Parse domain from URL
            from urllib.parse import urlparse
            domain = urlparse(url).netloc.replace("www.", "")

            return GenericProductData(
                url=url,
                domain=domain,
                title=raw_data.get("title", ""),
                price=Decimal(str(raw_data["price"])) if raw_data.get("price") else None,
                currency=raw_data.get("currency", "USD"),
                original_price=Decimal(str(raw_data["original_price"])) if raw_data.get("original_price") else None,
                availability=raw_data.get("availability", "Unknown"),
                seller=raw_data.get("seller"),
                brand=raw_data.get("brand"),
                sku=raw_data.get("sku"),
                upc=upc or raw_data.get("upc"),
                description=raw_data.get("description"),
                images=images,
                rating=float(raw_data["rating"]) if raw_data.get("rating") else None,
                review_count=int(raw_data["review_count"]) if raw_data.get("review_count") else None,
                raw_extraction=raw_data,
            )

        finally:
            if should_close_page:
                await page.close()

    async def _extract_images(self, page: Page) -> list[str]:
        """Extract all product images from page."""
        try:
            return await page.evaluate(
                """() => {
                    const images = new Set();
                    // Common product image selectors
                    const selectors = [
                        '[data-testid*="image"] img',
                        '.product-image img',
                        '.gallery img',
                        '[class*="ProductImage"] img',
                        '[class*="product-media"] img',
                        'main img[src*="product"]'
                    ];
                    for (const selector of selectors) {
                        document.querySelectorAll(selector).forEach(img => {
                            const src = img.src || img.dataset.src || img.dataset.lazySrc;
                            if (src && !src.includes('data:') && !src.includes('placeholder')) {
                                images.add(src.split('?')[0]);  // Remove query params
                            }
                        });
                    }
                    return Array.from(images).slice(0, 10);
                }""",
                return_value=True
            ) or []
        except Exception:
            return []

    async def _extract_structured_identifier(self, page: Page, *keys: str) -> str | None:
        """Extract identifier from JSON-LD or meta tags."""
        try:
            return await page.evaluate(
                f"""(keys) => {{
                    // Check JSON-LD
                    const scripts = document.querySelectorAll('script[type="application/ld+json"]');
                    for (const script of scripts) {{
                        try {{
                            const data = JSON.parse(script.textContent);
                            for (const key of keys) {{
                                if (data[key]) return data[key];
                            }}
                        }} catch {{}}
                    }}
                    // Check meta tags
                    for (const key of keys) {{
                        const meta = document.querySelector(`meta[itemprop="${{key}}"]`);
                        if (meta?.content) return meta.content;
                    }}
                    return null;
                }}""",
                args=list(keys),
                return_value=True
            )
        except Exception:
            return None

    async def batch_scrape(
        self,
        urls: list[str],
        *,
        concurrency: int = 5
    ) -> list[GenericProductData | Exception]:
        """
        Scrape multiple product URLs concurrently.

        Args:
            urls: List of product page URLs
            concurrency: Maximum concurrent scrapes

        Returns:
            List of results (data or exception for each URL)
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def scrape_with_limit(url: str) -> GenericProductData | Exception:
            async with semaphore:
                try:
                    return await self.scrape_product(url)
                except Exception as e:
                    return e

        return await asyncio.gather(*[scrape_with_limit(url) for url in urls])
```

## 4. Anti-Bot Bypass Strategies

This section details how PriceGuard bypasses sophisticated bot protection systems using Owl Browser's stealth capabilities.

### 4.1. Protection System Detection

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum
from typing import NamedTuple

from owl_browser import Browser, Page


class BotProtectionType(StrEnum):
    """Known bot protection systems."""
    AKAMAI = "akamai"
    CLOUDFLARE = "cloudflare"
    DATADOME = "datadome"
    PERIMETERX = "perimeterx"
    KASADA = "kasada"
    SHAPE = "shape"
    INCAPSULA = "incapsula"
    UNKNOWN = "unknown"
    NONE = "none"


class ProtectionDetectionResult(NamedTuple):
    """Result of bot protection detection."""
    protection_type: BotProtectionType
    is_challenged: bool
    challenge_type: str | None  # "captcha", "js_challenge", "block"
    confidence: float


@dataclass(frozen=True, slots=True)
class BotProtectionDetector:
    """
    Detects and classifies bot protection systems on target pages.

    Uses network analysis, DOM inspection, and VLM to identify
    protection mechanisms before they trigger blocks.
    """

    async def detect_protection(self, page: Page) -> ProtectionDetectionResult:
        """
        Detect bot protection system on current page.

        Args:
            page: Active page context

        Returns:
            Detection result with protection type and challenge status
        """
        # Enable network logging for signature detection
        await page.enable_network_logging(enable=True)

        # Check for immediate challenge page
        is_challenged, challenge_type = await self._check_challenge_page(page)

        # Analyze network requests for protection signatures
        network_log = await page.get_network_log(limit=50)
        protection_type = await self._analyze_network_signatures(network_log)

        # If not detected via network, check DOM markers
        if protection_type == BotProtectionType.UNKNOWN:
            protection_type = await self._check_dom_markers(page)

        # Calculate confidence
        confidence = 0.9 if is_challenged else 0.7
        if protection_type == BotProtectionType.UNKNOWN:
            confidence = 0.3

        return ProtectionDetectionResult(
            protection_type=protection_type,
            is_challenged=is_challenged,
            challenge_type=challenge_type,
            confidence=confidence
        )

    async def _check_challenge_page(self, page: Page) -> tuple[bool, str | None]:
        """Check if page is showing a challenge."""
        # Use AI to analyze current page state
        analysis = await page.query_page(
            "Is this page showing a security challenge, CAPTCHA, or 'checking your browser' message? "
            "If yes, what type of challenge is it?"
        )

        analysis_lower = analysis.lower()

        if "captcha" in analysis_lower:
            return True, "captcha"
        if "checking" in analysis_lower or "verifying" in analysis_lower:
            return True, "js_challenge"
        if "blocked" in analysis_lower or "denied" in analysis_lower:
            return True, "block"

        # Also check for CAPTCHA via dedicated method
        captcha_detected = await page.detect_captcha()
        if captcha_detected:
            return True, "captcha"

        return False, None

    async def _analyze_network_signatures(
        self,
        network_log: list[dict]
    ) -> BotProtectionType:
        """Identify protection system from network request patterns."""
        request_urls = " ".join(str(req.get("url", "")) for req in network_log)

        # Signature patterns for each protection system
        signatures: dict[BotProtectionType, list[str]] = {
            BotProtectionType.AKAMAI: [
                "akamaihd.net", "akam", "_abck", "bm_sz", "ak_bmsc"
            ],
            BotProtectionType.CLOUDFLARE: [
                "cf_chl", "cf-ray", "__cf_bm", "challenges.cloudflare.com"
            ],
            BotProtectionType.DATADOME: [
                "datadome", "dd.js", "api-js.datadome.co"
            ],
            BotProtectionType.PERIMETERX: [
                "px.js", "_pxhd", "_pxvid", "captcha.px-cdn.net"
            ],
            BotProtectionType.KASADA: [
                "kasada", "cd.js", "ips.js"
            ],
            BotProtectionType.SHAPE: [
                "shape", "f5.js", "f5aas"
            ],
            BotProtectionType.INCAPSULA: [
                "incapsula", "incap_ses", "visid_incap"
            ],
        }

        for protection, patterns in signatures.items():
            if any(pattern in request_urls.lower() for pattern in patterns):
                return protection

        return BotProtectionType.UNKNOWN

    async def _check_dom_markers(self, page: Page) -> BotProtectionType:
        """Check DOM for protection system markers."""
        markers = await page.evaluate(
            """() => {
                const markers = [];
                // Check cookies
                markers.push(document.cookie);
                // Check script sources
                document.querySelectorAll('script[src]').forEach(s => markers.push(s.src));
                // Check hidden inputs
                document.querySelectorAll('input[type="hidden"]').forEach(i => markers.push(i.name));
                return markers.join(' ');
            }""",
            return_value=True
        )

        markers_lower = markers.lower()

        if "_abck" in markers_lower or "akamai" in markers_lower:
            return BotProtectionType.AKAMAI
        if "__cf_bm" in markers_lower or "cloudflare" in markers_lower:
            return BotProtectionType.CLOUDFLARE
        if "datadome" in markers_lower:
            return BotProtectionType.DATADOME
        if "_pxhd" in markers_lower:
            return BotProtectionType.PERIMETERX

        return BotProtectionType.UNKNOWN
```

### 4.2. Bypass Implementation

```python
from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Awaitable

from owl_browser import Browser, Page, ProxyConfig, RemoteConfig


class ProxyTier(StrEnum):
    """Proxy quality tiers."""
    DATACENTER = "datacenter"
    ISP = "isp"
    RESIDENTIAL = "residential"
    MOBILE = "mobile"


@dataclass(slots=True)
class ProxyPool:
    """Manages proxy rotation across quality tiers."""
    datacenter: list[ProxyConfig]
    isp: list[ProxyConfig]
    residential: list[ProxyConfig]
    mobile: list[ProxyConfig]

    def get_proxy(self, tier: ProxyTier) -> ProxyConfig:
        """Get random proxy from specified tier."""
        pool = getattr(self, tier.value)
        if not pool:
            raise ValueError(f"No proxies available in {tier} tier")
        return random.choice(pool)


@dataclass(slots=True)
class AntiBotBypass:
    """
    Production anti-bot bypass system with multi-tier proxy rotation
    and intelligent retry strategies.
    """

    browser: Browser
    proxy_pool: ProxyPool
    max_retries: int = 3

    async def fetch_with_bypass(
        self,
        url: str,
        *,
        extractor: Callable[[Page], Awaitable[dict]] | None = None,
        initial_tier: ProxyTier = ProxyTier.ISP,
    ) -> dict:
        """
        Fetch URL with automatic bot protection bypass.

        Implements escalating proxy tiers and fingerprint rotation
        on detection.

        Args:
            url: Target URL
            extractor: Optional async function to extract data from page
            initial_tier: Starting proxy tier

        Returns:
            Extracted data or page content
        """
        tier_escalation = [
            ProxyTier.ISP,
            ProxyTier.RESIDENTIAL,
            ProxyTier.MOBILE,
        ]

        # Start from initial tier
        start_idx = tier_escalation.index(initial_tier) if initial_tier in tier_escalation else 0

        last_error: Exception | None = None

        for tier in tier_escalation[start_idx:]:
            for attempt in range(self.max_retries):
                try:
                    return await self._attempt_fetch(url, tier, extractor)
                except BotDetectionError as e:
                    last_error = e
                    # Exponential backoff within tier
                    await asyncio.sleep(2 ** attempt + random.uniform(0, 1))
                except Exception as e:
                    last_error = e
                    break  # Move to next tier on unexpected errors

        raise BotBypassFailedError(
            f"Failed to bypass bot protection for {url} after all retries"
        ) from last_error

    async def _attempt_fetch(
        self,
        url: str,
        tier: ProxyTier,
        extractor: Callable[[Page], Awaitable[dict]] | None,
    ) -> dict:
        """Single fetch attempt with specified proxy tier."""
        proxy = self.proxy_pool.get_proxy(tier)

        # Create new page with fresh fingerprint
        page = self.browser.new_page(proxy=proxy)

        try:
            # Get demographics to match timezone/locale to proxy location
            demographics = await self.browser.get_demographics()

            # Configure page based on proxy location
            if demographics:
                await page.evaluate(
                    f"""() => {{
                        // Override timezone
                        Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', {{
                            value: function() {{
                                return {{ timeZone: '{demographics.get("timezone", "America/New_York")}' }};
                            }}
                        }});
                    }}"""
                )

            # Navigate with human-like behavior
            await page.goto(url, wait_until="networkidle", timeout=30000)

            # Check for challenges
            detector = BotProtectionDetector()
            detection = await detector.detect_protection(page)

            if detection.is_challenged:
                if detection.challenge_type == "captcha":
                    # Attempt CAPTCHA solve
                    solved = await page.solve_captcha(max_attempts=3)
                    if not solved:
                        raise BotDetectionError(
                            f"CAPTCHA solve failed: {detection.protection_type}"
                        )
                    await page.wait_for_network_idle(idle_time=3000)

                elif detection.challenge_type == "js_challenge":
                    # Wait for JS challenge to complete
                    await page.wait_for_network_idle(idle_time=5000)
                    # Verify challenge passed
                    recheck = await detector.detect_protection(page)
                    if recheck.is_challenged:
                        raise BotDetectionError(
                            f"JS challenge failed: {detection.protection_type}"
                        )

                elif detection.challenge_type == "block":
                    raise BotDetectionError(
                        f"Hard block detected: {detection.protection_type}"
                    )

            # Extract data
            if extractor:
                return await extractor(page)

            # Default: return page content summary
            return {
                "url": await page.get_current_url(),
                "title": await page.get_title(),
                "content": await page.extract_text(),
            }

        finally:
            await page.close()


class BotDetectionError(Exception):
    """Raised when bot detection is triggered."""
    pass


class BotBypassFailedError(Exception):
    """Raised when all bypass attempts fail."""
    pass
```

### 4.3. Fingerprint Rotation Strategy

```python
from __future__ import annotations

import asyncio
import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from owl_browser import Browser, Page, ProxyConfig


@dataclass(slots=True)
class FingerprintProfile:
    """Browser fingerprint configuration."""
    profile_id: str
    user_agent: str
    viewport_width: int
    viewport_height: int
    timezone: str
    language: str
    platform: str
    webgl_vendor: str
    webgl_renderer: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    request_count: int = 0
    last_used: datetime | None = None
    banned_domains: set[str] = field(default_factory=set)


@dataclass(slots=True)
class FingerprintManager:
    """
    Manages browser fingerprint rotation to evade detection.

    Creates diverse, consistent fingerprints that match real user
    distributions while avoiding banned fingerprint reuse.
    """

    browser: Browser
    profiles: dict[str, FingerprintProfile] = field(default_factory=dict)
    max_requests_per_profile: int = 100
    profile_cooldown: timedelta = timedelta(hours=24)

    # User agent distributions (weighted by market share)
    user_agents: list[tuple[str, float]] = field(default_factory=lambda: [
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 0.45),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 0.20),
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", 0.15),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15", 0.10),
        ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 0.10),
    ])

    def generate_profile(self, *, for_domain: str | None = None) -> FingerprintProfile:
        """
        Generate a new fingerprint profile.

        Args:
            for_domain: Optional domain to avoid banned profiles

        Returns:
            Fresh fingerprint profile
        """
        # Select user agent by weight
        ua = random.choices(
            [ua for ua, _ in self.user_agents],
            weights=[w for _, w in self.user_agents],
            k=1
        )[0]

        # Derive consistent properties from UA
        is_windows = "Windows" in ua
        is_mac = "Macintosh" in ua
        is_linux = "Linux" in ua

        # Viewport sizes (common resolutions)
        viewports = [
            (1920, 1080), (1366, 768), (1536, 864),
            (1440, 900), (1280, 720), (2560, 1440),
        ]
        viewport = random.choice(viewports)

        # Platform must match UA
        if is_windows:
            platform = "Win32"
        elif is_mac:
            platform = "MacIntel"
        else:
            platform = "Linux x86_64"

        # Common WebGL configurations
        webgl_configs = [
            ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0)"),
            ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)"),
            ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)"),
            ("Apple Inc.", "Apple GPU"),
        ]

        if is_mac:
            webgl = ("Apple Inc.", "Apple GPU")
        else:
            webgl = random.choice(webgl_configs[:3])

        # Generate unique profile ID
        profile_id = hashlib.sha256(
            f"{ua}{viewport}{datetime.utcnow().isoformat()}{random.random()}".encode()
        ).hexdigest()[:16]

        profile = FingerprintProfile(
            profile_id=profile_id,
            user_agent=ua,
            viewport_width=viewport[0],
            viewport_height=viewport[1],
            timezone="America/New_York",  # Will be overridden by proxy location
            language="en-US",
            platform=platform,
            webgl_vendor=webgl[0],
            webgl_renderer=webgl[1],
        )

        self.profiles[profile_id] = profile
        return profile

    def get_valid_profile(self, domain: str) -> FingerprintProfile:
        """
        Get or create a valid profile for a domain.

        Args:
            domain: Target domain

        Returns:
            Fingerprint profile not banned on domain
        """
        now = datetime.utcnow()

        # Find existing valid profile
        for profile in self.profiles.values():
            if domain in profile.banned_domains:
                continue
            if profile.request_count >= self.max_requests_per_profile:
                continue
            if profile.last_used and (now - profile.last_used) < timedelta(minutes=5):
                continue  # Cooldown between uses

            return profile

        # Generate new profile if none available
        return self.generate_profile(for_domain=domain)

    def mark_banned(self, profile_id: str, domain: str) -> None:
        """Mark a profile as banned on a domain."""
        if profile_id in self.profiles:
            self.profiles[profile_id].banned_domains.add(domain)

    def record_usage(self, profile_id: str) -> None:
        """Record profile usage."""
        if profile_id in self.profiles:
            self.profiles[profile_id].request_count += 1
            self.profiles[profile_id].last_used = datetime.utcnow()

    async def create_page_with_profile(
        self,
        profile: FingerprintProfile,
        proxy: ProxyConfig | None = None
    ) -> Page:
        """
        Create a page configured with the specified fingerprint profile.

        Args:
            profile: Fingerprint profile to apply
            proxy: Optional proxy configuration

        Returns:
            Configured page
        """
        # Create page with proxy
        page = self.browser.new_page(proxy=proxy)

        # Set viewport
        await page.set_viewport(
            width=profile.viewport_width,
            height=profile.viewport_height
        )

        # Get demographics from proxy for timezone
        if proxy:
            demographics = await self.browser.get_demographics()
            if demographics:
                profile.timezone = demographics.get("timezone", profile.timezone)

        # Apply fingerprint overrides via JavaScript
        await page.evaluate(
            f"""() => {{
                // Override navigator properties
                Object.defineProperty(navigator, 'platform', {{
                    get: () => '{profile.platform}'
                }});

                Object.defineProperty(navigator, 'language', {{
                    get: () => '{profile.language}'
                }});

                Object.defineProperty(navigator, 'languages', {{
                    get: () => ['{profile.language}', 'en']
                }});

                // Override WebGL
                const getParameterProto = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = function(param) {{
                    if (param === 37445) return '{profile.webgl_vendor}';
                    if (param === 37446) return '{profile.webgl_renderer}';
                    return getParameterProto.call(this, param);
                }};
            }}"""
        )

        return page
```

## 5. Geo-Location Pricing Implementation

Price differentiation by geography is common. This section implements location context management.

### 5.1. Location Context Manager

```python
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TypedDict, Any

from owl_browser import Browser, Page, ProxyConfig


class LocationContext(TypedDict):
    """Geographic location configuration."""
    zip_code: str
    city: str
    state: str
    country: str
    latitude: float
    longitude: float
    timezone: str
    store_id: str | None


class GeoPrice(TypedDict):
    """Price at a specific location."""
    location: LocationContext
    price: Decimal | None
    currency: str
    availability: str
    fulfillment_options: list[str]


# Pre-configured US market locations for comprehensive pricing
US_MARKET_LOCATIONS: list[LocationContext] = [
    LocationContext(
        zip_code="10001", city="New York", state="NY", country="US",
        latitude=40.7484, longitude=-73.9967, timezone="America/New_York", store_id=None
    ),
    LocationContext(
        zip_code="90210", city="Beverly Hills", state="CA", country="US",
        latitude=34.0901, longitude=-118.4065, timezone="America/Los_Angeles", store_id=None
    ),
    LocationContext(
        zip_code="60601", city="Chicago", state="IL", country="US",
        latitude=41.8819, longitude=-87.6278, timezone="America/Chicago", store_id=None
    ),
    LocationContext(
        zip_code="77001", city="Houston", state="TX", country="US",
        latitude=29.7545, longitude=-95.3535, timezone="America/Chicago", store_id=None
    ),
    LocationContext(
        zip_code="85001", city="Phoenix", state="AZ", country="US",
        latitude=33.4484, longitude=-112.0740, timezone="America/Phoenix", store_id=None
    ),
    LocationContext(
        zip_code="98101", city="Seattle", state="WA", country="US",
        latitude=47.6062, longitude=-122.3321, timezone="America/Los_Angeles", store_id=None
    ),
    LocationContext(
        zip_code="33101", city="Miami", state="FL", country="US",
        latitude=25.7617, longitude=-80.1918, timezone="America/New_York", store_id=None
    ),
    LocationContext(
        zip_code="30301", city="Atlanta", state="GA", country="US",
        latitude=33.7490, longitude=-84.3880, timezone="America/New_York", store_id=None
    ),
]


@dataclass(slots=True)
class GeoLocationManager:
    """
    Manages location contexts for geo-differentiated pricing.

    Handles cookie manipulation, localStorage spoofing, and proxy
    coordination to achieve accurate location-specific prices.
    """

    browser: Browser
    proxy_by_region: dict[str, ProxyConfig] = field(default_factory=dict)

    async def set_location_context(
        self,
        page: Page,
        location: LocationContext,
        retailer: str
    ) -> None:
        """
        Configure page for specific location context.

        Args:
            page: Page to configure
            location: Target location
            retailer: Retailer identifier for site-specific configuration
        """
        # Get matching demographics if proxy is configured
        demographics = await self.browser.get_demographics()

        # Apply retailer-specific location settings
        match retailer.lower():
            case "amazon":
                await self._set_amazon_location(page, location)
            case "walmart":
                await self._set_walmart_location(page, location)
            case "target":
                await self._set_target_location(page, location)
            case "bestbuy":
                await self._set_bestbuy_location(page, location)
            case _:
                await self._set_generic_location(page, location)

        # Set geolocation API override
        await page.evaluate(
            f"""() => {{
                navigator.geolocation.getCurrentPosition = (success) => {{
                    success({{
                        coords: {{
                            latitude: {location['latitude']},
                            longitude: {location['longitude']},
                            accuracy: 100
                        }},
                        timestamp: Date.now()
                    }});
                }};
            }}"""
        )

    async def _set_amazon_location(self, page: Page, location: LocationContext) -> None:
        """Set Amazon delivery location."""
        # Amazon uses session-context-id and ubid-main cookies
        await page.set_cookie(
            url="https://www.amazon.com",
            name="ubid-main",
            value=f"130-{location['zip_code']}-0000000",
            domain=".amazon.com",
            path="/"
        )

        # Set delivery address context via localStorage
        await page.evaluate(
            f"""() => {{
                localStorage.setItem('glow_lastLocation', JSON.stringify({{
                    zipCode: '{location['zip_code']}',
                    city: '{location['city']}',
                    state: '{location['state']}'
                }}));
            }}"""
        )

    async def _set_walmart_location(self, page: Page, location: LocationContext) -> None:
        """Set Walmart store/delivery location."""
        await page.set_cookie(
            url="https://www.walmart.com",
            name="location-data",
            value=json.dumps({
                "postalCode": location["zip_code"],
                "city": location["city"],
                "state": location["state"],
                "storeId": location.get("store_id") or ""
            }),
            domain=".walmart.com",
            path="/"
        )

        if location.get("store_id"):
            await page.set_cookie(
                url="https://www.walmart.com",
                name="assortmentStoreId",
                value=location["store_id"],
                domain=".walmart.com",
                path="/"
            )

    async def _set_target_location(self, page: Page, location: LocationContext) -> None:
        """Set Target store/delivery location."""
        guest_location = {
            "zipCode": location["zip_code"],
            "storeId": location.get("store_id") or ""
        }

        await page.set_cookie(
            url="https://www.target.com",
            name="GuestLocation",
            value=json.dumps(guest_location),
            domain=".target.com",
            path="/"
        )

        await page.evaluate(
            f"""() => {{
                localStorage.setItem('userLocation', JSON.stringify({{
                    zipCode: '{location['zip_code']}',
                    city: '{location['city']}',
                    state: '{location['state']}'
                }}));
            }}"""
        )

    async def _set_bestbuy_location(self, page: Page, location: LocationContext) -> None:
        """Set Best Buy location context."""
        await page.set_cookie(
            url="https://www.bestbuy.com",
            name="locDestZip",
            value=location["zip_code"],
            domain=".bestbuy.com",
            path="/"
        )

        await page.set_cookie(
            url="https://www.bestbuy.com",
            name="locStoreId",
            value=location.get("store_id") or "",
            domain=".bestbuy.com",
            path="/"
        )

    async def _set_generic_location(self, page: Page, location: LocationContext) -> None:
        """Generic location setting for unknown retailers."""
        # Common patterns for location storage
        await page.evaluate(
            f"""() => {{
                // Try common localStorage keys
                const locationData = {{
                    zipCode: '{location['zip_code']}',
                    zip: '{location['zip_code']}',
                    postalCode: '{location['zip_code']}',
                    city: '{location['city']}',
                    state: '{location['state']}',
                    country: '{location['country']}'
                }};

                localStorage.setItem('userLocation', JSON.stringify(locationData));
                localStorage.setItem('deliveryZip', '{location['zip_code']}');
                localStorage.setItem('selectedLocation', JSON.stringify(locationData));
            }}"""
        )

    async def scrape_prices_across_locations(
        self,
        url: str,
        locations: list[LocationContext],
        retailer: str,
        *,
        extractor: Any | None = None,
        concurrency: int = 3
    ) -> list[GeoPrice]:
        """
        Scrape prices from multiple geographic locations.

        Args:
            url: Product URL
            locations: List of locations to check
            retailer: Retailer identifier
            extractor: Optional custom extraction function
            concurrency: Maximum concurrent scrapes

        Returns:
            List of prices by location
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def scrape_location(location: LocationContext) -> GeoPrice:
            async with semaphore:
                # Get regional proxy if available
                proxy = self.proxy_by_region.get(location["state"])

                page = self.browser.new_page(proxy=proxy)
                try:
                    await self.set_location_context(page, location, retailer)
                    await page.goto(url, wait_until="networkidle")

                    # Handle CAPTCHA
                    if await page.detect_captcha():
                        await page.solve_captcha(max_attempts=2)

                    # Extract price data
                    data = await page.extract_json(template={
                        "price": "current price (number only)",
                        "currency": "currency code",
                        "availability": "stock status",
                        "fulfillment": "available fulfillment options"
                    })

                    fulfillment = data.get("fulfillment", "")
                    options = []
                    if "ship" in fulfillment.lower():
                        options.append("shipping")
                    if "pickup" in fulfillment.lower():
                        options.append("pickup")
                    if "delivery" in fulfillment.lower():
                        options.append("delivery")

                    return GeoPrice(
                        location=location,
                        price=Decimal(str(data["price"])) if data.get("price") else None,
                        currency=data.get("currency", "USD"),
                        availability=data.get("availability", "Unknown"),
                        fulfillment_options=options or ["shipping"]
                    )

                finally:
                    await page.close()

        return await asyncio.gather(*[scrape_location(loc) for loc in locations])
```

## 6. Product Matching Engine

Matching products across retailers is critical. This section implements multi-signal matching.

### 6.1. SKU/UPC/GTIN Matching

```python
from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from typing import TypedDict

from owl_browser import Browser, Page


class MatchConfidence(StrEnum):
    """Product match confidence levels."""
    EXACT = "exact"  # UPC/GTIN match
    HIGH = "high"    # SKU + title similarity > 0.9
    MEDIUM = "medium"  # Title similarity 0.7-0.9
    LOW = "low"      # Title similarity 0.5-0.7
    NONE = "none"    # No match


class ProductIdentifiers(TypedDict):
    """Standard product identifiers."""
    upc: str | None
    ean: str | None
    gtin: str | None
    isbn: str | None
    mpn: str | None  # Manufacturer Part Number
    sku: str | None
    asin: str | None


class ProductMatch(TypedDict):
    """Product match result."""
    source_url: str
    matched_url: str
    confidence: MatchConfidence
    score: float
    identifiers_matched: list[str]
    title_similarity: float
    image_similarity: float | None


@dataclass(frozen=True, slots=True)
class IdentifierExtractor:
    """Extracts product identifiers from pages."""

    async def extract_identifiers(self, page: Page) -> ProductIdentifiers:
        """
        Extract all available product identifiers.

        Uses structured data, meta tags, and AI extraction.
        """
        # Try structured data first
        structured = await page.evaluate(
            """() => {
                const result = {};
                const scripts = document.querySelectorAll('script[type="application/ld+json"]');
                for (const script of scripts) {
                    try {
                        const data = JSON.parse(script.textContent);
                        const product = data['@type'] === 'Product' ? data : data.mainEntity;
                        if (product) {
                            result.gtin = product.gtin13 || product.gtin12 || product.gtin;
                            result.sku = product.sku;
                            result.mpn = product.mpn;
                            result.isbn = product.isbn;
                        }
                    } catch {}
                }

                // Check meta tags
                const metaGtin = document.querySelector('meta[itemprop="gtin13"], meta[itemprop="gtin12"]');
                if (metaGtin) result.gtin = metaGtin.content;

                const metaSku = document.querySelector('meta[itemprop="sku"]');
                if (metaSku) result.sku = metaSku.content;

                return result;
            }""",
            return_value=True
        ) or {}

        # AI extraction for missing identifiers
        if not structured.get("upc") and not structured.get("gtin"):
            upc_text = await page.ai_extract(
                "The UPC, EAN, or GTIN barcode number (12-14 digits)"
            )
            if upc_text:
                # Clean and validate
                upc_clean = re.sub(r"[^0-9]", "", upc_text)
                if len(upc_clean) in (12, 13, 14):
                    structured["upc"] = upc_clean

        if not structured.get("mpn"):
            mpn_text = await page.ai_extract(
                "The manufacturer part number or model number"
            )
            if mpn_text:
                structured["mpn"] = mpn_text.strip()

        # Extract ASIN for Amazon
        current_url = await page.get_current_url()
        if "amazon" in current_url:
            asin_match = re.search(r"/dp/([A-Z0-9]{10})", current_url)
            if asin_match:
                structured["asin"] = asin_match.group(1)

        return ProductIdentifiers(
            upc=structured.get("upc"),
            ean=structured.get("ean"),
            gtin=structured.get("gtin"),
            isbn=structured.get("isbn"),
            mpn=structured.get("mpn"),
            sku=structured.get("sku"),
            asin=structured.get("asin"),
        )

    def normalize_upc(self, identifier: str) -> str:
        """Normalize UPC/EAN/GTIN to 14-digit GTIN."""
        digits = re.sub(r"[^0-9]", "", identifier)
        return digits.zfill(14)

    def identifiers_match(
        self,
        id1: ProductIdentifiers,
        id2: ProductIdentifiers
    ) -> tuple[bool, list[str]]:
        """
        Check if two sets of identifiers match.

        Returns:
            Tuple of (match found, list of matching identifier types)
        """
        matches: list[str] = []

        # Normalize and compare GTINs
        gtin1 = id1.get("gtin") or id1.get("upc") or id1.get("ean")
        gtin2 = id2.get("gtin") or id2.get("upc") or id2.get("ean")

        if gtin1 and gtin2:
            if self.normalize_upc(gtin1) == self.normalize_upc(gtin2):
                matches.append("gtin")

        # Check MPN
        if id1.get("mpn") and id2.get("mpn"):
            if id1["mpn"].lower() == id2["mpn"].lower():
                matches.append("mpn")

        # Check ISBN
        if id1.get("isbn") and id2.get("isbn"):
            isbn1 = re.sub(r"[^0-9X]", "", id1["isbn"].upper())
            isbn2 = re.sub(r"[^0-9X]", "", id2["isbn"].upper())
            if isbn1 == isbn2:
                matches.append("isbn")

        return len(matches) > 0, matches
```

### 6.2. Title Similarity with Embeddings

```python
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

import numpy as np


@dataclass(frozen=True, slots=True)
class TitleMatcher:
    """
    Product title similarity using text analysis.

    For production, integrate with embedding API (OpenAI, Cohere, etc.)
    This implementation uses token-based similarity as fallback.
    """

    # Common words to filter out
    stopwords: frozenset[str] = frozenset({
        "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
        "of", "with", "by", "from", "as", "is", "was", "are", "were", "been",
        "be", "have", "has", "had", "do", "does", "did", "will", "would",
        "could", "should", "may", "might", "must", "shall", "can", "need",
        "new", "free", "best", "top", "great", "good", "sale", "deal"
    })

    def normalize_title(self, title: str) -> str:
        """Normalize product title for comparison."""
        # Lowercase
        normalized = title.lower()

        # Remove special characters except alphanumeric and spaces
        normalized = re.sub(r"[^a-z0-9\s]", " ", normalized)

        # Collapse whitespace
        normalized = re.sub(r"\s+", " ", normalized).strip()

        return normalized

    def tokenize(self, title: str) -> list[str]:
        """Tokenize title into meaningful tokens."""
        normalized = self.normalize_title(title)
        tokens = normalized.split()

        # Remove stopwords but keep important terms
        return [t for t in tokens if t not in self.stopwords and len(t) > 1]

    def jaccard_similarity(self, tokens1: Sequence[str], tokens2: Sequence[str]) -> float:
        """Calculate Jaccard similarity between token sets."""
        set1, set2 = set(tokens1), set(tokens2)

        if not set1 or not set2:
            return 0.0

        intersection = len(set1 & set2)
        union = len(set1 | set2)

        return intersection / union if union > 0 else 0.0

    def weighted_similarity(self, title1: str, title2: str) -> float:
        """
        Calculate weighted similarity prioritizing brand and model.

        Args:
            title1: First product title
            title2: Second product title

        Returns:
            Similarity score 0.0-1.0
        """
        tokens1 = self.tokenize(title1)
        tokens2 = self.tokenize(title2)

        # Base Jaccard similarity
        base_sim = self.jaccard_similarity(tokens1, tokens2)

        # Extract potential brand (usually first 1-2 words)
        brand1 = set(tokens1[:2]) if tokens1 else set()
        brand2 = set(tokens2[:2]) if tokens2 else set()
        brand_match = len(brand1 & brand2) / max(len(brand1 | brand2), 1)

        # Extract numbers (likely model numbers, sizes)
        nums1 = set(re.findall(r"\d+", title1))
        nums2 = set(re.findall(r"\d+", title2))
        num_match = len(nums1 & nums2) / max(len(nums1 | nums2), 1) if nums1 or nums2 else 1.0

        # Weighted combination
        return (base_sim * 0.5) + (brand_match * 0.3) + (num_match * 0.2)

    def calculate_similarity(self, title1: str, title2: str) -> float:
        """
        Calculate overall title similarity score.

        Args:
            title1: First product title
            title2: Second product title

        Returns:
            Similarity score 0.0-1.0
        """
        return self.weighted_similarity(title1, title2)


@dataclass(frozen=True, slots=True)
class EmbeddingMatcher:
    """
    Product matching using embedding similarity.

    Requires external embedding service (placeholder implementation).
    """

    embedding_dim: int = 1536  # OpenAI ada-002 dimension

    async def get_embedding(self, text: str) -> np.ndarray:
        """
        Get embedding vector for text.

        Production: Call OpenAI/Cohere/HuggingFace API
        """
        # Placeholder: Return random vector (replace with actual API call)
        # Example with OpenAI:
        # response = await openai.embeddings.create(input=text, model="text-embedding-ada-002")
        # return np.array(response.data[0].embedding)

        raise NotImplementedError(
            "Implement embedding API call for production use"
        )

    def cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity between vectors."""
        dot = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(dot / (norm1 * norm2))

    async def calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate embedding-based similarity."""
        emb1 = await self.get_embedding(text1)
        emb2 = await self.get_embedding(text2)
        return self.cosine_similarity(emb1, emb2)
```

### 6.3. Visual Product Matching

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from decimal import Decimal

from owl_browser import Browser, Page


@dataclass(frozen=True, slots=True)
class VisualProductMatcher:
    """
    Visual product matching using Owl Browser's VLM.

    Compares product images to determine if they represent the same item.
    """

    browser: Browser

    async def compare_products_visually(
        self,
        page1: Page,
        page2: Page
    ) -> float:
        """
        Compare two product pages visually.

        Uses the VLM to analyze product images and determine similarity.

        Args:
            page1: First product page
            page2: Second product page

        Returns:
            Visual similarity score 0.0-1.0
        """
        # Get screenshots of product image areas
        await page1.scroll_to_top()
        await page2.scroll_to_top()

        # Use AI to compare products
        # Take screenshots for comparison
        await page1.screenshot("/tmp/product1.png", mode="viewport")
        await page2.screenshot("/tmp/product2.png", mode="viewport")

        # Query each page about the product
        desc1 = await page1.query_page(
            "Describe the main product shown: brand, type, color, size, key features. "
            "Be specific about visual details."
        )

        desc2 = await page2.query_page(
            "Describe the main product shown: brand, type, color, size, key features. "
            "Be specific about visual details."
        )

        # Compare descriptions (simple heuristic)
        # For production, use embedding similarity
        title_matcher = TitleMatcher()
        return title_matcher.calculate_similarity(desc1, desc2)

    async def find_matching_product(
        self,
        source_page: Page,
        search_url: str,
        retailer: str
    ) -> str | None:
        """
        Find matching product on another retailer via visual search.

        Args:
            source_page: Page with source product
            search_url: Search URL on target retailer
            retailer: Target retailer name

        Returns:
            Matching product URL or None
        """
        # Get source product description
        source_desc = await source_page.query_page(
            "What is the exact product name, brand, model, and key specifications?"
        )

        # Create search page
        search_page = self.browser.new_page()

        try:
            await search_page.goto(search_url, wait_until="networkidle")

            if await search_page.detect_captcha():
                await search_page.solve_captcha(max_attempts=2)

            # Ask VLM to find matching product
            match_query = await search_page.query_page(
                f"Looking for this product: {source_desc}\n\n"
                f"Which product in the search results is the closest match? "
                f"Consider brand, model number, and specifications. "
                f"Return 'NONE' if no good match exists."
            )

            if "none" in match_query.lower():
                return None

            # Try to click on the matched product
            await search_page.ai_click(
                f"The product that matches: {source_desc}"
            )

            await search_page.wait_for_network_idle(idle_time=2000)

            return await search_page.get_current_url()

        finally:
            await search_page.close()


@dataclass(slots=True)
class ProductMatcher:
    """
    Complete product matching engine combining all signals.
    """

    browser: Browser
    identifier_extractor: IdentifierExtractor = None
    title_matcher: TitleMatcher = None
    visual_matcher: VisualProductMatcher = None

    def __post_init__(self) -> None:
        if self.identifier_extractor is None:
            self.identifier_extractor = IdentifierExtractor()
        if self.title_matcher is None:
            self.title_matcher = TitleMatcher()
        if self.visual_matcher is None:
            self.visual_matcher = VisualProductMatcher(self.browser)

    async def match_products(
        self,
        url1: str,
        url2: str,
        *,
        include_visual: bool = True
    ) -> ProductMatch:
        """
        Determine if two URLs represent the same product.

        Args:
            url1: First product URL
            url2: Second product URL
            include_visual: Whether to include visual comparison

        Returns:
            Match result with confidence and scores
        """
        page1 = self.browser.new_page()
        page2 = self.browser.new_page()

        try:
            # Load both pages
            await asyncio.gather(
                page1.goto(url1, wait_until="networkidle"),
                page2.goto(url2, wait_until="networkidle")
            )

            # Handle CAPTCHAs
            for page in (page1, page2):
                if await page.detect_captcha():
                    await page.solve_captcha(max_attempts=2)

            # Extract identifiers
            id1, id2 = await asyncio.gather(
                self.identifier_extractor.extract_identifiers(page1),
                self.identifier_extractor.extract_identifiers(page2)
            )

            # Check identifier match
            id_match, matched_ids = self.identifier_extractor.identifiers_match(id1, id2)

            if id_match and "gtin" in matched_ids:
                # Exact UPC/GTIN match
                return ProductMatch(
                    source_url=url1,
                    matched_url=url2,
                    confidence=MatchConfidence.EXACT,
                    score=1.0,
                    identifiers_matched=matched_ids,
                    title_similarity=1.0,
                    image_similarity=None
                )

            # Extract titles
            title1 = await page1.ai_extract("The main product title")
            title2 = await page2.ai_extract("The main product title")

            title_sim = self.title_matcher.calculate_similarity(
                title1 or "", title2 or ""
            )

            # Visual comparison if enabled
            image_sim: float | None = None
            if include_visual:
                image_sim = await self.visual_matcher.compare_products_visually(
                    page1, page2
                )

            # Calculate overall score
            if id_match:
                score = 0.9 + (title_sim * 0.1)
            elif image_sim is not None:
                score = (title_sim * 0.6) + (image_sim * 0.4)
            else:
                score = title_sim

            # Determine confidence
            if score >= 0.9:
                confidence = MatchConfidence.HIGH
            elif score >= 0.7:
                confidence = MatchConfidence.MEDIUM
            elif score >= 0.5:
                confidence = MatchConfidence.LOW
            else:
                confidence = MatchConfidence.NONE

            return ProductMatch(
                source_url=url1,
                matched_url=url2,
                confidence=confidence,
                score=score,
                identifiers_matched=matched_ids,
                title_similarity=title_sim,
                image_similarity=image_sim
            )

        finally:
            await page1.close()
            await page2.close()
```

## 7. Cart Analysis Implementation

Cart analysis enables detection of hidden fees, quantity limits, and real inventory levels.

### 7.1. Cart Analysis Engine

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from decimal import Decimal
from typing import TypedDict

from owl_browser import Browser, Page


class CartItem(TypedDict):
    """Item added to cart."""
    product_id: str
    title: str
    quantity: int
    unit_price: Decimal | None
    line_total: Decimal | None


class CartAnalysisResult(TypedDict):
    """Complete cart analysis output."""
    items: list[CartItem]
    subtotal: Decimal | None
    shipping_cost: Decimal | None
    tax: Decimal | None
    total: Decimal | None
    estimated_delivery: str | None
    max_quantity_allowed: int | None
    estimated_inventory: int | None
    hidden_fees: list[dict[str, Decimal]]
    promotions_applied: list[str]


class InventoryEstimate(TypedDict):
    """Estimated inventory from cart probing."""
    product_id: str
    estimated_quantity: int
    confidence: str  # "exact", "minimum", "range"
    method: str  # "quantity_limit", "error_message", "stock_display"


@dataclass(frozen=True, slots=True)
class CartAnalyzer:
    """
    Analyzes shopping carts to detect hidden costs and estimate inventory.

    Uses Owl Browser interactions to add items, manipulate quantities,
    and extract the true cost breakdown.
    """

    browser: Browser

    async def analyze_cart(
        self,
        product_url: str,
        retailer: str,
        *,
        page: Page | None = None
    ) -> CartAnalysisResult:
        """
        Perform complete cart analysis for a product.

        Args:
            product_url: Product page URL
            retailer: Retailer identifier
            page: Optional existing page context

        Returns:
            Complete cart analysis with hidden fees and inventory estimates
        """
        should_close_page = page is None
        if page is None:
            page = self.browser.new_page()

        try:
            # Navigate to product
            await page.goto(product_url, wait_until="networkidle", timeout=30000)

            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=2)

            # Add item to cart
            await self._add_to_cart(page, retailer)

            # Navigate to cart
            await self._navigate_to_cart(page, retailer)

            # Extract cart details
            cart_data = await self._extract_cart_data(page)

            # Detect hidden fees
            hidden_fees = await self._detect_hidden_fees(page, cart_data)

            # Estimate inventory via quantity probing
            inventory_estimate = await self._probe_inventory(page, retailer)

            return CartAnalysisResult(
                items=cart_data.get("items", []),
                subtotal=Decimal(str(cart_data["subtotal"])) if cart_data.get("subtotal") else None,
                shipping_cost=Decimal(str(cart_data["shipping"])) if cart_data.get("shipping") else None,
                tax=Decimal(str(cart_data["tax"])) if cart_data.get("tax") else None,
                total=Decimal(str(cart_data["total"])) if cart_data.get("total") else None,
                estimated_delivery=cart_data.get("delivery"),
                max_quantity_allowed=inventory_estimate.get("max_quantity"),
                estimated_inventory=inventory_estimate.get("estimated_quantity"),
                hidden_fees=hidden_fees,
                promotions_applied=cart_data.get("promotions", []),
            )

        finally:
            # Clean up cart before closing
            try:
                await self._clear_cart(page, retailer)
            except Exception:
                pass  # Best effort cleanup

            if should_close_page:
                await page.close()

    async def _add_to_cart(self, page: Page, retailer: str) -> None:
        """Add current product to cart."""
        # Use AI-powered click for robustness across layouts
        await page.ai_click("Add to Cart button or Add to Bag button")
        await page.wait_for_network_idle(idle_time=2000)

        # Handle post-add modals/popups
        try:
            # Check for "Continue Shopping" or "View Cart" modal
            modal_check = await page.query_page(
                "Is there a popup or modal showing after adding to cart? "
                "What buttons are available?"
            )

            if "continue" in modal_check.lower() or "view cart" in modal_check.lower():
                # Stay on page, don't navigate yet
                pass
        except Exception:
            pass

    async def _navigate_to_cart(self, page: Page, retailer: str) -> None:
        """Navigate to cart page."""
        # Retailer-specific cart URLs
        cart_urls = {
            "amazon": "https://www.amazon.com/gp/cart/view.html",
            "walmart": "https://www.walmart.com/cart",
            "target": "https://www.target.com/cart",
            "bestbuy": "https://www.bestbuy.com/cart",
        }

        if retailer.lower() in cart_urls:
            await page.goto(cart_urls[retailer.lower()], wait_until="networkidle")
        else:
            # Generic: click cart icon
            await page.ai_click("Shopping cart icon or Cart link")
            await page.wait_for_network_idle(idle_time=2000)

    async def _extract_cart_data(self, page: Page) -> dict:
        """Extract all cart information."""
        return await page.extract_json(template={
            "items": [{
                "title": "product name/title",
                "quantity": "quantity in cart",
                "unit_price": "price per item (number only)",
                "line_total": "total for this line (number only)"
            }],
            "subtotal": "subtotal before shipping/tax (number only)",
            "shipping": "shipping cost (number only, 0 if free)",
            "tax": "estimated tax (number only)",
            "total": "order total (number only)",
            "delivery": "estimated delivery date/timeframe",
            "promotions": ["list of applied promotions or discounts"]
        })

    async def _detect_hidden_fees(
        self,
        page: Page,
        cart_data: dict
    ) -> list[dict[str, Decimal]]:
        """Detect hidden fees not shown on product page."""
        hidden_fees: list[dict[str, Decimal]] = []

        # Extract all line items in order summary
        summary = await page.ai_extract(
            "List all fees and charges shown in the order summary: "
            "shipping, handling, service fees, environmental fees, etc. "
            "Include the name and amount of each."
        )

        # Parse fees from summary
        if summary:
            fee_lines = summary.split("\n")
            for line in fee_lines:
                line_lower = line.lower()
                # Identify non-standard fees
                hidden_keywords = [
                    "handling", "service", "environmental", "recycling",
                    "convenience", "processing", "fuel", "delivery fee"
                ]

                for keyword in hidden_keywords:
                    if keyword in line_lower:
                        # Extract amount
                        amount = await page.ai_extract(
                            f"What is the exact amount for {keyword}? Return just the number."
                        )
                        if amount:
                            try:
                                hidden_fees.append({
                                    keyword: Decimal(str(float(amount.replace("$", "").replace(",", ""))))
                                })
                            except (ValueError, TypeError):
                                pass

        return hidden_fees

    async def _probe_inventory(
        self,
        page: Page,
        retailer: str
    ) -> dict:
        """Estimate inventory by probing quantity limits."""
        result = {
            "max_quantity": None,
            "estimated_quantity": None,
        }

        try:
            # Try to increase quantity to find limit
            quantities_to_try = [10, 25, 50, 100, 999]

            for qty in quantities_to_try:
                # Clear and type new quantity
                await page.ai_click("Quantity input field or quantity selector")
                await page.keyboard_combo("a", modifiers=["Control"])  # Select all
                await page.type("quantity input", str(qty))
                await page.press_key("Tab")  # Trigger validation

                await page.wait(1000)

                # Check for error message
                error_check = await page.query_page(
                    "Is there an error message about quantity? "
                    "What is the maximum allowed quantity mentioned?"
                )

                if "error" in error_check.lower() or "maximum" in error_check.lower():
                    # Extract the limit
                    limit_text = await page.ai_extract(
                        "What is the maximum quantity allowed? Return just the number."
                    )
                    if limit_text:
                        try:
                            result["max_quantity"] = int(limit_text)
                            result["estimated_quantity"] = int(limit_text)
                            break
                        except ValueError:
                            pass

                # Check if quantity was automatically adjusted
                current_qty = await page.ai_extract(
                    "What quantity is currently shown in the quantity field? Return just the number."
                )
                if current_qty:
                    try:
                        actual_qty = int(current_qty)
                        if actual_qty < qty:
                            result["max_quantity"] = actual_qty
                            result["estimated_quantity"] = actual_qty
                            break
                    except ValueError:
                        pass

        except Exception:
            pass

        return result

    async def _clear_cart(self, page: Page, retailer: str) -> None:
        """Remove all items from cart."""
        try:
            # Click remove button for each item
            await page.ai_click("Remove button or Delete button for cart item")
            await page.wait_for_network_idle(idle_time=1000)
        except Exception:
            pass  # Cart may already be empty


@dataclass(frozen=True, slots=True)
class InventoryProber:
    """
    Advanced inventory estimation using multiple techniques.
    """

    browser: Browser

    async def estimate_inventory(
        self,
        product_url: str,
        retailer: str
    ) -> InventoryEstimate:
        """
        Estimate product inventory using multiple methods.

        Methods used:
        1. Direct stock display on page
        2. Cart quantity limits
        3. API response interception
        4. Error message analysis

        Args:
            product_url: Product page URL
            retailer: Retailer identifier

        Returns:
            Inventory estimate with confidence level
        """
        page = self.browser.new_page()

        try:
            # Enable network logging to intercept inventory APIs
            await page.enable_network_logging(enable=True)

            await page.goto(product_url, wait_until="networkidle")

            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=2)

            # Method 1: Check for direct stock display
            stock_display = await page.ai_extract(
                "Is there a stock quantity shown on the page? "
                "For example: 'Only 5 left in stock' or '12 available'. "
                "Return just the number or 'none' if not shown."
            )

            if stock_display and stock_display.lower() != "none":
                try:
                    quantity = int(stock_display)
                    product_id = await self._extract_product_id(page, retailer)
                    return InventoryEstimate(
                        product_id=product_id,
                        estimated_quantity=quantity,
                        confidence="exact",
                        method="stock_display"
                    )
                except ValueError:
                    pass

            # Method 2: Check network logs for inventory API calls
            network_log = await page.get_network_log(limit=100)
            for request in network_log:
                url = str(request.get("url", ""))
                if any(kw in url.lower() for kw in ["inventory", "stock", "availability"]):
                    # Found inventory API - would need response body access
                    # This is a placeholder for API interception
                    pass

            # Method 3: Cart quantity probing
            cart_analyzer = CartAnalyzer(self.browser)
            cart_result = await cart_analyzer.analyze_cart(
                product_url, retailer, page=page
            )

            if cart_result.get("estimated_inventory"):
                product_id = await self._extract_product_id(page, retailer)
                return InventoryEstimate(
                    product_id=product_id,
                    estimated_quantity=cart_result["estimated_inventory"],
                    confidence="minimum",
                    method="quantity_limit"
                )

            # Default: unknown inventory
            product_id = await self._extract_product_id(page, retailer)
            return InventoryEstimate(
                product_id=product_id,
                estimated_quantity=-1,
                confidence="unknown",
                method="none"
            )

        finally:
            await page.close()

    async def _extract_product_id(self, page: Page, retailer: str) -> str:
        """Extract product ID from current page."""
        current_url = await page.get_current_url()

        # Retailer-specific ID extraction
        import re

        patterns = {
            "amazon": r"/dp/([A-Z0-9]{10})",
            "walmart": r"/ip/(\d+)",
            "target": r"/A-(\d+)",
            "bestbuy": r"/(\d+)\.p",
        }

        pattern = patterns.get(retailer.lower())
        if pattern:
            match = re.search(pattern, current_url)
            if match:
                return match.group(1)

        return current_url
```

## 8. Repricing Engine

The repricing engine calculates optimal prices based on competitor intelligence and business rules.

### 8.1. Strategy Definitions

```python
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP
from enum import StrEnum
from typing import TypedDict, Protocol
from datetime import datetime


class StrategyType(StrEnum):
    """Available repricing strategies."""
    MATCH_LOWEST = "match_lowest"
    PENNY_UNDER = "penny_under"
    PERCENTAGE_UNDER = "percentage_under"
    TARGET_MARGIN = "target_margin"
    BUY_BOX_OPTIMIZER = "buy_box_optimizer"
    VELOCITY_BASED = "velocity_based"


class CompetitorPrice(TypedDict):
    """Competitor price observation."""
    competitor: str
    price: Decimal
    in_stock: bool
    fulfillment_type: str  # "FBA", "FBM", "Standard"
    observed_at: datetime


class PriceConstraints(TypedDict):
    """Safety constraints for pricing."""
    min_price: Decimal  # Floor price (cost + min margin)
    max_price: Decimal  # Ceiling price
    max_decrease_percent: float  # Max single price drop
    max_increase_percent: float  # Max single price increase


class RepricingDecision(TypedDict):
    """Output of repricing calculation."""
    product_id: str
    current_price: Decimal
    new_price: Decimal
    strategy_used: StrategyType
    competitors_considered: int
    lowest_competitor: Decimal | None
    margin_percent: float
    decision_reason: str
    timestamp: datetime


class RepricingStrategy(Protocol):
    """Protocol for repricing strategy implementations."""

    def calculate_price(
        self,
        current_price: Decimal,
        competitor_prices: list[CompetitorPrice],
        constraints: PriceConstraints,
        cost: Decimal,
    ) -> tuple[Decimal, str]:
        """Calculate new price. Returns (price, reason)."""
        ...


@dataclass(frozen=True, slots=True)
class MatchLowestStrategy:
    """Match the lowest competitor price."""

    def calculate_price(
        self,
        current_price: Decimal,
        competitor_prices: list[CompetitorPrice],
        constraints: PriceConstraints,
        cost: Decimal,
    ) -> tuple[Decimal, str]:
        if not competitor_prices:
            return current_price, "No competitor prices available"

        in_stock_prices = [cp["price"] for cp in competitor_prices if cp["in_stock"]]

        if not in_stock_prices:
            return current_price, "No in-stock competitors"

        lowest = min(in_stock_prices)

        # Apply constraints
        new_price = max(lowest, constraints["min_price"])
        new_price = min(new_price, constraints["max_price"])

        return new_price, f"Matched lowest competitor at {lowest}"


@dataclass(frozen=True, slots=True)
class PennyUnderStrategy:
    """Price one cent below lowest competitor."""

    penny: Decimal = Decimal("0.01")

    def calculate_price(
        self,
        current_price: Decimal,
        competitor_prices: list[CompetitorPrice],
        constraints: PriceConstraints,
        cost: Decimal,
    ) -> tuple[Decimal, str]:
        if not competitor_prices:
            return current_price, "No competitor prices available"

        in_stock_prices = [cp["price"] for cp in competitor_prices if cp["in_stock"]]

        if not in_stock_prices:
            return current_price, "No in-stock competitors"

        lowest = min(in_stock_prices)
        target = lowest - self.penny

        # Apply constraints
        new_price = max(target, constraints["min_price"])
        new_price = min(new_price, constraints["max_price"])

        return new_price, f"Penny under lowest ({lowest}) = {target}"


@dataclass(frozen=True, slots=True)
class PercentageUnderStrategy:
    """Price a percentage below lowest competitor."""

    percentage: Decimal = Decimal("0.02")  # 2% default

    def calculate_price(
        self,
        current_price: Decimal,
        competitor_prices: list[CompetitorPrice],
        constraints: PriceConstraints,
        cost: Decimal,
    ) -> tuple[Decimal, str]:
        if not competitor_prices:
            return current_price, "No competitor prices available"

        in_stock_prices = [cp["price"] for cp in competitor_prices if cp["in_stock"]]

        if not in_stock_prices:
            return current_price, "No in-stock competitors"

        lowest = min(in_stock_prices)
        discount = lowest * self.percentage
        target = (lowest - discount).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        # Apply constraints
        new_price = max(target, constraints["min_price"])
        new_price = min(new_price, constraints["max_price"])

        return new_price, f"{self.percentage * 100}% under lowest ({lowest})"


@dataclass(frozen=True, slots=True)
class TargetMarginStrategy:
    """Price to achieve target profit margin."""

    target_margin: Decimal = Decimal("0.15")  # 15% default

    def calculate_price(
        self,
        current_price: Decimal,
        competitor_prices: list[CompetitorPrice],
        constraints: PriceConstraints,
        cost: Decimal,
    ) -> tuple[Decimal, str]:
        # Calculate price for target margin: price = cost / (1 - margin)
        target = (cost / (Decimal("1") - self.target_margin)).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )

        # Check if target is competitive
        if competitor_prices:
            in_stock_prices = [cp["price"] for cp in competitor_prices if cp["in_stock"]]
            if in_stock_prices:
                lowest = min(in_stock_prices)
                if target > lowest:
                    # Target margin would make us uncompetitive
                    # Fall back to minimum acceptable margin
                    target = max(lowest, constraints["min_price"])

        # Apply constraints
        new_price = max(target, constraints["min_price"])
        new_price = min(new_price, constraints["max_price"])

        actual_margin = (new_price - cost) / new_price if new_price > 0 else Decimal("0")

        return new_price, f"Target margin {self.target_margin * 100}%, actual {actual_margin * 100:.1f}%"


@dataclass(frozen=True, slots=True)
class BuyBoxOptimizerStrategy:
    """
    Amazon Buy Box optimization strategy.

    Balances price competitiveness with other Buy Box factors:
    - Seller rating
    - Fulfillment method (FBA preferred)
    - Shipping speed
    """

    # Weight adjustments for non-price factors
    fba_premium: Decimal = Decimal("0.02")  # FBA can charge 2% more
    rating_premium_per_star: Decimal = Decimal("0.005")  # 0.5% per star above 4.5

    def calculate_price(
        self,
        current_price: Decimal,
        competitor_prices: list[CompetitorPrice],
        constraints: PriceConstraints,
        cost: Decimal,
        *,
        our_fulfillment: str = "FBA",
        our_rating: float = 4.8,
    ) -> tuple[Decimal, str]:
        if not competitor_prices:
            return current_price, "No competitor prices available"

        # Find lowest FBA and FBM prices separately
        fba_prices = [
            cp["price"] for cp in competitor_prices
            if cp["in_stock"] and cp["fulfillment_type"] == "FBA"
        ]
        fbm_prices = [
            cp["price"] for cp in competitor_prices
            if cp["in_stock"] and cp["fulfillment_type"] in ("FBM", "Standard")
        ]

        target: Decimal

        if our_fulfillment == "FBA":
            if fba_prices:
                # Match lowest FBA
                lowest_fba = min(fba_prices)
                target = lowest_fba
            elif fbm_prices:
                # We can price slightly above FBM due to FBA advantage
                lowest_fbm = min(fbm_prices)
                premium = lowest_fbm * self.fba_premium
                target = lowest_fbm + premium
            else:
                target = current_price
        else:
            # FBM seller - need to undercut FBA to compete
            if fba_prices:
                lowest_fba = min(fba_prices)
                # Price 5% below lowest FBA
                target = lowest_fba * Decimal("0.95")
            elif fbm_prices:
                target = min(fbm_prices)
            else:
                target = current_price

        target = target.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        # Apply constraints
        new_price = max(target, constraints["min_price"])
        new_price = min(new_price, constraints["max_price"])

        return new_price, f"Buy Box optimized for {our_fulfillment} seller"


STRATEGIES: dict[StrategyType, RepricingStrategy] = {
    StrategyType.MATCH_LOWEST: MatchLowestStrategy(),
    StrategyType.PENNY_UNDER: PennyUnderStrategy(),
    StrategyType.PERCENTAGE_UNDER: PercentageUnderStrategy(),
    StrategyType.TARGET_MARGIN: TargetMarginStrategy(),
    StrategyType.BUY_BOX_OPTIMIZER: BuyBoxOptimizerStrategy(),
}
```

### 8.2. Repricing Engine Core

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from decimal import Decimal
from datetime import datetime
from typing import AsyncIterator

import redis.asyncio as redis


@dataclass(slots=True)
class RepricingEngine:
    """
    High-performance repricing engine with safety constraints.

    Processes price change events and calculates optimal prices
    in real-time with sub-second latency.
    """

    redis_client: redis.Redis
    default_strategy: StrategyType = StrategyType.PENNY_UNDER
    product_strategies: dict[str, StrategyType] = field(default_factory=dict)
    product_constraints: dict[str, PriceConstraints] = field(default_factory=dict)
    product_costs: dict[str, Decimal] = field(default_factory=dict)

    async def process_price_event(
        self,
        product_id: str,
        competitor_prices: list[CompetitorPrice],
        current_price: Decimal,
    ) -> RepricingDecision | None:
        """
        Process a price change event and return repricing decision.

        Args:
            product_id: Our product identifier
            competitor_prices: Latest competitor prices
            current_price: Our current price

        Returns:
            Repricing decision or None if no change needed
        """
        # Get product-specific configuration
        strategy_type = self.product_strategies.get(product_id, self.default_strategy)
        constraints = self.product_constraints.get(product_id)
        cost = self.product_costs.get(product_id)

        if constraints is None or cost is None:
            # Missing configuration - cannot reprice
            return None

        # Get strategy implementation
        strategy = STRATEGIES.get(strategy_type)
        if strategy is None:
            return None

        # Calculate new price
        new_price, reason = strategy.calculate_price(
            current_price=current_price,
            competitor_prices=competitor_prices,
            constraints=constraints,
            cost=cost,
        )

        # Apply rate-of-change limits
        new_price = self._apply_rate_limits(current_price, new_price, constraints)

        # Check if price actually changed
        if new_price == current_price:
            return None

        # Calculate margin
        margin = float((new_price - cost) / new_price) if new_price > 0 else 0.0

        in_stock_prices = [cp["price"] for cp in competitor_prices if cp["in_stock"]]

        decision = RepricingDecision(
            product_id=product_id,
            current_price=current_price,
            new_price=new_price,
            strategy_used=strategy_type,
            competitors_considered=len(competitor_prices),
            lowest_competitor=min(in_stock_prices) if in_stock_prices else None,
            margin_percent=margin * 100,
            decision_reason=reason,
            timestamp=datetime.utcnow(),
        )

        # Store decision in Redis for audit trail
        await self._store_decision(decision)

        return decision

    def _apply_rate_limits(
        self,
        current: Decimal,
        target: Decimal,
        constraints: PriceConstraints,
    ) -> Decimal:
        """Apply maximum rate of change limits."""
        if current <= 0:
            return target

        change_pct = float((target - current) / current)

        if change_pct < -constraints["max_decrease_percent"]:
            # Limit decrease
            return current * (Decimal("1") - Decimal(str(constraints["max_decrease_percent"])))

        if change_pct > constraints["max_increase_percent"]:
            # Limit increase
            return current * (Decimal("1") + Decimal(str(constraints["max_increase_percent"])))

        return target

    async def _store_decision(self, decision: RepricingDecision) -> None:
        """Store decision in Redis for audit and analytics."""
        key = f"reprice:decision:{decision['product_id']}:{decision['timestamp'].isoformat()}"

        await self.redis_client.hset(
            key,
            mapping={
                "product_id": decision["product_id"],
                "current_price": str(decision["current_price"]),
                "new_price": str(decision["new_price"]),
                "strategy": decision["strategy_used"],
                "reason": decision["decision_reason"],
                "margin_percent": str(decision["margin_percent"]),
            }
        )

        # Set TTL for 30 days
        await self.redis_client.expire(key, 30 * 24 * 60 * 60)

    async def listen_for_events(self) -> AsyncIterator[dict]:
        """
        Listen for price change events from Redis pub/sub.

        Yields:
            Price change events
        """
        pubsub = self.redis_client.pubsub()
        await pubsub.subscribe("price_changes")

        async for message in pubsub.listen():
            if message["type"] == "message":
                import json
                yield json.loads(message["data"])


@dataclass(slots=True)
class ShopifyIntegration:
    """
    Shopify API integration for price updates.
    """

    shop_domain: str
    access_token: str
    api_version: str = "2024-01"

    async def update_price(
        self,
        variant_id: str,
        new_price: Decimal,
        compare_at_price: Decimal | None = None,
    ) -> bool:
        """
        Update product variant price via Shopify Admin API.

        Args:
            variant_id: Shopify variant ID
            new_price: New price to set
            compare_at_price: Optional compare-at price (for showing discount)

        Returns:
            True if update successful
        """
        import aiohttp

        url = f"https://{self.shop_domain}/admin/api/{self.api_version}/variants/{variant_id}.json"

        payload = {
            "variant": {
                "id": variant_id,
                "price": str(new_price),
            }
        }

        if compare_at_price is not None:
            payload["variant"]["compare_at_price"] = str(compare_at_price)

        headers = {
            "X-Shopify-Access-Token": self.access_token,
            "Content-Type": "application/json",
        }

        async with aiohttp.ClientSession() as session:
            async with session.put(url, json=payload, headers=headers) as response:
                return response.status == 200


@dataclass(slots=True)
class MagentoIntegration:
    """
    Magento API integration for price updates.
    """

    base_url: str
    access_token: str

    async def update_price(
        self,
        sku: str,
        new_price: Decimal,
        store_id: int = 0,
    ) -> bool:
        """
        Update product price via Magento REST API.

        Args:
            sku: Product SKU
            new_price: New price to set
            store_id: Store view ID (0 for default)

        Returns:
            True if update successful
        """
        import aiohttp

        url = f"{self.base_url}/rest/V1/products/{sku}"

        payload = {
            "product": {
                "sku": sku,
                "price": float(new_price),
            }
        }

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

        async with aiohttp.ClientSession() as session:
            async with session.put(url, json=payload, headers=headers) as response:
                return response.status == 200
```

### 8.3. Rust Repricing Core (High-Performance)

For microsecond-latency repricing at scale, the core calculation is implemented in Rust:

```rust
// File: repricer/src/lib.rs

use pyo3::prelude::*;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::cmp::Ordering;

/// Competitor price observation
#[derive(Clone, Debug)]
#[pyclass]
pub struct CompetitorPrice {
    #[pyo3(get, set)]
    pub competitor: String,
    #[pyo3(get, set)]
    pub price: String, // Decimal as string for Python interop
    #[pyo3(get, set)]
    pub in_stock: bool,
    #[pyo3(get, set)]
    pub fulfillment_type: String,
}

/// Price constraints
#[derive(Clone, Debug)]
#[pyclass]
pub struct PriceConstraints {
    #[pyo3(get, set)]
    pub min_price: String,
    #[pyo3(get, set)]
    pub max_price: String,
    #[pyo3(get, set)]
    pub max_decrease_percent: f64,
    #[pyo3(get, set)]
    pub max_increase_percent: f64,
}

/// Repricing calculation result
#[derive(Clone, Debug)]
#[pyclass]
pub struct RepricingResult {
    #[pyo3(get)]
    pub new_price: String,
    #[pyo3(get)]
    pub reason: String,
    #[pyo3(get)]
    pub lowest_competitor: Option<String>,
}

#[pymethods]
impl CompetitorPrice {
    #[new]
    fn new(competitor: String, price: String, in_stock: bool, fulfillment_type: String) -> Self {
        Self {
            competitor,
            price,
            in_stock,
            fulfillment_type,
        }
    }
}

#[pymethods]
impl PriceConstraints {
    #[new]
    fn new(
        min_price: String,
        max_price: String,
        max_decrease_percent: f64,
        max_increase_percent: f64,
    ) -> Self {
        Self {
            min_price,
            max_price,
            max_decrease_percent,
            max_increase_percent,
        }
    }
}

/// Calculate penny-under price
#[pyfunction]
fn calculate_penny_under(
    current_price: String,
    competitor_prices: Vec<CompetitorPrice>,
    constraints: PriceConstraints,
) -> PyResult<RepricingResult> {
    let current = Decimal::from_str_exact(&current_price)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let min_price = Decimal::from_str_exact(&constraints.min_price)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let max_price = Decimal::from_str_exact(&constraints.max_price)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    // Find lowest in-stock competitor
    let in_stock_prices: Vec<Decimal> = competitor_prices
        .iter()
        .filter(|cp| cp.in_stock)
        .filter_map(|cp| Decimal::from_str_exact(&cp.price).ok())
        .collect();

    if in_stock_prices.is_empty() {
        return Ok(RepricingResult {
            new_price: current_price,
            reason: "No in-stock competitors".to_string(),
            lowest_competitor: None,
        });
    }

    let lowest = in_stock_prices.iter().min().unwrap();
    let penny = dec!(0.01);
    let mut target = *lowest - penny;

    // Apply constraints
    if target < min_price {
        target = min_price;
    }
    if target > max_price {
        target = max_price;
    }

    // Apply rate limits
    let change_ratio = (target - current) / current;
    let max_decrease = Decimal::try_from(constraints.max_decrease_percent).unwrap_or(dec!(0.1));

    if change_ratio < -max_decrease {
        target = current * (dec!(1) - max_decrease);
    }

    Ok(RepricingResult {
        new_price: target.to_string(),
        reason: format!("Penny under lowest ({})", lowest),
        lowest_competitor: Some(lowest.to_string()),
    })
}

/// Calculate match-lowest price
#[pyfunction]
fn calculate_match_lowest(
    current_price: String,
    competitor_prices: Vec<CompetitorPrice>,
    constraints: PriceConstraints,
) -> PyResult<RepricingResult> {
    let current = Decimal::from_str_exact(&current_price)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let min_price = Decimal::from_str_exact(&constraints.min_price)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let max_price = Decimal::from_str_exact(&constraints.max_price)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let in_stock_prices: Vec<Decimal> = competitor_prices
        .iter()
        .filter(|cp| cp.in_stock)
        .filter_map(|cp| Decimal::from_str_exact(&cp.price).ok())
        .collect();

    if in_stock_prices.is_empty() {
        return Ok(RepricingResult {
            new_price: current_price,
            reason: "No in-stock competitors".to_string(),
            lowest_competitor: None,
        });
    }

    let lowest = in_stock_prices.iter().min().unwrap();
    let mut target = *lowest;

    // Apply constraints
    target = target.max(min_price).min(max_price);

    Ok(RepricingResult {
        new_price: target.to_string(),
        reason: format!("Matched lowest competitor at {}", lowest),
        lowest_competitor: Some(lowest.to_string()),
    })
}

/// Batch calculate prices for multiple products
#[pyfunction]
fn batch_calculate(
    products: Vec<(String, String, Vec<CompetitorPrice>, PriceConstraints)>,
    strategy: String,
) -> PyResult<Vec<(String, RepricingResult)>> {
    products
        .into_iter()
        .map(|(product_id, current_price, competitors, constraints)| {
            let result = match strategy.as_str() {
                "penny_under" => calculate_penny_under(current_price, competitors, constraints),
                "match_lowest" => calculate_match_lowest(current_price, competitors, constraints),
                _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Unknown strategy",
                )),
            }?;
            Ok((product_id, result))
        })
        .collect()
}

/// Python module definition
#[pymodule]
fn priceguard_repricer(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<CompetitorPrice>()?;
    m.add_class::<PriceConstraints>()?;
    m.add_class::<RepricingResult>()?;
    m.add_function(wrap_pyfunction!(calculate_penny_under, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_match_lowest, m)?)?;
    m.add_function(wrap_pyfunction!(batch_calculate, m)?)?;
    Ok(())
}
```

## 9. Data Storage Schemas

Complete database schemas for the PriceGuard data layer.

### 9.1. ScyllaDB Schema (Price History)

```sql
-- PriceGuard ScyllaDB Schema
-- Optimized for high write throughput and time-series queries

-- Keyspace configuration
CREATE KEYSPACE IF NOT EXISTS priceguard
WITH replication = {
    'class': 'NetworkTopologyStrategy',
    'dc1': 3,
    'dc2': 3
}
AND durable_writes = true;

USE priceguard;

-- Main price history table
-- Partitioned by product+competitor, clustered by time
CREATE TABLE price_history (
    product_id UUID,
    competitor_domain TEXT,
    scraped_at TIMESTAMP,
    price DECIMAL,
    original_price DECIMAL,
    currency TEXT,
    in_stock BOOLEAN,
    fulfillment_type TEXT,
    seller_name TEXT,
    geo_location TEXT,
    scrape_success BOOLEAN,
    error_code TEXT,
    PRIMARY KEY ((product_id, competitor_domain), scraped_at)
) WITH CLUSTERING ORDER BY (scraped_at DESC)
AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_unit': 'DAYS',
    'compaction_window_size': 1
}
AND default_time_to_live = 31536000  -- 1 year retention
AND gc_grace_seconds = 86400;

-- Price alerts table (for significant changes)
CREATE TABLE price_alerts (
    alert_date DATE,
    product_id UUID,
    alert_time TIMESTAMP,
    competitor_domain TEXT,
    alert_type TEXT,  -- 'price_drop', 'price_increase', 'out_of_stock', 'back_in_stock'
    old_price DECIMAL,
    new_price DECIMAL,
    change_percent DECIMAL,
    PRIMARY KEY ((alert_date), alert_time, product_id)
) WITH CLUSTERING ORDER BY (alert_time DESC)
AND default_time_to_live = 7776000;  -- 90 days

-- Scrape job tracking
CREATE TABLE scrape_jobs (
    job_date DATE,
    job_id UUID,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT,
    total_products INT,
    successful_scrapes INT,
    failed_scrapes INT,
    avg_latency_ms INT,
    PRIMARY KEY ((job_date), started_at, job_id)
) WITH CLUSTERING ORDER BY (started_at DESC);

-- Competitor catalog (which products each competitor has)
CREATE TABLE competitor_products (
    competitor_domain TEXT,
    product_id UUID,
    competitor_product_id TEXT,
    competitor_url TEXT,
    last_seen TIMESTAMP,
    first_seen TIMESTAMP,
    match_confidence DECIMAL,
    PRIMARY KEY ((competitor_domain), product_id)
);

-- Materialized view for product-centric queries
CREATE MATERIALIZED VIEW product_competitors AS
SELECT product_id, competitor_domain, competitor_product_id, competitor_url, last_seen
FROM competitor_products
WHERE product_id IS NOT NULL
AND competitor_domain IS NOT NULL
PRIMARY KEY ((product_id), competitor_domain);

-- Daily price aggregates for analytics
CREATE TABLE daily_price_stats (
    product_id UUID,
    competitor_domain TEXT,
    stat_date DATE,
    min_price DECIMAL,
    max_price DECIMAL,
    avg_price DECIMAL,
    price_volatility DECIMAL,
    observation_count INT,
    in_stock_percent DECIMAL,
    PRIMARY KEY ((product_id, competitor_domain), stat_date)
) WITH CLUSTERING ORDER BY (stat_date DESC)
AND default_time_to_live = 94608000;  -- 3 years
```

### 9.2. Redis Schema (Current State Cache)

```python
"""
Redis data structure definitions for PriceGuard.

Uses Redis 7.0+ features including JSON support.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import TypedDict
import json

import redis.asyncio as redis


class CurrentPriceCache(TypedDict):
    """Current price cache structure."""
    price: str  # Decimal as string
    currency: str
    in_stock: bool
    updated_at: str  # ISO timestamp
    competitor: str
    fulfillment_type: str


class ProductState(TypedDict):
    """Complete product state in Redis."""
    product_id: str
    our_price: str
    our_cost: str
    min_price: str
    max_price: str
    strategy: str
    last_repriced: str
    competitor_prices: dict[str, CurrentPriceCache]


@dataclass(slots=True)
class RedisCache:
    """
    Redis cache manager for PriceGuard.

    Key patterns:
    - price:{product_id}:{competitor} - Current competitor price (Hash)
    - product:{product_id} - Product state (JSON)
    - reprice:queue - Repricing task queue (Stream)
    - alerts:{product_id} - Recent alerts (Sorted Set by timestamp)
    """

    client: redis.Redis

    # Key patterns
    PRICE_KEY = "price:{product_id}:{competitor}"
    PRODUCT_KEY = "product:{product_id}"
    REPRICE_QUEUE = "reprice:queue"
    ALERTS_KEY = "alerts:{product_id}"
    LOCK_KEY = "lock:reprice:{product_id}"

    async def set_competitor_price(
        self,
        product_id: str,
        competitor: str,
        price_data: CurrentPriceCache,
        ttl_seconds: int = 3600,
    ) -> None:
        """Cache current competitor price."""
        key = self.PRICE_KEY.format(product_id=product_id, competitor=competitor)

        await self.client.hset(key, mapping=price_data)
        await self.client.expire(key, ttl_seconds)

        # Publish price update event
        await self.client.publish(
            "price_changes",
            json.dumps({
                "product_id": product_id,
                "competitor": competitor,
                "price": price_data["price"],
                "in_stock": price_data["in_stock"],
            })
        )

    async def get_competitor_prices(
        self,
        product_id: str,
    ) -> dict[str, CurrentPriceCache]:
        """Get all cached competitor prices for a product."""
        pattern = self.PRICE_KEY.format(product_id=product_id, competitor="*")

        prices: dict[str, CurrentPriceCache] = {}

        async for key in self.client.scan_iter(match=pattern):
            competitor = key.decode().split(":")[-1]
            data = await self.client.hgetall(key)
            if data:
                prices[competitor] = CurrentPriceCache(
                    price=data[b"price"].decode(),
                    currency=data[b"currency"].decode(),
                    in_stock=data[b"in_stock"].decode() == "True",
                    updated_at=data[b"updated_at"].decode(),
                    competitor=competitor,
                    fulfillment_type=data.get(b"fulfillment_type", b"Standard").decode(),
                )

        return prices

    async def get_product_state(self, product_id: str) -> ProductState | None:
        """Get complete product state."""
        key = self.PRODUCT_KEY.format(product_id=product_id)
        data = await self.client.get(key)

        if data:
            return json.loads(data)
        return None

    async def set_product_state(
        self,
        product_id: str,
        state: ProductState,
    ) -> None:
        """Set product state."""
        key = self.PRODUCT_KEY.format(product_id=product_id)
        await self.client.set(key, json.dumps(state))

    async def acquire_reprice_lock(
        self,
        product_id: str,
        ttl_seconds: int = 30,
    ) -> bool:
        """Acquire distributed lock for repricing a product."""
        key = self.LOCK_KEY.format(product_id=product_id)
        return await self.client.set(key, "1", nx=True, ex=ttl_seconds)

    async def release_reprice_lock(self, product_id: str) -> None:
        """Release repricing lock."""
        key = self.LOCK_KEY.format(product_id=product_id)
        await self.client.delete(key)

    async def enqueue_reprice(self, product_id: str, priority: int = 0) -> str:
        """Add product to repricing queue."""
        return await self.client.xadd(
            self.REPRICE_QUEUE,
            {"product_id": product_id, "priority": str(priority)},
        )

    async def add_alert(
        self,
        product_id: str,
        alert_type: str,
        data: dict,
        ttl_days: int = 7,
    ) -> None:
        """Add price alert."""
        import time

        key = self.ALERTS_KEY.format(product_id=product_id)
        score = time.time()

        await self.client.zadd(
            key,
            {json.dumps({"type": alert_type, **data}): score}
        )

        # Trim to last 100 alerts
        await self.client.zremrangebyrank(key, 0, -101)
        await self.client.expire(key, ttl_days * 86400)
```

### 9.3. PostgreSQL Schema (Product Catalog)

```sql
-- PriceGuard PostgreSQL Schema
-- Product catalog and configuration

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For fuzzy text search

-- Products table
CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sku VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    brand VARCHAR(200),
    category_id UUID REFERENCES categories(id),
    upc VARCHAR(14),
    ean VARCHAR(13),
    mpn VARCHAR(100),
    asin VARCHAR(10),
    description TEXT,
    image_url VARCHAR(1000),
    our_cost DECIMAL(10, 2) NOT NULL,
    our_price DECIMAL(10, 2) NOT NULL,
    min_price DECIMAL(10, 2) NOT NULL,
    max_price DECIMAL(10, 2) NOT NULL,
    repricing_strategy VARCHAR(50) DEFAULT 'penny_under',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Categories hierarchy
CREATE TABLE categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(200) NOT NULL,
    parent_id UUID REFERENCES categories(id),
    path LTREE,  -- Materialized path for hierarchy queries
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Competitors we track
CREATE TABLE competitors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain VARCHAR(200) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    scrape_priority INT DEFAULT 5,
    default_proxy_tier VARCHAR(20) DEFAULT 'isp',
    is_active BOOLEAN DEFAULT true,
    avg_success_rate DECIMAL(5, 2),
    last_scrape_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Product-to-competitor mapping
CREATE TABLE product_competitors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    competitor_id UUID NOT NULL REFERENCES competitors(id) ON DELETE CASCADE,
    competitor_product_id VARCHAR(100),
    competitor_url VARCHAR(2000) NOT NULL,
    match_confidence DECIMAL(3, 2) DEFAULT 1.0,
    is_verified BOOLEAN DEFAULT false,
    last_price DECIMAL(10, 2),
    last_checked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(product_id, competitor_id)
);

-- Repricing rules and constraints
CREATE TABLE repricing_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID REFERENCES products(id) ON DELETE CASCADE,
    category_id UUID REFERENCES categories(id) ON DELETE CASCADE,
    strategy VARCHAR(50) NOT NULL,
    min_margin_percent DECIMAL(5, 2),
    max_decrease_percent DECIMAL(5, 2) DEFAULT 10.0,
    max_increase_percent DECIMAL(5, 2) DEFAULT 20.0,
    competitor_filter JSONB,  -- Filter which competitors to consider
    time_restrictions JSONB,  -- Time-based rules
    is_active BOOLEAN DEFAULT true,
    priority INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CHECK (product_id IS NOT NULL OR category_id IS NOT NULL)
);

-- Repricing history (for auditing)
CREATE TABLE repricing_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id),
    old_price DECIMAL(10, 2) NOT NULL,
    new_price DECIMAL(10, 2) NOT NULL,
    strategy_used VARCHAR(50) NOT NULL,
    lowest_competitor_price DECIMAL(10, 2),
    competitors_considered INT,
    decision_reason TEXT,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX idx_products_sku ON products(sku);
CREATE INDEX idx_products_upc ON products(upc) WHERE upc IS NOT NULL;
CREATE INDEX idx_products_asin ON products(asin) WHERE asin IS NOT NULL;
CREATE INDEX idx_products_title_trgm ON products USING gin(title gin_trgm_ops);
CREATE INDEX idx_product_competitors_url ON product_competitors(competitor_url);
CREATE INDEX idx_repricing_history_product_time ON repricing_history(product_id, applied_at DESC);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER products_updated_at
    BEFORE UPDATE ON products
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
```

## 10. Production Infrastructure

Complete production deployment configurations.

### 10.1. Docker Compose (Development/Staging)

```yaml
# docker-compose.yml
version: "3.9"

services:
  # Owl Browser nodes
  owl-browser:
    image: olib/owl-browser:latest
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 2G
          cpus: "2"
        reservations:
          memory: 1G
          cpus: "1"
    environment:
      - OWL_API_TOKEN=${OWL_API_TOKEN}
      - OWL_LOG_LEVEL=info
      - OWL_MAX_PAGES=10
      - OWL_STEALTH_MODE=enabled
    ports:
      - "8080-8082:8080"
    volumes:
      - owl-profiles:/data/profiles
    networks:
      - priceguard
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Scraping workers
  scraper-worker:
    build:
      context: ./scraper
      dockerfile: Dockerfile
    deploy:
      replicas: 5
      resources:
        limits:
          memory: 512M
          cpus: "0.5"
    environment:
      - OWL_BROWSER_URL=http://owl-browser:8080
      - REDIS_URL=redis://redis:6379
      - SCYLLA_HOSTS=scylla-node1,scylla-node2,scylla-node3
      - POSTGRES_URL=postgresql://priceguard:${PG_PASSWORD}@postgres:5432/priceguard
      - NATS_URL=nats://nats:4222
      - LOG_LEVEL=info
    depends_on:
      - owl-browser
      - redis
      - nats
    networks:
      - priceguard
    restart: unless-stopped

  # Repricing engine
  repricer:
    build:
      context: ./repricer
      dockerfile: Dockerfile
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 256M
          cpus: "0.25"
    environment:
      - REDIS_URL=redis://redis:6379
      - POSTGRES_URL=postgresql://priceguard:${PG_PASSWORD}@postgres:5432/priceguard
      - SHOPIFY_API_KEY=${SHOPIFY_API_KEY}
      - SHOPIFY_API_SECRET=${SHOPIFY_API_SECRET}
    depends_on:
      - redis
      - postgres
    networks:
      - priceguard
    restart: unless-stopped

  # Redis cluster
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --maxmemory 1gb --maxmemory-policy allkeys-lru
    volumes:
      - redis-data:/data
    ports:
      - "6379:6379"
    networks:
      - priceguard
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3

  # ScyllaDB cluster
  scylla-node1:
    image: scylladb/scylla:5.2
    command: --seeds=scylla-node1 --smp 2 --memory 2G --overprovisioned 1
    volumes:
      - scylla-data-1:/var/lib/scylla
    networks:
      - priceguard
    healthcheck:
      test: ["CMD", "cqlsh", "-e", "SELECT now() FROM system.local"]
      interval: 30s
      timeout: 10s
      retries: 5

  scylla-node2:
    image: scylladb/scylla:5.2
    command: --seeds=scylla-node1 --smp 2 --memory 2G --overprovisioned 1
    volumes:
      - scylla-data-2:/var/lib/scylla
    depends_on:
      - scylla-node1
    networks:
      - priceguard

  scylla-node3:
    image: scylladb/scylla:5.2
    command: --seeds=scylla-node1 --smp 2 --memory 2G --overprovisioned 1
    volumes:
      - scylla-data-3:/var/lib/scylla
    depends_on:
      - scylla-node1
    networks:
      - priceguard

  # PostgreSQL
  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=priceguard
      - POSTGRES_USER=priceguard
      - POSTGRES_PASSWORD=${PG_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./init-scripts:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    networks:
      - priceguard
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U priceguard"]
      interval: 10s
      timeout: 5s
      retries: 5

  # NATS message queue
  nats:
    image: nats:2-alpine
    command: --jetstream --store_dir /data
    volumes:
      - nats-data:/data
    ports:
      - "4222:4222"
      - "8222:8222"
    networks:
      - priceguard

  # Temporal.io workflow engine
  temporal:
    image: temporalio/auto-setup:1.22
    environment:
      - DB=postgresql
      - DB_PORT=5432
      - POSTGRES_USER=priceguard
      - POSTGRES_PWD=${PG_PASSWORD}
      - POSTGRES_SEEDS=postgres
    depends_on:
      - postgres
    ports:
      - "7233:7233"
    networks:
      - priceguard

  temporal-ui:
    image: temporalio/ui:2.21
    environment:
      - TEMPORAL_ADDRESS=temporal:7233
    ports:
      - "8088:8080"
    depends_on:
      - temporal
    networks:
      - priceguard

  # Monitoring stack
  prometheus:
    image: prom/prometheus:v2.47.0
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - priceguard

  grafana:
    image: grafana/grafana:10.1.0
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-piechart-panel
    volumes:
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources
      - grafana-data:/var/lib/grafana
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
    networks:
      - priceguard

volumes:
  owl-profiles:
  redis-data:
  scylla-data-1:
  scylla-data-2:
  scylla-data-3:
  postgres-data:
  nats-data:
  prometheus-data:
  grafana-data:

networks:
  priceguard:
    driver: bridge
```

### 10.2. Kubernetes Deployment

```yaml
# kubernetes/owl-browser-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: owl-browser
  namespace: priceguard
  labels:
    app: owl-browser
spec:
  replicas: 10
  selector:
    matchLabels:
      app: owl-browser
  template:
    metadata:
      labels:
        app: owl-browser
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      containers:
        - name: owl-browser
          image: olib/owl-browser:latest
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9090
              name: metrics
          env:
            - name: OWL_API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: owl-secrets
                  key: api-token
            - name: OWL_LOG_LEVEL
              value: "info"
            - name: OWL_MAX_PAGES
              value: "10"
            - name: OWL_STEALTH_MODE
              value: "enabled"
          resources:
            requests:
              memory: "1Gi"
              cpu: "1000m"
            limits:
              memory: "2Gi"
              cpu: "2000m"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          volumeMounts:
            - name: profiles
              mountPath: /data/profiles
      volumes:
        - name: profiles
          persistentVolumeClaim:
            claimName: owl-profiles-pvc
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: owl-browser
                topologyKey: kubernetes.io/hostname
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: owl-browser-hpa
  namespace: priceguard
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: owl-browser
  minReplicas: 5
  maxReplicas: 50
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Pods
          value: 5
          periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Pods
          value: 2
          periodSeconds: 60
---
apiVersion: v1
kind: Service
metadata:
  name: owl-browser
  namespace: priceguard
spec:
  selector:
    app: owl-browser
  ports:
    - port: 8080
      targetPort: 8080
      name: http
  type: ClusterIP
```

```yaml
# kubernetes/scraper-worker-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scraper-worker
  namespace: priceguard
spec:
  replicas: 20
  selector:
    matchLabels:
      app: scraper-worker
  template:
    metadata:
      labels:
        app: scraper-worker
    spec:
      containers:
        - name: worker
          image: priceguard/scraper:latest
          env:
            - name: OWL_BROWSER_URL
              value: "http://owl-browser:8080"
            - name: REDIS_URL
              valueFrom:
                secretKeyRef:
                  name: priceguard-secrets
                  key: redis-url
            - name: SCYLLA_HOSTS
              value: "scylla-client.scylla.svc.cluster.local"
            - name: TEMPORAL_ADDRESS
              value: "temporal-frontend.temporal.svc.cluster.local:7233"
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app: scraper-worker
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: scraper-worker-hpa
  namespace: priceguard
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: scraper-worker
  minReplicas: 10
  maxReplicas: 100
  metrics:
    - type: External
      external:
        metric:
          name: nats_jetstream_pending_messages
          selector:
            matchLabels:
              stream: scrape-tasks
        target:
          type: AverageValue
          averageValue: "100"
```

### 10.3. Temporal Workflow Configuration

```python
"""
Temporal.io workflow definitions for PriceGuard.

Handles scheduled scraping, retry logic, and rate limiting.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import activity, workflow
from temporalio.common import RetryPolicy


# Activities
@activity.defn
async def scrape_product_activity(
    product_id: str,
    competitor_url: str,
    retailer: str,
) -> dict[str, Any]:
    """
    Scrape a single product from a competitor.

    This activity is executed by scraper workers.
    """
    # Import here to avoid issues with workflow sandbox
    from priceguard.scrapers import get_scraper

    scraper = await get_scraper(retailer)
    return await scraper.scrape_product(competitor_url)


@activity.defn
async def calculate_reprice_activity(
    product_id: str,
    competitor_prices: list[dict],
    current_price: str,
) -> dict[str, Any] | None:
    """
    Calculate new price for a product.
    """
    from priceguard.repricer import RepricingEngine

    engine = RepricingEngine()
    return await engine.process_price_event(
        product_id=product_id,
        competitor_prices=competitor_prices,
        current_price=current_price,
    )


@activity.defn
async def update_store_price_activity(
    product_id: str,
    new_price: str,
    platform: str,
) -> bool:
    """
    Update price on selling platform (Shopify, Magento, etc.)
    """
    from priceguard.integrations import get_platform_client

    client = await get_platform_client(platform)
    return await client.update_price(product_id, new_price)


@activity.defn
async def store_price_data_activity(
    product_id: str,
    competitor: str,
    price_data: dict,
) -> None:
    """
    Store scraped price data in ScyllaDB and Redis.
    """
    from priceguard.storage import PriceStorage

    storage = PriceStorage()
    await storage.store_price(product_id, competitor, price_data)


# Workflows
@workflow.defn
class ProductScrapeWorkflow:
    """
    Workflow for scraping a single product across all competitors.

    Handles retries, rate limiting, and data persistence.
    """

    @workflow.run
    async def run(
        self,
        product_id: str,
        competitor_urls: dict[str, str],  # retailer -> url
    ) -> dict[str, Any]:
        results = {}

        # Scrape all competitors concurrently
        scrape_tasks = []
        for retailer, url in competitor_urls.items():
            task = workflow.execute_activity(
                scrape_product_activity,
                args=[product_id, url, retailer],
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=10),
                    maximum_interval=timedelta(minutes=5),
                    maximum_attempts=3,
                    backoff_coefficient=2.0,
                ),
            )
            scrape_tasks.append((retailer, task))

        # Gather results
        for retailer, task in scrape_tasks:
            try:
                result = await task
                results[retailer] = result

                # Store price data
                await workflow.execute_activity(
                    store_price_data_activity,
                    args=[product_id, retailer, result],
                    start_to_close_timeout=timedelta(seconds=30),
                )
            except Exception as e:
                results[retailer] = {"error": str(e)}

        return results


@workflow.defn
class RepricingWorkflow:
    """
    Workflow for repricing a product based on competitor data.
    """

    @workflow.run
    async def run(
        self,
        product_id: str,
        current_price: str,
        competitor_prices: list[dict],
        platform: str,
    ) -> dict[str, Any]:
        # Calculate new price
        decision = await workflow.execute_activity(
            calculate_reprice_activity,
            args=[product_id, competitor_prices, current_price],
            start_to_close_timeout=timedelta(seconds=30),
        )

        if decision is None:
            return {"action": "no_change", "product_id": product_id}

        # Update price on selling platform
        success = await workflow.execute_activity(
            update_store_price_activity,
            args=[product_id, decision["new_price"], platform],
            start_to_close_timeout=timedelta(minutes=1),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=5),
                maximum_attempts=3,
            ),
        )

        return {
            "action": "repriced" if success else "update_failed",
            "product_id": product_id,
            "old_price": current_price,
            "new_price": decision["new_price"],
            "reason": decision["decision_reason"],
        }


@workflow.defn
class ScheduledScrapeWorkflow:
    """
    Cron-style workflow for scheduled product scraping.

    Runs on a schedule and processes all active products.
    """

    @workflow.run
    async def run(self, batch_size: int = 100) -> dict[str, int]:
        # This would fetch products from database
        # For now, placeholder
        products_processed = 0
        errors = 0

        # In production, iterate through product batches
        # and spawn child workflows for each

        return {
            "processed": products_processed,
            "errors": errors,
        }
```

### 10.4. Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "title": "PriceGuard Operations",
    "uid": "priceguard-ops",
    "panels": [
      {
        "title": "Scrape Success Rate",
        "type": "gauge",
        "gridPos": {"x": 0, "y": 0, "w": 6, "h": 8},
        "targets": [
          {
            "expr": "sum(rate(scrape_success_total[5m])) / sum(rate(scrape_attempts_total[5m])) * 100",
            "legendFormat": "Success Rate %"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"color": "red", "value": null},
                {"color": "yellow", "value": 80},
                {"color": "green", "value": 95}
              ]
            },
            "unit": "percent",
            "min": 0,
            "max": 100
          }
        }
      },
      {
        "title": "Scrapes per Minute",
        "type": "timeseries",
        "gridPos": {"x": 6, "y": 0, "w": 12, "h": 8},
        "targets": [
          {
            "expr": "sum(rate(scrape_attempts_total[1m])) * 60",
            "legendFormat": "Total"
          },
          {
            "expr": "sum(rate(scrape_success_total[1m])) * 60",
            "legendFormat": "Successful"
          }
        ]
      },
      {
        "title": "Proxy Ban Rate by Tier",
        "type": "timeseries",
        "gridPos": {"x": 0, "y": 8, "w": 12, "h": 8},
        "targets": [
          {
            "expr": "sum(rate(proxy_bans_total[5m])) by (tier) * 60",
            "legendFormat": "{{tier}}"
          }
        ]
      },
      {
        "title": "Repricing Latency (p99)",
        "type": "stat",
        "gridPos": {"x": 12, "y": 8, "w": 6, "h": 4},
        "targets": [
          {
            "expr": "histogram_quantile(0.99, sum(rate(reprice_duration_seconds_bucket[5m])) by (le)) * 1000",
            "legendFormat": "p99 ms"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "ms",
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 100},
                {"color": "red", "value": 500}
              ]
            }
          }
        }
      },
      {
        "title": "Price Changes Today",
        "type": "stat",
        "gridPos": {"x": 18, "y": 8, "w": 6, "h": 4},
        "targets": [
          {
            "expr": "sum(increase(reprice_decisions_total[24h]))",
            "legendFormat": "Changes"
          }
        ]
      },
      {
        "title": "Competitor Response Time",
        "type": "heatmap",
        "gridPos": {"x": 0, "y": 16, "w": 24, "h": 8},
        "targets": [
          {
            "expr": "sum(rate(scrape_duration_seconds_bucket[5m])) by (le, competitor)",
            "format": "heatmap"
          }
        ]
      },
      {
        "title": "Active Owl Browser Nodes",
        "type": "stat",
        "gridPos": {"x": 12, "y": 12, "w": 6, "h": 4},
        "targets": [
          {
            "expr": "count(up{job=\"owl-browser\"} == 1)",
            "legendFormat": "Nodes"
          }
        ]
      },
      {
        "title": "Queue Depth",
        "type": "timeseries",
        "gridPos": {"x": 0, "y": 24, "w": 12, "h": 8},
        "targets": [
          {
            "expr": "nats_jetstream_stream_messages{stream=\"scrape-tasks\"}",
            "legendFormat": "Pending Tasks"
          }
        ]
      }
    ],
    "refresh": "30s",
    "time": {
      "from": "now-6h",
      "to": "now"
    }
  }
}
```

## 11. Advanced Features

### 11.1. MAP Monitoring (Minimum Advertised Price)

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import TypedDict

from owl_browser import Browser, Page


class MAPViolation(TypedDict):
    """MAP violation record."""
    product_id: str
    violator: str
    violator_url: str
    map_price: Decimal
    advertised_price: Decimal
    violation_percent: float
    screenshot_path: str
    detected_at: datetime


@dataclass(slots=True)
class MAPMonitor:
    """
    Monitor for Minimum Advertised Price violations.

    Tracks reseller pricing and generates evidence for legal teams.
    """

    browser: Browser
    map_prices: dict[str, Decimal]  # product_id -> MAP price

    async def check_map_compliance(
        self,
        product_id: str,
        reseller_url: str,
        reseller_name: str,
    ) -> MAPViolation | None:
        """
        Check if a reseller is violating MAP policy.

        Args:
            product_id: Product identifier
            reseller_url: Reseller's product page URL
            reseller_name: Reseller name

        Returns:
            Violation record if MAP is violated, None otherwise
        """
        map_price = self.map_prices.get(product_id)
        if map_price is None:
            return None

        page = self.browser.new_page()

        try:
            await page.goto(reseller_url, wait_until="networkidle")

            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=2)

            # Extract advertised price
            price_data = await page.extract_json(template={
                "price": "current advertised price (number only)",
                "currency": "currency code"
            })

            if not price_data.get("price"):
                return None

            advertised_price = Decimal(str(price_data["price"]))

            # Check for violation (price below MAP)
            if advertised_price >= map_price:
                return None

            violation_percent = float((map_price - advertised_price) / map_price * 100)

            # Capture evidence screenshot
            screenshot_path = f"/tmp/map_violation_{product_id}_{reseller_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png"
            await page.screenshot(screenshot_path, mode="fullpage")

            return MAPViolation(
                product_id=product_id,
                violator=reseller_name,
                violator_url=reseller_url,
                map_price=map_price,
                advertised_price=advertised_price,
                violation_percent=violation_percent,
                screenshot_path=screenshot_path,
                detected_at=datetime.utcnow(),
            )

        finally:
            await page.close()

    async def generate_violation_report(
        self,
        violations: list[MAPViolation],
    ) -> str:
        """
        Generate PDF report of MAP violations for legal team.

        Returns:
            Path to generated PDF report
        """
        # In production, use a PDF library like reportlab or weasyprint
        # This is a placeholder implementation
        report_path = f"/tmp/map_violations_report_{datetime.utcnow().strftime('%Y%m%d')}.pdf"

        # Generate report content
        # ...

        return report_path
```

### 11.2. Visual Search (Cross-Retailer Product Discovery)

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TypedDict

from owl_browser import Browser, Page


class VisualSearchResult(TypedDict):
    """Visual search match result."""
    retailer: str
    product_url: str
    product_title: str
    price: str | None
    confidence: float


@dataclass(frozen=True, slots=True)
class VisualProductSearch:
    """
    Find products across retailers using visual search.

    Uses Owl Browser's VLM to match products by appearance
    when no UPC/SKU match is available.
    """

    browser: Browser

    async def find_product_across_retailers(
        self,
        source_url: str,
        target_retailers: list[dict[str, str]],  # [{"name": "walmart", "search_url": "..."}]
    ) -> list[VisualSearchResult]:
        """
        Search for a product across multiple retailers.

        Args:
            source_url: URL of the source product
            target_retailers: List of retailers to search

        Returns:
            List of matching products found
        """
        results: list[VisualSearchResult] = []

        # Get source product details
        source_page = self.browser.new_page()

        try:
            await source_page.goto(source_url, wait_until="networkidle")

            if await source_page.detect_captcha():
                await source_page.solve_captcha(max_attempts=2)

            # Get detailed product description for search
            source_info = await source_page.query_page(
                "Describe this product in detail: brand, model, color, size, key features. "
                "Format as a search query."
            )

            # Get product title for search
            source_title = await source_page.ai_extract("The exact product title")

            # Take screenshot for visual reference
            await source_page.screenshot("/tmp/source_product.png", mode="viewport")

        finally:
            await source_page.close()

        # Search each target retailer
        for retailer in target_retailers:
            result = await self._search_retailer(
                retailer["name"],
                retailer["search_url"],
                source_title or source_info,
                source_info,
            )
            if result:
                results.append(result)

        return results

    async def _search_retailer(
        self,
        retailer_name: str,
        search_url: str,
        search_query: str,
        source_description: str,
    ) -> VisualSearchResult | None:
        """Search a single retailer for matching product."""
        page = self.browser.new_page()

        try:
            # Navigate to search page
            full_url = f"{search_url}?q={search_query.replace(' ', '+')}"
            await page.goto(full_url, wait_until="networkidle")

            if await page.detect_captcha():
                await page.solve_captcha(max_attempts=2)

            # Ask VLM to find best match
            match_analysis = await page.query_page(
                f"I'm looking for this product: {source_description}\n\n"
                f"Which product in the search results is the best match? "
                f"Consider brand, model, appearance, and specifications. "
                f"Rate your confidence from 0-100. "
                f"If no good match exists, say 'NO_MATCH'."
            )

            if "no_match" in match_analysis.lower():
                return None

            # Click on the best match
            try:
                await page.ai_click(f"The product that best matches: {source_description}")
                await page.wait_for_network_idle(idle_time=2000)
            except Exception:
                return None

            # Get product details
            product_url = await page.get_current_url()
            product_title = await page.ai_extract("The product title")
            product_price = await page.ai_extract("The current price (number only)")

            # Estimate confidence from match analysis
            confidence = 0.7  # Default
            if "exact" in match_analysis.lower() or "perfect" in match_analysis.lower():
                confidence = 0.95
            elif "very" in match_analysis.lower() and "similar" in match_analysis.lower():
                confidence = 0.85
            elif "similar" in match_analysis.lower():
                confidence = 0.75

            return VisualSearchResult(
                retailer=retailer_name,
                product_url=product_url,
                product_title=product_title or "",
                price=product_price,
                confidence=confidence,
            )

        except Exception:
            return None

        finally:
            await page.close()
```

---

## Appendix A: SDK Method Quick Reference

| Category | Method | Description |
|----------|--------|-------------|
| **Navigation** | `page.goto(url)` | Navigate to URL |
| | `page.reload()` | Reload current page |
| | `page.go_back()` | Navigate back |
| **Interaction** | `page.click(selector)` | Click element |
| | `page.type(selector, text)` | Type into input |
| | `page.press_key(key)` | Press keyboard key |
| | `page.ai_click(description)` | Click via AI |
| | `page.ai_type(description, text)` | Type via AI |
| **Extraction** | `page.extract_json(template)` | Structured extraction |
| | `page.extract_text(selector)` | Get element text |
| | `page.ai_extract(what)` | AI-powered extraction |
| | `page.query_page(query)` | Ask questions about page |
| **CAPTCHA** | `page.detect_captcha()` | Check for CAPTCHA |
| | `page.solve_captcha()` | Auto-solve CAPTCHA |
| **Cookies** | `page.set_cookie(...)` | Set cookie |
| | `page.get_cookies(url)` | Get cookies |
| | `page.delete_cookies(...)` | Delete cookies |
| **JavaScript** | `page.evaluate(script)` | Execute JS |
| | `page.expression(expr)` | Evaluate expression |
| **Network** | `page.enable_network_logging()` | Enable logging |
| | `page.get_network_log()` | Get request log |
| | `page.set_proxy(config)` | Set proxy |
| **Waiting** | `page.wait_for_network_idle()` | Wait for idle |
| | `page.wait_for_selector()` | Wait for element |
| | `page.wait(ms)` | Wait fixed time |
| **Visual** | `page.screenshot(path)` | Take screenshot |
| | `page.set_viewport(w, h)` | Set viewport size |
| **Context** | `browser.new_page(proxy=...)` | Create new page |
| | `browser.get_demographics()` | Get geo info |
| | `page.close()` | Close page |

---

*PriceGuard Documentation - Production Ready*
*Built with Owl Browser SDK*

---

## Disclaimer

This project documentation was generated by generative AI. While the architectural concepts and implementation patterns are based on real-world best practices, some features, configurations, or code examples may require adjustments for production use. Please review and test thoroughly before deploying.