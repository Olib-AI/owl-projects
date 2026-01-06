# AutoQA AI Testing System

Production-ready test automation framework with natural language YAML definitions, self-healing selectors, enterprise visual regression, ML-based assertions, and version tracking capabilities.

**No LLM/AI dependency required** - All assertions use deterministic algorithms (computer vision, OCR, DOM analysis).

## Key Features

- **Natural Language YAML Tests**: Human-readable test definitions replacing Selenium/Playwright boilerplate
- **Self-Healing Selectors**: Automatic recovery from broken selectors using deterministic strategies (text matching, fuzzy attributes, XPath fallbacks)
- **Enterprise Visual Regression**: Anti-aliasing tolerance, auto-mask dynamic regions, multi-threshold modes, device-specific baselines
- **ML Assertions**: OCR text extraction, color analysis, layout validation, accessibility checks - all without LLM
- **Version Tracking**: Compare test runs over time with visual and DOM diff reports
- **CI/CD Integration**: Ready-to-use templates for GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, CircleCI

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [CLI Reference](#cli-reference)
4. [Test DSL Reference](#test-dsl-reference)
5. [Assertions](#assertions)
6. [Visual Regression](#visual-regression)
7. [Version Tracking](#version-tracking)
8. [Self-Healing](#self-healing)
9. [CI/CD Integration](#cicd-integration)
10. [Example Tests](#example-tests)
11. [Environment Variables](#environment-variables)
12. [Architecture](#architecture)

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/Olib-AI/owl-projects.git
cd owl-projects/autoqa-ai-testing

# Install with pip
pip install -e .

# Or with development dependencies
pip install -e ".[dev]"
```

### Dependencies

Core dependencies (automatically installed):
- `owl-browser>=1.0.0` - Browser automation engine
- `pydantic>=2.10.0` - Data validation
- `pyyaml>=6.0.2` - YAML parsing
- `pillow>=11.0.0`, `scikit-image>=0.24.0` - Visual regression
- `opencv-python>=4.10.0`, `easyocr>=1.7.0` - ML assertions
- `fastapi>=0.115.0`, `uvicorn>=0.32.0` - API server

### Environment Setup

Create a `.env` file in your project root:

```bash
# Required: Remote browser connection
OWL_BROWSER_URL=https://your-browser-server.example.com
OWL_BROWSER_TOKEN=your-auth-token

# Optional: Storage configuration
ARTIFACT_PATH=./artifacts
REDIS_URL=redis://localhost:6379/0
DATABASE_URL=postgresql://user:pass@localhost/autoqa
S3_BUCKET=your-artifacts-bucket
```

---

## Quick Start

### 1. Create a Test Specification

```yaml
# tests/login_test.yaml
name: Login Flow Test
description: Verify user can log in successfully

variables:
  base_url: https://example.com

steps:
  - name: Navigate to login
    action: navigate
    url: ${base_url}/login

  - name: Enter username
    action: type
    selector: "#username"
    text: testuser

  - name: Enter password
    action: type
    selector: "#password"
    text: secret123

  - name: Click login button
    action: click
    selector: "button[type='submit']"

  - name: Verify dashboard loads
    action: assert
    assertion:
      selector: ".dashboard"
      operator: is_visible
      timeout: 5000
      message: "Dashboard should be visible after login"
```

### 2. Run Your First Test

```bash
# Run a single test
autoqa run tests/login_test.yaml

# Run with verbose output
autoqa run tests/login_test.yaml -v

# Run with fast mode (reduced timeouts)
autoqa run tests/login_test.yaml --fast-mode
```

---

## CLI Reference

### `autoqa run` - Execute Tests

```bash
autoqa run <paths> [options]
```

**Arguments:**
- `paths` - One or more test files or directories

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `-e, --environment` | Target environment name | `default` |
| `--parallel` | Run tests in parallel | `false` |
| `--max-parallel` | Maximum parallel tests | `5` |
| `--record-video` | Record video of execution | `false` |
| `--artifacts-dir` | Directory for artifacts | `./artifacts` |
| `--output-format` | Output format: `json`, `junit`, `html` | `json` |
| `--output-file` | Write results to file | stdout |
| `--var KEY=VALUE` | Set variable (repeatable) | - |
| `--healing-history` | Path to self-healing history file | - |
| `--default-timeout` | Default timeout in ms | `10000` |
| `--no-network-idle-wait` | Skip network idle wait | `false` |
| `--fast-mode` | Reduced timeouts (5000ms default) | `false` |
| `--versioned` | Enable version tracking | `false` |
| `--versioning-path` | Version history storage path | `.autoqa/history` |
| `-v, --verbose` | Verbose logging | `false` |

**Examples:**
```bash
# Run all tests in directory with JUnit output
autoqa run tests/ --output-format junit --output-file results.xml

# Run with custom variables
autoqa run tests/ --var BASE_URL=https://staging.example.com --var USER=testuser

# Run with versioning enabled
autoqa run tests/ --versioned --versioning-path .autoqa/history

# Fast mode for local development
autoqa run tests/ --fast-mode --parallel --max-parallel 3
```

### `autoqa validate` - Validate Test Specs

```bash
autoqa validate <paths>
```

Validates YAML syntax and DSL schema without executing tests.

```bash
autoqa validate tests/
# Output: Valid: tests/login_test.yaml (Login Flow Test, 5 steps)
```

### `autoqa history` - View Test Version History

```bash
autoqa history <test_name> [options]
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--storage-path` | Version history path | `.autoqa/history` |
| `--limit` | Maximum versions to show | `20` |
| `--format` | Output format: `table`, `json` | `table` |

**Example:**
```bash
autoqa history "Login Flow Test" --limit 10

# Output:
# Version History: Login Flow Test
# Storage: .autoqa/history
# --------------------------------------------------------------------------------
# Version ID           Timestamp              Status     Duration   Screenshot
# --------------------------------------------------------------------------------
# 20250106143022-a1b2  2025-01-06 14:30:22   passed     1523ms     Yes
# 20250105091545-c3d4  2025-01-05 09:15:45   passed     1489ms     Yes
```

### `autoqa diff` - Compare Test Versions

```bash
autoqa diff <test_name> [options]
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--from` | Start date (YYYY-MM-DD) or version ID | - |
| `--to` | End date or version ID | latest |
| `--latest N` | Compare last N runs | - |
| `--storage-path` | Version history path | `.autoqa/history` |
| `--output` | Output: `terminal`, `html`, `json` | `terminal` |
| `--output-file` | Save report to file | - |

**Examples:**
```bash
# Compare last 2 runs
autoqa diff "Login Flow Test" --latest 2

# Compare specific dates
autoqa diff "Login Flow Test" --from 2025-01-01 --to 2025-01-06

# Generate HTML report
autoqa diff "Login Flow Test" --latest 2 --output html --output-file diff_report.html
```

### `autoqa ci` - Generate CI/CD Configuration

```bash
autoqa ci <provider> [options]
```

**Providers:** `github`, `gitlab`, `jenkins`, `azure`, `circleci`

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--test-paths` | Paths to test specs | `tests/` |
| `-o, --output` | Output file path | stdout |
| `--python-version` | Python version | `3.12` |
| `--parallel` | Enable parallel execution | `false` |
| `--nodes` | Number of parallel nodes | `1` |

**Examples:**
```bash
# Generate GitHub Actions workflow
autoqa ci github --test-paths tests/ -o .github/workflows/autoqa.yml

# Generate GitLab CI with parallel execution
autoqa ci gitlab --test-paths tests/ --parallel --nodes 3 -o .gitlab-ci.yml
```

### `autoqa server` - Start API Server

```bash
autoqa server [options]
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--host` | Server host | `0.0.0.0` |
| `--port` | Server port | `8080` |

```bash
autoqa server --host 127.0.0.1 --port 8080
```

---

## Test DSL Reference

### Actions

#### Navigation Actions

| Action | Description | Required Parameters |
|--------|-------------|---------------------|
| `navigate` | Navigate to URL | `url` |
| `wait` | Wait for time (ms) | `timeout` |
| `wait_for_selector` | Wait for element | `selector` |
| `wait_for_network_idle` | Wait for network idle | - |
| `wait_for_url` | Wait for URL change | `url` |

```yaml
- action: navigate
  url: https://example.com
  wait_until: networkidle  # load, domcontentloaded, networkidle
  timeout: 10000
```

#### Interaction Actions

| Action | Description | Required Parameters |
|--------|-------------|---------------------|
| `click` | Click element | `selector` |
| `double_click` | Double-click element | `selector` |
| `right_click` | Right-click element | `selector` |
| `hover` | Hover over element | `selector` |
| `drag_drop` | Drag and drop | `start_x`, `start_y`, `end_x`, `end_y` |

```yaml
- action: click
  selector: "button.submit"
  timeout: 5000

- action: drag_drop
  start_x: 100
  start_y: 200
  end_x: 300
  end_y: 400
```

#### Form Actions

| Action | Description | Required Parameters |
|--------|-------------|---------------------|
| `type` | Type text into element | `selector`, `text` |
| `pick` | Select dropdown option | `selector`, `value` |
| `press_key` | Press keyboard key | `key` |
| `submit` | Submit form | `selector` |
| `upload` | Upload files | `selector`, `file_paths` |

```yaml
- action: type
  selector: "#email"
  text: "user@example.com"

- action: pick
  selector: "#country"
  value: "US"

- action: press_key
  key: Enter
  modifiers: ["Control"]  # Optional: Shift, Control, Alt, Meta
```

#### Scroll Actions

| Action | Description | Required Parameters |
|--------|-------------|---------------------|
| `scroll` | Scroll by offset | `scroll_x`, `scroll_y` |
| `scroll_to` | Scroll to position | `x`, `y` |
| `scroll_to_element` | Scroll element into view | `selector` |

#### Extraction Actions

| Action | Description | Required Parameters |
|--------|-------------|---------------------|
| `screenshot` | Take screenshot | - |
| `extract_text` | Extract element text | `selector` |
| `extract_json` | Extract JSON data | `template` |
| `get_html` | Get element HTML | `selector` |
| `get_markdown` | Get page as markdown | - |
| `get_attribute` | Get element attribute | `selector`, `attribute_name` |
| `get_network_log` | Get network requests | - |

```yaml
- action: extract_text
  selector: ".price"
  capture_as: product_price  # Store in variable

- action: get_attribute
  selector: "img.logo"
  attribute_name: "src"
  capture_as: logo_url
```

#### State Check Actions

| Action | Description | Required Parameters |
|--------|-------------|---------------------|
| `check_visible` | Check if visible | `selector` |
| `check_enabled` | Check if enabled | `selector` |
| `check_checked` | Check if checked | `selector` |

#### Cookie Actions

| Action | Description | Required Parameters |
|--------|-------------|---------------------|
| `set_cookie` | Set cookie | `cookie_name`, `cookie_value` |
| `delete_cookies` | Delete all cookies | - |

```yaml
- action: set_cookie
  cookie_name: session
  cookie_value: abc123
  cookie_domain: example.com
  cookie_path: /
  cookie_secure: true
  cookie_http_only: true
```

#### Viewport Actions

| Action | Description | Required Parameters |
|--------|-------------|---------------------|
| `set_viewport` | Set viewport size | `width`, `height` |
| `new_page` | Open new page | - |
| `close_page` | Close current page | - |

```yaml
- action: set_viewport
  width: 1920
  height: 1080
```

### Variables and Loops

Variables can be defined at test or suite level and referenced with `${variable_name}`:

```yaml
variables:
  base_url: https://example.com
  username: testuser
  timeout: 5000

steps:
  - action: navigate
    url: ${base_url}/login

  - action: type
    selector: "#username"
    text: ${username}
```

**Variable Sources:**
```yaml
variables:
  # Plain value
  app_name: MyApp

  # Environment variable
  api_key: ${env:API_KEY}

  # HashiCorp Vault
  password: ${vault:secrets/test-password}

  # AWS Secrets Manager
  token: ${aws_secrets:my-api-token}

  # Kubernetes Secret
  db_pass: ${k8s_secret:db-credentials/password}
```

### Versioning Configuration

Enable version tracking in test specs:

```yaml
versioning:
  enabled: true
  storage_path: .autoqa/history
  retention_days: 90
  capture_screenshots: true
  capture_network: true
  capture_elements: true
  element_selectors:
    - "h1"
    - "nav"
    - ".main-content"
  auto_compare_previous: false
  diff_threshold: 0.05
```

---

## Assertions

### Standard Assertions

```yaml
- action: assert
  assertion:
    selector: ".element"
    operator: <operator>
    expected: <value>
    timeout: 5000
    message: "Custom error message"
```

**Operators:**

| Category | Operators |
|----------|-----------|
| Value | `equals`, `not_equals`, `contains`, `not_contains`, `matches`, `starts_with`, `ends_with` |
| Numeric | `greater_than`, `less_than`, `greater_or_equal`, `less_or_equal` |
| Element State | `is_visible`, `is_hidden`, `is_enabled`, `is_disabled`, `is_checked`, `is_unchecked`, `exists`, `not_exists` |
| Boolean | `is_truthy`, `is_falsy` |
| Attribute | `has_attribute`, `attribute_equals`, `attribute_contains` |

**Examples:**
```yaml
# Element visibility
- action: assert
  assertion:
    selector: ".dashboard"
    operator: is_visible

# Text contains
- action: assert
  assertion:
    selector: "h1"
    operator: contains
    expected: "Welcome"

# Attribute value
- action: assert
  assertion:
    selector: "input#email"
    attribute: "value"
    operator: equals
    expected: "user@example.com"
```

### URL Assertions

```yaml
- action: url_assert
  url_pattern: "/dashboard"
  is_regex: false
```

**URL Operators:** `url_equals`, `url_contains`, `url_matches`

### Network Assertions

```yaml
- action: network_assert
  network_assertion:
    url_pattern: "/api/users"
    is_regex: false
    method: GET
    status_code: 200
    status_range: [200, 299]
    response_contains: "success"
    headers_contain:
      Content-Type: "application/json"
    max_response_time_ms: 2000
    should_be_blocked: false
    timeout: 30000
```

### Visual Regression Assertions

```yaml
- action: visual_assert
  visual_assertion:
    baseline_name: homepage
    selector: "body"  # Optional: element-specific screenshot
    mode: semantic    # pixel, perceptual, structural, semantic
    threshold: 0.05
    threshold_mode: normal  # strict, normal, loose, custom
```

See [Visual Regression](#visual-regression) for detailed configuration.

### ML-Based Assertions (No LLM Required)

#### OCR Text Assertion
```yaml
- action: ocr_assert
  ocr_assertion:
    backend: easyocr  # or pytesseract
    languages: ["en"]
    region: [100, 100, 400, 200]  # x, y, width, height
    expected_text: "Welcome"
    contains: "Hello"
    min_confidence: 0.5
```

#### UI State Assertion
```yaml
- action: ui_state_assert
  ui_state_assertion:
    expected_state: normal  # loading, error, success, empty, normal
    min_confidence: 0.5
```

#### Color Assertion
```yaml
- action: color_assert
  color_assertion:
    dominant_color: "#ffffff"  # or RGB: "(255, 255, 255)"
    has_color: "#007bff"
    tolerance: 30
    min_percentage: 0.01
```

#### Layout Assertion
```yaml
- action: layout_assert
  layout_assertion:
    expected_count: 5
    min_count: 3
    max_count: 10
    alignment: center  # left, right, center, top, bottom, vertical_center
    alignment_tolerance: 10
    element_type: button  # icon, button, input_field, container
```

#### Icon/Logo Assertion
```yaml
- action: icon_assert
  icon_assertion:
    template_path: ./templates/logo.png
    method: feature  # feature (ORB) or correlation (template matching)
    min_confidence: 0.5
```

#### Accessibility Assertion
```yaml
- action: accessibility_assert
  accessibility_assertion:
    min_contrast_ratio: 4.5  # WCAG AA = 4.5, AAA = 7.0
    wcag_level: AA  # or AAA
    region: [0, 0, 1920, 1080]
```

---

## Visual Regression

### Threshold Modes

| Mode | Similarity Required | Use Case |
|------|---------------------|----------|
| `strict` | 99% (1% tolerance) | Pixel-perfect UIs |
| `normal` | 95% (5% tolerance) | Standard testing |
| `loose` | 85% (15% tolerance) | Highly dynamic pages |
| `custom` | User-defined | Fine-tuned thresholds |

### Comparison Modes

| Mode | Algorithm | Best For |
|------|-----------|----------|
| `pixel` | Exact pixel comparison | Static layouts |
| `perceptual` | Perceptual hash (pHash) | Minor variations |
| `structural` | SSIM (Structural Similarity) | Layout changes |
| `semantic` | Combined analysis | General use |

### Anti-Aliasing Tolerance

Handle font rendering differences across platforms:

```yaml
visual_assertion:
  baseline_name: cross_platform_test
  anti_aliasing_tolerance: 0.5  # 0-1, higher = more tolerance
  anti_aliasing_sigma: 1.5      # Gaussian blur sigma (0.1-5.0)
```

### Auto-Mask Dynamic Regions

Automatically detect and ignore dynamic content (ads, timestamps, avatars):

```yaml
visual_assertion:
  baseline_name: homepage
  auto_mask_dynamic: true
```

### Manual Ignore Regions

```yaml
visual_assertion:
  baseline_name: page_with_ads
  ignore_regions:
    - x: 0
      y: 0
      width: 300
      height: 250
    - x: 800
      y: 100
      width: 160
      height: 600
```

### Device-Specific Baselines

```yaml
steps:
  - action: set_viewport
    width: 375
    height: 812

  - action: visual_assert
    visual_assertion:
      baseline_name: mobile_homepage
      threshold_mode: normal

  - action: set_viewport
    width: 1920
    height: 1080

  - action: visual_assert
    visual_assertion:
      baseline_name: desktop_homepage
      threshold_mode: normal
```

### HTML Diff Reports

```yaml
visual_assertion:
  baseline_name: homepage
  generate_html_report: true
```

### Full Enterprise Configuration

```yaml
visual_assertion:
  baseline_name: enterprise_test
  selector: "main.content"
  mode: semantic
  threshold_mode: normal
  threshold: 0.08
  anti_aliasing_tolerance: 0.3
  anti_aliasing_sigma: 1.2
  auto_mask_dynamic: true
  normalize_scroll: true
  generate_html_report: true
  ignore_colors: false
  ignore_regions:
    - x: 0
      y: 0
      width: 100
      height: 50
  update_baseline: false
```

---

## Version Tracking

### Enabling Version Tracking

**Method 1: CLI Flag**
```bash
autoqa run tests/ --versioned --versioning-path .autoqa/history
```

**Method 2: Test Spec Configuration**
```yaml
versioning:
  enabled: true
  storage_path: .autoqa/history
  retention_days: 90
  capture_screenshots: true
  capture_network: true
  capture_elements: true
  element_selectors:
    - "h1"
    - "nav"
    - ".main-content"
```

### Viewing History

```bash
autoqa history "My Test Name" --limit 20
```

### Comparing Versions

```bash
# Compare last 2 runs
autoqa diff "My Test Name" --latest 2

# Compare by date range
autoqa diff "My Test Name" --from 2025-01-01 --to 2025-01-06

# Generate HTML report
autoqa diff "My Test Name" --latest 2 --output html --output-file report.html
```

### Diff Report Contents

- **Visual Changes**: Screenshot diff with percentage change and severity
- **Text Changes**: Added/removed/modified text content
- **Element Changes**: DOM element additions, removals, modifications
- **Layout Shifts**: Element position changes with pixel distances
- **Network Changes**: API request/response differences

---

## Self-Healing

AutoQA automatically recovers from broken selectors using deterministic strategies (no AI/LLM dependency).

### Healing Strategies

| Strategy | Confidence | Description |
|----------|------------|-------------|
| `cached_history` | 98% | Previously successful selector |
| `id_fallback` | 95% | Element ID variations |
| `data_testid` | 92% | `data-testid` attribute |
| `text_match` | 90% | Visible text content |
| `name_fallback` | 90% | Form element `name` |
| `aria_label` | 88% | Accessibility labels |
| `placeholder_fallback` | 85% | Input placeholders |
| `xpath_fallback` | 70-90% | XPath alternatives |
| `attribute_fuzzy` | 65-85% | Partial attribute matching |

### Enabling Healing History

```bash
autoqa run tests/ --healing-history ./healing_history.json
```

The healing history file persists successful selector mappings for future runs.

### How It Works

1. Test attempts to find element with original selector
2. If element not found, healing engine activates
3. Engine tries strategies in order of confidence
4. First working selector is used and cached
5. Mapping saved to history for future runs

---

## CI/CD Integration

### GitHub Actions

```bash
autoqa ci github --test-paths tests/ -o .github/workflows/autoqa.yml
```

**Generated workflow:**
```yaml
name: AutoQA Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install autoqa-ai-testing
      - run: autoqa run tests/ --output-format junit --output-file results.xml
        env:
          OWL_BROWSER_URL: ${{ secrets.OWL_BROWSER_URL }}
          OWL_BROWSER_TOKEN: ${{ secrets.OWL_BROWSER_TOKEN }}
      - uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: results.xml
```

### GitLab CI

```bash
autoqa ci gitlab --test-paths tests/ --parallel --nodes 3 -o .gitlab-ci.yml
```

**Generated configuration:**
```yaml
stages:
  - test

autoqa:
  stage: test
  image: python:3.12
  parallel: 3
  script:
    - pip install autoqa-ai-testing
    - autoqa run tests/ --output-format junit --output-file results.xml
  variables:
    OWL_BROWSER_URL: $OWL_BROWSER_URL
    OWL_BROWSER_TOKEN: $OWL_BROWSER_TOKEN
  artifacts:
    reports:
      junit: results.xml
```

### Jenkins

```bash
autoqa ci jenkins --test-paths tests/ -o Jenkinsfile
```

### Azure Pipelines

```bash
autoqa ci azure --test-paths tests/ -o azure-pipelines.yml
```

### CircleCI

```bash
autoqa ci circleci --test-paths tests/ -o .circleci/config.yml
```

---

## Example Tests

### Example 1: Google Search Test

```yaml
name: Google Search Test
description: Validates navigation, form input, and text assertions

metadata:
  tags: [search, forms, navigation]
  priority: high
  timeout_ms: 60000

steps:
  - name: Navigate to Google
    action: navigate
    url: https://www.google.com
    wait_until: domcontentloaded

  - name: Wait for search box
    action: wait_for_selector
    selector: "textarea[name='q'], input[name='q']"
    timeout: 5000

  - name: Type search query
    action: type
    selector: "textarea[name='q'], input[name='q']"
    text: "AutoQA testing"

  - name: Submit search
    action: press_key
    key: Enter

  - name: Wait for results
    action: wait_for_selector
    selector: "#search, #rso"
    timeout: 5000

  - name: Assert results contain search term
    action: assert
    assertion:
      selector: "body"
      operator: contains
      expected: "AutoQA"
      message: "Search results should contain the search term"

  - name: Screenshot results
    action: screenshot
    filename: google_search_results.png
```

### Example 2: Visual Regression with Enterprise Features

```yaml
name: Visual Regression Test
description: Enterprise visual regression with anti-aliasing and auto-masking

metadata:
  tags: [visual-regression, enterprise]
  priority: high

steps:
  - action: navigate
    url: https://example.com

  - action: wait_for_network_idle
    timeout: 5000

  # Strict mode for critical UI
  - name: Visual check - strict
    action: visual_assert
    visual_assertion:
      baseline_name: homepage_strict
      threshold_mode: strict
      update_baseline: true

  # Cross-platform with anti-aliasing tolerance
  - name: Visual check - anti-aliased
    action: visual_assert
    visual_assertion:
      baseline_name: homepage_cross_platform
      anti_aliasing_tolerance: 0.5
      anti_aliasing_sigma: 1.5
      threshold_mode: normal
      update_baseline: true

  # Auto-mask dynamic content
  - name: Visual check - auto-masked
    action: visual_assert
    visual_assertion:
      baseline_name: homepage_dynamic
      auto_mask_dynamic: true
      generate_html_report: true
      threshold_mode: normal
```

### Example 3: Version Tracking Test

```yaml
name: Version Tracking Demo
description: Test with full version tracking enabled

versioning:
  enabled: true
  storage_path: .autoqa/history
  retention_days: 90
  capture_screenshots: true
  capture_network: true
  capture_elements: true
  element_selectors:
    - "h1"
    - "nav"
    - ".main-content"

variables:
  target_url: https://example.com

steps:
  - name: Navigate to page
    action: navigate
    url: ${target_url}
    wait_until: networkidle

  - name: Capture heading
    action: extract_text
    selector: "h1"
    capture_as: page_heading

  - name: Screenshot for baseline
    action: screenshot
    filename: version_test.png

  - name: Verify page loaded
    action: assert
    assertion:
      selector: "body"
      operator: exists
```

---

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `OWL_BROWSER_URL` | Remote browser server URL | Yes | - |
| `OWL_BROWSER_TOKEN` | Authentication token | No | - |
| `ARTIFACT_PATH` | Local artifact directory | No | `./artifacts` |
| `REDIS_URL` | Redis connection URL | No | `redis://localhost:6379/0` |
| `DATABASE_URL` | PostgreSQL connection URL | No | - |
| `S3_BUCKET` | S3 bucket for artifacts | No | - |

---

## Architecture

```
autoqa-ai-testing/
├── src/autoqa/
│   ├── api/           # FastAPI REST gateway
│   ├── ci/            # CI/CD template generation
│   ├── dsl/           # YAML parser and Pydantic models
│   │   ├── models.py  # All DSL action/assertion definitions
│   │   └── parser.py  # YAML parsing and validation
│   ├── runner/        # Test execution engine
│   │   ├── test_runner.py    # Main runner
│   │   └── self_healing.py   # Selector healing
│   ├── versioning/    # Version tracking system
│   │   ├── history_tracker.py
│   │   ├── diff_analyzer.py
│   │   └── models.py
│   ├── visual/        # Visual regression engine
│   ├── ml/            # ML-based assertions (OCR, color, layout)
│   ├── storage/       # S3 and PostgreSQL persistence
│   └── orchestrator/  # Distributed test scheduling
├── tests/             # Example test specifications
└── templates/         # Example templates
```

---

## License

MIT License - see LICENSE file for details.

---

## Support

- **Repository**: [https://github.com/Olib-AI/owl-projects](https://github.com/Olib-AI/owl-projects)
- **Homepage**: [https://owlbrowser.net](https://owlbrowser.net)
