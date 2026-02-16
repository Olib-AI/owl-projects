# AutoQA AI Testing System

Production-ready test automation with natural language YAML definitions, self-healing selectors, and visual regression.

**No LLM/AI dependency required** - All core features use deterministic algorithms.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Where to Start?

The fastest way to get started is to **automatically generate tests** for any website:

```bash
# Install
pip install autoqa-ai-testing

# Build tests automatically for any website
autoqa build https://your-website.com --output my_tests.yaml

# Run the generated tests
autoqa run my_tests.yaml
```

That's it! AutoQA will:
1. Crawl your website and discover all interactive elements
2. Detect login forms, navigation flows, and key user journeys
3. Optionally use **vision AI** to analyze page screenshots for richer element detection
4. Generate a complete YAML test specification
5. Execute the tests with self-healing selector recovery

---

## Quick Start

### 1. Generate Tests Automatically

```bash
# Simple page
autoqa build https://example.com -o tests/example.yaml

# With authentication (auto-detects login forms)
autoqa build https://myapp.com/login -u testuser -p secret123 -o tests/login.yaml

# Deep crawl (multiple pages)
autoqa build https://myapp.com --depth 2 --max-pages 20 -o tests/full.yaml

# With vision-enhanced analysis (requires LLM config - see .env.example)
autoqa build https://myapp.com --vision -o tests/vision.yaml
```

### 2. Run Tests

```bash
# Run single test
autoqa run tests/example.yaml

# Run all tests with verbose output
autoqa run tests/ -v

# Parallel execution with JUnit report
autoqa run tests/ --parallel --output-format junit --output-file results.xml
```

### 3. Write Custom Tests (YAML)

```yaml
name: Login Flow Test
description: Verify user can log in successfully

variables:
  base_url: https://example.com

steps:
  - name: Navigate to login
    action: navigate
    url: ${base_url}/login

  - name: Enter credentials
    action: type
    selector: "#username"
    text: testuser

  - name: Enter password
    action: type
    selector: "#password"
    text: secret123

  - name: Click login
    action: click
    selector: "button[type='submit']"

  - name: Verify dashboard
    action: assert
    assertion:
      selector: ".dashboard"
      operator: is_visible
      message: "Dashboard should be visible after login"
```

---

## Key Features

- **Auto Test Generation** - Build tests automatically from any URL
- **Vision-Enhanced Analysis** - Optionally use vision AI to detect UI elements from screenshots
- **Natural Language YAML** - Human-readable test definitions
- **Self-Healing Selectors** - Automatic recovery from broken selectors (no AI required)
- **Visual Regression** - Screenshot comparison with anti-aliasing tolerance
- **ML Assertions** - OCR, color analysis, layout validation, accessibility checks
- **Version Tracking** - Compare test runs over time with visual diffs
- **Parallel Execution** - Run tests concurrently with resource-aware scaling
- **CI/CD Ready** - GitHub Actions, GitLab CI, Jenkins, Azure, CircleCI templates

---

## Installation

```bash
# From source
git clone https://github.com/Olib-AI/owl-projects.git
cd owl-projects/autoqa-ai-testing
pip install -e .

# With development dependencies
pip install -e ".[dev]"
```

### Environment Setup

Copy the example and fill in your values:

```bash
cp .env.example .env
```

At minimum you need the browser connection:

```bash
# Required: Remote browser connection
OWL_BROWSER_URL=https://your-browser-server.example.com
OWL_BROWSER_TOKEN=your-auth-token
```

See [`.env.example`](.env.example) for all available options including LLM and vision configuration.

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `autoqa build <url>` | Auto-generate tests from a webpage |
| `autoqa run <paths>` | Execute test specifications |
| `autoqa validate <paths>` | Validate YAML syntax |
| `autoqa history <test>` | View test version history |
| `autoqa diff <test>` | Compare test versions |
| `autoqa ci <provider>` | Generate CI/CD config |
| `autoqa server` | Start API server |

### `autoqa build` Options

```
autoqa build <url> [options]

Options:
  -o, --output FILE          Output YAML file path (default: stdout)
  -u, --username USER        Username for authentication
  -p, --password PASS        Password for authentication
  -d, --depth N              Crawl depth for same-domain pages (default: 1)
  --max-pages N              Maximum pages to analyze (default: 10)
  --include-hidden           Include hidden elements in analysis
  --timeout MS               Timeout in milliseconds (default: 30000)
  --exclude PATTERN          Regex pattern for URLs to exclude (repeatable)
  --include PATTERN          Regex pattern for URLs to include (repeatable)
  --selector-strategy MODE   'semantic' (default) or 'css'
  --vision                   Use vision model to enhance page analysis
```

### `autoqa run` Options

```
autoqa run <paths> [options]

Options:
  -e, --environment ENV      Target environment (default: "default")
  --parallel                 Run tests in parallel
  --max-parallel N           Maximum parallel tests (default: 5)
  --record-video             Record video of test execution
  --artifacts-dir DIR        Directory for artifacts (default: ./artifacts)
  --output-format FORMAT     json | junit | html (default: json)
  --output-file FILE         Output file path
  --var KEY=VALUE            Set variable (repeatable)
  --healing-history FILE     Path to self-healing history file
  --default-timeout MS       Default timeout (default: 10000)
  --no-network-idle-wait     Disable network idle wait after navigation
  --fast-mode                Reduced timeouts for faster execution
  --versioned                Enable versioned test tracking
  --versioning-path PATH     Version history storage (default: .autoqa/history)
```

See [CLI Reference](docs/TECHNICAL.md#cli-reference) for full details.

---

## Example: Visual Regression

```yaml
steps:
  - action: navigate
    url: https://example.com

  - action: visual_assert
    visual_assertion:
      baseline_name: homepage
      threshold_mode: normal  # strict, normal, loose
      auto_mask_dynamic: true  # Mask ads, timestamps
      anti_aliasing_tolerance: 0.5
```

---

## Example: Self-Healing

Tests automatically recover from broken selectors:

```bash
autoqa run tests/ --healing-history ./healing.json
```

Self-healing uses deterministic strategies:
- Text content matching
- ID/name/aria-label fallbacks
- Attribute fuzzy matching
- XPath alternatives

---

## Vision-Enhanced Analysis

When `--vision` is passed to `autoqa build`, AutoQA takes a screenshot of each page and sends it to a vision-capable LLM for analysis. This is **additive** -- DOM-based analysis always runs first, and vision enriches the results with:

- Richer semantic descriptions of detected elements
- Elements that may be missed by DOM inspection alone (e.g., canvas content, SVG buttons)
- Layout observations and form grouping insights

### Setup

Vision requires an OpenAI-compatible endpoint with a vision-capable model. Any of these work:

| Provider | Example Model |
|----------|---------------|
| OpenAI | `gpt-4o`, `gpt-4-turbo` |
| Anthropic | `claude-3-sonnet`, `claude-4-opus` |
| Google | `gemini-pro` |
| Local (LM Studio) | `zai-org/glm-4.6v-flash` |
| Local (Ollama) | `llava`, `qwen-vl` |

```bash
# .env - Example with local LM Studio
AUTOQA_LLM_ENABLED=true
AUTOQA_LLM_BASE_URL=http://127.0.0.1:1234/v1
AUTOQA_LLM_MODEL=zai-org/glm-4.6v-flash
AUTOQA_LLM_API_KEY=lm-studio
AUTOQA_LLM_PROVIDER=custom
AUTOQA_LLM_TIMEOUT_MS=120000
AUTOQA_LLM_TEST_BUILDER_ENABLED=true
AUTOQA_LLM_TEST_BUILDER_VISION=true
```

```bash
# Run with vision
autoqa build https://myapp.com --vision -o tests/enhanced.yaml
```

Vision capability is auto-detected from the model name. If your model supports vision but isn't detected, set `AUTOQA_LLM_VISION_CAPABLE=true` explicitly.

### Security

Screenshots may contain untrusted content. AutoQA defends against prompt injection with:

1. System prompt explicitly marks screenshots as untrusted input
2. No DOM text sent alongside the image (prevents text reinforcement)
3. Strict JSON output schema enforced
4. Response sanitization (string truncation, control char stripping, array length caps)
5. Confidence thresholds (< 0.3 discarded, vision-only elements require >= 0.7)

### Graceful Fallback

If vision fails for any reason (model unavailable, timeout, invalid response), the builder continues with DOM-only analysis. Vision never blocks test generation.

---

## Configuration

### Variables

```yaml
variables:
  base_url: https://example.com
  api_key: ${env:API_KEY}           # Environment variable
  password: ${vault:secrets/pass}    # HashiCorp Vault
```

### Version Tracking

```yaml
versioning:
  enabled: true
  storage_path: .autoqa/history
  capture_screenshots: true
```

```bash
# View history
autoqa history "My Test" --limit 10

# Compare runs
autoqa diff "My Test" --latest 2 --output html
```

---

## CI/CD Integration

Generate ready-to-use CI configurations:

```bash
# GitHub Actions
autoqa ci github -o .github/workflows/autoqa.yml

# GitLab CI (parallel)
autoqa ci gitlab --parallel --nodes 3 -o .gitlab-ci.yml

# Jenkins
autoqa ci jenkins -o Jenkinsfile
```

---

## API Server

Start the REST API:

```bash
autoqa server --port 8080
```

Key endpoints:
- `POST /api/v1/jobs` - Submit test job
- `GET /api/v1/jobs/{id}` - Get job status
- `POST /api/v1/build` - Auto-generate tests
- `GET /api/v1/runs` - List test runs

See [API Reference](docs/TECHNICAL.md#api-reference) for full documentation.

---

## Documentation

- **[Technical Documentation](docs/TECHNICAL.md)** - Complete architecture, module reference, DSL schema
- **[Examples](examples/)** - Sample test specifications

---

## Project Structure

```
autoqa-ai-testing/
├── src/autoqa/
│   ├── builder/       # Auto Test Builder (test generation)
│   ├── runner/        # Test execution engine
│   ├── dsl/           # YAML parser and models
│   ├── llm/           # Optional LLM integration
│   ├── concurrency/   # Parallel execution
│   ├── visual/        # Visual regression
│   ├── versioning/    # Version tracking
│   └── api/           # REST API
├── tests/             # Test specifications
├── examples/          # Example tests
└── docs/              # Documentation
```

---

## License

MIT License - see LICENSE file for details.

---

## Links

- **Repository**: [https://github.com/Olib-AI/owl-projects](https://github.com/Olib-AI/owl-projects)
- **Homepage**: [https://owlbrowser.net](https://owlbrowser.net)
