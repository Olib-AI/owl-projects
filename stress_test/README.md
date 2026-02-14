# Owl Stress

Browser-based stress testing framework powered by [Owl Browser](https://owlbrowser.net). Runs concurrent browser sessions against a target application using JSON flow templates and generates professional PDF reports.

## Requirements

- Python 3.12+
- A running Owl Browser instance (Docker or native)

## Setup

```bash
pip install -r requirements.txt
```

Create a `.env` file (or copy from `.env.example`):

```bash
cp .env.example .env
```

Edit `.env` with your Owl Browser connection details:

```
OWL_ENDPOINT=http://localhost:8080
OWL_TOKEN=your-secret-token
```

## Usage

```bash
python run.py <flow.json> [options]
```

### Required

| Argument | Description |
|----------|-------------|
| `flow` | Path to a flow JSON file (see `flows/` for examples) |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--target-name` | `Unknown Target` | Name of the target app (appears in the report) |
| `--target-url` | | Base URL of the target app |
| `--batches` | `1 5 10 25 50 75 100` | Concurrency levels to test |
| `--max-concurrent` | `100` | Max concurrent browser connections |
| `--timeout` | `30000` | Timeout per flow step in milliseconds |
| `--delay` | `5.0` | Cooldown between batches in seconds |
| `--stagger` | `0.5` | Stagger between flow launches within a batch |
| `-o, --output` | `reports/<name>_report.pdf` | Output path for the PDF report |
| `--owl-endpoint` | `$OWL_ENDPOINT` | Owl Browser endpoint URL |
| `--owl-token` | `$OWL_TOKEN` | Owl Browser auth token |
| `-v, --verbose` | off | Enable debug logging |

### Examples

Run a full stress test with all default batch sizes:

```bash
python run.py flows/example_login.json \
  --target-name "Acme Dashboard" \
  --target-url "https://app.acme.com"
```

Run only small batches for a quick check:

```bash
python run.py flows/example_login.json \
  --target-name "Acme Dashboard" \
  --target-url "https://app.acme.com" \
  --batches 1 5 10
```

Custom output path and longer timeouts:

```bash
python run.py flows/example_login.json \
  --target-name "Acme Dashboard" \
  --target-url "https://app.acme.com" \
  --timeout 60000 \
  --delay 10 \
  -o results/acme_feb_2026.pdf
```

Override Owl Browser connection from CLI:

```bash
python run.py flows/example_login.json \
  --target-name "Staging" \
  --owl-endpoint http://owl.internal:8080 \
  --owl-token my-staging-token
```

## Flow JSON Format

Tests are defined as JSON flow files, not raw Python. Each flow is a sequence of browser actions:

```json
{
  "name": "Login Flow",
  "description": "Log in and verify dashboard loads",
  "steps": [
    {
      "type": "browser_navigate",
      "url": "https://app.example.com/login"
    },
    {
      "type": "browser_wait_for_network_idle"
    },
    {
      "type": "browser_type",
      "selector": "email input",
      "text": "user@example.com"
    },
    {
      "type": "browser_type",
      "selector": "password input",
      "text": "password123"
    },
    {
      "type": "browser_click",
      "selector": "sign in button"
    },
    {
      "type": "browser_wait_for_url",
      "url_pattern": "**/dashboard**"
    }
  ]
}
```

Selectors support CSS (`#email`), coordinates (`100x200`), or natural language (`sign in button`).

See `flows/example_login.json` for a complete example.

## How It Works

1. The flow JSON defines a single user journey (e.g. login, navigate, interact)
2. The runner creates **isolated browser contexts** for each concurrent user, each with a unique fingerprint
3. Batches escalate concurrency: `1 -> 5 -> 10 -> 25 -> 50 -> 75 -> 100`
4. Each batch runs all flows concurrently with a small stagger to avoid thundering herd
5. Metrics are collected per-step and per-flow (timing, success/failure)
6. A branded PDF report is generated with charts, tables, and a verdict

## Project Structure

```
stress_test/
├── assets/              # Logo and brand assets
├── flows/               # Flow JSON templates
├── owl_stress/
│   ├── config.py        # Branding, batch sizes, StressConfig
│   ├── flow_loader.py   # Load & validate flow JSON
│   ├── metrics.py       # Timing aggregation (avg, median, p95, p99)
│   ├── runner.py        # Async concurrent flow execution via SDK
│   ├── report.py        # PDF report generation (charts + tables)
│   └── cli.py           # CLI entry point
├── reports/             # Generated PDF reports (gitignored)
├── run.py               # Main entry point
├── requirements.txt
└── .env.example
```
