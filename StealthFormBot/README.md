# StealthFormBot

Enterprise Form Submission with Anti-Detection - Apify Actor

## Overview

StealthFormBot is an Apify actor that automates form submissions across websites with sophisticated anti-detection measures. It handles complex multi-step forms, file uploads, CAPTCHAs (via third-party services), and dynamic JavaScript forms while evading bot detection systems.

Unlike simple HTTP-based form submitters, StealthFormBot renders pages like a real browser, handles JavaScript-generated form fields, manages sessions with cookies, and rotates fingerprints to avoid pattern detection.

## Features

- **Simple Contact Forms**: Auto-detect field types and fill accordingly
- **Multi-Step Wizards**: Handle forms with multiple pages/steps
- **Dynamic Forms**: Fields that appear based on selections
- **File Uploads**: Support for uploading files to forms
- **All Field Types**: Dropdowns, checkboxes, radio buttons, date pickers
- **Form Validation**: Handle client-side validation gracefully
- **Login Support**: Authenticate before accessing protected forms
- **Anti-Detection**: Stealth mode with fingerprint rotation
- **Error Recovery**: Automatic retries with configurable backoff
- **Apify Integration**: Full support for Apify datasets, key-value stores, and input schema

## Apify Deployment

This actor can be deployed on the [Apify Platform](https://apify.com). To deploy:

1. Set up an Apify account
2. Create a new actor using the StealthFormBot source code
3. Configure input schema from `.actor/input_schema.json`
4. Set environment variables: `OWL_BROWSER_URL`, `OWL_BROWSER_TOKEN`
5. Run on Apify platform

### Input Example (Apify Console)

```json
{
    "targetUrl": "https://example.com/contact",
    "formData": {
        "name": "John Doe",
        "email": "john@example.com",
        "message": "Hello!"
    },
    "fieldConfigs": [],
    "submitSelector": "button[type='submit']",
    "owlBrowserUrl": "http://your-owl-browser:8080",
    "owlBrowserToken": "your-secret-token",
    "navigationTimeout": 30000,
    "fieldTimeout": 5000,
    "screenshotBeforeSubmit": true,
    "screenshotAfterSubmit": true,
    "verbose": false
}
```

## Local Development

### Installation

```bash
cd StealthFormBot
pip install -e .
```

### Configuration

Create a `.env` file in the project root with Owl Browser credentials:

```env
OWL_BROWSER_URL=http://localhost:8080
OWL_BROWSER_TOKEN=your-secret-token
```

Note: These can also be provided via the Apify input JSON (`owlBrowserUrl` and `owlBrowserToken` fields). Input values override environment variables.

### Running Locally

```bash
# Run with test configuration
python main.py

# Or use Apify CLI
apify run
```

## Usage

### Basic Form Submission

```python
from main import run_actor

result = run_actor({
    "targetUrl": "https://example.com/contact",
    "formData": {
        "name": "John Doe",
        "email": "john@example.com",
        "message": "Hello, this is a test message."
    },
    "submitSelector": "button[type='submit']",
    "owlBrowserUrl": "http://localhost:8080",
    "owlBrowserToken": "your-token"
})

print(f"Success: {result['success']}")
print(f"Status: {result['status']}")
```

### Multi-Step Form

```python
result = run_actor({
    "targetUrl": "https://example.com/apply",
    "steps": [
        {
            "name": "Personal Info",
            "fields": [
                {"selector": "#firstName", "value": "John"},
                {"selector": "#lastName", "value": "Doe"},
                {"selector": "#email", "value": "john@example.com"}
            ],
            "nextSelector": ".next-button"
        },
        {
            "name": "Address",
            "fields": [
                {"selector": "#street", "value": "123 Main St"},
                {"selector": "#city", "value": "New York"},
                {"selector": "#state", "value": "NY", "fieldType": "select"}
            ],
            "nextSelector": ".submit-button"
        }
    ],
    "successIndicator": ".confirmation-message"
})
```

### Form with Login

```python
result = run_actor({
    "targetUrl": "https://example.com/dashboard/form",
    "login": {
        "url": "https://example.com/login",
        "usernameSelector": "#email",
        "passwordSelector": "#password",
        "username": "user@example.com",
        "password": "secret123",
        "successIndicator": ".dashboard"
    },
    "formData": {
        "report_name": "Monthly Report",
        "description": "Generated report"
    }
})
```

### With Proxy and Stealth Mode

```python
result = run_actor({
    "targetUrl": "https://example.com/form",
    "formData": {"field": "value"},
    "proxy": {
        "type": "socks5h",
        "host": "proxy.example.com",
        "port": 1080,
        "username": "user",
        "password": "pass",
        "timezoneOverride": "America/New_York",
        "languageOverride": "en-US"
    },
    "profilePath": "/profiles/persistent_identity.json"
})
```

## Input Schema

All inputs go through the Apify actor input system. Below are the key fields:

### Required Fields
- `targetUrl` (string): The URL of the form to submit

### Form Filling
- `formData` (object): Simple key-value mapping of field names to values. The actor auto-detects field types.
- `fieldConfigs` (array): Advanced field configurations for complex forms. Each object: `{"selector": "#field", "value": "text", "fieldType": "text|email|select|checkbox|radio|textarea|date|file", "clearFirst": true}`
- `steps` (array): Multi-step form configuration. Each step: `{"name": "Step 1", "fields": [...], "nextSelector": "button.next", "waitCondition": "networkidle"}`

### Authentication
- `login` (object, optional): Login credentials before accessing form. Fields: `url`, `usernameSelector`, `passwordSelector`, `username`, `password`, `successIndicator`

### Submission & Detection
- `submitSelector` (string): CSS selector for submit button (if not provided, common patterns tried)
- `successIndicator` (string): CSS selector that appears on successful submission
- `successUrlPattern` (string): URL pattern that indicates success

### Browser Configuration
- `owlBrowserUrl` (string): URL of Owl Browser service (default: `http://localhost:8080`)
- `owlBrowserToken` (string): Authentication token for Owl Browser service

### Network & Proxy
- `proxy` (object, optional): `{"type": "http|https|socks5", "host": "...", "port": 8080, "username": "...", "password": "...", "timezoneOverride": "America/New_York", "languageOverride": "en-US"}`

### Timeouts (ms)
- `navigationTimeout` (integer, default: 30000): Page navigation timeout
- `fieldTimeout` (integer, default: 5000): Field finding/filling timeout

### Screenshots
- `screenshotBeforeSubmit` (boolean, default: true): Capture before submission
- `screenshotAfterSubmit` (boolean, default: true): Capture after submission
- `screenshotOnError` (boolean, default: true): Capture on error

### Dialogs
- `autoAcceptAlerts` (boolean, default: true): Auto-accept alert dialogs
- `autoAcceptConfirms` (boolean, default: true): Auto-accept confirm dialogs

### Retry Strategy
- `retry` (object): `{"maxRetries": 3, "retryDelay": 1000, "exponentialBackoff": true, "retryOn": ["timeout", "element_not_found"]}`
- `retryOnErrors` (array): List of error types to retry on

### Advanced
- `profilePath` (string): Path to persistent browser profile
- `verbose` (boolean, default: false): Enable debug logging

### Complete Example
```json
{
    "targetUrl": "https://example.com/contact",
    "formData": {
        "name": "John Doe",
        "email": "john@example.com"
    },
    "fieldConfigs": [],
    "steps": [],
    "submitSelector": "button[type='submit']",
    "owlBrowserUrl": "http://localhost:8080",
    "owlBrowserToken": "your-secret-token",
    "navigationTimeout": 30000,
    "fieldTimeout": 5000,
    "screenshotBeforeSubmit": true,
    "screenshotAfterSubmit": true,
    "screenshotOnError": true,
    "autoAcceptAlerts": true,
    "autoAcceptConfirms": true,
    "successIndicator": null,
    "successUrlPattern": null,
    "retry": {
        "maxRetries": 3,
        "retryDelay": 1000,
        "exponentialBackoff": true
    },
    "retryOnErrors": ["timeout", "element_not_found"],
    "verbose": false
}
```

## Output Schema

```json
{
    "success": true,
    "status": "success",
    "targetUrl": "https://example.com/form",
    "confirmationId": "REF-12345",
    "submittedAt": "2024-01-09T12:00:00Z",
    "stepsCompleted": 2,
    "totalSteps": 2,
    "stepResults": [...],
    "screenshotBefore": "screenshot_before_20240109_120000.png",
    "screenshotAfter": "screenshot_after_20240109_120001.png",
    "cookies": [...],
    "finalUrl": "https://example.com/form/success",
    "errors": [],
    "durationMs": 5432
}
```

## Supported Field Types

- `text` - Standard text input
- `email` - Email input with validation
- `password` - Password input
- `phone` - Phone number input
- `number` - Numeric input
- `textarea` - Multi-line text
- `select` - Dropdown select
- `checkbox` - Checkbox (boolean or multiple)
- `radio` - Radio button group
- `date` - Date picker
- `datetime` - Date and time picker
- `file` - File upload
- `hidden` - Hidden form fields
- `custom` - Custom components (React, Vue, etc.)

## Error Handling

The actor automatically handles common issues:

- Element not found: Retries with configurable count
- Network timeouts: Waits for network idle
- JavaScript dialogs: Auto-accepts alerts/confirms
- Dynamic content: Waits for elements to appear
- Form validation: Continues even with non-required field failures

## License

MIT License - Olib AI
