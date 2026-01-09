"""
Utility functions for SecureProbe scanner.

Provides common utilities for URL handling, entropy calculation,
regex pattern matching, and data extraction.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import structlog

logger = structlog.get_logger(__name__)


def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy in bits per character.

    Args:
        data: Input string to analyze

    Returns:
        Entropy value in bits per character (0.0 to 8.0 for ASCII)
    """
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy(value: str, threshold: float = 4.0) -> bool:
    """
    Check if a value has high entropy (likely a secret).

    Args:
        value: String to analyze
        threshold: Minimum entropy threshold (default 4.0 bits/char)

    Returns:
        True if entropy exceeds threshold
    """
    return calculate_entropy(value) >= threshold


def normalize_url(base_url: str, path: str) -> str:
    """
    Normalize and resolve a URL path against a base URL.

    Args:
        base_url: Base URL for resolution
        path: Path or URL to normalize

    Returns:
        Normalized absolute URL
    """
    if path.startswith(("http://", "https://")):
        return path

    return urljoin(base_url, path)


def extract_domain(url: str) -> str:
    """
    Extract domain from URL.

    Args:
        url: URL to parse

    Returns:
        Domain string
    """
    parsed = urlparse(url)
    return parsed.netloc


def is_same_origin(url1: str, url2: str) -> bool:
    """
    Check if two URLs have the same origin.

    Args:
        url1: First URL
        url2: Second URL

    Returns:
        True if same origin (scheme + domain + port)
    """
    p1 = urlparse(url1)
    p2 = urlparse(url2)
    return (p1.scheme, p1.netloc) == (p2.scheme, p2.netloc)


def safe_regex_match(pattern: str, text: str, flags: int = 0) -> list[str]:
    """
    Safely execute regex match with error handling.

    Args:
        pattern: Regex pattern
        text: Text to search
        flags: Regex flags

    Returns:
        List of matches (empty on error)
    """
    try:
        return re.findall(pattern, text, flags)
    except re.error as e:
        logger.warning("regex_error", pattern=pattern, error=str(e))
        return []


def hash_content(content: str) -> str:
    """
    Generate SHA256 hash of content.

    Args:
        content: Content to hash

    Returns:
        Hex digest of hash
    """
    return hashlib.sha256(content.encode()).hexdigest()


def truncate_string(s: str, max_length: int = 200, suffix: str = "...") -> str:
    """
    Truncate string to maximum length with suffix.

    Args:
        s: String to truncate
        max_length: Maximum length including suffix
        suffix: Suffix to append when truncated

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix


def parse_cookie_header(header: str) -> dict[str, Any]:
    """
    Parse Set-Cookie header into attributes.

    Args:
        header: Set-Cookie header value

    Returns:
        Dictionary of cookie attributes
    """
    result: dict[str, Any] = {
        "name": "",
        "value": "",
        "domain": "",
        "path": "/",
        "secure": False,
        "httponly": False,
        "samesite": "",
        "expires": None,
        "max_age": None,
    }

    if not header:
        return result

    parts = header.split(";")
    if not parts:
        return result

    name_value = parts[0].strip()
    if "=" in name_value:
        name, value = name_value.split("=", 1)
        result["name"] = name.strip()
        result["value"] = value.strip()

    for part in parts[1:]:
        part = part.strip().lower()
        if "=" in part:
            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip()

            match key:
                case "domain":
                    result["domain"] = value
                case "path":
                    result["path"] = value
                case "samesite":
                    result["samesite"] = value
                case "expires":
                    result["expires"] = value
                case "max-age":
                    try:
                        result["max_age"] = int(value)
                    except ValueError:
                        pass
        else:
            match part:
                case "secure":
                    result["secure"] = True
                case "httponly":
                    result["httponly"] = True

    return result


def get_utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration string
    """
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


COMMON_SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    # AWS secret key requires context - matched near AWS-related keywords
    "aws_secret_key": r"(?:aws_secret_access_key|AWS_SECRET_KEY|aws_secret|secret_access_key|SecretAccessKey)[\s:=]+['\"]?([0-9a-zA-Z/+]{40})['\"]?",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "github_oauth": r"gho_[A-Za-z0-9_]{36,255}",
    "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "google_api_key": r"AIza[0-9A-Za-z_-]{35}",
    "stripe_secret": r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_publishable": r"pk_live_[0-9a-zA-Z]{24,}",
    "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[a-z0-9]{24})?",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[a-zA-Z0-9]{24}",
    "private_key": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    # Heroku API key requires context - matched near Heroku-related keywords
    "heroku_api": r"(?:HEROKU_API_KEY|heroku_api_key|heroku[_-]?api|heroku[_-]?token)[\s:=]+['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?",
    "postgres_uri": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+",
    "mysql_uri": r"mysql://[^:]+:[^@]+@[^/]+/\w+",
    "mongodb_uri": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+",
    "redis_uri": r"redis://[^:]+:[^@]+@[^/]+",
    "firebase_key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    # Twilio SID/token require context - matched near Twilio-related keywords
    "twilio_sid": r"(?:TWILIO_ACCOUNT_SID|twilio_sid|account_sid|twilio[_-]?account)[\s:=]+['\"]?(AC[a-z0-9]{32})['\"]?",
    "twilio_token": r"(?:TWILIO_AUTH_TOKEN|twilio_token|auth_token|twilio[_-]?auth|twilio[_-]?secret)[\s:=]+['\"]?(SK[a-z0-9]{32})['\"]?",
    "sendgrid_key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "npm_token": r"npm_[A-Za-z0-9]{36}",
    "pypi_token": r"pypi-[A-Za-z0-9_-]{100,}",
    "generic_api_key": r"(?:api[_-]?key|apikey|api[_-]?token)[\s:=]+['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
    # Generic secret pattern - requires actual value assignment (not config key names)
    "generic_secret": r"(?:secret|password|passwd|pwd)[\s]*[=:][\s]*['\"]([^'\"\s]{8,})['\"]",
    "bearer_token": r"Bearer\s+([a-zA-Z0-9_.-]{20,})",
    "basic_auth": r"Basic\s+[A-Za-z0-9+/=]{20,}",
    "ssh_private_key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
}


# Patterns that indicate false positives for generic_secret detection
GENERIC_SECRET_FALSE_POSITIVE_PATTERNS: list[str] = [
    r"password_min_length",
    r"password_max_length",
    r"password_policy",
    r"password_requirements",
    r"password_validation",
    r"password_strength",
    r"secret_key_rotation",
    r"secret_key_base",
    r"secret_version",
    r"password_reset",
    r"password_hash",
    r"password_field",
    r"password_input",
    r"password_label",
    r"secret_name",
    r"secret_type",
    r"placeholder",
    r"example",
    r"sample",
    r"demo",
    r"test",
    r"dummy",
    r"fake",
    r"mock",
]


def is_generic_secret_false_positive(context: str, match: str) -> bool:
    """
    Check if a generic secret match is likely a false positive.

    Args:
        context: Surrounding text context (typically 100 chars before and after)
        match: The matched secret value

    Returns:
        True if likely a false positive, False if it appears to be a real secret
    """
    context_lower = context.lower()
    match_lower = match.lower()

    # Check for false positive patterns in context
    for fp_pattern in GENERIC_SECRET_FALSE_POSITIVE_PATTERNS:
        if re.search(fp_pattern, context_lower):
            return True

    # Check if the match itself looks like a config key rather than a value
    if re.match(r"^[a-z_]+$", match_lower):
        return True

    # Check for documentation/comment indicators
    doc_indicators = [
        "//",
        "/*",
        "*/",
        "#",
        "<!--",
        "-->",
        "example:",
        "e.g.",
        "i.e.",
        "such as",
        "for instance",
        "documentation",
        "@param",
        "@returns",
        ":param",
        ":returns",
    ]
    for indicator in doc_indicators:
        if indicator in context_lower:
            return True

    return False


DEBUG_PATTERNS: list[str] = [
    r"Traceback \(most recent call last\)",
    r"at .+\.java:\d+",
    r"at .+\.py:\d+",
    r"at .+\.js:\d+",
    r"at .+\.ts:\d+",
    r"at .+\.rb:\d+",
    r"at .+\.php:\d+",
    r"Exception in thread",
    r"java\.lang\.\w+Exception",
    r"System\.Exception",
    r"Fatal error:",
    r"Stack trace:",
    r"DEBUG\s*[=:]\s*[Tt]rue",
    r"debug\s*[=:]\s*1",
    r"FLASK_DEBUG\s*=\s*1",
    r"APP_DEBUG\s*=\s*true",
    r"Warning:\s+\w+\(\):",
    r"Notice:\s+Undefined",
    r"PHP Fatal error",
    r"Parse error:",
    r"(?:MySQL|Postgres|SQLite)\s+error",
    r"SQLSTATE\[\w+\]",
    r"ORA-\d+",
    r"Syntax error.*line \d+",
]


TECHNOLOGY_SIGNATURES: dict[str, list[str]] = {
    "react": [
        r"_react",
        r"__REACT",
        r"reactjs",
        r'data-reactroot',
        r'data-reactid',
    ],
    "angular": [
        r"ng-version",
        r"ng-app",
        r"angular\.js",
        r"angular\.min\.js",
        r"\[\[ngModel\]\]",
    ],
    "vue": [
        r"vue\.js",
        r"vue\.min\.js",
        r"__VUE__",
        r"v-bind",
        r"v-model",
    ],
    "jquery": [
        r"jquery[.-]\d",
        r"jQuery",
        r"\$\(document\)",
        r"\$\(function",
    ],
    "wordpress": [
        r"wp-content",
        r"wp-includes",
        r"wp-json",
        r"/wp-admin",
    ],
    "drupal": [
        r"Drupal\.settings",
        r"sites/default/files",
        r"/node/\d+",
    ],
    "django": [
        r"csrfmiddlewaretoken",
        r"__admin_media_prefix__",
        r"django",
    ],
    "rails": [
        r"rails",
        r"csrf-token",
        r"turbolinks",
        r"data-turbo",
    ],
    "laravel": [
        r"laravel_session",
        r"XSRF-TOKEN",
        r"laravel",
    ],
    "express": [
        r"express",
        r"X-Powered-By: Express",
    ],
    "nginx": [
        r"nginx",
        r"Server: nginx",
    ],
    "apache": [
        r"apache",
        r"Server: Apache",
        r"mod_ssl",
    ],
    "cloudflare": [
        r"cf-ray",
        r"__cf_bm",
        r"cloudflare",
    ],
    "aws": [
        r"x-amz-",
        r"aws-sdk",
        r"amazonaws\.com",
    ],
    "bootstrap": [
        r"bootstrap[.-]\d",
        r"bootstrap\.min",
        r"class=\"[^\"]*\b(container|row|col-)\b",
    ],
    "tailwind": [
        r"tailwindcss",
        r"tailwind\.config",
        r"@tailwind\s+(?:base|components|utilities)",
        # More specific Tailwind patterns with multiple utility classes
        r"class=\"[^\"]*\b(?:sm:|md:|lg:|xl:|2xl:)[a-z]",
        r"class=\"[^\"]*\b(?:hover:|focus:|active:)[a-z]",
    ],
}
