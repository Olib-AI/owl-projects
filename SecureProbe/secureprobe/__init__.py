"""
SecureProbe - Production-ready web vulnerability scanner.

A comprehensive security scanner leveraging browser automation for
deep vulnerability analysis including headers, cookies, forms, TLS,
information leakage, and endpoint discovery.
"""

__version__ = "1.0.0"
__author__ = "Olib AI"

from secureprobe.models import (
    AnalyzerType,
    Finding,
    ScanConfig,
    ScanResult,
    Severity,
)
from secureprobe.orchestrator import ScanOrchestrator
from secureprobe.rate_limiter import TokenBucketRateLimiter
from secureprobe.utils import (
    BrowserConfigError,
    browser_context,
    get_browser,
    get_browser_config,
)

__all__ = [
    "__version__",
    "Finding",
    "ScanResult",
    "ScanConfig",
    "Severity",
    "AnalyzerType",
    "ScanOrchestrator",
    "TokenBucketRateLimiter",
    "BrowserConfigError",
    "browser_context",
    "get_browser",
    "get_browser_config",
]
