"""
Command-line interface for SecureProbe vulnerability scanner.

Provides a comprehensive CLI with argparse for security scanning
operations with multiple output formats.

Supports all 13 analyzer types including APT-level attack patterns
for authorized defensive security testing.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import structlog  # noqa: I001

# All available analyzer types for CLI
ANALYZER_CHOICES = [
    "header",
    "cookie",
    "form",
    "tls",
    "info_leak",
    "endpoint",
    "session_security",
    "input_validation",
    "access_control",
    "crypto_analysis",
    "api_security",
    "chaos_attacks",
    "apt_attacks",
]


def configure_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure structlog for CLI output."""
    import logging

    log_level = "DEBUG" if debug else "INFO" if verbose else "WARNING"

    # Configure standard logging first
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, log_level),
    )

    # Use simpler structlog config without stdlib filter
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for CLI."""
    parser = argparse.ArgumentParser(
        prog="secureprobe",
        description="SecureProbe - Production-ready web vulnerability scanner with APT-level attack patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secureprobe https://example.com
  secureprobe https://example.com --output report.html --report-format html
  secureprobe https://example.com --scan-mode active --output report.json
  secureprobe https://example.com --depth 2 --rate 1.0
  secureprobe https://example.com --analyzers header cookie tls apt_attacks

Available Analyzers:
  header          - HTTP security headers analysis
  cookie          - Cookie security analysis
  form            - Form security analysis
  tls             - TLS/SSL configuration analysis
  info_leak       - Information leakage detection
  endpoint        - Endpoint security analysis
  session_security - Session management analysis
  input_validation - Input validation testing
  access_control  - Access control testing
  crypto_analysis - Cryptographic implementation analysis
  api_security    - API security analysis
  chaos_attacks   - Unconventional attack patterns
  apt_attacks     - APT-level attack patterns (active mode only)

Scan Modes:
  passive         - Observation only, no test payloads (safe for production)
  active          - With test payloads for authorized testing (may cause side effects)

Severity Levels (CVSS-aligned):
  CRITICAL  (9.0-10.0): Immediate action required
  HIGH      (7.0-8.9):  Priority remediation
  MEDIUM    (4.0-6.9):  Planned remediation
  LOW       (0.1-3.9):  Best practice improvements
  INFO      (0.0):      Informational findings
""",
    )

    parser.add_argument(
        "target",
        help="Target URL to scan (must include http:// or https://)",
    )

    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path for report (default: stdout)",
    )

    parser.add_argument(
        "--report-format",
        choices=["json", "html"],
        default="json",
        dest="report_format",
        help="Report output format (default: json)",
    )

    # Keep -f/--format as alias for backward compatibility
    parser.add_argument(
        "-f", "--format",
        choices=["json", "html"],
        default=None,
        dest="format_legacy",
        help=argparse.SUPPRESS,  # Hidden, use --report-format instead
    )

    parser.add_argument(
        "--scan-mode",
        choices=["passive", "active"],
        default="passive",
        dest="scan_mode",
        help="Scan mode: passive (observation) or active (test payloads) (default: passive)",
    )

    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=3,
        help="Maximum crawl depth (default: 3)",
    )

    parser.add_argument(
        "-r", "--rate",
        type=float,
        default=2.0,
        help="Rate limit in requests per second (default: 2.0)",
    )

    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )

    parser.add_argument(
        "--analyzers",
        nargs="+",
        choices=ANALYZER_CHOICES,
        default=None,
        help="Specific analyzers to run (default: all). See available analyzers above.",
    )

    parser.add_argument(
        "--exclude",
        nargs="+",
        default=[],
        help="URL patterns to exclude from scanning",
    )

    parser.add_argument(
        "--proxy",
        action="append",
        default=[],
        help="Proxy URL(s) for rotation (can be specified multiple times)",
    )

    parser.add_argument(
        "--auth-token",
        default=None,
        help="Authorization token for authenticated scans",
    )

    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification",
    )

    parser.add_argument(
        "--browser-contexts",
        type=int,
        default=1,
        help="Number of browser contexts for isolation testing (default: 1)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="SecureProbe 1.0.0",
    )

    return parser


async def run_scan(args: argparse.Namespace) -> int:
    """
    Execute the security scan.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    from secureprobe.models import AnalyzerType, ScanConfig, ScanMode, Severity
    from secureprobe.orchestrator import ScanOrchestrator
    from secureprobe.reports import ReportGenerator

    logger = structlog.get_logger(__name__)

    # Determine report format (prefer --report-format, fallback to -f/--format)
    report_format = args.format_legacy if args.format_legacy else args.report_format

    # Determine scan mode
    scan_mode = ScanMode(args.scan_mode)

    # Set up enabled analyzers
    enabled_analyzers: set[AnalyzerType] = set(AnalyzerType)
    if args.analyzers:
        enabled_analyzers = {AnalyzerType(a) for a in args.analyzers}

    try:
        config = ScanConfig(
            target_url=args.target,
            max_depth=args.depth,
            rate_limit=args.rate,
            timeout=args.timeout,
            verify_ssl=not args.no_verify_ssl,
            authorization_token=args.auth_token,
            proxy_urls=args.proxy if args.proxy else [],
            enabled_analyzers=enabled_analyzers,
            exclude_patterns=args.exclude,
            scan_mode=scan_mode,
            browser_contexts=args.browser_contexts,
        )
    except ValueError as e:
        logger.error("configuration_error", error=str(e))
        return 1

    logger.info(
        "scan_starting",
        target=config.target_url,
        depth=config.max_depth,
        rate=config.rate_limit,
        scan_mode=scan_mode.value,
        analyzers=[a.value for a in enabled_analyzers],
    )

    # Show warning for active mode
    if scan_mode == ScanMode.ACTIVE:
        logger.warning(
            "active_mode_warning",
            message="Active scan mode enabled - sending test payloads to target",
        )

    orchestrator = ScanOrchestrator(config)
    result = await orchestrator.scan()

    reporter = ReportGenerator(result)

    report = reporter.generate_json() if report_format == "json" else reporter.generate_html()

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(report)
        logger.info("report_saved", path=str(output_path.absolute()))
    else:
        print(report)

    # Get severity counts
    critical_count = result.severity_counts.get(Severity.CRITICAL, 0)
    high_count = result.severity_counts.get(Severity.HIGH, 0)
    medium_count = result.severity_counts.get(Severity.MEDIUM, 0)
    low_count = result.severity_counts.get(Severity.LOW, 0)
    info_count = result.severity_counts.get(Severity.INFO, 0)

    logger.info(
        "scan_summary",
        total_findings=len(result.findings),
        critical=critical_count,
        high=high_count,
        medium=medium_count,
        low=low_count,
        info=info_count,
        duration=f"{result.duration_seconds:.2f}s",
        urls_scanned=result.urls_scanned,
    )

    if critical_count > 0:
        return 2
    elif high_count > 0:
        return 1
    return 0


def main() -> None:
    """Main entry point for CLI."""
    parser = create_parser()
    args = parser.parse_args()

    configure_logging(verbose=args.verbose, debug=args.debug)

    try:
        exit_code = asyncio.run(run_scan(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger = structlog.get_logger(__name__)
        logger.error("fatal_error", error=str(e))
        if args.debug:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()
