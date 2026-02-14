"""CLI entry point for Owl Stress."""

import argparse
import asyncio
import logging
import sys

from dotenv import load_dotenv

from .config import StressConfig, BATCH_SIZES
from .runner import run_stress_test
from .report import generate_report


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="owl-stress",
        description="Owl Stress - Browser-based stress testing powered by Owl Browser",
    )

    parser.add_argument(
        "flow",
        help="Path to the flow JSON file",
    )
    parser.add_argument(
        "--target-name",
        default="Unknown Target",
        help="Name of the target application (used in report)",
    )
    parser.add_argument(
        "--target-url",
        default="",
        help="Base URL of the target application",
    )
    parser.add_argument(
        "--batches",
        type=int,
        nargs="+",
        default=list(BATCH_SIZES),
        help=f"Batch sizes to run (default: {BATCH_SIZES})",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=100,
        help="Maximum concurrent browser connections (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30000,
        help="Timeout per flow step in milliseconds (default: 30000)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=5.0,
        help="Delay between batches in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--stagger",
        type=float,
        default=0.5,
        help="Stagger between flow launches within a batch in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--output", "-o",
        default="",
        help="Output path for the PDF report",
    )
    parser.add_argument(
        "--owl-endpoint",
        default="",
        help="Owl Browser endpoint (default: from OWL_ENDPOINT env var)",
    )
    parser.add_argument(
        "--owl-token",
        default="",
        help="Owl Browser auth token (default: from OWL_TOKEN env var)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None):
    load_dotenv()
    args = parse_args(argv)
    setup_logging(args.verbose)

    logger = logging.getLogger("owl_stress")

    config = StressConfig(
        flow_path=args.flow,
        target_name=args.target_name,
        target_url=args.target_url,
        batch_sizes=sorted(args.batches),
        max_concurrent=args.max_concurrent,
        timeout_per_step=args.timeout,
        delay_between_batches=args.delay,
        cooldown_between_flows=args.stagger,
        owl_endpoint=args.owl_endpoint,
        owl_token=args.owl_token,
        report_output=args.output,
    )

    if not config.owl_endpoint or not config.owl_token:
        logger.error("OWL_ENDPOINT and OWL_TOKEN must be set (via env or --owl-endpoint/--owl-token)")
        sys.exit(1)

    # Run the stress test
    logger.info("=" * 60)
    logger.info("  OWL STRESS - Browser Stress Testing")
    logger.info("=" * 60)

    result = asyncio.run(run_stress_test(config))

    # Generate report
    logger.info("Generating PDF report...")
    report_path = generate_report(result, config.report_output)
    logger.info(f"Report saved to: {report_path}")

    # Print summary to stdout
    print()
    print("=" * 60)
    print("  STRESS TEST COMPLETE")
    print("=" * 60)
    print(f"  Target:       {result.target_name}")
    print(f"  Total flows:  {result.total_flows_executed}")
    print(f"  Success rate: {result.overall_success_rate:.1f}%")
    print(f"  Duration:     {result.total_wall_time_s:.1f}s")
    print(f"  Report:       {report_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
