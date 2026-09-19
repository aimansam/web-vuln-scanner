# -*- coding: utf-8 -*-
"""CLI orchestration — argparse wiring, scan pipeline, report output."""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone

from vulnscan.auth import AuthorizationError, require_authorization
from vulnscan.crawler import Crawler
from vulnscan.models import CrawlResult, FormInfo, ScanResult
from vulnscan.report import generate_json_report, generate_terminal_summary
from vulnscan.scanners.sensitive_files import SensitiveFilesScanner
from vulnscan.scanners.sqli import SQLiScanner
from vulnscan.scanners.traversal import TraversalScanner
from vulnscan.scanners.xss import XSSScanner
from vulnscan.session import VulnSession


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("vulnscan")


CONFIDENCE_ORDER = ["high", "medium", "low"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Lightweight web vulnerability scanner (authorized testing only).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a target URL for vulnerabilities.")
    scan.add_argument("target", help="Target URL (e.g. http://localhost:5000)")
    scan.add_argument(
        "--authorized",
        action="store_true",
        default=False,
        help="Confirm you own/have permission to scan this target (REQUIRED).",
    )
    scan.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10).")
    scan.add_argument("--user-agent", default="vulnscan/1.0", help="Custom User-Agent string.")
    scan.add_argument("--max-depth", type=int, default=1, help="Maximum crawl depth (default: 1).")
    scan.add_argument("--max-urls", type=int, default=50, help="Maximum URLs to crawl (default: 50).")
    scan.add_argument(
        "--confidence",
        choices=["low", "medium", "high"],
        default="medium",
        help="Minimum confidence to include in the report (default: medium).",
    )
    scan.add_argument(
        "--output",
        default=None,
        help="Output file path for JSON report. Default: vulnscan-report.json.",
    )
    scan.add_argument(
        "--format",
        choices=["json", "terminal", "all"],
        default="all",
        help="Output format(s) (default: all).",
    )
    return parser


def confidence_threshold_enabled(min_conf: str) -> bool:
    """Return True if a finding with `min_conf` confidence should be included."""
    idx = CONFIDENCE_ORDER.index(min_conf)
    return idx


def should_include(finding_confidence: str, min_conf: str) -> bool:
    """Return True if a finding's confidence meets or exceeds the minimum."""
    fc_idx = CONFIDENCE_ORDER.index(finding_confidence)
    mc_idx = CONFIDENCE_ORDER.index(min_conf)
    return fc_idx <= mc_idx  # low index = higher confidence


def run_scan(args: argparse.Namespace) -> ScanResult:
    """Run the full scan pipeline and return a ScanResult."""
    # 1) Authorization gate
    try:
        require_authorization(args.authorized)
    except AuthorizationError:
        sys.exit(2)

    print("═" * 66)
    print("  vulnscan — authorized web vulnerability scan")
    print("  This tool is for authorized testing only.")
    print("  Unauthorized scanning is illegal.")
    print("═" * 66)
    print()

    target_url = args.target
    # Normalize the target for crawling
    if "://" not in target_url:
        target_url = "http://" + target_url

    # 2) HTTP session
    session = VulnSession(
        user_agent=args.user_agent,
        timeout=args.timeout,
        delay=0.5,
        max_retries=2,
    )

    try:
        # 3) Crawl
        logger.info("Crawling %s", target_url)
        crawler = Crawler(
            base_url=target_url,
            session=session,
            max_depth=args.max_depth,
            max_urls=args.max_urls,
        )
        crawl: CrawlResult = crawler.run()
        logger.info("Crawl complete: %d URLs, %d forms", len(crawl.urls), len(crawl.forms))

        # 4) Scan
        scanners = [
            SQLiScanner(),
            XSSScanner(),
            TraversalScanner(),
            SensitiveFilesScanner(),
        ]

        all_findings: list = []
        for scanner in scanners:
            logger.info("Running scanner: %s", scanner.name)
            findings = scanner.probe(crawl, session)
            logger.info("%s found %d potential issues", scanner.name, len(findings))
            all_findings.extend(findings)

        # 5) Filter by confidence threshold
        filtered = [f for f in all_findings if should_include(f.confidence.lower(), args.confidence.lower())]

        # Build summary
        severity_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        for f in filtered:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            type_counts[f.vuln_type] = type_counts.get(f.vuln_type, 0) + 1

        now = datetime.now(timezone.utc)
        result = ScanResult(
            target=target_url,
            timestamp=now,
            crawl=crawl,
            findings=filtered,
            summary={
                "total": len(filtered),
                "by_severity": severity_counts,
                "by_type": type_counts,
            },
        )
        return result

    finally:
        session.close()


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        sys.exit(0)

    result = run_scan(args)

    # Output
    output_path = args.output or "vulnscan-report.json"

    if args.format in ("all", "terminal"):
        generate_terminal_summary(result, stream=sys.stdout)
        print()

    if args.format in ("all", "json"):
        json_text = generate_json_report(result, stream=sys.stdout)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(json_text)
        print(f"\nJSON report written to: {output_path}", file=sys.stderr)

    # Exit code: non-zero if findings present
    if result.findings:
        sys.exit(1)  # findings detected
    sys.exit(0)
