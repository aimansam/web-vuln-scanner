# -*- coding: utf-8 -*-
"""Report generation: terminal summary + JSON serialization."""

import json
import sys
from datetime import datetime, timezone
from typing import TextIO

from vulnscan.models import ScanResult


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _severity_color(severity: str) -> str:
    """ANSI color code per severity (best-effort, no-op if stdout is a pipe)."""
    colors = {
        "Critical": "\033[91m",  # bright red
        "High": "\033[95m",  # bright magenta
        "Medium": "\033[93m",  # bright yellow
        "Low": "\033[96m",  # bright cyan
        "Info": "\033[90m",  # dark gray
    }
    return colors.get(severity, "\033[0m")


def _reset() -> str:
    return "\033[0m"


def generate_terminal_summary(result: ScanResult, stream: TextIO = sys.stdout) -> str:
    """Return a colored terminal summary string. Also writes to `stream`."""
    lines: list[str] = []
    sep = "─" * 66

    lines.append(sep)
    lines.append(f"  vulnscan — Web Vulnerability Scan Report")
    lines.append(f"  Target:    {result.target}")
    lines.append(f"  Scanned at: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"  URLs crawled: {len(result.crawl.urls)}")
    lines.append(f"  Forms found:  {len(result.crawl.forms)}")
    lines.append(sep)

    # Severity counts
    severity_counts: dict[str, int] = {}
    for sev in SEVERITY_ORDER:
        severity_counts[sev] = 0
    for f in result.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    lines.append("  Findings by severity")
    for sev in SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if count:
            color = _severity_color(sev)
            lines.append(f"    {color}{sev:10s}{_reset()}: {count}")
    lines.append("")

    if not result.findings:
        lines.append("  No findings detected. (Detection is heuristic; absence is not proof.)")
    else:
        lines.append("  Findings")
        for f in result.findings:
            color = _severity_color(f.severity)
            lines.append(f"    {color}[{f.severity:8s}]{_reset()} {f.vuln_type}")
            lines.append(f"      URL        : {f.target_url}")
            lines.append(f"      Parameter  : {f.parameter}")
            lines.append(f"      Payload    : {f.payload}")
            lines.append(f"      Evidence   : {f.evidence}")
            lines.append(f"      Method     : {f.http_method}")
            lines.append(f"      Confidence : {f.confidence}")
            lines.append(f"      Remediation: {f.remediation}")
            lines.append("")

    lines.append(sep)
    summary = "\n".join(lines)
    print(summary, file=stream)
    return summary


def generate_json_report(result: ScanResult, stream: TextIO = sys.stdout) -> str:
    """Serialize the ScanResult as JSON and write to `stream`."""
    data = result.to_dict()
    text = json.dumps(data, indent=2, ensure_ascii=False)
    print(text, file=stream)
    return text
