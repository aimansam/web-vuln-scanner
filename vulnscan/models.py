# -*- coding: utf-8 -*-
"""Data classes for vulnerability findings and scan results."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Finding:
    """A single vulnerability finding."""

    vuln_type: str
    owasp_mapping: str
    target_url: str
    parameter: str
    payload: str
    evidence: str
    http_method: str
    severity: str  # Critical | High | Medium | Low | Info
    confidence: str  # High | Medium | Low
    remediation: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-serializable dict."""
        return {
            "vuln_type": self.vuln_type,
            "owasp_mapping": self.owasp_mapping,
            "target_url": self.target_url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "http_method": self.http_method,
            "severity": self.severity,
            "confidence": self.confidence,
            "remediation": self.remediation,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class FormInfo:
    """A discovered HTML form."""

    action: str
    method: str
    inputs: list[dict[str, str]]  # each: {name, type, default}
    source_url: str


@dataclass
class CrawlResult:
    """Result of crawling a target surface."""

    base_url: str
    urls: list[str]
    forms: list[FormInfo]


@dataclass
class ResponseInfo:
    """Lightweight wrapper around an HTTP response."""

    status: int
    body: str
    url: str
    elapsed: float  # seconds
    headers: dict[str, str]

    @property
    def content_type(self) -> str:
        """Best-effort Content-Type header value, lowercased."""
        return self.headers.get("Content-Type", "").lower()


@dataclass
class ScanResult:
    """Final scan result aggregating crawl + findings."""

    target: str
    timestamp: datetime
    crawl: CrawlResult
    findings: list[Finding]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-serializable dict."""
        return {
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "crawl": {
                "base_url": self.crawl.base_url,
                "urls": self.crawl.urls,
                "forms": [
                    {
                        "action": f.action,
                        "method": f.method,
                        "inputs": f.inputs,
                        "source_url": f.source_url,
                    }
                    for f in self.crawl.forms
                ],
            },
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
        }
