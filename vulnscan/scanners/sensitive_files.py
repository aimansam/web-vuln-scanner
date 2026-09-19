# -*- coding: utf-8 -*-
"""Sensitive / backup file scanner — probes for exposed config, backups, dumps."""

import logging
from urllib.parse import urlparse

from vulnscan.models import Finding, ResponseInfo
from vulnscan.payloads import SENSITIVE_FILES
from vulnscan.scanners.base import BaseScanner
from vulnscan.session import VulnSession

logger = logging.getLogger(__name__)

OWASP_SENSITIVE = "A05:2021 Security Misconfiguration"


class SensitiveFilesScanner(BaseScanner):
    """Probe known sensitive/backup file names against discovered URL paths."""

    name = "sensitive_files"

    def probe(self, crawl, session: VulnSession) -> list[Finding]:
        findings: list[Finding] = []

        for url in crawl.urls:
            findings.extend(self._probe_path(url, session))

        return findings

    def _probe_path(self, url: str, session: VulnSession) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)

        # Ensure path ends with /
        path = parsed.path
        if not path.endswith("/"):
            path += "/"

        for entry in SENSITIVE_FILES:
            file_path = entry["path"]
            probe_url = f"{parsed.scheme}://{parsed.netloc}{path}{file_path}"
            if parsed.query:
                probe_url += "?" + parsed.query

            # HEAD first
            head_resp = session.get(probe_url)
            if head_resp.status == 200 and self._looks_like_a_file(head_resp):
                # Confirm with GET
                get_resp = session.get(probe_url)
                if get_resp.status == 200:
                    findings.append(
                        Finding(
                            vuln_type="Exposed Sensitive File",
                            owasp_mapping=OWASP_SENSITIVE,
                            target_url=probe_url,
                            parameter="path",
                            payload=file_path,
                            evidence=self._build_evidence(get_resp, entry),
                            http_method="GET",
                            severity=entry["severity"],
                            confidence="High",
                            remediation=self._remediation(entry),
                        )
                    )
        return findings

    @staticmethod
    def _looks_like_a_file(resp: ResponseInfo) -> bool:
        """Heuristic: skip directory listings and empty responses."""
        if resp.status != 200 or resp.status == 0:
            return False
        ct = resp.content_type
        if "text/html" in ct and "Index of" in resp.body:
            return False
        if len(resp.body) < 10:
            return False
        return True

    @staticmethod
    def _build_evidence(resp: ResponseInfo, entry: dict) -> str:
        snippet_len = min(300, len(resp.body))
        snippet = resp.body[:snippet_len].replace("\n", " ").replace("\r", "")
        return (
            f"File '{entry['path']}' returned HTTP {resp.status}; "
            f"Content-Type: {resp.content_type}; "
            f"size: {len(resp.body)} bytes; "
            f"first {snippet_len} chars: {snippet}"
        )

    @staticmethod
    def _remediation(entry: dict) -> str:
        kind = entry["desc"]
        return (
            f"Remove or restrict access to '{entry['path']}' ({kind}) from the web root. "
            "Use server config to deny access to backup/old/extensions (.bak, .old, .orig, .env, .git). "
            "Store backups and config files outside the document root. "
            "Ensure version control directories (.git) are not served."
        )
