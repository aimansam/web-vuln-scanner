# -*- coding: utf-8 -*-
"""Directory traversal / LFI scanner — content-signature based detection."""

import logging
from urllib.parse import quote, urlparse, parse_qs, urlencode, urlunparse

from vulnscan.models import Finding, ResponseInfo
from vulnscan.payloads import TRAVERSAL_CONTENT_SIGNATURES, TRAVERSAL_PAYLOADS
from vulnscan.scanners.base import BaseScanner
from vulnscan.session import VulnSession

logger = logging.getLogger(__name__)

OWASP_TRAVERSAL = "A01:2021 Broken Access Control"


class TraversalScanner(BaseScanner):
    """Probe URL paths and query parameters for directory traversal read access."""

    name = "traversal"

    def probe(self, crawl, session: VulnSession) -> list[Finding]:
        findings: list[Finding] = []

        for url in crawl.urls:
            findings.extend(self._probe_url(url, session))

        return findings

    def _probe_url(self, url: str, session: VulnSession) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        path = parsed.path

        # 1) Probe path-based traversal (appending payloads to the path)
        for entry in TRAVERSAL_PAYLOADS:
            payload = entry["payload"]
            probe_path = path + "/" + payload if path.endswith("/") else path.rstrip("/") + "/" + payload
            probe_url = f"{parsed.scheme}://{parsed.netloc}{probe_path}"
            if parsed.query:
                probe_url += "?" + parsed.query
            resp = session.get(probe_url)
            sig = self._match_content_signature(resp)
            if sig:
                evidence = self._build_evidence(resp, sig)
                findings.append(
                    Finding(
                        vuln_type="Directory Traversal",
                        owasp_mapping=OWASP_TRAVERSAL,
                        target_url=probe_url,
                        parameter="path",
                        payload=payload,
                        evidence=evidence,
                        http_method="GET",
                        severity="High",
                        confidence="High",
                        remediation=self._remediation(),
                    )
                )
                return findings

        # 2) Probe query-parameter traversal (e.g. ?file=../passwd)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param_name in params:
                for entry in TRAVERSAL_PAYLOADS:
                    payload = entry["payload"]
                    params_copy = dict(params)
                    params_copy[param_name] = [payload]
                    qs = urlencode(params_copy, doseq=True)
                    probe_url = f"{parsed.scheme}://{parsed.netloc}{path}?{qs}"
                    resp = session.get(probe_url)
                    sig = self._match_content_signature(resp)
                    if sig:
                        evidence = self._build_evidence(resp, sig)
                        findings.append(
                            Finding(
                                vuln_type="Directory Traversal",
                                owasp_mapping=OWASP_TRAVERSAL,
                                target_url=probe_url,
                                parameter=param_name,
                                payload=payload,
                                evidence=evidence,
                                http_method="GET",
                                severity="High",
                                confidence="High",
                                remediation=self._remediation(),
                            )
                        )
                        return findings

        return findings

    @staticmethod
    def _match_content_signature(resp: ResponseInfo) -> str | None:
        if resp.status not in (200, 201, 206) or resp.status == 0:
            return None
        body_lower = resp.body.lower()
        for sig_name, sigs in TRAVERSAL_CONTENT_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in body_lower:
                    return sig_name
        return None

    @staticmethod
    def _build_evidence(resp: ResponseInfo, sig_name: str) -> str:
        snippet = resp.body[:400].replace("\n", " ").replace("\r", "")
        return f"Traversal returned HTTP {resp.status}; content-signature '{sig_name}' matched; first 400 chars: {snippet}"

    @staticmethod
    def _remediation() -> str:
        return (
            "Do not pass user input directly to filesystem APIs. Use a whitelist / allowlist of permitted files. "
            "Resolve and canonicalize paths (os.path.realpath / Path.resolve) and verify the result stays within an intended "
            "base directory. Reject inputs containing '..', null bytes, and encoded traversal sequences. "
            "Run the application with least-privilege filesystem permissions."
        )
