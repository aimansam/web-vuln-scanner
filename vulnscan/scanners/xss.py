# -*- coding: utf-8 -*-
"""Reflected XSS scanner — canary-based reflection detection."""

import logging
import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from vulnscan.models import Finding, FormInfo, ResponseInfo
from vulnscan.payloads import XSS_CANARY_PAYLOADS
from vulnscan.scanners.base import BaseScanner
from vulnscan.session import VulnSession
from vulnscan.utils import generate_canary

logger = logging.getLogger(__name__)

OWASP_XSS = "A03:2021 Injection"


class XSSScanner(BaseScanner):
    """Inject unique canary tokens inside XSS vectors and detect unencoded reflection."""

    name = "xss"

    def probe(self, crawl, session: VulnSession) -> list[Finding]:
        findings: list[Finding] = []

        for url in crawl.urls:
            findings.extend(self._probe_url_params(url, session))

        for form in crawl.forms:
            findings.extend(self._probe_form(form, session))

        return findings

    def _probe_url_params(self, url: str, session: VulnSession) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        if not parsed.query:
            return findings

        params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name in params:
            for vector_entry in XSS_CANARY_PAYLOADS:
                canary = generate_canary("XSS")
                payload = vector_entry["vector"].format(canary=canary)
                resp = self._inject_url_param(url, param_name, payload, session)
                if self._reflected_unencoded(canary, payload, resp):
                    context = self._reflection_context(canary, resp.body)
                    findings.append(
                        Finding(
                            vuln_type="Reflected XSS",
                            owasp_mapping=OWASP_XSS,
                            target_url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Canary {canary} reflected unencoded ({context})",
                            http_method="GET",
                            severity=self._severity_from_context(context),
                            confidence="High",
                            remediation=self._remediation(),
                        )
                    )
                    return findings
        return findings

    def _inject_url_param(self, url: str, param: str, value: str, session: VulnSession) -> ResponseInfo:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        qs = urlencode(params, doseq=True)
        new_url = urlunparse(parsed._replace(query=qs))
        return session.get(new_url)

    def _probe_form(self, form: FormInfo, session: VulnSession) -> list[Finding]:
        findings: list[Finding] = []
        for inp in form.inputs:
            name = inp["name"]
            for vector_entry in XSS_CANARY_PAYLOADS:
                canary = generate_canary("XSS")
                payload = vector_entry["vector"].format(canary=canary)
                overrides = {name: payload}
                resp = self._submit_form_with(session, form, overrides)
                if self._reflected_unencoded(canary, payload, resp):
                    context = self._reflection_context(canary, resp.body)
                    findings.append(
                        Finding(
                            vuln_type="Reflected XSS",
                            owasp_mapping=OWASP_XSS,
                            target_url=form.action,
                            parameter=name,
                            payload=payload,
                            evidence=f"Canary {canary} reflected unencoded ({context})",
                            http_method=form.method.upper(),
                            severity=self._severity_from_context(context),
                            confidence="High",
                            remediation=self._remediation(),
                        )
                    )
                    return findings
            return findings
        return findings

    def _submit_form_with(self, session: VulnSession, form: FormInfo, overrides: dict[str, str]) -> ResponseInfo:
        data = {
            inp["name"]: overrides.get(inp["name"], inp.get("default", ""))
            for inp in form.inputs
        }
        if form.method.lower() == "post":
            return session.post(form.action, data=data)
        return session.get(form.action, params=data)

    def _reflected_unencoded(self, canary: str, payload: str, resp: ResponseInfo) -> bool:
        """True if the raw canary string appears in the response body unencoded.

        Checks both that the canary is present and that the full payload vector
        is NOT HTML-entity-encoded (which would indicate proper output encoding).
        """
        if not canary or resp.status == 0:
            return False
        body = resp.body
        if canary not in body:
            return False
        encoded = (
            payload.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
        return encoded not in body

    def _reflection_context(self, canary: str, body: str) -> str:
        idx = body.find(canary)
        if idx == -1:
            return "unknown"
        window = body[max(0, idx - 80):idx + len(canary) + 80]

        if "<script" in window.lower():
            return "inside <script> block"
        if re.search(r'<[^>]*\bon\w+\s*=', window, re.IGNORECASE):
            return "inside HTML event handler"
        if re.search(r'<[^>]*\bsrc\s*=\s*["\']?\\s*javascript:', window, re.IGNORECASE):
            return "inside javascript: URI"
        if re.search(r'<[^>]*\bstyle\s*=', window, re.IGNORECASE):
            return "inside HTML attribute (style)"
        if re.search(r'<[^>]+>', window):
            return "inside HTML tag/attribute"
        return "plain HTML context"

    @staticmethod
    def _severity_from_context(context: str) -> str:
        if "script block" in context or "event handler" in context:
            return "High"
        return "Medium"

    @staticmethod
    def _remediation() -> str:
        return (
            "Output-encode all user-supplied data before rendering in HTML (HTML entity encoding, "
            "attribute encoding, JS encoding depending on context). Use a templating engine with auto-escaping "
            "(e.g. Jinja2 autoescape, React JSX). Apply Content-Security-Policy headers. "
            "Validate input length/type at the edge but rely on output encoding for XSS defense."
        )
