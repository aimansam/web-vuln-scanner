# -*- coding: utf-8 -*-
"""SQL injection scanner — error-based detection over URL params and form inputs."""

import logging
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from vulnscan.models import Finding, FormInfo, ResponseInfo
from vulnscan.payloads import SQLI_ERROR_SIGNATURES, SQLI_PAYLOADS
from vulnscan.scanners.base import BaseScanner
from vulnscan.session import VulnSession

logger = logging.getLogger(__name__)

OWASP_SQLI = "A03:2021 Injection"


class SQLiScanner(BaseScanner):
    """Probe each parameter and form input for SQL injection error signals."""

    name = "sqli"

    def probe(self, crawl, session: VulnSession) -> list[Finding]:
        findings: list[Finding] = []

        # URL parameters
        for url in crawl.urls:
            findings.extend(self._probe_url_params(url, session))

        # Form inputs
        for form in crawl.forms:
            findings.extend(self._probe_form(form, session))

        return findings

    # ------------------------------------------------------------------
    # URL-parameter probing
    # ------------------------------------------------------------------

    def _probe_url_params(self, url: str, session: VulnSession) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        if not parsed.query:
            return findings

        params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name, values in params.items():
            for orig_value in values:
                baseline = self._build_response(url, session, param_name, orig_value, "GET")
                for entry in SQLI_PAYLOADS:
                    payload = entry["payload"]
                    resp = self._build_response(url, session, param_name, payload, "GET")
                    if self._is_sensitive_error(baseline, resp, payload):
                        evidence = self._extract_evidence(resp, SQLI_ERROR_SIGNATURES)
                        findings.append(
                            Finding(
                                vuln_type="SQL Injection",
                                owasp_mapping=OWASP_SQLI,
                                target_url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=evidence,
                                http_method="GET",
                                severity="High",
                                confidence="High",
                                remediation=self._remediation(),
                            )
                        )
                        break  # one finding per param is enough for V1

        return findings

    def _build_response(
        self,
        url: str,
        session: VulnSession,
        param_name: str,
        value: str,
        method: str,
    ) -> ResponseInfo:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        qs = urlencode(params, doseq=True)
        new_url = urlunparse(parsed._replace(query=qs))
        return session.get(new_url)

    # ------------------------------------------------------------------
    # Form probing
    # ------------------------------------------------------------------

    def _probe_form(self, form: FormInfo, session: VulnSession) -> list[Finding]:
        findings: list[Finding] = []
        for inp in form.inputs:
            name = inp["name"]
            default = inp.get("default", "")
            baseline = self._submit_form(form, {name: default}, session)
            for entry in SQLI_PAYLOADS:
                payload = entry["payload"]
                resp = self._submit_form(form, {name: payload}, session)
                if self._is_sensitive_error(baseline, resp, payload):
                    evidence = self._extract_evidence(resp, SQLI_ERROR_SIGNATURES)
                    findings.append(
                        Finding(
                            vuln_type="SQL Injection",
                            owasp_mapping=OWASP_SQLI,
                            target_url=form.action,
                            parameter=name,
                            payload=payload,
                            evidence=evidence,
                            http_method=form.method.upper(),
                            severity="High",
                            confidence="High",
                            remediation=self._remediation(),
                        )
                    )
                    break
        return findings

    def _submit_form(self, form: FormInfo, overrides: dict[str, str], session: VulnSession) -> ResponseInfo:
        data = {inp["name"]: overrides.get(inp["name"], inp.get("default", "")) for inp in form.inputs}
        if form.method.lower() == "post":
            return session.post(form.action, data=data)
        return session.get(form.action, params=data)

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _is_sensitive_error(
        self, baseline: ResponseInfo, probe: ResponseInfo, payload: str
    ) -> bool:
        if probe.status == 0:
            return False  # connection error, not a vuln

        # 1) Error-string match (highest signal)
        matched_engine = self._match_error_signature(probe)
        if matched_engine:
            return True

        # 2) Status-code change + significant size shift
        if baseline.status == 200 and probe.status != baseline.status:
            if self._significant_size_change(baseline, probe, factor=1.5):
                return True
        if self._significant_size_change(baseline, probe, factor=2.0):
            return True

        return False

    def _match_error_signature(self, resp: ResponseInfo) -> str | None:
        body_lower = resp.body.lower()
        for engine, sigs in SQLI_ERROR_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in body_lower:
                    return engine
        return None

    def _extract_evidence(self, resp: ResponseInfo, signatures: dict[str, list[str]]) -> str:
        body_lower = resp.body.lower()
        for engine, sigs in signatures.items():
            for sig in sigs:
                if sig.lower() in body_lower:
                    idx = body_lower.find(sig.lower())
                    snippet = resp.body[max(0, idx - 60) : idx + len(sig) + 120].replace("\n", " ")
                    return f"{engine} error signature: ...{snippet}..."
        return f"HTTP {resp.status}; response length {len(resp.body)}"

    @staticmethod
    def _significant_size_change(baseline: ResponseInfo, probe: ResponseInfo, factor: float) -> bool:
        if baseline.status == 0 or probe.status == 0:
            return False
        baseline_len = len(baseline.body)
        probe_len = len(probe.body)
        if baseline_len == 0:
            return False
        return abs(probe_len - baseline_len) / baseline_len > factor

    @staticmethod
    def _remediation() -> str:
        return (
            "Use parameterized queries / prepared statements for all database access. "
            "Never concatenate user input into SQL strings. Apply least-privilege DB accounts. "
            "Use an ORM or query builder with proper escaping. Validate input type/length at the edge."
        )
