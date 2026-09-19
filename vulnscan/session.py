# -*- coding: utf-8 -*-
"""HTTP session helper: requests wrapper with headers, timeout, rate limiting, retries."""

import logging
import time
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from vulnscan.models import ResponseInfo

logger = logging.getLogger(__name__)


class VulnSession:
    """Wraps requests.Session with sane defaults for scanning."""

    def __init__(
        self,
        user_agent: str = "vulnscan/1.0",
        timeout: float = 10.0,
        delay: float = 0.5,
        max_retries: int = 2,
        retry_backoff: float = 1.0,
    ) -> None:
        self.timeout = timeout
        self.delay = delay
        self._last_request_time: float = 0.0

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

        # Retry on connection errors (not on 4xx/5xx).
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=retry_backoff,
            status_forcelist=[],  # don't retry server errors by default
            allowed_methods=["GET", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _rate_limit(self) -> None:
        """Sleep if we're hitting the target faster than configured delay."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request_time = time.monotonic()

    def get(self, url: str, **kwargs) -> ResponseInfo:
        """Send a GET request and return a ResponseInfo."""
        self._rate_limit()
        try:
            resp = self.session.get(url, timeout=self.timeout, **kwargs)
            return ResponseInfo(
                status=resp.status_code,
                body=resp.text,
                url=resp.url,
                elapsed=resp.elapsed.total_seconds(),
                headers=dict(resp.headers),
            )
        except requests.RequestException as exc:
            logger.warning("GET %s failed: %s", url, exc)
            return ResponseInfo(
                status=0,
                body="",
                url=url,
                elapsed=0.0,
                headers={},
            )

    def post(self, url: str, **kwargs) -> ResponseInfo:
        """Send a POST request and return a ResponseInfo."""
        self._rate_limit()
        try:
            resp = self.session.post(url, timeout=self.timeout, **kwargs)
            return ResponseInfo(
                status=resp.status_code,
                body=resp.text,
                url=resp.url,
                elapsed=resp.elapsed.total_seconds(),
                headers=dict(resp.headers),
            )
        except requests.RequestException as exc:
            logger.warning("POST %s failed: %s", url, exc)
            return ResponseInfo(
                status=0,
                body="",
                url=url,
                elapsed=0.0,
                headers={},
            )

    def close(self) -> None:
        self.session.close()
