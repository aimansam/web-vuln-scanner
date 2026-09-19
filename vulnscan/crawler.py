# -*- coding: utf-8 -*-
"""Crawler: BFS surface mapping of URLs and HTML forms."""

import logging
from collections import deque
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from vulnscan.models import CrawlResult, FormInfo, ResponseInfo
from vulnscan.session import VulnSession
from vulnscan.utils import generate_canary, is_html_content, is_same_domain, make_absolute_url

logger = logging.getLogger(__name__)

MAX_FORMS_PER_PAGE = 30


class Crawler:
    """Fetch a base URL, discover links + forms, BFS up to configured depth."""

    def __init__(
        self,
        base_url: str,
        session: VulnSession,
        max_depth: int = 1,
        max_urls: int = 50,
    ) -> None:
        self.base_url = base_url
        self.session = session
        self.max_depth = max_depth
        self.max_urls = max_urls
        self._seen: set[str] = set()
        self._urls: list[str] = []
        self._forms: list[FormInfo] = []

    def run(self) -> CrawlResult:
        """Execute the crawl and return a CrawlResult."""
        logger.info("Crawling %s (depth=%d, max_urls=%d)", self.base_url, self.max_depth, self.max_urls)
        self._seen.add(self.base_url)
        queue: deque[tuple[str, int]] = deque([(self.base_url, 0)])

        while queue and len(self._urls) < self.max_urls:
            url, depth = queue.popleft()
            if depth > self.max_depth:
                continue
            self._urls.append(url)

            resp = self.session.get(url)
            if resp.status != 200 or not is_html_content(resp):
                logger.debug("Skipping %s (status=%d, html=%s)", url, resp.status, is_html_content(resp))
                continue

            self._extract_links(url, resp.body, depth, queue)
            self._extract_forms(url, resp.body)

        logger.info("Crawl complete: %d URLs, %d forms", len(self._urls), len(self._forms))
        return CrawlResult(
            base_url=self.base_url,
            urls=self._urls,
            forms=self._forms,
        )

    def _extract_links(self, source_url: str, body: str, depth: int, queue: deque[tuple[str, int]]) -> None:
        soup = BeautifulSoup(body, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href:
                continue
            absolute = make_absolute_url(source_url, href)
            if not absolute:
                continue
            if not is_same_domain(self.base_url, absolute):
                continue
            if absolute in self._seen:
                continue
            self._seen.add(absolute)
            if len(self._urls) + len(queue) < self.max_urls:
                queue.append((absolute, depth + 1))

    def _extract_forms(self, source_url: str, body: str) -> None:
        soup = BeautifulSoup(body, "html.parser")
        for form in soup.find_all("form"):
            if len(self._forms) >= MAX_FORMS_PER_PAGE:
                break
            action = form.get("action", "").strip() or source_url
            method = (form.get("method") or "get").lower()
            inputs = []
            for inp in form.find_all("input"):
                name = inp.get("name", "").strip()
                if not name:
                    continue
                input_type = inp.get("type", "text").lower()
                default = inp.get("value", "").strip()
                inputs.append({"name": name, "type": input_type, "default": default})
            action_absolute = make_absolute_url(source_url, action)
            if not action_absolute:
                continue
            self._forms.append(
                FormInfo(
                    action=action_absolute,
                    method=method,
                    inputs=inputs,
                    source_url=source_url,
                )
            )
