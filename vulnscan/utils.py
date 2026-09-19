# -*- coding: utf-8 -*-
"""Utility helpers: canary generation, URL normalization, content-type filtering."""

import uuid
from urllib.parse import urljoin, urlparse


def generate_canary(prefix: str = "VULNSCAN") -> str:
    """Return a globally-unique canary token like `VULNSCAN_a1b2c3d4`."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def normalize_url(url: str) -> str:
    """Ensure a URL has a scheme and trailing slash on the path root."""
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not path.endswith("/") and path.count("/") == 1:
        path += "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def is_same_domain(base: str, candidate: str) -> bool:
    """Return True if `candidate` points to the same netloc as `base`."""
    return urlparse(base).netloc == urlparse(candidate).netloc


def is_html_content(response: object) -> bool:
    """Heuristic: True if Content-Type suggests HTML."""
    ct = getattr(response, "content_type", "")
    if not ct:
        return False
    return "text/html" in ct or "application/xhtml" in ct


def make_absolute_url(base_url: str, href: str) -> str:
    """Resolve a (possibly relative) href against a base URL."""
    if href.startswith("mailto:") or href.startswith("tel:"):
        return ""
    if href.startswith("//"):
        return "http:" + href
    return urljoin(base_url, href)
