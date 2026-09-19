# -*- coding: utf-8 -*-
"""Abstract scanner base class."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vulnscan.crawler import CrawlResult
    from vulnscan.models import Finding
    from vulnscan.session import VulnSession


class BaseScanner(ABC):
    """Contract every scanner implements."""

    name: str = "base"

    @abstractmethod
    def probe(self, crawl: "CrawlResult", session: "VulnSession") -> list["Finding"]:  # noqa: F811
        """Probe the crawled surface and return any findings."""
        ...
