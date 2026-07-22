from __future__ import annotations

import time
from typing import List

import requests
from bs4 import BeautifulSoup

from app.models import SearchResult
from .base import SearchClient, SearchClientError


class BingHTMLClient(SearchClient):
    """Cliente sin API key basado en la página HTML pública de Bing.

    No evade captchas, bloqueos, autenticación, paywalls ni controles anti-abuso. Si el
    buscador rechaza la consulta, se reporta el error para que quede trazabilidad.
    """

    name = "bing_html"

    def __init__(self, timeout_seconds: int = 15, delay_seconds: float = 0.75, market: str = "es-CO") -> None:
        self.timeout_seconds = timeout_seconds
        self.delay_seconds = delay_seconds
        self.market = market
        self._last_request_at = 0.0
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/124.0 Safari/537.36 employee-virtual-risk-osint/1.0",
            "Accept-Language": "es-CO,es;q=0.9,en;q=0.7",
        })

    def search(self, query: str, count: int = 10) -> List[SearchResult]:
        self._polite_delay()
        count = min(max(int(count or 10), 1), 20)
        try:
            response = self.session.get(
                "https://www.bing.com/search",
                params={"q": query, "mkt": self.market, "cc": "CO"},
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise SearchClientError(f"Error consultando Bing HTML sin API: {exc}") from exc

        soup = BeautifulSoup(response.text, "html.parser")
        output: List[SearchResult] = []
        for item in soup.select("li.b_algo"):
            a = item.select_one("h2 a") or item.select_one("a")
            if not a or not a.get("href"):
                continue
            url = a.get("href", "").strip()
            title = a.get_text(" ", strip=True)
            snippet_el = item.select_one(".b_caption p") or item.select_one("p")
            snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
            if not url or not title:
                continue
            output.append(SearchResult(
                query=query,
                url=url,
                title=title,
                snippet=snippet,
                source=self.name,
            ))
            if len(output) >= count:
                break
        return output

    def _polite_delay(self) -> None:
        elapsed = time.time() - self._last_request_at
        if elapsed < self.delay_seconds:
            time.sleep(self.delay_seconds - elapsed)
        self._last_request_at = time.time()
