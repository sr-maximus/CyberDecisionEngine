from __future__ import annotations

import time
from typing import List
from urllib.parse import parse_qs, unquote, urlparse

import requests
from bs4 import BeautifulSoup

from app.models import SearchResult
from .base import SearchClient, SearchClientError


class DuckDuckGoLiteClient(SearchClient):
    """Cliente sin API key basado en páginas HTML públicas de búsqueda.

    Notas operativas:
    - No usa APIs ni credenciales.
    - No intenta evadir captchas, bloqueos, autenticación ni paywalls.
    - Incluye pausa entre consultas para reducir carga y evitar comportamiento agresivo.
    - Puede romperse si cambia el HTML del buscador.
    """

    name = "duckduckgo_lite"

    def __init__(self, timeout_seconds: int = 5, delay_seconds: float = 0.15, locale: str = "co-es") -> None:
        self.timeout_seconds = timeout_seconds
        self.delay_seconds = delay_seconds
        self.locale = locale
        self._last_request_at = 0.0
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/124.0 Safari/537.36 employee-virtual-risk-osint/1.0",
            "Accept-Language": "es-CO,es;q=0.9,en;q=0.7",
        })

    def search(self, query: str, count: int = 10) -> List[SearchResult]:
        count = min(max(int(count or 10), 1), 20)
        self._polite_delay()
        try:
            results = self._search_html(query, count)
            if results:
                return results[:count]
            self._polite_delay()
            return self._search_lite(query, count)[:count]
        except requests.RequestException as exc:
            raise SearchClientError(f"Error consultando búsqueda HTML sin API: {exc}") from exc

    def _polite_delay(self) -> None:
        elapsed = time.time() - self._last_request_at
        if elapsed < self.delay_seconds:
            time.sleep(self.delay_seconds - elapsed)
        self._last_request_at = time.time()

    def _search_html(self, query: str, count: int) -> List[SearchResult]:
        endpoint = "https://html.duckduckgo.com/html/"
        response = self.session.get(
            endpoint,
            params={"q": query, "kl": self.locale},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        output: List[SearchResult] = []
        for result in soup.select(".result"):
            anchor = result.select_one(".result__a")
            if not anchor:
                continue
            raw_url = anchor.get("href", "")
            url = self._clean_duckduckgo_redirect(raw_url)
            if not url or url.startswith("javascript:"):
                continue
            snippet_el = result.select_one(".result__snippet")
            title = anchor.get_text(" ", strip=True)
            snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
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

    def _search_lite(self, query: str, count: int) -> List[SearchResult]:
        endpoint = "https://lite.duckduckgo.com/lite/"
        response = self.session.get(
            endpoint,
            params={"q": query, "kl": self.locale},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        output: List[SearchResult] = []
        anchors = soup.select("a.result-link")
        if not anchors:
            anchors = [a for a in soup.select("a") if a.get("href") and "uddg=" in a.get("href", "")]
        for anchor in anchors:
            raw_url = anchor.get("href", "")
            url = self._clean_duckduckgo_redirect(raw_url)
            title = anchor.get_text(" ", strip=True)
            if not url or not title:
                continue
            # Buscar texto cercano como snippet sin depender de una estructura frágil.
            row = anchor.find_parent("tr")
            snippet = ""
            if row:
                next_row = row.find_next_sibling("tr")
                if next_row:
                    snippet = next_row.get_text(" ", strip=True)
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

    @staticmethod
    def _clean_duckduckgo_redirect(raw_url: str) -> str:
        if not raw_url:
            return ""
        raw_url = raw_url.strip()
        parsed = urlparse(raw_url)
        if "duckduckgo.com" in parsed.netloc and parsed.query:
            qs = parse_qs(parsed.query)
            if "uddg" in qs and qs["uddg"]:
                return unquote(qs["uddg"][0])
        if raw_url.startswith("//duckduckgo.com/l/?"):
            qs = parse_qs(urlparse("https:" + raw_url).query)
            if "uddg" in qs and qs["uddg"]:
                return unquote(qs["uddg"][0])
        if raw_url.startswith("/l/?"):
            qs = parse_qs(urlparse("https://duckduckgo.com" + raw_url).query)
            if "uddg" in qs and qs["uddg"]:
                return unquote(qs["uddg"][0])
        return raw_url
