from __future__ import annotations

from typing import List

from app.models import SearchResult
from .base import SearchClient, SearchClientError
from .duckduckgo_lite_client import DuckDuckGoLiteClient
from .bing_html_client import BingHTMLClient


class MultiNoAPIClient(SearchClient):
    """Metabuscador sin API.

    Intenta varias fuentes HTML normales y consolida resultados. No intenta saltar
    captchas/bloqueos; si un buscador falla, continúa con el siguiente y registra el origen
    en el campo source de cada resultado.
    """

    name = "multi_noapi"

    def __init__(self, timeout_seconds: int = 15) -> None:
        self.clients: List[SearchClient] = [
            DuckDuckGoLiteClient(timeout_seconds=timeout_seconds),
            BingHTMLClient(timeout_seconds=timeout_seconds),
        ]

    def search(self, query: str, count: int = 10) -> List[SearchResult]:
        output: List[SearchResult] = []
        errors: List[str] = []
        seen_urls = set()
        per_client_count = max(3, int(count or 10))
        for client in self.clients:
            try:
                results = client.search(query, count=per_client_count)
            except SearchClientError as exc:
                errors.append(f"{client.name}: {exc}")
                continue
            for result in results:
                normalized = (result.url or "").strip().lower().rstrip("/")
                if not normalized or normalized in seen_urls:
                    continue
                seen_urls.add(normalized)
                result.source = f"{self.name}:{client.name}"
                output.append(result)
                if len(output) >= count:
                    return output
        if not output and errors:
            raise SearchClientError("; ".join(errors))
        return output[:count]
