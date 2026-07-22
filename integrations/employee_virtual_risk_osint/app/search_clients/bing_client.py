from __future__ import annotations

from typing import List

import requests

from app.models import SearchResult
from .base import SearchClient, SearchClientError


class BingSearchClient(SearchClient):
    name = "bing"

    def __init__(self, api_key: str, endpoint: str, timeout_seconds: int = 15, market: str = "es-CO") -> None:
        self.api_key = api_key
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.market = market
        if not self.api_key:
            raise SearchClientError("Falta BING_SEARCH_API_KEY")

    def search(self, query: str, count: int = 10) -> List[SearchResult]:
        params = {"q": query, "count": min(max(count, 1), 50), "mkt": self.market, "safeSearch": "Moderate"}
        headers = {"Ocp-Apim-Subscription-Key": self.api_key}
        try:
            response = requests.get(self.endpoint, headers=headers, params=params, timeout=self.timeout_seconds)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise SearchClientError(f"Error consultando Bing Search API: {exc}") from exc

        payload = response.json()
        values = payload.get("webPages", {}).get("value", [])
        results: List[SearchResult] = []
        for item in values:
            results.append(SearchResult(
                query=query,
                url=item.get("url", ""),
                title=item.get("name", ""),
                snippet=item.get("snippet", ""),
                source=self.name,
                published_date=item.get("datePublished", "") or item.get("dateLastCrawled", ""),
            ))
        return results
