from __future__ import annotations

from typing import List

import requests

from app.models import SearchResult
from .base import SearchClient, SearchClientError


class GoogleCSEClient(SearchClient):
    name = "google_cse"

    def __init__(self, api_key: str, cse_id: str, timeout_seconds: int = 15) -> None:
        self.api_key = api_key
        self.cse_id = cse_id
        self.timeout_seconds = timeout_seconds
        if not self.api_key or not self.cse_id:
            raise SearchClientError("Faltan GOOGLE_CSE_API_KEY o GOOGLE_CSE_ID")

    def search(self, query: str, count: int = 10) -> List[SearchResult]:
        endpoint = "https://www.googleapis.com/customsearch/v1"
        params = {"q": query, "key": self.api_key, "cx": self.cse_id, "num": min(max(count, 1), 10), "safe": "active"}
        try:
            response = requests.get(endpoint, params=params, timeout=self.timeout_seconds)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise SearchClientError(f"Error consultando Google Custom Search API: {exc}") from exc

        payload = response.json()
        results: List[SearchResult] = []
        for item in payload.get("items", []):
            pagemap = item.get("pagemap", {})
            metatags = pagemap.get("metatags", [{}])
            published = ""
            if metatags:
                published = metatags[0].get("article:published_time", "") or metatags[0].get("date", "")
            results.append(SearchResult(
                query=query,
                url=item.get("link", ""),
                title=item.get("title", ""),
                snippet=item.get("snippet", ""),
                source=self.name,
                published_date=published,
            ))
        return results
