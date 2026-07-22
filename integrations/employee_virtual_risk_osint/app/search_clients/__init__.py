from __future__ import annotations

from app.config import Settings
from .base import SearchClient
from .bing_client import BingSearchClient
from .google_cse_client import GoogleCSEClient
from .mock_client import MockSearchClient
from .duckduckgo_lite_client import DuckDuckGoLiteClient
from .bing_html_client import BingHTMLClient
from .multi_noapi_client import MultiNoAPIClient


def make_search_client(name: str, settings: Settings) -> SearchClient:
    normalized = (name or settings.search_client or "mock").strip().lower()
    if normalized == "mock":
        return MockSearchClient()
    if normalized == "bing":
        return BingSearchClient(
            api_key=settings.bing_search_api_key,
            endpoint=settings.bing_search_endpoint,
            timeout_seconds=settings.request_timeout_seconds,
        )
    if normalized in {"duckduckgo_lite", "ddg_lite", "ddg", "duckduckgo"}:
        return DuckDuckGoLiteClient(timeout_seconds=settings.request_timeout_seconds)
    if normalized in {"bing_html", "bing-noapi", "bing_web"}:
        return BingHTMLClient(timeout_seconds=settings.request_timeout_seconds)
    if normalized in {"multi_noapi", "noapi", "html_multi", "normal_search"}:
        return MultiNoAPIClient(timeout_seconds=settings.request_timeout_seconds)
    if normalized in {"google", "google_cse", "google-custom-search"}:
        return GoogleCSEClient(
            api_key=settings.google_cse_api_key,
            cse_id=settings.google_cse_id,
            timeout_seconds=settings.request_timeout_seconds,
        )
    raise ValueError(f"Cliente de búsqueda no soportado: {name}")
