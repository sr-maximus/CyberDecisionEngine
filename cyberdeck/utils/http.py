from __future__ import annotations

from typing import Any, Dict, Optional

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential


DEFAULT_HEADERS = {
    "User-Agent": "CyberDecisionEngine/0.1 defensive-intelligence"
}


class HttpClient:
    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError)),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    async def get_json(self, url: str, headers: Optional[Dict[str, str]] = None) -> Any:
        request_headers = {**DEFAULT_HEADERS, **(headers or {})}
        async with httpx.AsyncClient(timeout=self.timeout, headers=request_headers, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError)),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    async def get_text(self, url: str, headers: Optional[Dict[str, str]] = None) -> str:
        request_headers = {**DEFAULT_HEADERS, **(headers or {})}
        async with httpx.AsyncClient(timeout=self.timeout, headers=request_headers, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text
