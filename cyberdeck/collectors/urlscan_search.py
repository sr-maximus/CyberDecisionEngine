from __future__ import annotations

import os
import re
from typing import Iterable, List, Optional

import httpx

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent


class UrlscanSearchCollector(Collector):
    name = "Indice publico"

    def __init__(
        self,
        terms: Iterable[str],
        enabled: bool = True,
        max_records: int = 60,
        api_key: Optional[str] = None,
        api_key_env: str = "URLSCAN_API_KEY",
        timeout_seconds: float = 8.0,
    ):
        self.terms = [term for term in terms if term]
        self.enabled = enabled
        self.max_records = max(1, int(max_records))
        self.api_key = api_key or os.getenv(api_key_env)
        self.timeout_seconds = max(3.0, float(timeout_seconds))

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"), [])
        if not self.terms:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="No hay terminos para consultar en el indice publico."), [])

        events: List[ThreatEvent] = []
        seen: set[str] = set()
        warnings: List[str] = []
        headers = {"User-Agent": "CyberDecisionEngine/1.0"}
        if self.api_key:
            headers["API-Key"] = self.api_key
        async with httpx.AsyncClient(timeout=self.timeout_seconds, headers=headers, follow_redirects=True) as client:
            for term in self.terms:
                if len(events) >= self.max_records:
                    break
                query = _build_query(term)
                try:
                    response = await client.get("https://urlscan.io/api/v1/search/", params={"q": query, "size": min(25, self.max_records - len(events))})
                    response.raise_for_status()
                    for event in _parse_results(term, response.json(), self.max_records - len(events)):
                        key = event.evidence_url or event.id
                        if key in seen:
                            continue
                        seen.add(key)
                        events.append(event)
                        if len(events) >= self.max_records:
                            break
                except httpx.HTTPStatusError as exc:  # pragma: no cover - network dependent
                    warnings.append(f"Indice publico {term}: HTTP {exc.response.status_code}")
                    if exc.response.status_code in {401, 403, 429}:
                        break
                except Exception as exc:  # pragma: no cover - network dependent
                    warnings.append(f"Indice publico {term}: {exc}")
        status = "ok" if events and not warnings else "partial" if events else "skipped"
        return CollectionResult(SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join(warnings) or None), events)


def _build_query(term: str) -> str:
    value = term.strip()
    if re.search(r"\.[a-z]{2,}$", value, re.I):
        return f'domain:"{value}" OR page.domain:"{value}" OR task.url:"{value}"'
    return f'page.url:"{value}" OR task.url:"{value}" OR page.title:"{value}"'


def _parse_results(term: str, payload: object, remaining: int) -> List[ThreatEvent]:
    if not isinstance(payload, dict):
        return []
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    events: List[ThreatEvent] = []
    for index, item in enumerate(results[:remaining]):
        if not isinstance(item, dict):
            continue
        page = item.get("page") if isinstance(item.get("page"), dict) else {}
        task = item.get("task") if isinstance(item.get("task"), dict) else {}
        verdicts = item.get("verdicts") if isinstance(item.get("verdicts"), dict) else {}
        overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}
        url = str(page.get("url") or task.get("url") or "")
        domain = str(page.get("domain") or "")
        result_url = str(item.get("result") or item.get("reportURL") or "")
        public_result_url = _public_result_url(result_url)
        score = float(overall.get("score") or 0.0)
        malicious = bool(overall.get("malicious") or score > 0)
        tags = ["urlscan_public", "surface_web", "brand_monitoring"]
        if domain:
            tags.append(f"host:{domain}")
        if term:
            tags.append(f"query:{term}")
        events.append(
            ThreatEvent(
                id=str(item.get("_id") or item.get("uuid") or f"URLSCAN-{index}-{term}"),
                title=f"Indice publico detecto {domain or url or term}",
                category="phishing" if malicious else "brand_reputation",
                source="Indice publico",
                source_weight=0.72,
                confidence=0.68 if result_url else 0.58,
                severity=min(1.0, 0.40 + score / 100.0) if malicious else 0.35,
                actor="unattributed",
                technique="T1583",
                tags=tags,
                evidence_url=public_result_url or url or None,
                demo=False,
            )
        )
    return events


def _public_result_url(url: str) -> str:
    match = re.search(r"urlscan\.io/(?:api/v1/)?result/([0-9a-f-]{32,36})/?", url, re.I)
    if not match:
        return url
    return f"https://urlscan.io/result/{match.group(1)}/"
