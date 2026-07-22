from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable, List, Optional
from urllib.parse import urlencode

import httpx

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent


COMMON_CRAWL_COLLECTIONS_URL = "https://index.commoncrawl.org/collinfo.json"


class CommonCrawlCollector(Collector):
    name = "Indice historico publico"

    def __init__(self, domains: Iterable[str], enabled: bool = True, max_records: int = 40, max_indexes: int = 1):
        self.domains = [domain.lower().strip() for domain in domains if domain]
        self.enabled = enabled
        self.max_records = max(1, int(max_records))
        self.max_indexes = max(1, int(max_indexes))

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"), [])
        if not self.domains:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="No hay dominios OSINT configurados."), [])

        events: List[ThreatEvent] = []
        warnings: List[str] = []
        seen: set[str] = set()
        async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers={"User-Agent": "CyberDecisionEngine/1.0"}) as client:
            try:
                collections_response = await client.get(COMMON_CRAWL_COLLECTIONS_URL)
                collections_response.raise_for_status()
                collections = collections_response.json()[: self.max_indexes]
            except Exception as exc:  # pragma: no cover - network dependent
                return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning=f"Consulta de indice historico publico fallida: {exc}"), [])

            for collection in collections:
                cdx_api = collection.get("cdx-api")
                if not cdx_api:
                    continue
                for domain in self.domains:
                    if len(events) >= self.max_records:
                        break
                    try:
                        remaining = max(1, self.max_records - len(events))
                        params = {
                            "url": f"*.{domain}/*",
                            "output": "json",
                            "fl": "url,status,mime,timestamp",
                            "filter": "status:200",
                            "collapse": "urlkey",
                            "limit": str(min(remaining, 25)),
                        }
                        response = await client.get(f"{cdx_api}?{urlencode(params)}")
                        response.raise_for_status()
                        _extend_unique(
                            events,
                            _parse_common_crawl(domain, collection.get("id", "Common Crawl"), response.text, remaining),
                            seen,
                            self.max_records,
                        )
                    except Exception as exc:  # pragma: no cover - network dependent
                        warnings.append(f"{domain}: {exc}")
                if len(events) >= self.max_records:
                    break

        status = "ok" if events and not warnings else "partial" if events else "skipped"
        if not events and not warnings:
            warnings.append("No public Common Crawl URLs found for configured domains.")
        return CollectionResult(
            SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join(warnings) or None),
            events,
        )


def _parse_common_crawl(domain: str, collection_id: str, text: str, limit: int) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    for index, line in enumerate(line for line in text.splitlines() if line.strip()):
        if len(events) >= limit:
            break
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = row.get("url")
        if not url:
            continue
        category, tags, severity = _classify_public_url(url, row.get("mime", ""))
        observed_at = _timestamp_to_iso(row.get("timestamp"))
        events.append(
            ThreatEvent(
                id=f"OSINT-CC-{abs(hash((domain, url, index))) % 10_000_000}",
                title=f"URL publica indexada para {domain}: {_compact_url(url)}",
                category=category,
                source=f"OSINT: Common Crawl CDX {collection_id}",
                source_weight=0.38,
                confidence=0.36,
                age_days=_age_days(observed_at),
                severity=severity,
                epss=0.02,
                cvss=0.0,
                actor="public_index",
                technique="T1593",
                tags=["osint", "common_crawl", "public_index", domain, *tags],
                evidence_url=url,
                observed_at=observed_at,
                demo=False,
            )
        )
    return events


def _classify_public_url(url: str, mime: str) -> tuple[str, List[str], float]:
    text = f"{url} {mime}".lower()
    if any(term in text for term in [".pdf", ".xls", ".xlsx", ".doc", ".docx", ".ppt", ".pptx", ".csv"]):
        return "osint_document_exposure", ["public_document", "document_index"], 0.54
    if any(term in text for term in [".env", ".bak", ".backup", ".sql", ".zip", ".tar", ".gz", "password", "credential", "secret"]):
        return "osint_sensitive_artifact", ["sensitive_artifact", "exposure_review"], 0.70
    if any(term in text for term in ["admin", "login", "api", "graphql", "swagger", "wp-admin"]):
        return "osint_endpoint_exposure", ["public_endpoint", "endpoint_review"], 0.58
    return "osint_public_index", ["public_url"], 0.42


def _extend_unique(events: List[ThreatEvent], candidates: List[ThreatEvent], seen: set[str], max_records: int) -> None:
    for event in candidates:
        key = event.evidence_url or event.title
        if key in seen:
            continue
        seen.add(key)
        events.append(event)
        if len(events) >= max_records:
            break


def _timestamp_to_iso(value: Optional[str]) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    try:
        parsed = datetime.strptime(value, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        return parsed.isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def _age_days(value: str) -> int:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return 0
    return max(0, (datetime.now(timezone.utc) - parsed).days)


def _compact_url(url: str) -> str:
    return url if len(url) <= 110 else f"{url[:92]}...{url[-12:]}"
