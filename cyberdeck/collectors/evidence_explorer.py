from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Iterable, List
from urllib.parse import urlparse

import httpx

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent


class EvidenceExplorerCollector(Collector):
    name = "Evidencia web validada"

    def __init__(
        self,
        events: Iterable[ThreatEvent],
        domains: Iterable[str],
        terms: Iterable[str],
        endpoint: str = "http://osint-tools:7001",
        enabled: bool = True,
        max_urls: int = 30,
        timeout_seconds: float = 8.0,
    ):
        self.events = list(events)
        self.domains = [item.strip().lower() for item in domains if item and item.strip()]
        self.terms = [item.strip().lower() for item in terms if item and item.strip()]
        self.endpoint = endpoint.rstrip("/")
        self.enabled = enabled
        self.max_urls = max(1, int(max_urls))
        self.timeout_seconds = max(3.0, float(timeout_seconds))

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"))
        urls = _select_evidence_urls(self.events, self.domains, self.max_urls)
        if not urls:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="No hay URLs de evidencia para validar."), [])
        try:
            async with httpx.AsyncClient(timeout=max(self.timeout_seconds * len(urls), self.timeout_seconds + 15.0)) as client:
                health = await client.get(f"{self.endpoint}/health")
                health.raise_for_status()
                response = await client.post(
                    f"{self.endpoint}/evidence/explore",
                    json={
                        "urls": urls,
                        "domains": self.domains,
                        "terms": self.terms,
                        "timeout_seconds": min(30, int(self.timeout_seconds)),
                        "max_urls": self.max_urls,
                    },
                )
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:  # pragma: no cover - sidecar/network dependent
            return CollectionResult(
                SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning=f"Explorador de evidencia no disponible: {exc}"),
                [],
            )
        events = _events_from_payload(payload, self.domains)
        warnings = payload.get("warnings") or []
        status = "ok" if events and not warnings else "partial" if events else "skipped"
        return CollectionResult(
            SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join(warnings[:8]) or None),
            events,
        )


def _select_evidence_urls(events: List[ThreatEvent], domains: List[str], limit: int) -> List[str]:
    scored: list[tuple[float, str]] = []
    seen: set[str] = set()
    for event in events:
        url = (event.evidence_url or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        key = _public_url(url).rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        text = " ".join([event.title, event.category, event.source, url, " ".join(event.tags)]).lower()
        scope_boost = 0.35 if any(domain in text for domain in domains) else 0.0
        source_boost = 0.16 if event.category in {"phishing", "fraud", "brand_reputation", "attack_surface", "osint_document_exposure"} else 0.0
        score = event.severity + event.confidence * 0.25 + event.source_weight * 0.15 + scope_boost + source_boost
        scored.append((score, _public_url(url)))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [url for _, url in scored[:limit]]


def _events_from_payload(payload: dict, domains: List[str]) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    for index, item in enumerate(payload.get("results") or []):
        relation_score = float(item.get("relation_score") or 0.0)
        if relation_score <= 0:
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        title = str(item.get("title") or "Evidencia publica validada").strip()
        host = str(item.get("host") or urlparse(url).netloc).strip()
        sha = str(item.get("sha256") or "")
        status_code = str(item.get("status_code") or "")
        matched_terms = [str(term) for term in item.get("matched_terms") or [] if term]
        tags = [
            "evidence_explorer",
            "public_evidence_validation",
            f"host:{host}",
            f"status:{status_code}",
            f"relation:{item.get('relationship') or 'contextual'}",
        ]
        if sha:
            tags.append(f"sha256:{sha[:12]}")
        for domain in domains:
            if domain in url.lower() or domain in " ".join(matched_terms):
                tags.append(f"domain:{domain}")
        events.append(
            ThreatEvent(
                id=f"EVIDENCE-{hashlib.sha256(f'{url}-{index}'.encode()).hexdigest()[:12]}",
                title=f"Validacion de evidencia publica: {title}",
                category="evidence_validation",
                source="Evidencia web validada",
                source_weight=0.62,
                confidence=min(0.9, 0.42 + relation_score * 0.45),
                age_days=0,
                severity=0.38 + min(0.24, relation_score * 0.24),
                epss=0.02,
                cvss=0.0,
                actor="public_evidence",
                technique=None,
                tags=tags,
                evidence_url=url,
                observed_at=item.get("validated_at") or datetime.now(timezone.utc).isoformat(),
                demo=False,
            )
        )
    return events


def _public_url(url: str) -> str:
    match = url.lower().split("urlscan.io/api/v1/result/", 1)
    if len(match) == 2:
        uuid = match[1].strip("/").split("/", 1)[0]
        return f"https://urlscan.io/result/{uuid}/"
    return url
