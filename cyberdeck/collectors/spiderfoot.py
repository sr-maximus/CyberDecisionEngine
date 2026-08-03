from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Iterable, List
from urllib.parse import urlparse

import httpx

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent


class SpiderFootCollector(Collector):
    name = "Inventario pasivo"

    def __init__(
        self,
        domains: Iterable[str],
        endpoint: str = "http://spiderfoot:7020",
        enabled: bool = True,
        max_records: int = 120,
        timeout_seconds: float = 900.0,
        max_threads: int = 4,
        include_raw: bool = False,
        depth: str = "deep",
    ):
        self.domains = [item for item in domains if item]
        self.endpoint = endpoint.rstrip("/")
        self.enabled = enabled
        self.max_records = max(1, int(max_records))
        self.timeout_seconds = max(0.0, float(timeout_seconds))
        self.max_threads = max(1, min(8, int(max_threads)))
        self.include_raw = include_raw
        self.depth = depth if depth in {"standard", "deep"} else "deep"

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"))
        if not self.domains:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="No domains configured."), [])
        try:
            request_timeout = (
                httpx.Timeout(None, connect=10.0)
                if self.timeout_seconds <= 0
                else httpx.Timeout(self.timeout_seconds + 12.0, connect=10.0)
            )
            async with httpx.AsyncClient(timeout=request_timeout) as client:
                health = await client.get(f"{self.endpoint}/health", timeout=10.0)
                health.raise_for_status()
                payload = {"domains": [], "warnings": []}
                semaphore = asyncio.Semaphore(2)
                results = await asyncio.gather(*[self._scan_domain(client, semaphore, domain) for domain in self.domains])
                for domain_payload in results:
                    payload["domains"].extend(domain_payload.get("domains") or [])
                    payload["warnings"].extend(domain_payload.get("warnings") or [])
        except Exception as exc:  # pragma: no cover - sidecar/network dependent
            return CollectionResult(
                SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning=f"Inventario pasivo no disponible: {exc}"),
                [],
            )
        events = _events_from_payload(payload, self.max_records)
        warnings = payload.get("warnings") or []
        status = "ok" if events and not warnings else "partial" if events else "skipped"
        return CollectionResult(
            SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join(warnings[:6]) or None),
            events,
        )

    async def _scan_domain(self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, domain: str) -> dict[str, Any]:
        async with semaphore:
            try:
                response = await client.post(
                    f"{self.endpoint}/scan",
                    json={
                        "domains": [domain],
                        "use_case": "passive",
                        "depth": self.depth,
                        "timeout_seconds": int(self.timeout_seconds),
                        "max_records": self.max_records,
                        "max_threads": self.max_threads,
                        "include_raw": self.include_raw,
                    },
                )
                response.raise_for_status()
                return response.json()
            except Exception as exc:  # pragma: no cover - sidecar/network dependent
                return {"domains": [], "warnings": [f"{domain}: {exc}"]}


def _events_from_payload(payload: dict[str, Any], limit: int) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    seen: set[str] = set()
    for domain_item in payload.get("domains") or []:
        domain = str(domain_item.get("domain") or "").strip()
        for record in domain_item.get("records") or []:
            if len(events) >= limit:
                break
            event = _event_from_record(domain, record)
            if event is None:
                continue
            key = f"{event.category}|{event.title}|{event.evidence_url or ''}".lower()
            if key in seen:
                continue
            seen.add(key)
            events.append(event)
    return events[:limit]


def _event_from_record(domain: str, record: dict[str, Any]) -> ThreatEvent | None:
    event_type = str(record.get("type") or "").strip()
    data = str(record.get("data") or "").strip()
    module = str(record.get("module") or "passive_inventory").strip()
    source = str(record.get("source") or "").strip()
    if not event_type or not data:
        return None
    if event_type.lower().startswith(("raw data", "raw dns", "raw whois", "raw rir")):
        return None
    category, severity, confidence, technique = _classify(event_type, data)
    evidence_url = _best_evidence_url(data, source)
    label = data if len(data) <= 120 else data[:117].rstrip() + "..."
    return ThreatEvent(
        id=f"SPIDERFOOT-{abs(hash((domain, event_type, data, module))) % 10_000_000}",
        title=f"{domain}: inventario pasivo observo {event_type} - {label}",
        category=category,
        source="Inventario pasivo",
        source_weight=0.64,
        confidence=confidence,
        age_days=0,
        severity=severity,
        epss=0.02,
        cvss=0.0,
        actor="external_reconnaissance",
        technique=technique,
        tags=[
            "passive_inventory",
            "passive",
            "real_source",
            f"type:{event_type}",
            f"domain:{domain}",
        ],
        evidence_url=evidence_url,
        observed_at=datetime.now(timezone.utc).isoformat(),
        demo=False,
    )


def _classify(event_type: str, data: str) -> tuple[str, float, float, str]:
    lowered = f"{event_type} {data}".lower()
    if any(token in lowered for token in ("malicious", "blacklist", "compromised", "breach", "leak")):
        return "threat_intel", 0.70, 0.68, "T1589"
    if any(token in lowered for token in ("email address", "phone number", "human name", "username")):
        return "osint_exposure", 0.50, 0.58, "T1589"
    if any(token in lowered for token in ("affiliate", "domain name", "internet name", "hostname", "dns")):
        return "attack_surface_dns", 0.38, 0.58, "T1590"
    if any(token in lowered for token in ("ip address", "netblock", "rir", "asn")):
        return "attack_surface_network", 0.40, 0.60, "T1590"
    if any(token in lowered for token in ("url", "web", "page")):
        return "attack_surface_web", 0.42, 0.60, "T1595"
    if any(token in lowered for token in ("certificate", "ssl", "tls")):
        return "attack_surface_tls", 0.44, 0.62, "T1595"
    return "osint_observation", 0.36, 0.56, "T1592"


def _best_evidence_url(data: str, source: str) -> str | None:
    for candidate in (data, source):
        parsed = urlparse(candidate)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return candidate
    return None
