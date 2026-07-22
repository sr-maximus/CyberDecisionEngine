from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List
from urllib.parse import urlparse

import httpx

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent


class OsintToolsCollector(Collector):
    name = "Correlacion OSINT"

    def __init__(
        self,
        targets: Iterable[str],
        endpoint: str = "http://osint-tools:7001",
        enabled: bool = False,
        max_records: int = 60,
        timeout_seconds: float = 80.0,
        proxy_url: str | None = None,
        tools: Iterable[str] | None = None,
        priority: bool = False,
    ):
        self.targets = [item for item in targets if item]
        self.endpoint = endpoint.rstrip("/")
        self.enabled = enabled
        self.max_records = max(1, int(max_records))
        self.timeout_seconds = max(10.0, float(timeout_seconds))
        self.proxy_url = proxy_url
        allowed_tools = {"sherlock", "user-scanner", "social-analyzer"}
        requested_tools = [tool for tool in (tools or ["sherlock", "user-scanner"]) if tool in allowed_tools]
        self.tools = requested_tools or ["sherlock"]
        self.priority = priority

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"))
        if not self.targets:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="No hay objetivos OSINT configurados."), [])
        request_timeout = max(self.timeout_seconds + 25, self.timeout_seconds * 4)
        per_target_timeout = min(120, int(self.timeout_seconds))
        try:
            async with httpx.AsyncClient(timeout=request_timeout) as client:
                health = await client.get(f"{self.endpoint}/health")
                health.raise_for_status()
                payload = {"results": [], "warnings": []}
                for batch in _chunks(self.targets, 4):
                    try:
                        response = await client.post(
                            f"{self.endpoint}/username-search",
                            json={
                                "targets": batch,
                                "tools": self.tools,
                                "timeout_seconds": per_target_timeout,
                                "max_results": min(200, self.max_records),
                                "priority": self.priority,
                                "proxy_url": self.proxy_url,
                            },
                        )
                        response.raise_for_status()
                        batch_payload = response.json()
                        payload["results"].extend(batch_payload.get("results") or [])
                        payload["warnings"].extend(batch_payload.get("warnings") or [])
                    except Exception as exc:  # pragma: no cover - sidecar/network dependent
                        message = str(exc).strip() or exc.__class__.__name__
                        payload["warnings"].append(f"{', '.join(batch)}: {message}")
        except Exception as exc:  # pragma: no cover - sidecar/network dependent
            return CollectionResult(
                SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning=f"Correlacion OSINT no disponible: {exc}"),
                [],
            )
        events = _events_from_payload(payload, self.max_records)
        warnings = payload.get("warnings") or []
        status = "ok" if events and not warnings else "partial" if events else "skipped"
        return CollectionResult(
            SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join(warnings[:8]) or None),
            events,
        )


def _chunks(values: List[str], size: int) -> Iterable[List[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def _events_from_payload(payload: dict, limit: int) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    seen: set[str] = set()
    for index, item in enumerate(payload.get("results") or []):
        if len(events) >= limit:
            break
        url = str(item.get("url") or "").strip()
        target = str(item.get("target") or "").strip()
        if not url or not target:
            continue
        key = url.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        platform = str(item.get("platform") or _platform_from_url(url))
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        tags = ["public_profile", "socmint", f"platform:{platform}", f"target:{target}"]
        if metadata:
            tags.append("profile_enriched")
            if str(metadata.get("is_verified") or metadata.get("verified") or "").lower() in {"true", "1", "yes"}:
                tags.append("profile_verified")
            if metadata.get("links") or metadata.get("website"):
                tags.append("profile_external_links")
        events.append(
            ThreatEvent(
                id=f"OSINT-TOOLS-{abs(hash((target, url, index))) % 10_000_000}",
                title=f"Perfil publico posible para {target} en {platform}",
                category="social_signal",
                source="Evidencia publica de perfil",
                source_weight=0.52,
                confidence=float(item.get("confidence") or 0.50),
                age_days=0,
                severity=0.42,
                epss=0.02,
                cvss=0.0,
                actor="public_profile_presence",
                technique="T1589",
                tags=tags,
                evidence_url=url,
                observed_at=datetime.now(timezone.utc).isoformat(),
                demo=False,
            )
        )
    return events


def _platform_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.removeprefix("www.") or "unknown"
