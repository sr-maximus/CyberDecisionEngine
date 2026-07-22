from __future__ import annotations

import os
from typing import Iterable, List, Optional

import httpx

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent


class OtxPulseCollector(Collector):
    name = "AlienVault OTX"

    def __init__(
        self,
        domains: Iterable[str],
        enabled: bool = True,
        max_records: int = 60,
        api_key: Optional[str] = None,
        api_key_env: str = "OTX_API_KEY",
        timeout_seconds: float = 8.0,
    ):
        self.domains = [domain for domain in domains if domain]
        self.enabled = enabled
        self.max_records = max(1, int(max_records))
        self.api_key = api_key or os.getenv(api_key_env)
        self.timeout_seconds = max(3.0, float(timeout_seconds))

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"), [])
        if not self.api_key:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="OTX_API_KEY no configurado; OTX queda como fuente opcional."), [])
        if not self.domains:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="No hay dominios para consultar en OTX."), [])

        events: List[ThreatEvent] = []
        warnings: List[str] = []
        headers = {"X-OTX-API-KEY": self.api_key, "User-Agent": "CyberDecisionEngine/1.0"}
        async with httpx.AsyncClient(timeout=self.timeout_seconds, headers=headers, follow_redirects=True) as client:
            for domain in self.domains:
                if len(events) >= self.max_records:
                    break
                try:
                    response = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general")
                    response.raise_for_status()
                    events.extend(_parse_domain(domain, response.json(), self.max_records - len(events)))
                except httpx.HTTPStatusError as exc:  # pragma: no cover - network dependent
                    warnings.append(f"OTX {domain}: HTTP {exc.response.status_code}")
                    if exc.response.status_code in {401, 403, 429}:
                        break
                except Exception as exc:  # pragma: no cover - network dependent
                    warnings.append(f"OTX {domain}: {exc}")
        status = "ok" if events and not warnings else "partial" if events else "skipped"
        return CollectionResult(SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join(warnings) or None), events)


def _parse_domain(domain: str, payload: object, remaining: int) -> List[ThreatEvent]:
    if not isinstance(payload, dict):
        return []
    pulse_info = payload.get("pulse_info")
    pulses = pulse_info.get("pulses") if isinstance(pulse_info, dict) else []
    if not isinstance(pulses, list):
        return []
    events: List[ThreatEvent] = []
    for index, pulse in enumerate(pulses[:remaining]):
        if not isinstance(pulse, dict):
            continue
        pulse_id = str(pulse.get("id") or pulse.get("pulse_id") or f"{domain}-{index}")
        name = str(pulse.get("name") or f"OTX pulse for {domain}")
        tags = [str(tag) for tag in pulse.get("tags", []) if tag] if isinstance(pulse.get("tags"), list) else []
        events.append(
            ThreatEvent(
                id=f"OTX-{pulse_id}",
                title=f"OTX relaciona {domain} con {name}",
                category="cti_indicator",
                source="AlienVault OTX",
                source_weight=0.76,
                confidence=0.68,
                severity=0.58,
                actor="unattributed",
                technique="T1589",
                tags=["otx", "cti", "surface_web", *tags[:6]],
                evidence_url=f"https://otx.alienvault.com/pulse/{pulse_id}",
                demo=False,
            )
        )
    return events
