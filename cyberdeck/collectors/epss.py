from __future__ import annotations

from typing import Iterable, List

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent
from cyberdeck.utils.http import HttpClient


class EpssCollector(Collector):
    name = "FIRST EPSS"

    def __init__(self, api: str, cves: Iterable[str]):
        self.api = api
        self.cves = sorted({cve for cve in cves if cve})
        self.http = HttpClient()

    async def collect(self) -> CollectionResult:
        if not self.cves:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real"))
        try:
            query = ",".join(self.cves[:80])
            data = await self.http.get_json(f"{self.api}?cve={query}")
            events: List[ThreatEvent] = []
            for item in data.get("data", []):
                epss = float(item.get("epss", 0.0))
                events.append(
                    ThreatEvent(
                        id=f"EPSS-{item.get('cve')}",
                        title=f"EPSS probability for {item.get('cve')}: {epss:.3f}",
                        category="vulnerability_probability",
                        source=self.name,
                        source_weight=0.90,
                        confidence=0.90,
                        age_days=0,
                        severity=min(1.0, epss * 2),
                        epss=epss,
                        cvss=0.0,
                        cve=item.get("cve"),
                        actor="unknown",
                        technique="T1190",
                        tags=["epss"],
                        evidence_url=self.api,
                        demo=False,
                    )
                )
            return CollectionResult(SourceStatus(name=self.name, status="ok", records=len(events), mode="real"), events)
        except Exception as exc:
            status = SourceStatus(name=self.name, status="fallback", records=0, mode="demo", warning=str(exc))
            return CollectionResult(status, [])
