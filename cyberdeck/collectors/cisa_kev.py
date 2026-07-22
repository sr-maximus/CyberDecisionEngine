from __future__ import annotations

from typing import Any, Dict, List

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent
from cyberdeck.utils.dates import age_days
from cyberdeck.utils.http import HttpClient


class CisaKevCollector(Collector):
    name = "CISA KEV"

    def __init__(self, url: str):
        self.url = url
        self.http = HttpClient()

    async def collect(self) -> CollectionResult:
        try:
            data = await self.http.get_json(self.url)
            vulnerabilities: List[Dict[str, Any]] = data.get("vulnerabilities", [])[:80]
            events = [
                ThreatEvent(
                    id=item.get("cveID", f"kev-{index}"),
                    title=f"{item.get('cveID', 'CVE')} exploited: {item.get('vulnerabilityName', 'Known exploited vulnerability')}",
                    category="vulnerability",
                    source=self.name,
                    source_weight=0.95,
                    confidence=0.95,
                    age_days=age_days(item.get("dateAdded")),
                    severity=0.82,
                    epss=0.20,
                    cvss=8.0,
                    cve=item.get("cveID"),
                    actor="unknown",
                    technique="T1190",
                    tags=["kev", "exploitation", "ransomware_signal"] if str(item.get("knownRansomwareCampaignUse", "")).lower() == "known" else ["kev", "exploitation"],
                    evidence_url=self.url,
                    demo=False,
                )
                for index, item in enumerate(vulnerabilities)
            ]
            return CollectionResult(SourceStatus(name=self.name, status="ok", records=len(events), mode="real"), events)
        except Exception as exc:
            status = SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning=str(exc))
            return CollectionResult(status, [])
