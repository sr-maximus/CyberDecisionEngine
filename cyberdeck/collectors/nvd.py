from __future__ import annotations

import os
from typing import Iterable, List

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent
from cyberdeck.utils.http import HttpClient


class NvdCollector(Collector):
    name = "NVD"

    def __init__(self, api: str, cves: Iterable[str], api_key_env: str = "NVD_API_KEY"):
        self.api = api
        self.cves = sorted({cve for cve in cves if cve})
        self.api_key_env = api_key_env
        self.http = HttpClient()

    async def collect(self) -> CollectionResult:
        if not self.cves:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real"))
        headers = {}
        if os.getenv(self.api_key_env):
            headers["apiKey"] = os.getenv(self.api_key_env, "")
        try:
            events: List[ThreatEvent] = []
            for cve in self.cves[:8]:
                data = await self.http.get_json(f"{self.api}?cveId={cve}", headers=headers)
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    continue
                cve_data = vulnerabilities[0].get("cve", {})
                metrics = cve_data.get("metrics", {})
                score = _extract_score(metrics)
                events.append(
                    ThreatEvent(
                        id=f"NVD-{cve}",
                        title=f"NVD enrichment for {cve}",
                        category="vulnerability",
                        source=self.name,
                        source_weight=0.85,
                        confidence=0.82,
                        age_days=0,
                        severity=min(1.0, score / 10),
                        epss=0.05,
                        cvss=score,
                        cve=cve,
                        actor="unknown",
                        technique="T1190",
                        tags=["nvd"],
                        evidence_url=self.api,
                        demo=False,
                    )
                )
            return CollectionResult(SourceStatus(name=self.name, status="ok", records=len(events), mode="real"), events)
        except Exception as exc:
            status = SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning=str(exc))
            return CollectionResult(status, [])


def _extract_score(metrics: dict) -> float:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            return float(values[0].get("cvssData", {}).get("baseScore", 0.0))
    return 0.0
