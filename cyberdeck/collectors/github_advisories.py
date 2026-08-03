from __future__ import annotations

from typing import Any, Dict

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent
from cyberdeck.utils.dates import age_days
from cyberdeck.utils.http import HttpClient


class GithubAdvisoriesCollector(Collector):
    name = "GitHub Security Advisories"

    def __init__(self, api: str):
        self.api = api
        self.http = HttpClient()

    async def collect(self) -> CollectionResult:
        try:
            data = await self.http.get_json(
                f"{self.api}?per_page=40&sort=published&direction=desc",
                headers={"Accept": "application/vnd.github+json"},
            )
            events = [_event_from_advisory(item) for item in data if isinstance(item, dict)]
            return CollectionResult(
                SourceStatus(name=self.name, status="ok", records=len(events), mode="real"),
                events,
            )
        except Exception as exc:
            return CollectionResult(
                SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning=str(exc)),
                [],
            )


def _event_from_advisory(item: Dict[str, Any]) -> ThreatEvent:
    cve = item.get("cve_id")
    ghsa = item.get("ghsa_id") or item.get("id") or "GHSA"
    severity_text = str(item.get("severity") or "").lower()
    severity = {
        "critical": 0.95,
        "high": 0.78,
        "medium": 0.52,
        "low": 0.25,
    }.get(severity_text, 0.50)
    cvss_data = item.get("cvss") if isinstance(item.get("cvss"), dict) else {}
    cvss_score = float(cvss_data.get("score") or 0.0)
    cvss_vector = str(cvss_data.get("vector_string") or "")
    return ThreatEvent(
        id=str(ghsa),
        title=str(item.get("summary") or f"GitHub advisory {ghsa}")[:240],
        category="vulnerability",
        source="GitHub Security Advisories",
        source_weight=0.75,
        confidence=0.82,
        age_days=age_days(item.get("published_at")),
        severity=severity,
        epss=0.0,
        cvss=cvss_score,
        cve=cve,
        actor="unknown",
        technique="T1190",
        tags=["github_advisory", "open_source"],
        evidence_url=item.get("html_url") or item.get("url"),
        demo=False,
        technical_validation={
            "validation_method": "github_security_advisory_api",
            "validation_result": "public_advisory_record",
            "direct_relationship": False,
            "cvss_vector": cvss_vector,
            "cvss_score": cvss_score,
            "does_not_demonstrate": "dependency presence or affected version in the analysed organization",
        },
    )
