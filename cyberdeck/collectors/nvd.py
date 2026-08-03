from __future__ import annotations

import os
from typing import Iterable, List

from cyberdeck.analysis.vulnerability_scoring import calculate_cvss_v4
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
                cvss = _extract_cvss(metrics)
                affected_configurations = _extract_affected_configurations(cve_data.get("configurations", []))
                events.append(
                    ThreatEvent(
                        id=f"NVD-{cve}",
                        title=f"NVD enrichment for {cve}",
                        category="vulnerability",
                        source=self.name,
                        source_weight=0.85,
                        confidence=0.82,
                        age_days=0,
                        severity=min(1.0, float(cvss["score"] or 0.0) / 10),
                        epss=0.0,
                        cvss=float(cvss["score"] or 0.0),
                        cve=cve,
                        actor="unknown",
                        technique="T1190",
                        tags=["nvd", f"cvss:{cvss['version']}"] if cvss["version"] else ["nvd"],
                        evidence_url=self.api,
                        demo=False,
                        technical_validation={
                            "validation_method": "nvd_cve_api",
                            "validation_result": "official_vulnerability_record",
                            "direct_relationship": False,
                            "cvss_version": cvss["version"],
                            "cvss_vector": cvss["vector"],
                            "cvss_score": cvss["score"],
                            "cvss_severity": cvss["severity"],
                            "cvss_v4_calculation": cvss["calculation"],
                            "affected_configurations": affected_configurations,
                            "does_not_demonstrate": "product version applicability or asset exposure",
                        },
                    )
                )
            return CollectionResult(SourceStatus(name=self.name, status="ok", records=len(events), mode="real"), events)
        except Exception as exc:
            status = SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning=str(exc))
            return CollectionResult(status, [])


def _extract_affected_configurations(configurations: object) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    def visit(value: object) -> None:
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, dict):
            return
        for match in value.get("cpeMatch", []) if isinstance(value.get("cpeMatch"), list) else []:
            if not isinstance(match, dict) or match.get("vulnerable") is not True:
                continue
            criteria = str(match.get("criteria") or "")
            parts = criteria.split(":")
            if len(parts) < 6:
                continue
            rows.append(
                {
                    "criteria": criteria,
                    "vendor": parts[3].replace("_", " "),
                    "product": parts[4].replace("_", " "),
                    "version": parts[5],
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding"),
                }
            )
        visit(value.get("nodes", []))

    visit(configurations)
    unique: dict[tuple[object, ...], dict[str, object]] = {}
    for row in rows:
        key = tuple(row.get(name) for name in sorted(row))
        unique[key] = row
    return list(unique.values())[:100]


def _extract_cvss(metrics: dict) -> dict[str, object]:
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        values = metrics.get(key) or []
        if values:
            data = values[0].get("cvssData", {})
            vector = str(data.get("vectorString") or "")
            score = float(data.get("baseScore") or 0.0)
            calculation = calculate_cvss_v4(vector) if version == "4.0" else {
                "status": "not_cvss_v4",
                "score": None,
                "vector": vector,
                "model_version": f"CVSS-{version}",
            }
            if version == "4.0" and calculation.get("status") == "calculated":
                calculated_score = float(calculation.get("score") or 0.0)
                calculation["matches_published_score"] = abs(calculated_score - score) < 0.05
            return {
                "score": score,
                "vector": vector,
                "version": version,
                "severity": data.get("baseSeverity") or values[0].get("baseSeverity"),
                "calculation": calculation,
            }
    return {"score": 0.0, "vector": "", "version": "", "severity": None, "calculation": None}
