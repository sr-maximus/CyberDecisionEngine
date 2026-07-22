from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List, Optional

import httpx

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent


class RansomwareLiveCollector(Collector):
    name = "Indice dark web autorizado"

    def __init__(
        self,
        search_terms: Iterable[str],
        enabled: bool = True,
        max_records: int = 30,
        country_filter: Optional[str] = None,
    ):
        self.search_terms = [term for term in search_terms if term]
        self.enabled = enabled
        self.max_records = max(1, int(max_records))
        self.country_filter = country_filter

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"))
        events: List[ThreatEvent] = []
        warnings: List[str] = []
        async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers={"User-Agent": "CyberDecisionEngine/1.0"}) as client:
            if self.country_filter:
                try:
                    response = await client.get("https://api.ransomware.live/v2/recentvictims")
                    response.raise_for_status()
                    events.extend(_events_from_rows(response.json(), "recentvictims", self.max_records, self.country_filter))
                except Exception as exc:  # pragma: no cover - network dependent
                    warnings.append(f"recentvictims: {exc}")
            else:
                warnings.append("recentvictims skipped: no country scope declared; target-specific search terms only")
            for term in self.search_terms:
                if len(events) >= self.max_records:
                    break
                try:
                    response = await client.get(f"https://api.ransomware.live/v2/searchvictims/{term}")
                    if response.status_code == 404:
                        warnings.append(f"{term}: no victims found")
                        continue
                    response.raise_for_status()
                    events.extend(_events_from_rows(response.json(), f"search:{term}", self.max_records - len(events), None))
                except Exception as exc:  # pragma: no cover - network dependent
                    warnings.append(f"{term}: {exc}")
        unique = _dedupe(events)[: self.max_records]
        soft_warnings = [warning for warning in warnings if "no victims found" in warning or "recentvictims skipped" in warning]
        hard_warnings = [warning for warning in warnings if warning not in soft_warnings]
        if unique:
            status = "partial" if hard_warnings else "ok"
        elif self.search_terms or self.country_filter:
            status = "searched" if not hard_warnings else "partial"
            warnings = [
                f"Indice publico de ransomware/dark web consultado para {len(self.search_terms)} terminos; no se encontraron victimas coincidentes."
            ] + hard_warnings[:3]
        else:
            status = "skipped"
            warnings.append("No search terms or country scope were configured.")
        return CollectionResult(
            SourceStatus(name=self.name, status=status, records=len(unique), mode="real", warning="; ".join(warnings[:8]) or None),
            unique,
        )


def _events_from_rows(rows: object, query: str, limit: int, country_filter: Optional[str]) -> List[ThreatEvent]:
    if not isinstance(rows, list):
        return []
    events: List[ThreatEvent] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        country = str(row.get("country") or "").upper()
        if country_filter and country != country_filter.upper():
            continue
        victim = str(row.get("victim") or row.get("post_title") or "Ransomware victim")
        group = str(row.get("group") or "unknown")
        claim_url = str(row.get("claim_url") or "")
        has_onion = ".onion" in claim_url
        title_suffix = "onion claim metadata present" if has_onion else "clearweb ransomware index"
        attack_date = row.get("attackdate") or row.get("discovered")
        events.append(
            ThreatEvent(
                id=f"RANSOMLIVE-{abs(hash((query, victim, group, index))) % 10_000_000}",
                title=f"Indice dark web autorizado {query}: {victim} / {group} ({title_suffix})",
                category="darkweb_ransomware",
                source="Indice dark web autorizado",
                source_weight=0.74,
                confidence=0.62,
                age_days=_age_days(attack_date),
                severity=0.72,
                epss=0.04,
                cvss=0.0,
                actor=group,
                technique="T1486",
                tags=["darkweb_index", "ransomware", "tor_onion_metadata" if has_onion else "clearweb_index", f"query:{query}", f"country:{country or 'unknown'}"],
                evidence_url=row.get("url") or "https://www.ransomware.live/",
                observed_at=_date_or_now(attack_date),
                demo=False,
            )
        )
        if len(events) >= limit:
            break
    return events


def _dedupe(events: List[ThreatEvent]) -> List[ThreatEvent]:
    seen = set()
    unique: List[ThreatEvent] = []
    for event in events:
        key = (event.title.lower(), event.evidence_url)
        if key in seen:
            continue
        seen.add(key)
        unique.append(event)
    return unique


def _date_or_now(value: object) -> str:
    parsed = _parse_date(value)
    return (parsed or datetime.now(timezone.utc)).isoformat()


def _age_days(value: object) -> int:
    parsed = _parse_date(value)
    if parsed is None:
        return 0
    return max(0, (datetime.now(timezone.utc) - parsed).days)


def _parse_date(value: object) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None
